// Copyright (C) 2020-2023 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
// MA 02110-1301, USA.

use crate::error::Error as ClamError;
use clamav_sys::cl_engine_field;
use clamav_sys::{cl_error_t, time_t};
use core::num;
use derivative::Derivative;
use std::ffi::NulError;
use std::{path::Path, pin::Pin, sync::Arc, time};

#[cfg(windows)]
use crate::windows_fd::WindowsFd;

use {tokio::sync::RwLock, tokio_stream::wrappers::ReceiverStream};

/// Stats of a loaded database
#[derive(Debug)]
pub struct DatabaseStats {
    /// The total number of loaded signatures
    pub signature_count: u32,
}

#[derive(Debug)]
pub enum ScanResult {
    /// Clean result
    Clean,
    /// Whitelisted result
    Whitelisted,
    /// Virus result, with detected name
    Virus(String),
}

impl ScanResult {
    pub(crate) fn from_ffi(scan_result: cl_error_t, c_virname: *const i8) -> Result<Self, Error> {
        use std::ffi::CStr;

        match scan_result {
            cl_error_t::CL_CLEAN => Ok(Self::Clean),
            cl_error_t::CL_BREAK => Ok(Self::Whitelisted),
            cl_error_t::CL_VIRUS => unsafe {
                Ok(ScanResult::Virus(
                    CStr::from_ptr(c_virname).to_string_lossy().to_string(),
                ))
            },
            code => Err(ClamError::new(code).into()),
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub enum ScanEvent {
    PreScan {
        file: Option<std::fs::File>,
        file_type: String,
    },
    MatchFound {
        file: Option<std::fs::File>,
        name: String,
    },
    PostScan {
        file: Option<std::fs::File>,
        result: isize,
        match_name: String,
    },
    FileInspect {
        ancestors: Vec<Option<String>>,
        file_name: Option<String>,
        file_size: usize,
        file_type: String,
        #[derivative(Debug = "ignore")]
        content: Option<Pin<Box<dyn tokio::io::AsyncRead + Send>>>,
        #[derivative(Debug = "ignore")]
        layer_attrs: crate::layer_attr::LayerAttributes,
        parent_file_size: usize,
        recursion_level: u32,
    },
    Result(Result<ScanResult, Error>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ValueType {
    U32,
    U64,
    String,
    Time,
}

#[derive(Debug)]
pub struct ClamTime(time_t);

impl ClamTime {
    #[must_use]
    // This function can't actually panic unless ClamTime (which is a time_t) is
    // somehow larger than a u64
    #[allow(clippy::missing_panics_doc)]
    pub fn as_system_time(&self) -> time::SystemTime {
        if self.0 >= 0 {
            time::UNIX_EPOCH + time::Duration::from_secs(u64::try_from(self.0).unwrap())
        } else {
            time::UNIX_EPOCH - time::Duration::from_secs(u64::try_from(-self.0).unwrap())
        }
    }
}

#[derive(Debug)]
pub enum SettingsValue {
    U32(u32),
    U64(u64),
    String(String),
    Time(ClamTime),
}

#[derive(Clone)]
/// Engine used for scanning files
pub struct Engine {
    handle: Arc<RwLock<EngineHandle>>,
}

pub(crate) struct EngineHandle(*mut clamav_sys::cl_engine);

impl EngineHandle {
    pub(crate) fn as_ptr(&self) -> *mut clamav_sys::cl_engine {
        self.0
    }
}

// # Safety
//
// libclamav docs claim that the engine is thread-safe *provided* that its
// options are not changed.  These checks are enforced within this crate.
unsafe impl Send for EngineHandle {}
unsafe impl Sync for EngineHandle {}

/// All errors that can be reported during engine configuration and execution.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("libclamav error: {0}")]
    Clam(#[from] ClamError),

    #[error("join error: {0}")]
    Join(#[from] tokio::task::JoinError),

    #[error("string provided contains embedded NUL")]
    Nul(#[from] NulError),

    #[error("unable to cast number: {0}")]
    TryFromInt(#[from] num::TryFromIntError),
}

impl Engine {
    /// Initialises the engine
    pub fn new() -> Self {
        unsafe {
            let handle = clamav_sys::cl_engine_new();

            // Set up some callbacks

            {
                use crate::callback;

                clamav_sys::cl_engine_set_clcb_pre_scan(handle, Some(callback::engine_pre_scan));
                clamav_sys::cl_engine_set_clcb_virus_found(
                    handle,
                    Some(callback::engine_virus_found),
                );
                clamav_sys::cl_engine_set_clcb_post_scan(handle, Some(callback::engine_post_scan));
                clamav_sys::cl_engine_set_clcb_file_inspection(
                    handle,
                    Some(callback::engine_file_inspection),
                );
            }

            Engine {
                handle: Arc::new(RwLock::new(EngineHandle(handle))),
            }
        }
    }

    /// Obtain a new reference to the wrapped `EngineHandle`.  It must still be
    /// locked prior to use.
    fn handle(&self) -> Arc<RwLock<EngineHandle>> {
        self.handle.clone()
    }

    /// Compile the loaded signatures
    pub async fn compile(&self) -> Result<(), Error> {
        let engine_handle = self.handle();
        tokio::task::spawn_blocking(move || ffi::compile(engine_handle.blocking_write().as_ptr()))
            .await?
    }

    /// An extended version of `compile()` that streams [`crate::callback::Progress`] events (concluding with a
    /// [`crate::callback::Progress::Result`] event).

    pub fn compile_with_progress(
        &mut self,
    ) -> tokio_stream::wrappers::ReceiverStream<crate::callback::Progress<(), Error>> {
        let (sender, receiver) = tokio::sync::mpsc::channel(128);
        let engine_handle = self.handle();

        tokio::task::spawn_blocking(move || unsafe {
            let engine_handle = engine_handle.blocking_write();
            let context = Box::into_raw(Box::new(sender));

            clamav_sys::cl_engine_set_clcb_engine_compile_progress(
                engine_handle.as_ptr(),
                Some(crate::callback::progress),
                context.cast::<libc::c_void>(),
            );

            let result = ffi::compile(engine_handle.as_ptr()).map_err(Error::from);

            // Clear the pointer from the libclamav engine context
            clamav_sys::cl_engine_set_clcb_engine_compile_progress(
                engine_handle.as_ptr(),
                None,
                std::ptr::null_mut(),
            );

            // Reclaim the sender
            let sender = Box::from_raw(context);
            sender.blocking_send(crate::callback::Progress::Complete(result))
        });

        receiver.into()
    }

    pub async fn load_databases<'a, P>(&self, dbpath: &'a P) -> Result<DatabaseStats, Error>
    where
        P: 'a + ?Sized + AsRef<Path>,
    {
        let engine_handle = self.handle();
        let dbpath = dbpath.as_ref().to_owned();
        tokio::task::spawn_blocking(move || {
            let engine_handle = engine_handle.blocking_write();
            let result = ffi::load_databases(dbpath.as_ref(), engine_handle.as_ptr());
            result
        })
        .await
        .map_err(Error::from)?
    }

    /// An extended version of `load_databases()` that streams [`crate::callback::Progress`] events (concluding with
    /// a [`crate::callback::Progress::Result`] event).
    pub fn load_databases_with_progress<'a, P>(
        &mut self,
        dbpath: &'a P,
    ) -> tokio_stream::wrappers::ReceiverStream<crate::callback::Progress<DatabaseStats, Error>>
    where
        P: 'a + ?Sized + AsRef<Path>,
    {
        let dbpath = dbpath.as_ref().to_owned();

        let (sender, receiver) = tokio::sync::mpsc::channel(128);
        let engine_handle = self.handle();

        tokio::task::spawn_blocking(move || unsafe {
            let engine_handle = engine_handle.blocking_write();
            let context = Box::into_raw(Box::new(sender));
            clamav_sys::cl_engine_set_clcb_sigload_progress(
                engine_handle.as_ptr(),
                Some(crate::callback::progress),
                context.cast::<libc::c_void>(),
            );

            let load_db_result =
                ffi::load_databases(dbpath.as_ref(), engine_handle.as_ptr()).map_err(Error::from);

            // Reclaim the sender
            let sender = Box::from_raw(context);
            let final_result =
                sender.blocking_send(crate::callback::Progress::Complete(load_db_result));

            // Clear the pointer from the libclamav engine context
            clamav_sys::cl_engine_set_clcb_sigload_progress(
                engine_handle.as_ptr(),
                None,
                std::ptr::null_mut(),
            );

            final_result
        });

        receiver.into()
    }

    pub fn scan<T: Into<crate::fmap::Fmap>>(
        &self,
        target: T,
        filename: Option<&str>,
        mut settings: crate::scan_settings::ScanSettings,
    ) -> Result<ReceiverStream<ScanEvent>, Error> {
        use crate::callback::ScanCbContext;
        use crate::fmap::Fmap;
        use std::ffi::CString;
        use std::os::raw::c_void;
        use std::ptr;

        let fmap: Fmap = target.into();

        let (sender, receiver) = tokio::sync::mpsc::channel::<ScanEvent>(128);
        let c_filename = filename.map(CString::new).transpose()?;
        let engine_handle = self.handle.clone();
        let fmap_handle = fmap.handle();

        // A placeholder callback that directs the file inspection callback to
        // copy content only for embedded files (and not the root document)
        //
        // This may be overridden in the future with API extensions.
        let should_copy_file_buffer = |recursion_level: u32,
                                       _file_type: &str,
                                       _file_name: Option<&str>,
                                       _file_size: usize|
         -> bool { recursion_level > 0 };

        tokio::task::spawn_blocking(move || {
            let mut c_virname = ptr::null();
            let scan_cb_context = ScanCbContext {
                sender: sender.clone(),
                should_copy_file_buffer: Some(Box::new(should_copy_file_buffer)),
            };
            let c_sender = Box::into_raw(Box::new(scan_cb_context));
            let c_filename = c_filename.map_or(ptr::null(), |n| n.as_ptr());
            let fmap_guard = fmap_handle.blocking_lock();

            let retval = unsafe {
                clamav_sys::cl_scanmap_callback(
                    fmap_guard.fmap,
                    c_filename,
                    &mut c_virname,
                    ptr::null_mut(),
                    engine_handle.blocking_read().as_ptr(),
                    &mut settings.settings,
                    c_sender.cast::<c_void>(),
                )
            };
            // Reclaim the sender from C-land and send a final message
            let scan_cb_cxt = unsafe { Box::from_raw(c_sender) };
            // Try to send back the final result, silently ignoring any failure
            // (as the receiving task may disappear during shutdown)
            let _ = scan_cb_cxt
                .sender
                .blocking_send(ScanEvent::Result(ScanResult::from_ffi(retval, c_virname)));
        });

        Ok(receiver.into())
    }

    async fn get(&self, field: cl_engine_field) -> Result<SettingsValue, Error> {
        let engine_handle = self.handle();
        let engine_handle = engine_handle.read().await;
        ffi::get(engine_handle.as_ptr(), field)
    }

    async fn set(&self, field: cl_engine_field, value: SettingsValue) -> Result<(), Error> {
        dbg!(&field, &value);
        let engine_handle = self.handle.write().await;
        ffi::set(engine_handle.as_ptr(), field, value).map_err(Error::from)
    }

    pub async fn database_version(&self) -> Result<u32, Error> {
        if let SettingsValue::U32(value) = self.get(cl_engine_field::CL_ENGINE_DB_VERSION).await? {
            Ok(value)
        } else {
            Err(ClamError::new(cl_error_t::CL_EARG).into())
        }
    }

    pub async fn database_timestamp(&self) -> Result<time::SystemTime, Error> {
        if let SettingsValue::Time(value) = self.get(cl_engine_field::CL_ENGINE_DB_TIME).await? {
            Ok(value.as_system_time())
        } else {
            Err(ClamError::new(cl_error_t::CL_EARG).into())
        }
    }

    pub async fn disable_cache(&self, disable_cache: bool) -> Result<(), Error> {
        self.set(
            cl_engine_field::CL_ENGINE_DISABLE_CACHE,
            SettingsValue::U32(disable_cache.into()),
        )
        .await
    }

    pub async fn set_max_scansize(&self, max_scansize: u64) -> Result<(), Error> {
        self.set(
            cl_engine_field::CL_ENGINE_MAX_SCANSIZE,
            SettingsValue::U64(max_scansize),
        )
        .await
    }

    pub async fn max_scansize(&self) -> Result<u64, Error> {
        if let SettingsValue::U64(value) = self.get(cl_engine_field::CL_ENGINE_MAX_SCANSIZE).await?
        {
            Ok(value)
        } else {
            Err(ClamError::new(cl_error_t::CL_EARG).into())
        }
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for EngineHandle {
    fn drop(&mut self) {
        unsafe {
            clamav_sys::cl_engine_free(self.0);
        }
    }
}

mod ffi {
    use super::{ClamError, ClamTime, DatabaseStats, Error, SettingsValue, ValueType};
    use clamav_sys::{
        cl_engine_field, cl_engine_get_num, cl_engine_get_str, cl_engine_set_num,
        cl_engine_set_str, cl_error_t, cl_load, time_t, CL_DB_STDOPT,
    };
    use std::{
        ffi::{CStr, CString},
        mem,
        os::{raw::c_int, unix::prelude::OsStrExt},
        path::Path,
    };

    pub(super) fn compile(handle: *mut clamav_sys::cl_engine) -> Result<(), Error> {
        unsafe {
            let result = clamav_sys::cl_engine_compile(handle);
            match result {
                cl_error_t::CL_SUCCESS => Ok(()),
                _ => Err(ClamError::new(result).into()),
            }
        }
    }

    pub(super) fn load_databases(
        dbpath: &Path,
        handle: *mut clamav_sys::cl_engine,
    ) -> Result<DatabaseStats, Error> {
        let raw_path = CString::new(dbpath.as_os_str().as_bytes()).unwrap();
        unsafe {
            let mut signature_count: u32 = 0;
            let result = cl_load(
                raw_path.as_ptr(),
                handle,
                &mut signature_count,
                CL_DB_STDOPT,
            );
            match result {
                cl_error_t::CL_SUCCESS => Ok(DatabaseStats { signature_count }),
                _ => Err(ClamError::new(result).into()),
            }
        }
    }

    pub(super) fn get(
        engine_handle: *mut clamav_sys::cl_engine,
        field: cl_engine_field,
    ) -> Result<SettingsValue, Error> {
        unsafe {
            match get_field_type(field) {
                ValueType::U32 => {
                    let mut err: c_int = 0;
                    let value: u32 =
                        cl_engine_get_num(engine_handle, field, &mut err).try_into()?;
                    if err == 0 {
                        Ok(SettingsValue::U32(value))
                    } else {
                        Err(ClamError::new(mem::transmute(err)).into())
                    }
                }
                ValueType::U64 => {
                    let mut err: c_int = 0;
                    let value = cl_engine_get_num(engine_handle, field, &mut err)
                        .try_into()
                        .expect("cast i64 to u64");
                    if err == 0 {
                        Ok(SettingsValue::U64(value))
                    } else {
                        Err(ClamError::new(mem::transmute(err)).into())
                    }
                }
                ValueType::String => {
                    let mut err = 0;
                    let value = cl_engine_get_str(engine_handle, field, &mut err);
                    if err == 0 {
                        Ok(SettingsValue::String(
                            CStr::from_ptr(value).to_str().unwrap().to_string(),
                        ))
                    } else {
                        Err(ClamError::new(mem::transmute(err)).into())
                    }
                }
                ValueType::Time => {
                    let mut err = 0;
                    let value = cl_engine_get_num(engine_handle, field, &mut err) as time_t;
                    if err == 0 {
                        Ok(SettingsValue::Time(ClamTime(value)))
                    } else {
                        Err(ClamError::new(mem::transmute(err)).into())
                    }
                }
            }
        }
    }

    pub(super) fn set(
        engine_handle: *mut clamav_sys::cl_engine,
        field: cl_engine_field,
        value: SettingsValue,
    ) -> Result<(), Error> {
        let expected_type = get_field_type(field);
        let actual_type = match &value {
            SettingsValue::U32(_) => ValueType::U32,
            SettingsValue::U64(_) => ValueType::U64,
            SettingsValue::String(_) => ValueType::String,
            SettingsValue::Time(_) => ValueType::Time,
        };

        if expected_type != actual_type {
            return Err(ClamError::new(cl_error_t::CL_EARG).into());
        }

        unsafe {
            match value {
                SettingsValue::U32(val) => {
                    let err = cl_engine_set_num(
                        engine_handle,
                        field,
                        val.try_into().expect("cast u32 to i64"),
                    );
                    if err == cl_error_t::CL_SUCCESS {
                        Ok(())
                    } else {
                        Err(ClamError::new(err).into())
                    }
                }
                SettingsValue::U64(val) => {
                    let err = cl_engine_set_num(
                        engine_handle,
                        field,
                        val.try_into().expect("cast u64 to i64"),
                    );
                    if err == cl_error_t::CL_SUCCESS {
                        Ok(())
                    } else {
                        Err(ClamError::new(err).into())
                    }
                }
                SettingsValue::String(val) => {
                    let val = CString::new(val).unwrap();
                    let err = cl_engine_set_str(engine_handle, field, val.as_ptr());
                    if err == cl_error_t::CL_SUCCESS {
                        Ok(())
                    } else {
                        Err(ClamError::new(err).into())
                    }
                }
                SettingsValue::Time(ClamTime(val)) => {
                    let err = cl_engine_set_num(engine_handle, field, val);
                    if err == cl_error_t::CL_SUCCESS {
                        Ok(())
                    } else {
                        Err(ClamError::new(err).into())
                    }
                }
            }
        }
    }

    fn get_field_type(field: cl_engine_field) -> ValueType {
        match field {
            cl_engine_field::CL_ENGINE_MAX_SCANSIZE | cl_engine_field::CL_ENGINE_MAX_FILESIZE => {
                ValueType::U64
            }
            cl_engine_field::CL_ENGINE_PUA_CATEGORIES | cl_engine_field::CL_ENGINE_TMPDIR => {
                ValueType::String
            }
            cl_engine_field::CL_ENGINE_DB_TIME => ValueType::Time,
            cl_engine_field::CL_ENGINE_MAX_RECURSION
            | cl_engine_field::CL_ENGINE_MAX_FILES
            | cl_engine_field::CL_ENGINE_MIN_CC_COUNT
            | cl_engine_field::CL_ENGINE_MIN_SSN_COUNT
            | cl_engine_field::CL_ENGINE_DB_OPTIONS
            | cl_engine_field::CL_ENGINE_DB_VERSION
            | cl_engine_field::CL_ENGINE_AC_ONLY
            | cl_engine_field::CL_ENGINE_AC_MINDEPTH
            | cl_engine_field::CL_ENGINE_AC_MAXDEPTH
            | cl_engine_field::CL_ENGINE_KEEPTMP
            | cl_engine_field::CL_ENGINE_BYTECODE_SECURITY
            | cl_engine_field::CL_ENGINE_BYTECODE_TIMEOUT
            | cl_engine_field::CL_ENGINE_BYTECODE_MODE
            | cl_engine_field::CL_ENGINE_DISABLE_PE_CERTS
            | cl_engine_field::CL_ENGINE_PE_DUMPCERTS
            | cl_engine_field::CL_ENGINE_FORCETODISK
            | cl_engine_field::CL_ENGINE_DISABLE_CACHE
            | cl_engine_field::CL_ENGINE_DISABLE_PE_STATS
            | cl_engine_field::CL_ENGINE_STATS_TIMEOUT
            | cl_engine_field::CL_ENGINE_MAX_PARTITIONS
            | cl_engine_field::CL_ENGINE_MAX_ICONSPE
            | cl_engine_field::CL_ENGINE_MAX_RECHWP3
            | cl_engine_field::CL_ENGINE_MAX_SCANTIME => ValueType::U32,
            cl_engine_field::CL_ENGINE_MAX_EMBEDDEDPE
            | cl_engine_field::CL_ENGINE_MAX_HTMLNORMALIZE
            | cl_engine_field::CL_ENGINE_MAX_HTMLNOTAGS
            | cl_engine_field::CL_ENGINE_MAX_SCRIPTNORMALIZE
            | cl_engine_field::CL_ENGINE_MAX_ZIPTYPERCG
            | cl_engine_field::CL_ENGINE_PCRE_MATCH_LIMIT
            | cl_engine_field::CL_ENGINE_PCRE_RECMATCH_LIMIT
            | cl_engine_field::CL_ENGINE_PCRE_MAX_FILESIZE => ValueType::U64,
            field => panic!("{field:?} not yet supported"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DATABASES_PATH: &str = "test_data/database/";
    const EXAMPLE_DATABASE_PATH: &str = "test_data/database/example.cud";

    #[tokio::test]
    async fn compile_empty_engine_success() {
        crate::initialize().expect("initialize should succeed");
        let scanner = Engine::new();
        assert!(scanner.compile().await.is_ok(), "compile should succeed");
    }

    #[tokio::test]
    async fn load_databases_success() {
        crate::initialize().expect("initialize should succeed");
        let scanner = Engine::new();
        let result = scanner.load_databases(TEST_DATABASES_PATH).await;
        assert!(result.is_ok(), "load should succeed");
        assert!(
            result.unwrap().signature_count > 0,
            "should load some signatures"
        );
    }

    #[tokio::test]
    async fn load_databases_with_file_success() {
        crate::initialize().expect("initialize should succeed");
        let scanner = Engine::new();
        let result = scanner.load_databases(EXAMPLE_DATABASE_PATH).await;
        assert!(result.is_ok(), "load should succeed");
        assert!(
            result.unwrap().signature_count > 0,
            "should load some signatures"
        );
    }

    #[tokio::test]
    async fn load_databases_fake_path_fails() {
        crate::initialize().expect("initialize should succeed");
        let scanner = Engine::new();
        assert!(
            scanner.load_databases("/dev/null").await.is_err(),
            "should fail to load invalid databases"
        );
    }
}
