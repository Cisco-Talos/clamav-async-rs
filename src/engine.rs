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
use clamav_sys::{
    cl_error_t, cl_verdict_t, cl_verdict_t_CL_VERDICT_NOTHING_FOUND,
    cl_verdict_t_CL_VERDICT_POTENTIALLY_UNWANTED, cl_verdict_t_CL_VERDICT_STRONG_INDICATOR,
    cl_verdict_t_CL_VERDICT_TRUSTED, time_t,
};
use core::num;
use derivative::Derivative;
use std::ffi::{c_char, NulError};
use std::{
    path::Path,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time,
};

use tokio_stream::wrappers::ReceiverStream;

/// Summary information returned after loading a signature database.
#[derive(Debug)]
pub struct DatabaseStats {
    /// The total number of loaded signatures
    pub signature_count: u32,
}

/// Final result of a scan after libclamav completes.
#[derive(Debug)]
pub enum ScanResult {
    /// No matches were found for the scanned target.
    NothingFound,
    /// Trusted result
    Trusted,
    /// Match found result, with detected name
    MatchFound(String),
}

impl ScanResult {
    #[allow(non_upper_case_globals)]
    pub(crate) fn from_ffi(
        scan_result: cl_error_t,
        verdict: cl_verdict_t,
        last_match: *const c_char,
    ) -> Result<Self, Error> {
        use std::ffi::CStr;

        match verdict {
            cl_verdict_t_CL_VERDICT_NOTHING_FOUND => {
                // cl_scanmap_ex returns CL_SUCCESS even for hits; only treat
                // non-success as an error when nothing was found.
                if scan_result != cl_error_t::CL_SUCCESS {
                    Err(ClamError::new(scan_result).into())
                } else {
                    Ok(Self::NothingFound)
                }
            }

            cl_verdict_t_CL_VERDICT_TRUSTED => Ok(Self::Trusted),

            cl_verdict_t_CL_VERDICT_STRONG_INDICATOR
            | cl_verdict_t_CL_VERDICT_POTENTIALLY_UNWANTED => unsafe {
                if last_match.is_null() {
                    Ok(ScanResult::MatchFound(String::from("Unknown")))
                } else {
                    Ok(ScanResult::MatchFound(
                        CStr::from_ptr(last_match).to_string_lossy().to_string(),
                    ))
                }
            },

            _ => Ok(Self::NothingFound),
        }
    }
}

/// Streamed event emitted during scanning.
///
/// The scan APIs return a stream of these values so callers can observe nested
/// layer activity and the terminal scan result in one sequence.
#[derive(Derivative)]
#[derivative(Debug)]
pub enum ScanEvent {
    /// A match was reported for a scan layer.
    MatchFound {
        entity_id: u64,
        ancestors: Vec<u64>,
        sha2_256: String,
        file_name: Option<String>,
        file_size: usize,
        file_type: String,
        match_name: String,
    },
    /// libclamav identified the type of a scan layer.
    FileType {
        entity_id: u64,
        ancestors: Vec<u64>,
        file_name: Option<String>,
        file_size: usize,
        file_type: String,
    },
    /// A scan layer is about to be scanned.
    PreScan {
        entity_id: u64,
        ancestors: Vec<u64>,
        sha2_256: String,
        file_name: Option<String>,
        file_size: usize,
        file_type: String,
    },
    /// A scan layer has finished scanning.
    PostScan {
        entity_id: u64,
        ancestors: Vec<u64>,
        sha2_256: String,
        file_name: Option<String>,
        file_size: usize,
        file_type: String,
    },
    /// The terminal scan result.
    Result(Result<ScanResult, Error>),
}

/// The libclamav type of an engine setting value.
#[derive(Debug, PartialEq, Eq)]
pub enum ValueType {
    /// A 32-bit unsigned integer.
    U32,
    /// A 64-bit unsigned integer.
    U64,
    /// A string value.
    String,
    /// A `time_t` value.
    Time,
}

/// Wrapper around libclamav `time_t` configuration values.
#[derive(Debug)]
pub struct ClamTime(time_t);

impl ClamTime {
    #[must_use]
    // This function can't actually panic unless ClamTime (which is a time_t) is
    // somehow larger than a u64
    #[allow(clippy::missing_panics_doc)]
    /// Converts the wrapped `time_t` to [`std::time::SystemTime`].
    pub fn as_system_time(&self) -> time::SystemTime {
        if self.0 >= 0 {
            time::UNIX_EPOCH + time::Duration::from_secs(u64::try_from(self.0).unwrap())
        } else {
            time::UNIX_EPOCH - time::Duration::from_secs(u64::try_from(-self.0).unwrap())
        }
    }
}

/// Typed representation of an engine setting value.
#[derive(Debug)]
pub enum SettingsValue {
    /// A 32-bit unsigned integer setting.
    U32(u32),
    /// A 64-bit unsigned integer setting.
    U64(u64),
    /// A string setting.
    String(String),
    /// A time setting.
    Time(ClamTime),
}

/// Configured libclamav engine used to load databases and scan content.
///
/// Create the engine with [`Engine::new`], load databases, compile it, and then
/// reuse it across scans.
///
/// Treat engine setup as a single-threaded phase: load databases, register
/// callbacks, adjust engine settings, and compile before sharing the engine
/// across threads or using it for scans. Once the engine is in active use,
/// mutation APIs are not intended to be called concurrently.
pub struct Engine {
    handle: Arc<RwLock<EngineHandle>>,
    pre_scan_logic: Option<Arc<dyn std::any::Any + Send + Sync>>,
    post_scan_logic: Option<Arc<dyn std::any::Any + Send + Sync>>,
    file_type_logic: Option<Arc<dyn std::any::Any + Send + Sync>>,
    match_logic: Option<Arc<dyn std::any::Any + Send + Sync>>,
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

fn read_engine_handle(lock: &RwLock<EngineHandle>) -> RwLockReadGuard<'_, EngineHandle> {
    match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn write_engine_handle(lock: &RwLock<EngineHandle>) -> RwLockWriteGuard<'_, EngineHandle> {
    match lock.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

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
    /// Creates a new unconfigured engine.
    pub fn new() -> Self {
        unsafe {
            let handle = clamav_sys::cl_engine_new();

            Engine {
                handle: Arc::new(RwLock::new(EngineHandle(handle))),
                pre_scan_logic: None,
                post_scan_logic: None,
                file_type_logic: None,
                match_logic: None,
            }
        }
    }

    /// Registers a callback to be invoked during future scans.
    ///
    /// Register callbacks before calling [`Engine::scan`]. Registering a new
    /// callback for the same hook replaces the previously stored callback.
    ///
    /// This is part of engine setup and is expected to be called before the
    /// engine is shared across threads or used for scans or compilation work.
    /// Calling it concurrently with other engine operations is not supported.
    ///
    /// Current behavior: if the engine is in use, this method blocks until it
    /// can take exclusive access to register the callback.
    pub fn register_callback(
        &mut self,
        callback: crate::callback::EngineCallback,
        operation: Box<crate::callback::ScanLayerLogic>,
    ) {
        use crate::callback;
        let engine_handle = write_engine_handle(self.handle.as_ref());

        unsafe {
            match callback {
                callback::EngineCallback::PreScan => {
                    self.pre_scan_logic = Some(Arc::new(operation));
                    let cb = crate::callback::engine_callback_pre_scan;
                    clamav_sys::cl_engine_set_scan_callback(
                        engine_handle.as_ptr(),
                        Some(cb),
                        clamav_sys::scan_callback_CL_SCAN_CALLBACK_PRE_SCAN,
                    );
                }
                callback::EngineCallback::PostScan => {
                    self.post_scan_logic = Some(Arc::new(operation));
                    let cb = crate::callback::engine_callback_post_scan;
                    clamav_sys::cl_engine_set_scan_callback(
                        engine_handle.as_ptr(),
                        Some(cb),
                        clamav_sys::scan_callback_CL_SCAN_CALLBACK_POST_SCAN,
                    );
                }
                callback::EngineCallback::FileType => {
                    self.file_type_logic = Some(Arc::new(operation));
                    let cb = crate::callback::engine_callback_file_type;
                    clamav_sys::cl_engine_set_scan_callback(
                        engine_handle.as_ptr(),
                        Some(cb),
                        clamav_sys::scan_callback_CL_SCAN_CALLBACK_FILE_TYPE,
                    );
                }
                callback::EngineCallback::Match => {
                    self.match_logic = Some(Arc::new(operation));
                    let cb = crate::callback::engine_callback_match;
                    clamav_sys::cl_engine_set_scan_callback(
                        engine_handle.as_ptr(),
                        Some(cb),
                        clamav_sys::scan_callback_CL_SCAN_CALLBACK_ALERT,
                    );
                }
            }
        }
    }

    /// Obtain a new reference to the wrapped `EngineHandle`.  It must still be
    /// locked prior to use.
    fn handle(&self) -> Arc<RwLock<EngineHandle>> {
        self.handle.clone()
    }

    /// Compiles the currently loaded signature databases.
    pub async fn compile(&self) -> Result<(), Error> {
        let engine_handle = self.handle();
        tokio::task::spawn_blocking(move || {
            ffi::compile(write_engine_handle(&engine_handle).as_ptr())
        })
        .await?
    }

    /// Compiles the currently loaded signatures and streams progress updates.
    pub fn compile_with_progress(
        &mut self,
    ) -> tokio_stream::wrappers::ReceiverStream<crate::callback::Progress<(), Error>> {
        let (sender, receiver) = tokio::sync::mpsc::channel(128);
        let engine_handle = self.handle();

        tokio::task::spawn_blocking(move || unsafe {
            let engine_handle = write_engine_handle(&engine_handle);
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

    /// Loads signature databases from a file or directory path.
    pub async fn load_databases<'a, P>(&self, dbpath: &'a P) -> Result<DatabaseStats, Error>
    where
        P: 'a + ?Sized + AsRef<Path>,
    {
        let engine_handle = self.handle();
        let dbpath = dbpath.as_ref().to_owned();
        tokio::task::spawn_blocking(move || {
            let engine_handle = write_engine_handle(&engine_handle);
            let result = ffi::load_databases(dbpath.as_ref(), engine_handle.as_ptr());
            result
        })
        .await
        .map_err(Error::from)?
    }

    /// Loads signature databases and streams progress updates.
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
            let engine_handle = write_engine_handle(&engine_handle);
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

    /// Scans a target and returns a stream of [`ScanEvent`] values.
    ///
    /// The scan runs on a blocking worker thread. The returned stream yields
    /// intermediate callback events followed by a terminal
    /// [`ScanEvent::Result`]. If provided, `scan_context` is forwarded as an
    /// opaque pointer to each registered scan callback for the lifetime of the
    /// scan; this crate never dereferences it.
    pub fn scan<T: Into<crate::fmap::Fmap>>(
        &self,
        target: T,
        filename: Option<&str>,
        file_type_hint: Option<&str>,
        hash_hint: Option<&str>,
        hash_algorithm: Option<&str>,
        mut settings: crate::scan_settings::ScanSettings,
        scan_context: Option<crate::callback::ScanContext>,
    ) -> Result<ReceiverStream<ScanEvent>, Error> {
        use crate::callback::ScanCbContext;
        use crate::fmap::Fmap;
        use std::ffi::CString;
        use std::os::raw::c_void;
        use std::ptr;

        let fmap: Fmap = target.into();

        let (sender, receiver) = tokio::sync::mpsc::channel::<ScanEvent>(128);
        let c_filename = filename.map(CString::new).transpose()?;
        let c_file_type_hint = file_type_hint.map(CString::new).transpose()?;
        let c_hash_hint = hash_hint.map(CString::new).transpose()?;
        let c_hash_algorithm = hash_algorithm.map(CString::new).transpose()?;
        let engine_handle = self.handle.clone();
        let fmap_handle = fmap.handle();

        let pre_scan_logic = self.pre_scan_logic.clone();
        let post_scan_logic = self.post_scan_logic.clone();
        let file_type_logic = self.file_type_logic.clone();
        let match_logic = self.match_logic.clone();

        tokio::task::spawn_blocking(move || {
            let mut verdict = cl_verdict_t_CL_VERDICT_NOTHING_FOUND;
            let mut last_match = ptr::null();
            let mut scanned_out = 0_u64;
            let scan_cb_context = ScanCbContext {
                sender: sender.clone(),
                scan_context,
                pre_scan_logic,
                post_scan_logic,
                file_type_logic,
                match_logic,
            };
            let c_sender = Box::into_raw(Box::new(scan_cb_context));
            let c_filename_ptr = c_filename.as_ref().map_or(ptr::null(), |n| n.as_ptr());
            let c_file_type_hint_ptr = c_file_type_hint
                .as_ref()
                .map_or(ptr::null(), |t| t.as_ptr());
            let c_hash_hint_ptr = c_hash_hint.as_ref().map_or(ptr::null(), |h| h.as_ptr());
            let c_hash_algorithm_ptr = c_hash_algorithm
                .as_ref()
                .map_or(ptr::null(), |h| h.as_ptr());
            let fmap_guard = fmap_handle.blocking_lock();

            let retval = unsafe {
                clamav_sys::cl_scanmap_ex(
                    fmap_guard.fmap,
                    c_filename_ptr,
                    &mut verdict,
                    &mut last_match,
                    &mut scanned_out,
                    read_engine_handle(&engine_handle).as_ptr(),
                    &mut settings.settings,
                    c_sender.cast::<c_void>(),
                    c_hash_hint_ptr,
                    ptr::null_mut(),
                    c_hash_algorithm_ptr,
                    c_file_type_hint_ptr,
                    ptr::null_mut(),
                )
            };
            // Reclaim the sender from C-land and send a final message
            let scan_cb_cxt = unsafe { Box::from_raw(c_sender) };
            // Try to send back the final result, silently ignoring any failure
            // (as the receiving task may disappear during shutdown)
            let _ = scan_cb_cxt
                .sender
                .blocking_send(ScanEvent::Result(ScanResult::from_ffi(
                    retval, verdict, last_match,
                )));
        });

        Ok(receiver.into())
    }

    async fn get(&self, field: cl_engine_field) -> Result<SettingsValue, Error> {
        let engine_handle = self.handle();
        let engine_handle = read_engine_handle(&engine_handle);
        ffi::get(engine_handle.as_ptr(), field)
    }

    async fn set(&self, field: cl_engine_field, value: SettingsValue) -> Result<(), Error> {
        dbg!(&field, &value);
        let engine_handle = write_engine_handle(self.handle.as_ref());
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
        os::raw::c_int,
        path::Path,
    };

    #[cfg(unix)]
    fn path_to_cstring(path: &Path) -> Result<CString, Error> {
        use std::os::unix::ffi::OsStrExt;

        Ok(CString::new(path.as_os_str().as_bytes())?)
    }

    #[cfg(windows)]
    fn path_to_cstring(path: &Path) -> Result<CString, Error> {
        Ok(CString::new(path.to_string_lossy().as_bytes())?)
    }

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
        #[cfg(windows)]
        if let Some(certs_dir) = std::env::var_os("CLAMAV_CVD_CERTS_DIR") {
            set(
                handle,
                cl_engine_field::CL_ENGINE_CVDCERTSDIR,
                SettingsValue::String(certs_dir.to_string_lossy().into_owned()),
            )?;
        }

        let raw_path = path_to_cstring(dbpath)?;
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
            cl_engine_field::CL_ENGINE_PUA_CATEGORIES
            | cl_engine_field::CL_ENGINE_TMPDIR
            | cl_engine_field::CL_ENGINE_CVDCERTSDIR => ValueType::String,
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
    use crate::callback;
    use std::{
        sync::{mpsc, Arc, Mutex},
        thread,
        time::Duration,
    };

    const TEST_DATABASES_PATH: &str = "test_data/database/";
    const EXAMPLE_DATABASE_PATH: &str = "test_data/database/example.cud";

    fn pre_scan_operation(hit: Arc<Mutex<bool>>) -> Box<callback::PreScanLogic> {
        Box::new(
            move |_scan_layer: &mut callback::ScanLayer, _scan_context| {
                *hit.lock().unwrap() = true;
                callback::ScanLogicResult::Success
            },
        )
    }

    fn post_scan_operation(hit: Arc<Mutex<bool>>) -> Box<callback::PostScanLogic> {
        Box::new(
            move |_scan_layer: &mut callback::ScanLayer, _scan_context| {
                *hit.lock().unwrap() = true;
                callback::ScanLogicResult::Success
            },
        )
    }

    fn file_type_operation(hit: Arc<Mutex<bool>>) -> Box<callback::FileTypeLogic> {
        Box::new(
            move |_scan_layer: &mut callback::ScanLayer, _scan_context| {
                *hit.lock().unwrap() = true;
                callback::ScanLogicResult::Success
            },
        )
    }

    fn match_operation(hit: Arc<Mutex<bool>>) -> Box<callback::MatchLogic> {
        Box::new(
            move |_scan_layer: &mut callback::ScanLayer, _scan_context| {
                *hit.lock().unwrap() = true;
                callback::ScanLogicResult::Success
            },
        )
    }

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

    #[test]
    fn register_callback_supports_pre_scan_operation() {
        crate::initialize().expect("initialize should succeed");
        let hit = Arc::new(Mutex::new(false));
        let mut engine = Engine::new();
        engine.register_callback(
            callback::EngineCallback::PreScan,
            pre_scan_operation(hit.clone()),
        );

        let logic = engine
            .pre_scan_logic
            .as_ref()
            .expect("pre-scan logic should be stored")
            .downcast_ref::<Box<callback::PreScanLogic>>()
            .expect("stored logic should have pre-scan callback type");
        let mut scan_layer = callback::ScanLayer::new(std::ptr::null_mut());
        assert_eq!(
            logic(&mut scan_layer, None),
            callback::ScanLogicResult::Success
        );
        assert!(
            *hit.lock().unwrap(),
            "registered pre-scan closure should run"
        );
    }

    #[test]
    fn register_callback_supports_file_type_operation() {
        crate::initialize().expect("initialize should succeed");
        let hit = Arc::new(Mutex::new(false));
        let mut engine = Engine::new();
        engine.register_callback(
            callback::EngineCallback::FileType,
            file_type_operation(hit.clone()),
        );

        let logic = engine
            .file_type_logic
            .as_ref()
            .expect("file-type logic should be stored")
            .downcast_ref::<Box<callback::FileTypeLogic>>()
            .expect("stored logic should have file-type callback type");
        let mut scan_layer = callback::ScanLayer::new(std::ptr::null_mut());
        assert_eq!(
            logic(&mut scan_layer, None),
            callback::ScanLogicResult::Success
        );
        assert!(
            *hit.lock().unwrap(),
            "registered file-type closure should run"
        );
    }

    #[test]
    fn register_callback_supports_post_scan_operation() {
        crate::initialize().expect("initialize should succeed");
        let hit = Arc::new(Mutex::new(false));
        let mut engine = Engine::new();
        engine.register_callback(
            callback::EngineCallback::PostScan,
            post_scan_operation(hit.clone()),
        );

        let logic = engine
            .post_scan_logic
            .as_ref()
            .expect("post-scan logic should be stored")
            .downcast_ref::<Box<callback::PostScanLogic>>()
            .expect("stored logic should have post-scan callback type");
        let mut scan_layer = callback::ScanLayer::new(std::ptr::null_mut());
        assert_eq!(
            logic(&mut scan_layer, None),
            callback::ScanLogicResult::Success
        );
        assert!(
            *hit.lock().unwrap(),
            "registered post-scan closure should run"
        );
    }

    #[test]
    fn register_callback_supports_match_operation() {
        crate::initialize().expect("initialize should succeed");
        let hit = Arc::new(Mutex::new(false));
        let mut engine = Engine::new();
        engine.register_callback(
            callback::EngineCallback::Match,
            match_operation(hit.clone()),
        );

        let logic = engine
            .match_logic
            .as_ref()
            .expect("match logic should be stored")
            .downcast_ref::<Box<callback::MatchLogic>>()
            .expect("stored logic should have match callback type");
        let mut scan_layer = callback::ScanLayer::new(std::ptr::null_mut());
        assert_eq!(
            logic(&mut scan_layer, None),
            callback::ScanLogicResult::Success
        );
        assert!(*hit.lock().unwrap(), "registered match closure should run");
    }

    #[test]
    fn register_callback_waits_for_engine_lock_instead_of_panicking() {
        crate::initialize().expect("initialize should succeed");
        let hit = Arc::new(Mutex::new(false));
        let engine = Arc::new(Mutex::new(Engine::new()));
        let handle = engine.lock().unwrap().handle();
        let (locked_tx, locked_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let lock_thread = thread::spawn(move || {
            let _guard = read_engine_handle(&handle);
            locked_tx
                .send(())
                .expect("lock acquisition signal should succeed");
            release_rx
                .recv()
                .expect("release signal receipt should succeed");
        });

        locked_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("background thread should hold the engine lock");

        let register_engine = engine.clone();
        let register_hit = hit.clone();
        let register_thread = thread::spawn(move || {
            register_engine.lock().unwrap().register_callback(
                callback::EngineCallback::PreScan,
                pre_scan_operation(register_hit),
            );
        });

        thread::sleep(Duration::from_millis(50));
        assert!(
            !register_thread.is_finished(),
            "callback registration should wait while the engine is in use"
        );

        release_tx
            .send(())
            .expect("release signal send should succeed");
        register_thread
            .join()
            .expect("registration thread should succeed");
        lock_thread.join().expect("lock thread should succeed");

        let engine = engine.lock().unwrap();
        let logic = engine
            .pre_scan_logic
            .as_ref()
            .expect("pre-scan logic should be stored after the wait")
            .downcast_ref::<Box<callback::PreScanLogic>>()
            .expect("stored logic should have pre-scan callback type");
        let mut scan_layer = callback::ScanLayer::new(std::ptr::null_mut());
        assert_eq!(
            logic(&mut scan_layer, None),
            callback::ScanLogicResult::Success
        );
        assert!(
            *hit.lock().unwrap(),
            "registered pre-scan closure should run after waiting for the lock"
        );
    }
}
