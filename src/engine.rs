use crate::error::ClamError;
use clamav_sys::cl_engine_field;
use clamav_sys::{cl_error_t, time_t};
use derivative::Derivative;
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
    pub(crate) fn from_ffi(
        scan_result: cl_error_t,
        c_virname: *const i8,
    ) -> Result<Self, ClamError> {
        use std::ffi::CStr;

        match scan_result {
            cl_error_t::CL_CLEAN => Ok(Self::Clean),
            cl_error_t::CL_BREAK => Ok(Self::Whitelisted),
            cl_error_t::CL_VIRUS => unsafe {
                Ok(ScanResult::Virus(
                    CStr::from_ptr(c_virname).to_string_lossy().to_string(),
                ))
            },
            code => Err(ClamError::new(code)),
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
        #[cfg(unix)]
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
    Result(Result<ScanResult, ClamError>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum EngineValueType {
    U32,
    U64,
    String,
    Time,
}

#[derive(Debug)]
pub struct ClamTime(time_t);

impl ClamTime {
    pub fn as_system_time(&self) -> time::SystemTime {
        if self.0 >= 0 {
            time::UNIX_EPOCH + time::Duration::from_secs(self.0 as u64)
        } else {
            time::UNIX_EPOCH - time::Duration::from_secs(-self.0 as u64)
        }
    }
}

#[derive(Debug)]
pub enum EngineValue {
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

    /// Obtain a new reference to the wrapped EngineHandle.  It must still be
    /// locked prior to use.
    fn handle(&self) -> Arc<RwLock<EngineHandle>> {
        self.handle.clone()
    }

    pub async fn compile(&self) -> Result<(), ClamError> {
        let engine_handle = self.handle();
        tokio::task::spawn_blocking(move || ffi::compile(engine_handle.blocking_write().as_ptr()))
            .await
            .expect("join thread")
    }

    /// An extended version of `compile()` that streams [crate::callback::Progress] events (concluding with a
    /// [crate::callback::Progress::Result] event).

    pub async fn compile_with_progress(
        &mut self,
    ) -> tokio_stream::wrappers::ReceiverStream<crate::callback::Progress<(), ClamError>> {
        let (sender, receiver) = tokio::sync::mpsc::channel(128);
        let engine_handle = self.handle();

        tokio::task::spawn_blocking(move || unsafe {
            let engine_handle = engine_handle.blocking_write();
            let context = Box::into_raw(Box::new(sender));

            clamav_sys::cl_engine_set_clcb_engine_compile_progress(
                engine_handle.as_ptr(),
                Some(crate::callback::progress),
                context as *mut libc::c_void,
            );

            let result = ffi::compile(engine_handle.as_ptr());

            // Clear the pointer from the libclamav engine context
            clamav_sys::cl_engine_set_clcb_engine_compile_progress(
                engine_handle.as_ptr(),
                None,
                std::ptr::null_mut(),
            );

            // Reclaim the sender
            let sender = Box::from_raw(context);
            sender
                .blocking_send(crate::callback::Progress::Complete(result))
                .expect("blocking send");
        });

        receiver.into()
    }

    pub async fn load_databases<'a, P>(&self, dbpath: &'a P) -> Result<DatabaseStats, ClamError>
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
        .unwrap()
    }

    /// An extended version of `load_databases()` that streams [crate::callback::Progress] events (concluding with
    /// a [crate::callback::Progress::Result] event).
    pub async fn load_databases_with_progress<'a, P>(
        &mut self,
        dbpath: &'a P,
    ) -> tokio_stream::wrappers::ReceiverStream<crate::callback::Progress<DatabaseStats, ClamError>>
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
                context as *mut libc::c_void,
            );

            let result = ffi::load_databases(dbpath.as_ref(), engine_handle.as_ptr());

            // Reclaim the sender
            let sender = Box::from_raw(context);
            sender
                .blocking_send(crate::callback::Progress::Complete(result))
                .expect("blocking send");

            // Clear the pointer from the libclamav engine context
            clamav_sys::cl_engine_set_clcb_sigload_progress(
                engine_handle.as_ptr(),
                None,
                std::ptr::null_mut(),
            );
        });

        receiver.into()
    }

    pub async fn scan<T: Into<crate::fmap::Fmap>>(
        &self,
        target: T,
        filename: Option<&str>,
        mut settings: crate::scan_settings::ScanSettings,
    ) -> ReceiverStream<ScanEvent> {
        use crate::callback::ScanCbContext;
        use crate::fmap::Fmap;
        use std::ffi::CString;
        use std::os::raw::c_void;
        use std::ptr;

        let fmap: Fmap = target.into();

        let (sender, receiver) = tokio::sync::mpsc::channel::<ScanEvent>(128);
        let c_filename = filename.map(|n| CString::new(n).expect("CString::new failed"));
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
                    c_sender as *mut c_void,
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

        receiver.into()
    }

    async fn get(&self, field: cl_engine_field) -> Result<EngineValue, ClamError> {
        let engine_handle = self.handle();
        let engine_handle = engine_handle.read().await;
        ffi::get(engine_handle.as_ptr(), field)
    }

    async fn set(&self, field: cl_engine_field, value: EngineValue) -> Result<(), ClamError> {
        dbg!(&field, &value);
        let engine_handle = self.handle.write().await;
        ffi::set(engine_handle.as_ptr(), field, value)
    }

    pub async fn database_version(&self) -> Result<u32, ClamError> {
        if let EngineValue::U32(value) = self.get(cl_engine_field::CL_ENGINE_DB_VERSION).await? {
            Ok(value)
        } else {
            Err(ClamError::new(cl_error_t::CL_EARG))
        }
    }

    pub async fn database_timestamp(&self) -> Result<time::SystemTime, ClamError> {
        if let EngineValue::Time(value) = self.get(cl_engine_field::CL_ENGINE_DB_TIME).await? {
            Ok(value.as_system_time())
        } else {
            Err(ClamError::new(cl_error_t::CL_EARG))
        }
    }

    pub async fn disable_cache(&self, disable_cache: bool) -> Result<(), ClamError> {
        self.set(
            cl_engine_field::CL_ENGINE_DISABLE_CACHE,
            EngineValue::U32(disable_cache.into()),
        )
        .await
    }

    pub async fn set_max_scansize(&self, max_scansize: u64) -> Result<(), ClamError> {
        self.set(
            cl_engine_field::CL_ENGINE_MAX_SCANSIZE,
            EngineValue::U64(max_scansize),
        )
        .await
    }

    pub async fn max_scansize(&self) -> Result<u64, ClamError> {
        if let EngineValue::U64(value) = self.get(cl_engine_field::CL_ENGINE_MAX_SCANSIZE).await? {
            Ok(value)
        } else {
            Err(ClamError::new(cl_error_t::CL_EARG))
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
    use super::{ClamTime, DatabaseStats, EngineValue, EngineValueType};
    use crate::ClamError;
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

    pub(super) fn compile(handle: *mut clamav_sys::cl_engine) -> Result<(), ClamError> {
        unsafe {
            let result = clamav_sys::cl_engine_compile(handle);
            match result {
                cl_error_t::CL_SUCCESS => Ok(()),
                _ => Err(ClamError::new(result)),
            }
        }
    }

    pub(super) fn load_databases(
        dbpath: &Path,
        handle: *mut clamav_sys::cl_engine,
    ) -> Result<DatabaseStats, ClamError> {
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
                _ => Err(ClamError::new(result)),
            }
        }
    }

    pub(super) fn get(
        engine_handle: *mut clamav_sys::cl_engine,
        field: cl_engine_field,
    ) -> Result<EngineValue, ClamError> {
        unsafe {
            match get_field_type(field) {
                EngineValueType::U32 => {
                    let mut err: c_int = 0;
                    let value = cl_engine_get_num(engine_handle, field, &mut err) as u32;
                    if err != 0 {
                        Err(ClamError::new(mem::transmute(err)))
                    } else {
                        Ok(EngineValue::U32(value))
                    }
                }
                EngineValueType::U64 => {
                    let mut err: c_int = 0;
                    let value = cl_engine_get_num(engine_handle, field, &mut err) as u64;
                    if err != 0 {
                        Err(ClamError::new(mem::transmute(err)))
                    } else {
                        Ok(EngineValue::U64(value))
                    }
                }
                EngineValueType::String => {
                    let mut err = 0;
                    let value = cl_engine_get_str(engine_handle, field, &mut err);
                    if err != 0 {
                        Err(ClamError::new(mem::transmute(err)))
                    } else {
                        Ok(EngineValue::String(
                            CStr::from_ptr(value).to_str().unwrap().to_string(),
                        ))
                    }
                }
                EngineValueType::Time => {
                    let mut err = 0;
                    let value = cl_engine_get_num(engine_handle, field, &mut err) as time_t;
                    if err != 0 {
                        Err(ClamError::new(mem::transmute(err)))
                    } else {
                        Ok(EngineValue::Time(ClamTime(value)))
                    }
                }
            }
        }
    }

    pub(super) fn set(
        engine_handle: *mut clamav_sys::cl_engine,
        field: cl_engine_field,
        value: EngineValue,
    ) -> Result<(), ClamError> {
        let expected_type = get_field_type(field);
        let actual_type = match &value {
            EngineValue::U32(_) => EngineValueType::U32,
            EngineValue::U64(_) => EngineValueType::U64,
            EngineValue::String(_) => EngineValueType::String,
            EngineValue::Time(_) => EngineValueType::Time,
        };

        if expected_type != actual_type {
            return Err(ClamError::new(cl_error_t::CL_EARG));
        }

        unsafe {
            match value {
                EngineValue::U32(val) => {
                    let err = cl_engine_set_num(engine_handle, field, val as i64);
                    if err != cl_error_t::CL_SUCCESS {
                        Err(ClamError::new(err))
                    } else {
                        Ok(())
                    }
                }
                EngineValue::U64(val) => {
                    let err = cl_engine_set_num(engine_handle, field, val as i64);
                    if err != cl_error_t::CL_SUCCESS {
                        Err(ClamError::new(err))
                    } else {
                        Ok(())
                    }
                }
                EngineValue::String(val) => {
                    let val = CString::new(val).unwrap();
                    let err = cl_engine_set_str(engine_handle, field, val.as_ptr());
                    if err != cl_error_t::CL_SUCCESS {
                        Err(ClamError::new(err))
                    } else {
                        Ok(())
                    }
                }
                EngineValue::Time(ClamTime(val)) => {
                    let err = cl_engine_set_num(engine_handle, field, val);
                    if err != cl_error_t::CL_SUCCESS {
                        Err(ClamError::new(err))
                    } else {
                        Ok(())
                    }
                }
            }
        }
    }

    fn get_field_type(field: cl_engine_field) -> EngineValueType {
        match field {
            cl_engine_field::CL_ENGINE_MAX_SCANSIZE => EngineValueType::U64,
            cl_engine_field::CL_ENGINE_MAX_FILESIZE => EngineValueType::U64,
            cl_engine_field::CL_ENGINE_MAX_RECURSION => EngineValueType::U32,
            cl_engine_field::CL_ENGINE_MAX_FILES => EngineValueType::U32,
            cl_engine_field::CL_ENGINE_MIN_CC_COUNT => EngineValueType::U32,
            cl_engine_field::CL_ENGINE_MIN_SSN_COUNT => EngineValueType::U32,
            cl_engine_field::CL_ENGINE_PUA_CATEGORIES => EngineValueType::String,
            cl_engine_field::CL_ENGINE_DB_OPTIONS => EngineValueType::U32,
            cl_engine_field::CL_ENGINE_DB_VERSION => EngineValueType::U32,
            cl_engine_field::CL_ENGINE_DB_TIME => EngineValueType::Time,
            cl_engine_field::CL_ENGINE_AC_ONLY => EngineValueType::U32,
            cl_engine_field::CL_ENGINE_AC_MINDEPTH => EngineValueType::U32,
            cl_engine_field::CL_ENGINE_AC_MAXDEPTH => EngineValueType::U32,
            cl_engine_field::CL_ENGINE_TMPDIR => EngineValueType::String,
            cl_engine_field::CL_ENGINE_KEEPTMP => EngineValueType::U32,
            cl_engine_field::CL_ENGINE_BYTECODE_SECURITY => EngineValueType::U32,
            cl_engine_field::CL_ENGINE_BYTECODE_TIMEOUT => EngineValueType::U32,
            cl_engine_field::CL_ENGINE_BYTECODE_MODE => EngineValueType::U32,
            cl_engine_field::CL_ENGINE_MAX_EMBEDDEDPE => EngineValueType::U64,
            cl_engine_field::CL_ENGINE_MAX_HTMLNORMALIZE => EngineValueType::U64,
            cl_engine_field::CL_ENGINE_MAX_HTMLNOTAGS => EngineValueType::U64,
            cl_engine_field::CL_ENGINE_MAX_SCRIPTNORMALIZE => EngineValueType::U64,
            cl_engine_field::CL_ENGINE_MAX_ZIPTYPERCG => EngineValueType::U64,
            cl_engine_field::CL_ENGINE_FORCETODISK => EngineValueType::U32,
            cl_engine_field::CL_ENGINE_DISABLE_CACHE => EngineValueType::U32,
            cl_engine_field::CL_ENGINE_DISABLE_PE_STATS => EngineValueType::U32,
            cl_engine_field::CL_ENGINE_STATS_TIMEOUT => EngineValueType::U32,
            cl_engine_field::CL_ENGINE_MAX_PARTITIONS => EngineValueType::U32,
            cl_engine_field::CL_ENGINE_MAX_ICONSPE => EngineValueType::U32,
            cl_engine_field::CL_ENGINE_MAX_RECHWP3 => EngineValueType::U32,
            cl_engine_field::CL_ENGINE_MAX_SCANTIME => EngineValueType::U32,
            cl_engine_field::CL_ENGINE_PCRE_MATCH_LIMIT => EngineValueType::U64,
            cl_engine_field::CL_ENGINE_PCRE_RECMATCH_LIMIT => EngineValueType::U64,
            cl_engine_field::CL_ENGINE_PCRE_MAX_FILESIZE => EngineValueType::U64,
            cl_engine_field::CL_ENGINE_DISABLE_PE_CERTS => EngineValueType::U32,
            cl_engine_field::CL_ENGINE_PE_DUMPCERTS => EngineValueType::U32,
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
