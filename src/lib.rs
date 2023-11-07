#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

/// Callback support structures and support functions
pub mod callback;
pub mod db;
pub mod engine;
mod error;
pub mod fmap;
/// File inspection layer attributes
pub mod layer_attr;
pub mod scan_settings;
pub mod version;

/// Signature database processing
pub mod cvd;

#[cfg(windows)]
pub mod windows_fd;

use clamav_sys::{cl_error_t, cl_init, cl_initialize_crypto};
pub use engine::Error as EngineError;
pub use error::Error as ClamError;
use lazy_static::lazy_static;
use std::{
    ffi::CStr,
    pin::Pin,
    sync::{Arc, Mutex, Once},
};
use tokio::io::AsyncRead;

lazy_static! {
    /// Optional function to call for message callbacks
    static ref CLAMAV_MESSAGE_CALLBACK: Arc<Mutex<Option<MsgCallback>>> = Arc::new(Mutex::new(None));
}

/// Initializes clamav
///
/// This must be called once per process. This is safe to call multiple times.
pub fn initialize() -> Result<(), ClamError> {
    // the cl_init implementation isn't thread-safe, which is painful for tests
    static ONCE: Once = Once::new();
    static mut RESULT: cl_error_t = cl_error_t::CL_SUCCESS;
    unsafe {
        extern "C" fn cleanup() {
            unsafe {
                clamav_sys::cl_cleanup_crypto();
            }
        }

        ONCE.call_once(|| {
            RESULT = cl_init(clamav_sys::CL_INIT_DEFAULT);
            // this function always returns OK
            if RESULT == cl_error_t::CL_SUCCESS {
                cl_initialize_crypto();
                libc::atexit(cleanup);
            }
        });

        match RESULT {
            cl_error_t::CL_SUCCESS => Ok(()),
            _ => Err(ClamError::new(RESULT)),
        }
    }
}

#[must_use]
pub fn version() -> String {
    let ver = unsafe { clamav_sys::cl_retver() };
    if ver.is_null() {
        String::new()
    } else {
        unsafe { std::ffi::CStr::from_ptr(ver).to_string_lossy().to_string() }
    }
}

pub type MsgCallback = Box<dyn Fn(log::Level, &str, &str) + Send>;

/// Specify a callback to execute when libclamav would emit a message to the
/// console
///
/// Note that the libclamav APIs do not permit restoring the default handler.
#[allow(clippy::missing_panics_doc)]
pub fn set_msg_callback(cb: MsgCallback) {
    unsafe {
        *(CLAMAV_MESSAGE_CALLBACK.lock().unwrap()) = Some(cb);
        clamav_sys::cl_set_clcb_msg(Some(clcb_msg_wrapper));
    }
}

///
/// Check whether the libclamav message callback has been overriden (which it
/// should be if this function is being called).  If so, safely capture a
/// C-string message emitted by libclamav (converting any non-UTF-8 content to
/// "safe" replacements) and pass to the previously-specified callback.
///
unsafe extern "C" fn clcb_msg_wrapper(
    severity: clamav_sys::cl_msg,
    fullmsg: *const i8,
    msg: *const i8,
    _context: *mut libc::c_void,
) {
    // Remap the log level to "standard" Rust log levels
    let log_level = match severity {
        clamav_sys::cl_msg::CL_MSG_WARN => log::Level::Warn,
        clamav_sys::cl_msg::CL_MSG_ERROR => log::Level::Error,
        _ => log::Level::Info,
    };
    if let Ok(cb) = CLAMAV_MESSAGE_CALLBACK.lock() {
        if let Some(cb) = &*cb {
            // Convert the provided C-strings into safe types
            let fullmsg = CStr::from_ptr(fullmsg).to_string_lossy().to_string();
            let msg = CStr::from_ptr(msg).to_string_lossy().to_string();
            cb(log_level, &fullmsg, &msg);
        } else {
            // This function shouldn't fire when the callback has been set to None
            unreachable!()
        }
    }
}

/// A type defining the trait object returned in the `FileInspect` event that
/// allows access to embedded file content.
pub type ContentHandle = Pin<Box<dyn AsyncRead + Send>>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    lazy_static! {
        // A global that can be modified in tests
        static ref TEST_STORE: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
    }

    #[test]
    fn initialize_success() {
        assert!(initialize().is_ok(), "initialize should succeed");
    }

    #[tokio::test]
    async fn clcb_msg_override() {
        const KEY: &str = module_path!();

        fn cb(_severity: log::Level, _fullmsg: &str, msg: &str) {
            let mut test_store = TEST_STORE.lock().unwrap();
            (*test_store).insert(KEY.into(), msg.into());
        }

        {
            let mut test_store = TEST_STORE.lock().unwrap();
            (*test_store).insert(KEY.into(), String::default());
        }

        // Override the message callback
        set_msg_callback(Box::new(cb));

        // Force an error
        let clam_engine = crate::engine::Engine::new();
        assert!(
            clam_engine.load_databases("/no-such-path").await.is_err(),
            "database load should have failed"
        );

        // Check that the message callback captured the error
        let test_store = TEST_STORE.lock().unwrap();
        let msg = (*test_store)
            .get(KEY)
            .expect(concat!("value of ", module_path!()));
        assert!(msg.contains("/no-such-path"));
    }
}
