use std::ffi::CStr;
use std::str;

/// Returns the database version level that the engine supports
pub fn flevel() -> u32 {
    unsafe { clamav_sys::cl_retflevel() }
}

/// Gets the clamav engine version
///
/// # Example
///
/// ```
/// use clamav_async::version;
///
/// println!("Running version {} flevel {}", version::version(), version::flevel());
/// ```
pub fn version() -> String {
    unsafe {
        let ptr = clamav_sys::cl_retver();
        let bytes = CStr::from_ptr(ptr).to_bytes();
        str::from_utf8(bytes)
            .expect("Invalid UTF8 string")
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_success() {
        crate::initialize().expect("initialize should succeed");
        assert!(!version().is_empty(), "expected a version");
    }

    #[test]
    fn flevel_success() {
        crate::initialize().expect("initialize should succeed");
        assert!(flevel() > 0, "expected an flevel");
    }
}
