use std::ffi::CStr;

/// Returns the database version level that the engine supports
#[must_use]
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
#[must_use]
pub fn version() -> String {
    unsafe {
        let ptr = clamav_sys::cl_retver();
        let bytes = CStr::from_ptr(ptr).to_bytes();
        String::from_utf8_lossy(bytes).to_string()
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
