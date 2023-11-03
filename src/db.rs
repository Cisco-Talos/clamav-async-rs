use std::ffi::CStr;
use std::str;

use clamav_sys::cl_retdbdir;

/// Gets the default database directory for clamav
pub fn default_directory() -> String {
    unsafe {
        let ptr = cl_retdbdir();
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
    fn default_directory_success() {
        crate::initialize().expect("initialize should succeed");
        assert!(
            !default_directory().is_empty(),
            "should have a default db dir"
        );
    }
}
