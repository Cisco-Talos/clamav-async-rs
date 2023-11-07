use std::error;
use std::ffi::CStr;
use std::fmt;

use clamav_sys::cl_error_t;

/// An error reported directly from a libclamav function call
#[derive(Clone, PartialEq, Eq)]
pub struct Error {
    code: cl_error_t,
}

impl Error {
    #[must_use]
    pub fn new(code: cl_error_t) -> Self {
        Error { code }
    }

    #[must_use]
    pub fn string_error(&self) -> String {
        unsafe {
            let ptr = clamav_sys::cl_strerror(self.code);
            let bytes = CStr::from_ptr(ptr).to_bytes();
            String::from_utf8_lossy(bytes).to_string()
        }
    }

    #[must_use]
    pub fn code(&self) -> u32 {
        self.code.0
    }
}

impl From<cl_error_t> for Error {
    fn from(code: cl_error_t) -> Self {
        Self::new(code)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "cl_error {}: {}", self.code(), self.string_error())
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_as_string_success() {
        let err = Error::new(cl_error_t::CL_EFORMAT);
        let err_string = err.to_string();
        dbg!(&err_string);
        assert!(
            err_string.contains("Bad format or broken data"),
            "error description should contain string error"
        );
    }
}
