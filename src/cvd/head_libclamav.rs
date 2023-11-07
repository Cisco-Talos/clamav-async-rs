use super::{HeadError, Meta};
use std::{borrow::Cow, ffi::CStr};

/// The header of a CVD
pub struct Header(*mut clamav_sys::cl_cvd);

impl Meta for Header {
    /// Parse a CVD header from a buffer obtained from the beginning of a CVD
    /// (or CLD) file
    fn from_header_bytes(bytes: &[u8; 512]) -> Result<Self, HeadError> {
        unsafe {
            let raw = clamav_sys::cl_cvdparse(bytes.as_ptr() as *const i8);

            if raw.is_null() {
                Err(HeadError::Parse)
            } else {
                Ok(Header(raw))
            }
        }
    }

    /// Database "feature level"
    fn f_level(&self) -> usize {
        unsafe { (*self.0).fl as usize }
    }

    /// Number of signatures reported to be within the database
    fn n_sigs(&self) -> usize {
        unsafe { (*self.0).sigs as usize }
    }

    /// Creation time (as a string)
    fn time_str(&self) -> Cow<'_, str> {
        // libclamav guarantees that this pointer is non-NULL
        unsafe { CStr::from_ptr((*self.0).time).to_string_lossy() }
    }

    /// Database version
    fn version(&self) -> usize {
        unsafe { (*self.0).version as usize }
    }

    /// MD5 digest (as a hex string)
    fn md5_str(&self) -> Cow<'_, str> {
        // libclamav guarantees that this pointer is non-NULL
        unsafe { CStr::from_ptr((*self.0).md5).to_string_lossy() }
    }

    /// Digital signature (as a hex string)
    fn dsig_str(&self) -> Cow<'_, str> {
        // libclamav guarantees that this pointer is non-NULL
        unsafe { CStr::from_ptr((*self.0).dsig).to_string_lossy() }
    }

    /// Database builder's ID
    fn builder(&self) -> Cow<'_, str> {
        // libclamav guarantees that this pointer is non-NULL
        unsafe { CStr::from_ptr((*self.0).builder).to_string_lossy() }
    }

    /// Creation time as seconds
    fn stime(&self) -> u64 {
        unsafe { (*self.0).stime }
    }
}

impl std::fmt::Debug for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CvdHead")
            .field("f_level", &self.f_level())
            .field("n_sigs", &self.n_sigs())
            .field("time", &self.time_str())
            .field("version", &self.version())
            .field("md5", &self.md5_str())
            .field("dsig", &self.dsig_str())
            .field("builder", &self.builder())
            .field("stime", &self.stime())
            .finish()
    }
}
