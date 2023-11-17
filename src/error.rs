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
