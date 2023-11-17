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
