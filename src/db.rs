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
use std::str;

use clamav_sys::cl_retdbdir;

/// Gets the default database directory for clamav
///
/// # Panics
///
/// Will panic if the default directory name is not valid UTF-8
#[must_use]
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
