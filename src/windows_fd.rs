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

use std::io;
use std::mem;
use std::os::raw;

#[cfg(windows)]
use bindings::Windows::{
    Win32::System::SystemServices::{HANDLE, INVALID_HANDLE_VALUE},
    Win32::System::Threading::GetCurrentProcess,
    Win32::System::WindowsProgramming::DuplicateHandle,
    Win32::System::WindowsProgramming::DUPLICATE_SAME_ACCESS,
};

extern "C" {
    // https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/open-osfhandle?view=msvc-160
    fn _open_osfhandle(osfhandle: isize, flags: raw::c_int) -> raw::c_int;

    // https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/close?view=msvc-160
    fn _close(fd: raw::c_int) -> raw::c_int;
}

pub const _O_RDONLY: raw::c_int = 0;

pub struct WindowsFd(i32);

impl WindowsFd {
    pub fn new(handle: std::os::windows::io::RawHandle) -> io::Result<WindowsFd> {
        let mut owned_handle = INVALID_HANDLE_VALUE;
        unsafe {
            if DuplicateHandle(
                GetCurrentProcess(),
                std::mem::transmute::<_, HANDLE>(handle),
                GetCurrentProcess(),
                &mut owned_handle,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )
            .as_bool()
                == false
            {
                return Err(io::Error::last_os_error());
            }

            let fd = _open_osfhandle(mem::transmute(owned_handle), _O_RDONLY);
            if fd == -1 {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Error converting Windows HANDLE to file descriptor",
                ))
            } else {
                Ok(WindowsFd(fd))
            }
        }
    }

    pub fn raw(&self) -> i32 {
        self.0
    }
}

impl Drop for WindowsFd {
    fn drop(&mut self) {
        unsafe {
            let _ = _close(self.0);
        }
    }
}
