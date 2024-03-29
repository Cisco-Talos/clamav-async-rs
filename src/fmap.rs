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

#[cfg(windows)]
use bindings::Windows::{
    Win32::Storage::FileSystem::ReadFile,
    Win32::System::Diagnostics::Debug::GetLastError,
    Win32::System::Diagnostics::Debug::ERROR_HANDLE_EOF,
    Win32::System::SystemServices::{HANDLE, OVERLAPPED},
};
use clamav_sys::{cl_fmap_close, cl_fmap_open_handle, cl_fmap_open_memory, cl_fmap_t};
use std::{
    fs::File,
    num::TryFromIntError,
    os::{self, raw::c_void, unix::prelude::AsRawFd},
    sync::Arc,
};

use tokio::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum MapError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("source consumed")]
    Consumed,

    #[error("converting integer: {0}")]
    TryFromInt(#[from] TryFromIntError),
}

#[cfg(windows)]
extern "C" fn pread_cb(
    handle: *mut os::raw::c_void,
    buf: *mut os::raw::c_void,
    count: os::raw::c_ulonglong,
    offset: os::raw::c_long,
) -> os::raw::c_long {
    let mut read_bytes = 0;

    unsafe {
        let mut overlapped: OVERLAPPED = std::mem::MaybeUninit::zeroed().assume_init();
        overlapped.InternalHigh = (offset as usize) >> 32;
        overlapped.Internal = (offset as usize) & 0xffffffff;

        if !ReadFile(
            std::mem::transmute::<_, HANDLE>(handle),
            buf,
            count as u32,
            &mut read_bytes,
            &mut overlapped,
        )
        .as_bool()
        {
            let err = GetLastError();
            if err != ERROR_HANDLE_EOF {
                return -1;
            }
        }
    }

    read_bytes as i32
}

#[cfg(unix)]
extern "C" fn pread_cb(
    handle: *mut os::raw::c_void,
    buf: *mut os::raw::c_void,
    count: usize,
    offset: os::raw::c_long,
) -> os::raw::c_long {
    unsafe {
        libc::pread(handle as i32, buf, count, offset)
            .try_into()
            .unwrap()
    }
}

/// A safer abstraction around `ClamAV`'s `cl_fmap_t`.
#[derive(Clone)]
pub struct Fmap {
    handle: Arc<Mutex<FmapHandle>>,
}

pub(crate) struct FmapHandle {
    source: Option<Source>,
    pub(crate) fmap: *mut cl_fmap_t,
}

pub enum Source {
    Vec(Vec<u8>),
    File(std::fs::File),
}

impl From<Vec<u8>> for Fmap {
    fn from(vec: Vec<u8>) -> Self {
        let fmap = unsafe { cl_fmap_open_memory(vec.as_ptr().cast::<c_void>(), vec.len()) };

        Self {
            handle: Arc::new(Mutex::new(FmapHandle {
                source: Some(Source::Vec(vec)),
                fmap,
            })),
        }
    }
}

impl TryFrom<File> for Fmap {
    type Error = MapError;

    fn try_from(file: File) -> std::result::Result<Self, Self::Error> {
        let offset = 0;
        let len = file.metadata()?.len();
        let aging = true;
        Ok(Self::from_file(file, offset, len.try_into()?, aging))
    }
}

impl Fmap {
    pub fn from_file(file: File, offset: usize, len: usize, aging: bool) -> Self {
        #[cfg(unix)]
        let fd = file.as_raw_fd();
        #[cfg(windows)]
        let fd = file.as_raw_handle();
        let fmap = unsafe {
            cl_fmap_open_handle(fd as *mut c_void, offset, len, Some(pread_cb), aging.into())
        };
        Self {
            handle: Arc::new(Mutex::new(FmapHandle {
                fmap,
                source: Some(Source::File(file)),
            })),
        }
    }

    pub(crate) fn handle(&self) -> Arc<Mutex<FmapHandle>> {
        self.handle.clone()
    }

    /// Reclaim the underlying structure from which the Fmap was created

    pub async fn into_inner(self) -> Result<Source, MapError> {
        let mut handle = self.handle.lock().await;
        handle.source.take().ok_or(MapError::Consumed)
    }
}

impl Drop for FmapHandle {
    fn drop(&mut self) {
        unsafe { cl_fmap_close(self.fmap) }
    }
}

unsafe impl Send for FmapHandle {}
