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
    Win32::System::Diagnostics::Debug::GetLastError,
    Win32::System::Diagnostics::Debug::ERROR_HANDLE_EOF,
};
use clamav_sys::{cl_fmap_close, cl_fmap_open_handle, cl_fmap_open_memory, cl_fmap_t};
use std::{
    ffi::{self, CStr},
    fs::File,
    num::TryFromIntError,
    os::{
        self,
        raw::{c_char, c_void},
    },
    path::{Path, PathBuf},
    sync::Arc,
};

use tokio::sync::Mutex;

use crate::EngineError;

#[cfg(windows)]
use crate::windows_fd::WindowsFd;

#[cfg(unix)]
use std::os::unix::prelude::AsRawFd;

#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

#[cfg(windows)]
extern "C" {
    fn _lseeki64(fd: os::raw::c_int, offset: i64, origin: os::raw::c_int) -> i64;
    fn _read(fd: os::raw::c_int, buffer: *mut c_void, count: os::raw::c_uint) -> os::raw::c_int;
}

/// Errors that can occur while constructing or reclaiming an [`Fmap`].
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
unsafe extern "C" fn pread_cb(
    handle: *mut os::raw::c_void,
    buf: *mut os::raw::c_void,
    count: usize,
    offset: clamav_sys::off_t,
) -> clamav_sys::off_t {
    let fd = handle as isize as os::raw::c_int;
    let offset = i64::from(offset);
    let count: os::raw::c_uint = match count.try_into() {
        Ok(count) => count,
        Err(_) => return -1,
    };

    if _lseeki64(fd, offset, 0) == -1 {
        return -1;
    }

    let read_bytes = _read(fd, buf, count);
    if read_bytes == -1 {
        let err = GetLastError();
        if err != ERROR_HANDLE_EOF {
            return -1;
        }
        return 0;
    }

    match clamav_sys::off_t::try_from(read_bytes) {
        Ok(n) => n,
        Err(_) => -1,
    }
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
///
/// `Fmap` can wrap either owned file or memory-backed content, or a borrowed
/// fmap originating from a scan callback layer.
#[derive(Clone)]
pub struct Fmap {
    handle: Arc<Mutex<FmapHandle>>,
}

pub(crate) struct FmapHandle {
    owns_fmap: bool,
    source: Option<Source>,
    #[cfg(windows)]
    _windows_fd: Option<WindowsFd>,
    pub(crate) fmap: *mut cl_fmap_t,
}

/// The underlying Rust source from which an [`Fmap`] was created.
pub enum Source {
    /// An in-memory buffer.
    Vec(Vec<u8>),
    /// A file-backed map.
    File(std::fs::File),
}

impl From<Vec<u8>> for Fmap {
    fn from(vec: Vec<u8>) -> Self {
        let fmap = unsafe { cl_fmap_open_memory(vec.as_ptr().cast::<c_void>(), vec.len()) };

        Self {
            handle: Arc::new(Mutex::new(FmapHandle {
                owns_fmap: true,
                source: Some(Source::Vec(vec)),
                #[cfg(windows)]
                _windows_fd: None,
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
        Self::from_file(file, offset, len.try_into()?, aging)
    }
}

impl Fmap {
    /// Creates a file-backed `Fmap` over a byte range within `file`.
    pub fn from_file(file: File, offset: usize, len: usize, aging: bool) -> Result<Self, MapError> {
        #[cfg(unix)]
        let fd = file.as_raw_fd();
        #[cfg(windows)]
        let windows_fd = WindowsFd::new(file.as_raw_handle())?;
        #[cfg(windows)]
        let fd = windows_fd.raw();
        let fmap = unsafe {
            cl_fmap_open_handle(fd as *mut c_void, offset, len, Some(pread_cb), aging.into())
        };
        Ok(Self {
            handle: Arc::new(Mutex::new(FmapHandle {
                owns_fmap: true,
                fmap,
                source: Some(Source::File(file)),
                #[cfg(windows)]
                _windows_fd: Some(windows_fd),
            })),
        })
    }

    pub(crate) unsafe fn from_raw_borrowed(fmap: *mut cl_fmap_t) -> Self {
        Self {
            handle: Arc::new(Mutex::new(FmapHandle {
                owns_fmap: false,
                fmap,
                source: None,
                #[cfg(windows)]
                _windows_fd: None,
            })),
        }
    }

    pub(crate) fn handle(&self) -> Arc<Mutex<FmapHandle>> {
        self.handle.clone()
    }

    pub(crate) fn sha2_256(&self) -> Result<String, EngineError> {
        // The output hash is a malloced C string that we need to free after converting.
        let hash_name_cstr = ffi::CString::new("sha2-256").unwrap();
        let fmap = self.handle.blocking_lock().fmap;

        let mut hash_out: *mut c_char = std::ptr::null_mut();
        let cl_result =
            unsafe { clamav_sys::cl_fmap_get_hash(fmap, hash_name_cstr.as_ptr(), &mut hash_out) };
        if cl_result != clamav_sys::cl_error_t::CL_SUCCESS {
            Err(EngineError::Clam(crate::error::Error::from(cl_result)))
        } else if hash_out.is_null() {
            Err(EngineError::Clam(crate::error::Error::from(
                clamav_sys::cl_error_t::CL_EARG,
            )))
        } else {
            let hash = unsafe { CStr::from_ptr(hash_out) }
                .to_string_lossy()
                .into_owned();
            unsafe { libc::free(hash_out.cast()) };
            Ok(hash)
        }
    }

    /// Returns `true` if the fmap already has a cached SHA-256 digest.
    pub fn have_sha2_256(&self) -> Result<bool, EngineError> {
        let hash_name_cstr = ffi::CString::new("sha2-256").unwrap();
        let fmap = self.handle.blocking_lock().fmap;

        let mut have_hash = false;
        let cl_result =
            unsafe { clamav_sys::cl_fmap_have_hash(fmap, hash_name_cstr.as_ptr(), &mut have_hash) };
        if cl_result != clamav_sys::cl_error_t::CL_SUCCESS {
            Err(EngineError::Clam(crate::error::Error::from(cl_result)))
        } else {
            Ok(have_hash)
        }
    }

    /// Returns the path associated with the fmap, if one is available.
    pub fn path(&self) -> Result<Option<PathBuf>, EngineError> {
        let fmap = self.handle.blocking_lock().fmap;
        let mut path_out: *const c_char = std::ptr::null();
        let cl_result = unsafe {
            clamav_sys::cl_fmap_get_path(
                fmap,
                &mut path_out,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if cl_result == clamav_sys::cl_error_t::CL_EACCES || path_out.is_null() {
            Ok(None)
        } else if cl_result != clamav_sys::cl_error_t::CL_SUCCESS {
            Err(EngineError::Clam(crate::error::Error::from(cl_result)))
        } else {
            let path = unsafe { CStr::from_ptr(path_out) }
                .to_string_lossy()
                .into_owned();
            Ok(Some(PathBuf::from(path)))
        }
    }

    /// Associates a path string with the fmap.
    pub fn set_path(&self, path: &Path) -> Result<(), EngineError> {
        let path = ffi::CString::new(path.to_string_lossy().as_bytes())?;
        let fmap = self.handle.blocking_lock().fmap;
        let cl_result = unsafe { clamav_sys::cl_fmap_set_path(fmap, path.as_ptr()) };
        if cl_result != clamav_sys::cl_error_t::CL_SUCCESS {
            Err(EngineError::Clam(crate::error::Error::from(cl_result)))
        } else {
            Ok(())
        }
    }

    /// Returns the file name associated with the fmap, if one is available.
    pub fn name(&self) -> Result<Option<String>, EngineError> {
        let fmap = self.handle.blocking_lock().fmap;
        let mut name_out: *const c_char = std::ptr::null();
        let cl_result = unsafe { clamav_sys::cl_fmap_get_name(fmap, &mut name_out) };
        if cl_result == clamav_sys::cl_error_t::CL_EACCES || name_out.is_null() {
            Ok(None)
        } else if cl_result != clamav_sys::cl_error_t::CL_SUCCESS {
            Err(EngineError::Clam(crate::error::Error::from(cl_result)))
        } else {
            Ok(Some(
                unsafe { CStr::from_ptr(name_out) }
                    .to_string_lossy()
                    .into_owned(),
            ))
        }
    }

    /// Associates a display name with the fmap.
    pub fn set_name(&self, name: &str) -> Result<(), EngineError> {
        let name = ffi::CString::new(name)?;
        let fmap = self.handle.blocking_lock().fmap;
        let cl_result = unsafe { clamav_sys::cl_fmap_set_name(fmap, name.as_ptr()) };
        if cl_result != clamav_sys::cl_error_t::CL_SUCCESS {
            Err(EngineError::Clam(crate::error::Error::from(cl_result)))
        } else {
            Ok(())
        }
    }

    /// Returns the OS file descriptor for the fmap, if it is file-backed.
    pub fn fd(&self) -> Result<Option<std::os::raw::c_int>, EngineError> {
        let fmap = self.handle.blocking_lock().fmap;
        let mut fd_out = -1;
        let cl_result = unsafe {
            clamav_sys::cl_fmap_get_fd(
                fmap,
                &mut fd_out,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if cl_result == clamav_sys::cl_error_t::CL_EACCES || fd_out < 0 {
            Ok(None)
        } else if cl_result != clamav_sys::cl_error_t::CL_SUCCESS {
            Err(EngineError::Clam(crate::error::Error::from(cl_result)))
        } else {
            Ok(Some(fd_out))
        }
    }

    /// Returns the size of the fmap in bytes.
    pub fn size(&self) -> Result<usize, EngineError> {
        let fmap = self.handle.blocking_lock().fmap;
        let mut size_out = 0;
        let cl_result = unsafe { clamav_sys::cl_fmap_get_size(fmap, &mut size_out) };
        if cl_result != clamav_sys::cl_error_t::CL_SUCCESS {
            Err(EngineError::Clam(crate::error::Error::from(cl_result)))
        } else {
            Ok(size_out)
        }
    }

    /// Returns a slice of fmap data beginning at `offset`.
    ///
    /// Passing `len == 0` requests the remainder of the fmap from `offset`.
    /// The returned slice borrows libclamav-managed memory.
    pub fn data(&self, offset: usize, len: usize) -> Result<&[u8], EngineError> {
        let fmap = self.handle.blocking_lock().fmap;
        let mut data_out: *const u8 = std::ptr::null();
        let mut data_len_out = 0;
        let cl_result = unsafe {
            clamav_sys::cl_fmap_get_data(fmap, offset, len, &mut data_out, &mut data_len_out)
        };
        if cl_result != clamav_sys::cl_error_t::CL_SUCCESS {
            Err(EngineError::Clam(crate::error::Error::from(cl_result)))
        } else if data_len_out == 0 {
            Ok(&[])
        } else if data_out.is_null() {
            Err(EngineError::Clam(crate::error::Error::from(
                clamav_sys::cl_error_t::CL_EARG,
            )))
        } else {
            Ok(unsafe { std::slice::from_raw_parts(data_out, data_len_out) })
        }
    }

    /// Reclaims the original Rust source used to create this `Fmap`.
    ///
    /// This only succeeds for owned fmaps created from a `Vec<u8>` or `File`.
    /// Borrowed callback-layer fmaps do not have reclaimable Rust backing data.
    pub async fn into_inner(self) -> Result<Source, MapError> {
        let mut handle = self.handle.lock().await;
        handle.source.take().ok_or(MapError::Consumed)
    }
}

impl Drop for FmapHandle {
    fn drop(&mut self) {
        if self.owns_fmap {
            unsafe { cl_fmap_close(self.fmap) }
        }
    }
}

unsafe impl Send for FmapHandle {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, path::Path};

    const ABC_SHA2_256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn memory_fmap_accessors_and_mutators_work() {
        crate::initialize().expect("initialize should succeed");

        let fmap = Fmap::from(b"abc".to_vec());

        assert_eq!(fmap.name().expect("name lookup should succeed"), None);
        assert_eq!(fmap.path().expect("path lookup should succeed"), None);
        assert_eq!(fmap.fd().expect("fd lookup should succeed"), None);
        assert_eq!(fmap.size().expect("size lookup should succeed"), 3);
        assert_eq!(fmap.data(0, 0).expect("data lookup should succeed"), b"abc");
        assert_eq!(fmap.data(1, 1).expect("data lookup should succeed"), b"b");
        assert!(!fmap
            .have_sha2_256()
            .expect("hash existence check should succeed"));

        fmap.set_name("memory.txt")
            .expect("setting the name should succeed");
        fmap.set_path(Path::new("/virtual/memory.txt"))
            .expect("setting the path should succeed");

        assert_eq!(
            fmap.name().expect("name lookup should succeed"),
            Some(String::from("memory.txt"))
        );
        assert_eq!(
            fmap.path().expect("path lookup should succeed"),
            Some(PathBuf::from("/virtual/memory.txt"))
        );
        assert_eq!(
            fmap.sha2_256().expect("hash retrieval should succeed"),
            ABC_SHA2_256
        );
        assert!(fmap
            .have_sha2_256()
            .expect("hash existence check should succeed"));
    }

    #[test]
    fn file_backed_fmap_fd_and_size_work() {
        crate::initialize().expect("initialize should succeed");

        let mut file = tempfile::NamedTempFile::new().expect("tempfile creation should succeed");
        file.write_all(b"abc")
            .expect("writing tempfile contents should succeed");

        let fmap = Fmap::try_from(file.reopen().expect("reopening tempfile should succeed"))
            .expect("file-backed fmap creation should succeed");

        assert!(fmap.fd().expect("fd lookup should succeed").is_some());
        assert_eq!(fmap.size().expect("size lookup should succeed"), 3);
        assert_eq!(fmap.data(0, 0).expect("data lookup should succeed"), b"abc");
    }
}
