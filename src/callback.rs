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

use crate::{engine::ScanEvent, layer_attr::LayerAttributes, ContentHandle, EngineError};
use clamav_sys::cl_error_t;
use std::{
    ffi::CStr,
    io::Cursor,
    os::raw::{c_char, c_int, c_uchar, c_void},
    pin::Pin,
};
use tokio::io::AsyncRead;

/// A type defining a closure or function that, when given a recursion depth,
/// file type, optional file name, and file size, returns whether or not the
/// content should be duplicated into a buffer that can be passed via
/// `FileInspect` messages.
type ShouldCopyFileBuffer = Box<dyn for<'a> Fn(u32, &'a str, Option<&'a str>, usize) -> bool>;

/// A wrapper structure around the context passed to callbacks that execute with scans
pub(crate) struct ScanCbContext {
    pub(crate) sender: tokio::sync::mpsc::Sender<ScanEvent>,
    pub(crate) should_copy_file_buffer: Option<ShouldCopyFileBuffer>,
}

impl ScanCbContext {
    /// Return a copy of a provided buffer if callback criteria are met
    unsafe fn scanned_content(
        &self,
        file_buffer: *const c_char,
        recursion_level: u32,
        file_type: &str,
        file_name: Option<&str>,
        file_size: usize,
    ) -> Option<Pin<Box<dyn AsyncRead + Send>>> {
        let Some(buffer) = file_buffer
            .cast::<c_uchar>()
            .as_ref()
            .map(|buf| core::slice::from_raw_parts(buf, file_size))
        else {
            // No buffer provided
            return None;
        };

        let Some(cb) = &self.should_copy_file_buffer else {
            return None;
        };

        // Never include content for the root document. That should be known to the caller already.
        if cb(recursion_level, file_type, file_name, file_size) {
            // NOTE: the content is provided as a trait object that
            // implements AsyncRead in order to facilitate future
            // functionality where this could be passed as a more
            // "lightweight" object, such as a file handle or socket, or
            // perhaps a ref-counted buffer that releases its reference once
            // completely read.
            Some(Box::pin(Cursor::new(buffer.to_vec())) as ContentHandle)
        } else {
            None
        }
    }
}

/// A completion progress report, with a final result
#[derive(Debug)]
pub enum Progress<T, E> {
    Update {
        /// How many elements have been handled
        now_completed: usize,
        /// How many elements are expected to be handled
        total_items: usize,
    },
    Complete(Result<T, E>),
}

/// Wrapper function for callbacks that accept a Progress message
///
/// This function has libclamav's `clcb_progress` function signature
pub(crate) unsafe extern "C" fn progress(
    total_items: usize,
    now_completed: usize,
    context: *mut c_void,
) -> cl_error_t {
    // All errors are handled silently as there is no other means to report errors
    if let Some(sender) = context
        .cast::<tokio::sync::mpsc::Sender<Progress<(), EngineError>>>()
        .as_ref()
    {
        let _ = sender.blocking_send(Progress::Update {
            total_items,
            now_completed,
        });
    }

    // ClamAV doesn't specify any action on this value, so it's hardcoded into
    // the wrapper
    cl_error_t::CL_SUCCESS
}

pub(crate) unsafe extern "C" fn engine_pre_scan(
    fd: c_int,
    type_: *const c_char,
    context: *mut c_void,
) -> cl_error_t {
    if let Some(cxt) = context.cast::<ScanCbContext>().as_ref() {
        let file_type = CStr::from_ptr(type_).to_string_lossy();

        let _ = cxt.sender.blocking_send(ScanEvent::PreScan {
            file: dup_fd_to_file(fd),
            file_type: file_type.into(),
        });
    }

    cl_error_t::CL_CLEAN
}

pub(crate) unsafe extern "C" fn engine_post_scan(
    fd: c_int,
    result: c_int,
    virname: *const c_char,
    context: *mut c_void,
) -> cl_error_t {
    if let Some(cxt) = context.cast::<ScanCbContext>().as_ref() {
        let result = result as isize;
        let match_name = if virname.is_null() {
            String::from("<NULL>")
        } else {
            CStr::from_ptr(virname).to_string_lossy().into()
        };

        let _ = cxt.sender.blocking_send(ScanEvent::PostScan {
            file: dup_fd_to_file(fd),
            result,
            match_name,
        });
    }

    cl_error_t::CL_CLEAN
}

pub(crate) unsafe extern "C" fn engine_virus_found(
    fd: c_int,
    virname: *const c_char,
    context: *mut c_void,
) {
    if let Some(cxt) = context.cast::<ScanCbContext>().as_ref() {
        let name = CStr::from_ptr(virname).to_string_lossy().into();

        let _ = cxt.sender.blocking_send(ScanEvent::MatchFound {
            file: dup_fd_to_file(fd),
            name,
        });
    }
}

pub(crate) unsafe extern "C" fn engine_file_inspection(
    // NOTE: this file descriptor is unsafe to use after the callback has
    // returned, even if dup'd. Hence, it's just ignored.
    _fd: c_int,
    file_type: *const c_char,
    c_ancestors: *mut *const c_char,
    parent_file_size: usize,
    file_name: *const c_char,
    file_size: usize,
    file_buffer: *const c_char,
    recursion_level: u32,
    layer_attributes: u32,
    context: *mut c_void,
) -> cl_error_t {
    let Some(cxt) = context.cast::<ScanCbContext>().as_ref() else {
        return cl_error_t::CL_CLEAN;
    };

    let Some(file_type) = file_type
        .as_ref()
        .map(|p| CStr::from_ptr(p))
        .map(CStr::to_string_lossy)
        .map(|s| s.to_string())
    else {
        // Quietly ignore NULL file types for safety, even though libclamav
        // guarantees us one.
        return cl_error_t::CL_CLEAN;
    };

    let file_name = file_name
        .as_ref()
        .map(|ptr| CStr::from_ptr(ptr))
        .map(CStr::to_string_lossy)
        .map(|s| s.to_string());

    let scanned_content = cxt.scanned_content(
        file_buffer,
        recursion_level,
        &file_type,
        file_name.as_deref(),
        file_size,
    );

    let _ = cxt.sender.blocking_send(ScanEvent::FileInspect {
        content: scanned_content,
        ancestors: build_ancestors(recursion_level, c_ancestors),
        file_name,
        file_size,
        file_type,
        layer_attrs: LayerAttributes::from_bits(layer_attributes).unwrap_or_default(),
        parent_file_size,
        recursion_level,
    });

    cl_error_t::CL_CLEAN
}

/// Helper function for `engine_file_inspection` that builds a vector laying out
/// the filenames of ancestors for a container element
unsafe fn build_ancestors(
    recursion_level: u32,
    c_ancestors: *mut *const c_char,
) -> Vec<Option<String>> {
    let mut ancestors = vec![];
    if let Ok(recursion_level) = isize::try_from(recursion_level) {
        if !c_ancestors.is_null() {
            for i in 0..recursion_level {
                let ancestor = *(c_ancestors.offset(i));
                if ancestor.is_null() {
                    ancestors.push(None);
                } else {
                    let ancestor = CStr::from_ptr(ancestor).to_string_lossy();
                    ancestors.push(Some(ancestor.into()));
                }
            }
        }
    }
    ancestors
}

#[cfg(unix)]
fn dup_fd_to_file(fd: c_int) -> Option<std::fs::File> {
    use std::os::unix::prelude::FromRawFd;

    if fd == -1 {
        None
    } else {
        // dup the file descriptor first in case this message isn't handled
        // before it's closed.  The file will be closed when the containing
        // message is discarded.
        let new_fd = unsafe { libc::dup(fd) };
        if new_fd == -1 {
            // TODO: log a warning? Or embed error in FileInspect message?
            None
        } else {
            Some(unsafe { std::fs::File::from_raw_fd(new_fd) })
        }
    }
}

#[cfg(windows)]
fn dup_fd_to_file(fd: c_int) -> Option<File> {
    // Not supported
    None
}
