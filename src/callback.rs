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

use crate::{engine::ScanEvent, fmap::Fmap, EngineError};
use clamav_sys::cl_error_t;
use std::{
    ffi::CStr,
    os::raw::{c_char, c_void},
    panic::{self, AssertUnwindSafe},
    sync::Arc,
};

/// A wrapper structure around the context passed to callbacks that execute with scans
pub(crate) struct ScanCbContext {
    pub(crate) sender: tokio::sync::mpsc::Sender<ScanEvent>,
    /// Additional user-defined logic for various callback types
    pub(crate) pre_scan_logic: Option<Arc<dyn std::any::Any + Send + Sync>>,
    pub(crate) post_scan_logic: Option<Arc<dyn std::any::Any + Send + Sync>>,
    pub(crate) match_logic: Option<Arc<dyn std::any::Any + Send + Sync>>,
    pub(crate) file_type_logic: Option<Arc<dyn std::any::Any + Send + Sync>>,
}

/// The scan callback hook points supported by [`crate::engine::Engine`].
pub enum EngineCallback {
    /// Invoked before a scan layer is scanned.
    PreScan,
    /// Invoked after a scan layer has been scanned.
    PostScan,
    /// Invoked when libclamav reports a match for a scan layer.
    Match,
    /// Invoked when libclamav identifies the type of a scan layer.
    FileType,
}

/// Trait object type used for scan-layer callback closures.
///
/// Callback logic receives mutable access to a [`ScanLayer`] so it can inspect
/// the current layer and optionally cache its [`Fmap`].
pub type ScanLayerLogic = dyn Fn(&mut ScanLayer) -> ScanLogicResult + Send + Sync;
/// Callback signature used for pre-scan callbacks.
pub type PreScanLogic = ScanLayerLogic;
/// Callback signature used for post-scan callbacks.
pub type PostScanLogic = ScanLayerLogic;
/// Callback signature used for file-type callbacks.
pub type FileTypeLogic = ScanLayerLogic;
/// Callback signature used for match callbacks.
pub type MatchLogic = ScanLayerLogic;

/// The decision returned by a scan callback.
///
/// These values are forwarded to libclamav and can alter the final scan
/// outcome, not just the control flow of the callback itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanLogicResult {
    /// Abort the scan immediately.
    Abort,
    /// Continue scanning without forcing a match or trusted result.
    Success,
    /// Accept or create a match and continue scanning.
    Match,
    /// Mark the layer as trusted, discard prior matches in the layer, and stop
    /// scanning the layer. Parent layers will not be trusted and the scan will continue.
    Trust,
}

fn scan_logic_result_to_cl(result: ScanLogicResult) -> cl_error_t {
    match result {
        ScanLogicResult::Abort => cl_error_t::CL_BREAK,
        ScanLogicResult::Success => cl_error_t::CL_SUCCESS,
        ScanLogicResult::Match => cl_error_t::CL_VIRUS,
        ScanLogicResult::Trust => cl_error_t::CL_VERIFIED,
    }
}

fn invoke_scan_logic(
    logic: &ScanLayerLogic,
    scan_layer: &mut ScanLayer,
    callback_name: &'static str,
) -> Result<ScanLogicResult, cl_error_t> {
    match panic::catch_unwind(AssertUnwindSafe(|| logic(scan_layer))) {
        Ok(decision) => Ok(decision),
        Err(_) => {
            log::error!("panic in {callback_name} scan callback; aborting scan");
            Err(cl_error_t::CL_BREAK)
        }
    }
}

/// A completion progress report, with a final result
#[derive(Debug)]
pub enum Progress<T, E> {
    /// An intermediate progress update.
    Update {
        /// How many elements have been handled
        now_completed: usize,
        /// How many elements are expected to be handled
        total_items: usize,
    },
    /// The terminal result of the operation.
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

/// Metadata and content access for the current libclamav scan layer.
///
/// A `ScanLayer` is only valid while the callback is executing. If you need to
/// keep any data after the callback returns, copy it out during the callback.
pub struct ScanLayer {
    layer: *mut clamav_sys::cl_scan_layer_t,
    fmap: Option<Fmap>,
}

impl ScanLayer {
    pub(crate) fn new(layer: *mut clamav_sys::cl_scan_layer_t) -> Self {
        Self { layer, fmap: None }
    }

    /// Returns the libclamav object id for the current scan layer.
    pub fn object_id(&self) -> Result<u64, EngineError> {
        let mut object_id: u64 = 0;
        let cl_result: cl_error_t = unsafe {
            clamav_sys::cl_scan_layer_get_object_id(self.layer, &mut object_id as *mut u64)
        };
        if cl_result != cl_error_t::CL_SUCCESS {
            Err(EngineError::Clam(crate::error::Error::from(cl_result)))
        } else {
            Ok(object_id)
        }
    }

    /// Returns the libclamav type string for the current scan layer.
    pub fn type_(&self) -> Result<String, EngineError> {
        let mut type_: *const c_char = std::ptr::null();
        let cl_result: cl_error_t = unsafe {
            clamav_sys::cl_scan_layer_get_type(self.layer, &mut type_ as *mut *const c_char)
        };
        if cl_result != cl_error_t::CL_SUCCESS || type_.is_null() {
            Err(EngineError::Clam(crate::error::Error::from(cl_result)))
        } else {
            let file_type = unsafe { CStr::from_ptr(type_).to_string_lossy().into_owned() };
            Ok(file_type)
        }
    }

    /// Returns the mapped file backing this scan layer.
    ///
    /// The first call fetches and caches the layer fmap from libclamav.
    pub fn fmap(&mut self) -> Result<&Fmap, EngineError> {
        if self.fmap.is_none() {
            let mut fmap_ptr: *mut clamav_sys::cl_fmap_t = std::ptr::null_mut();
            let cl_result: cl_error_t = unsafe {
                clamav_sys::cl_scan_layer_get_fmap(self.layer, &mut fmap_ptr as *mut *mut _)
            };
            if cl_result != cl_error_t::CL_SUCCESS || fmap_ptr.is_null() {
                return Err(EngineError::Clam(crate::error::Error::from(cl_result)));
            }

            let fmap = unsafe { Fmap::from_raw_borrowed(fmap_ptr) };
            self.fmap = Some(fmap);
        }

        // Safe to unwrap: we either had a cached fmap or just populated it above.
        Ok(self.fmap.as_ref().unwrap())
    }

    /// Returns the object ids of all ancestor layers, nearest parent first.
    pub fn ancestor_ids(&self) -> Result<Vec<u64>, EngineError> {
        let mut ancestors = Vec::new();
        let mut layer = self.layer;
        loop {
            let mut parent_layer: *mut clamav_sys::cl_scan_layer_t = std::ptr::null_mut();
            let cl_result = unsafe {
                clamav_sys::cl_scan_layer_get_parent_layer(
                    layer,
                    &mut parent_layer as *mut *mut clamav_sys::cl_scan_layer_t,
                )
            };
            if cl_result != cl_error_t::CL_SUCCESS || parent_layer.is_null() {
                break;
            }

            let parent = ScanLayer::new(parent_layer);
            ancestors.push(parent.object_id()?);
            layer = parent_layer;
        }
        Ok(ancestors)
    }

    /// Returns the file name associated with the layer, if one is available.
    pub fn file_name(&mut self) -> Option<String> {
        let fmap = self.fmap().ok()?;
        fmap.name().ok().flatten()
    }

    /// Returns the byte length of the layer, or `0` if it cannot be retrieved.
    pub fn file_size(&mut self) -> usize {
        self.fmap().and_then(|fmap| fmap.size()).unwrap_or(0)
    }

    /// Returns the SHA-256 digest for the layer contents.
    pub fn sha2_256(&mut self) -> Result<String, EngineError> {
        let fmap = self.fmap()?;
        fmap.sha2_256()
    }

    /// Returns a slice of the layer data.
    ///
    /// Passing `len == 0` requests the remainder of the layer from `offset`.
    /// The returned slice is borrowed from libclamav-managed memory and must
    /// not outlive the callback.
    pub fn data(&mut self, offset: usize, len: usize) -> Result<&[u8], EngineError> {
        if self.fmap.is_none() {
            let _ = self.fmap()?;
        }

        self.fmap
            .as_ref()
            .expect("fmap should be cached after retrieval")
            .data(offset, len)
    }

    /// Returns the most recent match name attached to the layer, if any.
    pub fn last_match(&self) -> Result<Option<String>, EngineError> {
        let mut match_out: *const c_char = std::ptr::null();
        let cl_result =
            unsafe { clamav_sys::cl_scan_layer_get_last_alert(self.layer, &mut match_out) };
        if cl_result != cl_error_t::CL_SUCCESS {
            Err(EngineError::Clam(crate::error::Error::from(cl_result)))
        } else if match_out.is_null() {
            Ok(None)
        } else {
            Ok(Some(
                unsafe { CStr::from_ptr(match_out) }
                    .to_string_lossy()
                    .into_owned(),
            ))
        }
    }
}

pub(crate) unsafe extern "C" fn engine_callback_match(
    layer: *mut clamav_sys::cl_scan_layer_t,
    context: *mut c_void,
) -> cl_error_t {
    let mut decision = ScanLogicResult::Success;
    if let Some(cxt) = context.cast::<ScanCbContext>().as_ref() {
        let mut scan_layer = ScanLayer::new(layer);
        if scan_layer.fmap().is_err() {
            return cl_error_t::CL_SUCCESS; // handle error?
        }

        let object_id = match scan_layer.object_id() {
            Ok(id) => id,
            // Return CL_VIRUS to preserve the match, despite the error in this handler.
            Err(_) => return cl_error_t::CL_VIRUS, // handle error?
        };

        let file_type = match scan_layer.type_() {
            Ok(ft) => ft,
            // Return CL_VIRUS to preserve the match, despite the error in this handler.
            Err(_) => return cl_error_t::CL_VIRUS, // handle error?
        };

        let ancestor_ids = match scan_layer.ancestor_ids() {
            Ok(ids) => ids,
            // Return CL_VIRUS to preserve the match, despite the error in this handler.
            Err(_) => return cl_error_t::CL_VIRUS, // handle error?
        };

        let file_name = scan_layer.file_name();
        let file_size = scan_layer.file_size();
        let sha2_256 = match scan_layer.sha2_256() {
            Ok(hash) => hash,
            // Return CL_VIRUS to preserve the match, despite the error in this handler.
            Err(_) => return cl_error_t::CL_VIRUS, // handle error?
        };

        // Get the last match name
        let mut match_out: *const c_char = std::ptr::null();
        let cl_result = unsafe { clamav_sys::cl_scan_layer_get_last_alert(layer, &mut match_out) };
        if cl_result != cl_error_t::CL_SUCCESS {
            // Return CL_VIRUS to preserve the match, despite the error in this handler.
            return cl_error_t::CL_VIRUS; // handle error?
        }
        let match_name = if match_out.is_null() {
            String::from("Unknown")
        } else {
            unsafe { CStr::from_ptr(match_out) }
                .to_string_lossy()
                .into_owned()
        };

        let match_logic = cxt
            .match_logic
            .as_ref()
            .and_then(|logic| logic.downcast_ref::<Box<MatchLogic>>());
        if let Some(logic) = match_logic {
            decision = match invoke_scan_logic(logic.as_ref(), &mut scan_layer, "match") {
                Ok(decision) => decision,
                Err(err) => return err,
            };
        }

        if decision == ScanLogicResult::Success || decision == ScanLogicResult::Trust {
            // The decision is to ignore the match or trust the file, which means
            // we do not want to report the match to the user, so we return early here
            // without sending an event.
        } else {
            let _ = cxt.sender.blocking_send(ScanEvent::MatchFound {
                entity_id: object_id,
                ancestors: ancestor_ids,
                sha2_256,
                file_name,
                file_size,
                file_type: file_type.into(),
                match_name,
            });
        }
    }

    scan_logic_result_to_cl(decision)
}

pub(crate) unsafe extern "C" fn engine_callback_file_type(
    layer: *mut clamav_sys::cl_scan_layer_t,
    context: *mut c_void,
) -> cl_error_t {
    let mut decision = ScanLogicResult::Success;
    if let Some(cxt) = context.cast::<ScanCbContext>().as_ref() {
        let mut scan_layer = ScanLayer::new(layer);
        if scan_layer.fmap().is_err() {
            return cl_error_t::CL_SUCCESS; // handle error?
        }

        let object_id = match scan_layer.object_id() {
            Ok(id) => id,
            Err(_) => return cl_error_t::CL_SUCCESS, // handle error?
        };

        let file_type = match scan_layer.type_() {
            Ok(ft) => ft,
            Err(_) => return cl_error_t::CL_SUCCESS, // handle error?
        };

        let ancestor_ids = match scan_layer.ancestor_ids() {
            Ok(ids) => ids,
            Err(_) => Vec::new(), // handle error?
        };

        let file_name = scan_layer.file_name();
        let file_size = scan_layer.file_size();

        // Run the user-defined file-type logic, if it exists.
        let file_type_logic = cxt
            .file_type_logic
            .as_ref()
            .and_then(|logic| logic.downcast_ref::<Box<FileTypeLogic>>());
        if let Some(logic) = file_type_logic {
            decision = match invoke_scan_logic(logic.as_ref(), &mut scan_layer, "file-type") {
                Ok(decision) => decision,
                Err(err) => return err,
            };
        }

        let _ = cxt.sender.blocking_send(ScanEvent::FileType {
            entity_id: object_id,
            ancestors: ancestor_ids,
            file_name,
            file_size,
            file_type: file_type.into(),
        });
    }

    scan_logic_result_to_cl(decision)
}

pub(crate) unsafe extern "C" fn engine_callback_pre_scan(
    layer: *mut clamav_sys::cl_scan_layer_t,
    context: *mut c_void,
) -> cl_error_t {
    let mut decision = ScanLogicResult::Success;
    if let Some(cxt) = context.cast::<ScanCbContext>().as_ref() {
        let mut scan_layer = ScanLayer::new(layer);
        if scan_layer.fmap().is_err() {
            return cl_error_t::CL_SUCCESS; // handle error?
        }

        let object_id = match scan_layer.object_id() {
            Ok(id) => id,
            Err(_) => return cl_error_t::CL_SUCCESS, // handle error?
        };

        let file_type = match scan_layer.type_() {
            Ok(ft) => ft,
            Err(_) => return cl_error_t::CL_SUCCESS, // handle error?
        };

        let ancestor_ids = match scan_layer.ancestor_ids() {
            Ok(ids) => ids,
            Err(_) => Vec::new(), // handle error?
        };

        let file_name = scan_layer.file_name();
        let file_size = scan_layer.file_size();
        let sha2_256 = match scan_layer.sha2_256() {
            Ok(hash) => hash,
            Err(_) => String::new(), // handle error?
        };

        // Run the user-defined pre-scan logic, if it exists.
        // This can be used for custom decisions or side effects before emitting the PreScan event.
        let pre_scan_logic = cxt
            .pre_scan_logic
            .as_ref()
            .and_then(|logic| logic.downcast_ref::<Box<PreScanLogic>>());
        if let Some(logic) = pre_scan_logic {
            decision = match invoke_scan_logic(logic.as_ref(), &mut scan_layer, "pre-scan") {
                Ok(decision) => decision,
                Err(err) => return err,
            };
        }

        let _ = cxt.sender.blocking_send(ScanEvent::PreScan {
            entity_id: object_id,
            ancestors: ancestor_ids,
            sha2_256,
            file_name,
            file_size,
            file_type: file_type.into(),
        });
    }

    scan_logic_result_to_cl(decision)
}

pub(crate) unsafe extern "C" fn engine_callback_post_scan(
    layer: *mut clamav_sys::cl_scan_layer_t,
    context: *mut c_void,
) -> cl_error_t {
    let mut decision = ScanLogicResult::Success;
    if let Some(cxt) = context.cast::<ScanCbContext>().as_ref() {
        let mut scan_layer = ScanLayer::new(layer);
        if scan_layer.fmap().is_err() {
            return cl_error_t::CL_SUCCESS;
        }

        let object_id = match scan_layer.object_id() {
            Ok(id) => id,
            Err(_) => return cl_error_t::CL_SUCCESS,
        };

        let file_type = match scan_layer.type_() {
            Ok(ft) => ft,
            Err(_) => return cl_error_t::CL_SUCCESS,
        };

        let ancestor_ids = match scan_layer.ancestor_ids() {
            Ok(ids) => ids,
            Err(_) => Vec::new(),
        };

        let file_name = scan_layer.file_name();
        let file_size = scan_layer.file_size();
        let sha2_256 = match scan_layer.sha2_256() {
            Ok(hash) => hash,
            Err(_) => String::new(),
        };

        let post_scan_logic = cxt
            .post_scan_logic
            .as_ref()
            .and_then(|logic| logic.downcast_ref::<Box<PostScanLogic>>());
        if let Some(logic) = post_scan_logic {
            decision = match invoke_scan_logic(logic.as_ref(), &mut scan_layer, "post-scan") {
                Ok(decision) => decision,
                Err(err) => return err,
            };
        }

        let _ = cxt.sender.blocking_send(ScanEvent::PostScan {
            entity_id: object_id,
            ancestors: ancestor_ids,
            sha2_256,
            file_name,
            file_size,
            file_type: file_type.into(),
        });
    }

    scan_logic_result_to_cl(decision)
}

#[cfg(test)]
mod tests {
    use crate::{
        callback::{EngineCallback, ScanLogicResult},
        engine::{Engine, ScanEvent, ScanResult},
        fmap::Fmap,
        scan_settings::{GeneralFlags, ParseFlags, ScanSettings},
    };
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, File},
        io::Cursor,
        io::Write,
        path::Path,
        sync::{Arc, Mutex},
    };
    use tempfile::{tempdir, Builder};
    use tokio_stream::StreamExt;
    use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

    const TEST_DATABASES_PATH: &str = "test_data/database/";

    fn scan_settings() -> ScanSettings {
        let mut settings = ScanSettings::default();
        settings.set_parse(&ParseFlags::all());
        settings.set_general(&GeneralFlags::CL_SCAN_GENERAL_HEURISTICS);
        settings
    }

    async fn configured_engine() -> Engine {
        crate::initialize().expect("initialize should succeed");
        let engine = Engine::new();
        engine
            .load_databases(TEST_DATABASES_PATH)
            .await
            .expect("database load should succeed");
        engine
            .compile()
            .await
            .expect("engine compile should succeed");
        engine
    }

    async fn scan_and_collect_events(
        engine: &Engine,
        target: Fmap,
        filename: Option<&str>,
    ) -> Vec<ScanEvent> {
        let mut stream = engine
            .scan(target, filename, None, None, None, scan_settings())
            .expect("scan setup should succeed");

        let mut events = Vec::new();
        while let Some(event) = stream.next().await {
            events.push(event);
        }
        events
    }

    fn fixture_metadata(path: &str) -> (String, usize, String) {
        let bytes = fs::read(path).expect("fixture should be readable");
        let file_name = Path::new(path)
            .file_name()
            .expect("fixture path should have file name")
            .to_string_lossy()
            .into_owned();
        let sha2_256 = Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        (file_name, bytes.len(), sha2_256)
    }

    fn stored_zip_bytes(entry_name: &str, contents: &[u8]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        writer
            .start_file(entry_name, options)
            .expect("zip entry should be created");
        writer
            .write_all(contents)
            .expect("zip contents should be written");
        writer
            .finish()
            .expect("zip archive should be finalized")
            .into_inner()
    }

    fn write_test_signature() -> tempfile::NamedTempFile {
        let signature = b"naughty_file_test;Engine:81-255,Target:0;0;6e617567687479\n";
        let mut db_file = Builder::new()
            .prefix("match_callback_")
            .suffix(".ldb")
            .tempfile_in(TEST_DATABASES_PATH)
            .expect("temporary database file creation should succeed");
        db_file
            .write_all(signature)
            .expect("writing signature to temp file should succeed");
        db_file
            .flush()
            .expect("flushing signature to temp file should succeed");
        db_file
    }

    fn write_sha256_signature(
        sha2_256: &str,
        file_size: usize,
        name: &str,
    ) -> tempfile::NamedTempFile {
        let signature = format!("{sha2_256}:{file_size}:{name}\n");
        let mut db_file = Builder::new()
            .prefix("match_callback_")
            .suffix(".hsb")
            .tempfile_in(TEST_DATABASES_PATH)
            .expect("temporary hash database file creation should succeed");
        db_file
            .write_all(signature.as_bytes())
            .expect("writing signature to temp file should succeed");
        db_file
            .flush()
            .expect("flushing signature to temp file should succeed");
        db_file
    }

    fn pre_scan_operation(hit: Arc<Mutex<bool>>) -> Box<crate::callback::PreScanLogic> {
        Box::new(move |_scan_layer: &mut crate::callback::ScanLayer| {
            *hit.lock().unwrap() = true;
            // Return Success here to keep scanning.
            ScanLogicResult::Success
        })
    }

    fn pre_scan_trust_operation(hit: Arc<Mutex<bool>>) -> Box<crate::callback::PreScanLogic> {
        Box::new(move |_scan_layer: &mut crate::callback::ScanLayer| {
            *hit.lock().unwrap() = true;
            // Return Trust here to stop scanning the current layer, and mark the result as trusted.
            // The parent layer will not be marked as trusted, and the scan will continue.
            ScanLogicResult::Trust
        })
    }

    fn post_scan_operation(hit: Arc<Mutex<bool>>) -> Box<crate::callback::PostScanLogic> {
        Box::new(move |_scan_layer: &mut crate::callback::ScanLayer| {
            *hit.lock().unwrap() = true;
            // Return Success here to keep scanning.
            ScanLogicResult::Success
        })
    }

    fn file_type_operation(
        hit: Arc<Mutex<bool>>,
        observed_file_type: Arc<Mutex<Option<String>>>,
    ) -> Box<crate::callback::FileTypeLogic> {
        Box::new(move |scan_layer: &mut crate::callback::ScanLayer| {
            *observed_file_type.lock().unwrap() =
                Some(scan_layer.type_().expect("file type should be available"));
            *hit.lock().unwrap() = true;
            // Return Success here to keep scanning.
            ScanLogicResult::Success
        })
    }

    fn match_operation(
        hit: Arc<Mutex<bool>>,
        copied_data: Arc<Mutex<Option<Vec<u8>>>>,
    ) -> Box<crate::callback::MatchLogic> {
        Box::new(move |scan_layer: &mut crate::callback::ScanLayer| {
            *hit.lock().unwrap() = true;
            *copied_data.lock().unwrap() = Some(
                scan_layer
                    .data(0, 0)
                    .expect("data retrieval should succeed")
                    .to_vec(),
            );
            // Return Match here to agree with the match, so it isn't dropped.
            ScanLogicResult::Match
        })
    }

    // Goal: prove that a registered pre-scan callback runs for a simple file scan.
    // Strategy: scan a known-good text fixture, assert the emitted PreScan event
    // metadata matches the fixture, confirm the final result is clean, and check
    // that the callback flipped its shared hit flag.
    #[tokio::test]
    async fn pre_scan_callback() {
        let hit = Arc::new(Mutex::new(false));
        let fixture_path = "test_data/files/good_file";
        let (file_name, file_size, sha2_256) = fixture_metadata(fixture_path);

        crate::initialize().expect("initialize should succeed");
        // crate::debug();

        let mut engine = configured_engine().await;
        engine.register_callback(EngineCallback::PreScan, pre_scan_operation(hit.clone()));

        let events = scan_and_collect_events(
            &engine,
            Fmap::try_from(File::open(fixture_path).expect("opening good_file should succeed"))
                .expect("file-backed fmap creation should succeed"),
            Some(&file_name),
        )
        .await;

        let pre_scan_event = events
            .iter()
            .find(|event| matches!(event, ScanEvent::PreScan { .. }))
            .expect("pre-scan event should be emitted");
        let ScanEvent::PreScan {
            entity_id,
            ancestors,
            sha2_256: event_sha2_256,
            file_name: event_file_name,
            file_size: event_file_size,
            file_type,
        } = pre_scan_event
        else {
            panic!("pre-scan event should match the expected variant");
        };
        assert_eq!(*entity_id, 0, "entity id should be the root layer");
        assert_eq!(*ancestors, Vec::<u64>::new(), "ancestors should be empty");
        assert_eq!(
            *event_sha2_256, sha2_256,
            "sha2-256 should match fixture content"
        );
        assert_eq!(
            *event_file_name,
            Some(file_name),
            "file name should match the scanned file name"
        );
        assert_eq!(
            *event_file_size, file_size,
            "file size should match fixture size"
        );
        assert_eq!(
            *file_type, "CL_TYPE_TEXT_ASCII",
            "file type should be ASCII text"
        );
        assert!(
            matches!(
                events.last(),
                Some(ScanEvent::Result(Ok(ScanResult::NothingFound)))
            ),
            "scan should finish with no matches found"
        );
        assert!(
            *hit.lock().unwrap(),
            "registered pre-scan callback should run"
        );
    }

    // Goal: prove that returning Trust from the root pre-scan callback marks the
    // final scan result as Trusted.
    // Strategy: register a pre-scan callback that always returns Trust, verify
    // the root PreScan event metadata, and assert the terminal Result event is
    // ScanResult::Trusted.
    #[tokio::test]
    async fn pre_scan_trust_returns_trusted_result() {
        let hit = Arc::new(Mutex::new(false));
        let fixture_path = "test_data/files/good_file";
        let (file_name, file_size, sha2_256) = fixture_metadata(fixture_path);

        crate::initialize().expect("initialize should succeed");

        let mut engine = configured_engine().await;
        engine.register_callback(
            EngineCallback::PreScan,
            pre_scan_trust_operation(hit.clone()),
        );

        let events = scan_and_collect_events(
            &engine,
            Fmap::try_from(File::open(fixture_path).expect("opening good_file should succeed"))
                .expect("file-backed fmap creation should succeed"),
            Some(&file_name),
        )
        .await;

        let pre_scan_event = events
            .iter()
            .find(|event| matches!(event, ScanEvent::PreScan { .. }))
            .expect("pre-scan event should be emitted");
        let ScanEvent::PreScan {
            entity_id,
            ancestors,
            sha2_256: event_sha2_256,
            file_name: event_file_name,
            file_size: event_file_size,
            file_type,
        } = pre_scan_event
        else {
            panic!("pre-scan event should match the expected variant");
        };
        assert_eq!(*entity_id, 0, "entity id should be the root layer");
        assert_eq!(*ancestors, Vec::<u64>::new(), "ancestors should be empty");
        assert_eq!(
            *event_sha2_256, sha2_256,
            "sha2-256 should match fixture content"
        );
        assert_eq!(
            *event_file_name,
            Some(file_name),
            "file name should match the scanned file name"
        );
        assert_eq!(
            *event_file_size, file_size,
            "file size should match fixture size"
        );
        assert_eq!(
            *file_type, "CL_TYPE_TEXT_ASCII",
            "file type should be ASCII text"
        );
        assert!(
            matches!(
                events.last(),
                Some(ScanEvent::Result(Ok(ScanResult::Trusted)))
            ),
            "returning Trust from the pre-scan callback should end the scan as trusted"
        );
        assert!(
            *hit.lock().unwrap(),
            "registered pre-scan trust callback should run"
        );
    }

    #[tokio::test]
    async fn panic_in_callback_is_caught_and_aborts_scan() {
        let fixture_path = "test_data/files/good_file";
        let (file_name, _file_size, _sha2_256) = fixture_metadata(fixture_path);

        crate::initialize().expect("initialize should succeed");

        let mut engine = configured_engine().await;
        engine.register_callback(
            EngineCallback::PreScan,
            Box::new(|_scan_layer: &mut crate::callback::ScanLayer| {
                panic!("callback panic should be caught inside the FFI shim");
            }),
        );

        let events = scan_and_collect_events(
            &engine,
            Fmap::try_from(File::open(fixture_path).expect("opening good_file should succeed"))
                .expect("file-backed fmap creation should succeed"),
            Some(&file_name),
        )
        .await;

        assert!(
            !events
                .iter()
                .any(|event| matches!(event, ScanEvent::PreScan { .. })),
            "a panicking callback should abort before emitting the callback event"
        );
        assert!(
            matches!(events.as_slice(), [ScanEvent::Result(_)]),
            "a panicking callback should still terminate through the normal result channel instead of unwinding across FFI"
        );
    }

    // Goal: prove that the file-type callback runs and sees the layer type that
    // libclamav reports for the scanned file.
    // Strategy: capture the type string from the callback, verify the emitted
    // FileType event fields match the fixture, and assert both the observed type
    // and the event type are CL_TYPE_TEXT_ASCII.
    #[tokio::test]
    async fn file_type_callback() {
        let hit = Arc::new(Mutex::new(false));
        let observed_file_type = Arc::new(Mutex::new(None));
        let fixture_path = "test_data/files/good_file";
        let (file_name, file_size, _sha2_256) = fixture_metadata(fixture_path);

        crate::initialize().expect("initialize should succeed");
        // crate::debug();

        let mut engine = configured_engine().await;
        engine.register_callback(
            EngineCallback::FileType,
            file_type_operation(hit.clone(), observed_file_type.clone()),
        );

        let events = scan_and_collect_events(
            &engine,
            Fmap::try_from(File::open(fixture_path).expect("opening good_file should succeed"))
                .expect("file-backed fmap creation should succeed"),
            Some(&file_name),
        )
        .await;

        let file_type_event = events
            .iter()
            .find(|event| matches!(event, ScanEvent::FileType { .. }))
            .expect("file-type event should be emitted");
        let ScanEvent::FileType {
            entity_id,
            ancestors,
            file_name: event_file_name,
            file_size: event_file_size,
            file_type,
        } = file_type_event
        else {
            panic!("file-type event should match the expected variant");
        };
        assert_eq!(*entity_id, 0, "entity id should be the root layer");
        assert_eq!(*ancestors, Vec::<u64>::new(), "ancestors should be empty");
        assert_eq!(
            *event_file_name,
            Some(file_name),
            "file name should match the scanned file name"
        );
        assert_eq!(
            *event_file_size, file_size,
            "file size should match fixture size"
        );
        assert_eq!(
            *file_type, "CL_TYPE_TEXT_ASCII",
            "file type should be ASCII text"
        );
        assert!(
            matches!(
                events.last(),
                Some(ScanEvent::Result(Ok(ScanResult::NothingFound)))
            ),
            "scan should finish with no matches found"
        );
        assert!(
            *hit.lock().unwrap(),
            "registered file-type callback should run"
        );
        assert_eq!(
            observed_file_type.lock().unwrap().as_deref(),
            Some("CL_TYPE_TEXT_ASCII"),
            "file-type callback should observe the ASCII text layer type"
        );
    }

    // Goal: prove that a registered post-scan callback runs after a successful
    // single-layer scan.
    // Strategy: scan a known-good text fixture, assert the emitted PostScan event
    // metadata matches the fixture, confirm the final result is clean, and check
    // that the callback flipped its shared hit flag.
    #[tokio::test]
    async fn post_scan_callback() {
        let hit = Arc::new(Mutex::new(false));
        let fixture_path = "test_data/files/good_file";
        let (file_name, file_size, sha2_256) = fixture_metadata(fixture_path);

        crate::initialize().expect("initialize should succeed");
        // crate::debug();

        let mut engine = configured_engine().await;
        engine.register_callback(EngineCallback::PostScan, post_scan_operation(hit.clone()));

        let events = scan_and_collect_events(
            &engine,
            Fmap::try_from(File::open(fixture_path).expect("opening good_file should succeed"))
                .expect("file-backed fmap creation should succeed"),
            Some(&file_name),
        )
        .await;

        let post_scan_event = events
            .iter()
            .find(|event| matches!(event, ScanEvent::PostScan { .. }))
            .expect("post-scan event should be emitted");
        let ScanEvent::PostScan {
            entity_id,
            ancestors,
            sha2_256: event_sha2_256,
            file_name: event_file_name,
            file_size: event_file_size,
            file_type,
        } = post_scan_event
        else {
            panic!("post-scan event should match the expected variant");
        };
        assert_eq!(*entity_id, 0, "entity id should be the root layer");
        assert_eq!(*ancestors, Vec::<u64>::new(), "ancestors should be empty");
        assert_eq!(
            *event_sha2_256, sha2_256,
            "sha2-256 should match fixture content"
        );
        assert_eq!(
            *event_file_name,
            Some(file_name),
            "file name should match the scanned file name"
        );
        assert_eq!(
            *event_file_size, file_size,
            "file size should match fixture size"
        );
        assert_eq!(
            *file_type, "CL_TYPE_TEXT_ASCII",
            "file type should be ASCII text"
        );
        assert!(
            matches!(
                events.last(),
                Some(ScanEvent::Result(Ok(ScanResult::NothingFound)))
            ),
            "scan should finish with no matches found"
        );
        assert!(
            *hit.lock().unwrap(),
            "registered post-scan callback should run"
        );
    }

    // Goal: prove that the match callback can both observe match-layer bytes and
    // preserve the detection by returning Match.
    // Strategy: generate a >1 MiB matching file and matching signature, copy the
    // layer bytes inside the callback, then assert the MatchFound event metadata,
    // terminal match result, and copied bytes all match the generated fixture.
    #[tokio::test]
    async fn match_callback() {
        let hit = Arc::new(Mutex::new(false));
        let copied_data = Arc::new(Mutex::new(None));
        let source_fixture_path = "test_data/files/naughty_file";
        let source_fixture_contents =
            fs::read(source_fixture_path).expect("fixture should be readable");
        let temp_dir = tempdir().expect("temporary directory creation should succeed");
        let fixture_path = temp_dir.path().join("naughty_file_large");
        let mut fixture_contents = Vec::new();
        while fixture_contents.len() <= 1024 * 1024 {
            fixture_contents.extend_from_slice(&source_fixture_contents);
        }
        fs::write(&fixture_path, &fixture_contents)
            .expect("expanded match fixture should be written");
        let (file_name, file_size, sha2_256) = fixture_metadata(
            fixture_path
                .to_str()
                .expect("expanded fixture path should be valid UTF-8"),
        );
        let signature_name = "naughty_file_large";
        let expected_match_name = "naughty_file_large.UNOFFICIAL";

        crate::initialize().expect("initialize should succeed");
        // crate::debug();

        let _signature = write_sha256_signature(&sha2_256, file_size, signature_name);

        let mut engine = configured_engine().await;
        engine.register_callback(
            EngineCallback::Match,
            match_operation(hit.clone(), copied_data.clone()),
        );

        let events = scan_and_collect_events(
            &engine,
            Fmap::try_from(
                File::open(&fixture_path).expect("opening expanded naughty_file should succeed"),
            )
            .expect("file-backed fmap creation should succeed"),
            Some(&file_name),
        )
        .await;

        let match_event = events
            .iter()
            .find(|event| matches!(event, ScanEvent::MatchFound { .. }))
            .expect("match event should be emitted");
        let ScanEvent::MatchFound {
            entity_id,
            ancestors,
            sha2_256: event_sha2_256,
            file_name: event_file_name,
            file_size: event_file_size,
            file_type,
            match_name,
        } = match_event
        else {
            panic!("match event should match the expected variant");
        };
        assert_eq!(*entity_id, 0, "entity id should be the root layer");
        assert_eq!(*ancestors, Vec::<u64>::new(), "ancestors should be empty");
        assert_eq!(
            *event_sha2_256, sha2_256,
            "sha2-256 should match fixture content"
        );
        assert_eq!(
            *event_file_name,
            Some(file_name),
            "file name should match the scanned file name"
        );
        assert_eq!(
            *event_file_size, file_size,
            "file size should match fixture size"
        );
        assert_eq!(
            *file_type, "CL_TYPE_TEXT_ASCII",
            "file type should be ASCII text"
        );
        assert_eq!(
            *match_name, expected_match_name,
            "match name should match the generated test signature"
        );
        assert!(
            matches!(
                events.last(),
                Some(ScanEvent::Result(Ok(ScanResult::MatchFound(name))))
                    if name == expected_match_name
            ),
            "scan should finish with a match found result"
        );
        assert!(*hit.lock().unwrap(), "registered match callback should run");
        assert_eq!(
            copied_data
                .lock()
                .unwrap()
                .as_deref()
                .expect("match callback should copy the file data"),
            fixture_contents.as_slice(),
            "copied match data should match the fixture contents"
        );
    }

    // Goal: prove callback ordering and per-layer metadata for a nested scan of
    // a zip archive containing a matching text file.
    // Strategy: register all callback types, scan a crafted zip fixture, assert
    // the exact event sequence and metadata for both the outer zip and inner
    // file, and verify the callback invocation counts.
    #[tokio::test]
    async fn combined_callback_with_zip() {
        let pre_scan_count = Arc::new(Mutex::new(0_u32));
        let file_type_count = Arc::new(Mutex::new(0_u32));
        let match_count = Arc::new(Mutex::new(0_u32));
        let post_scan_count = Arc::new(Mutex::new(0_u32));

        let inner_fixture_path = "test_data/files/naughty_file";
        let temp_dir = tempdir().expect("temporary directory creation should succeed");
        let inner_file_path = temp_dir.path().join("naughty_file");
        let zip_file_path = temp_dir.path().join("naughty_file.zip");
        let inner_contents = fs::read(inner_fixture_path).expect("fixture should be readable");
        fs::write(&inner_file_path, &inner_contents).expect("inner test file should be written");
        fs::write(
            &zip_file_path,
            stored_zip_bytes("naughty_file", &inner_contents),
        )
        .expect("zip archive should be written");

        let (inner_file_name, inner_file_size, inner_sha2_256) = fixture_metadata(
            inner_file_path
                .to_str()
                .expect("inner path should be valid UTF-8"),
        );
        let (zip_file_name, zip_file_size, zip_sha2_256) = fixture_metadata(
            zip_file_path
                .to_str()
                .expect("zip path should be valid UTF-8"),
        );

        crate::initialize().expect("initialize should succeed");
        // crate::debug();

        let _signature = write_test_signature();

        let mut engine = configured_engine().await;
        engine.register_callback(
            EngineCallback::FileType,
            Box::new({
                let file_type_count = file_type_count.clone();
                move |_scan_layer: &mut crate::callback::ScanLayer| {
                    *file_type_count.lock().unwrap() += 1;
                    ScanLogicResult::Success
                }
            }),
        );
        engine.register_callback(
            EngineCallback::PreScan,
            Box::new({
                let pre_scan_count = pre_scan_count.clone();
                move |_scan_layer: &mut crate::callback::ScanLayer| {
                    *pre_scan_count.lock().unwrap() += 1;
                    ScanLogicResult::Success
                }
            }),
        );
        engine.register_callback(
            EngineCallback::Match,
            Box::new({
                let match_count = match_count.clone();
                move |scan_layer: &mut crate::callback::ScanLayer| {
                    *match_count.lock().unwrap() += 1;

                    if scan_layer
                        .last_match()
                        .expect("last match retrieval should succeed")
                        .as_deref()
                        .is_some_and(|name| name.starts_with("SUBMIT."))
                    {
                        // Return Success to ignore the match and allow the scan to complete,
                        // so we can observe all callbacks.
                        ScanLogicResult::Success
                    } else {
                        // Keep the match, and keep scanning.
                        ScanLogicResult::Match
                    }
                }
            }),
        );
        engine.register_callback(
            EngineCallback::PostScan,
            Box::new({
                let post_scan_count = post_scan_count.clone();
                move |_scan_layer: &mut crate::callback::ScanLayer| {
                    *post_scan_count.lock().unwrap() += 1;
                    ScanLogicResult::Success
                }
            }),
        );

        let events = scan_and_collect_events(
            &engine,
            Fmap::try_from(File::open(&zip_file_path).expect("opening zip file should succeed"))
                .expect("file-backed fmap creation should succeed"),
            Some(&zip_file_name),
        )
        .await;

        assert_eq!(
            events.len(),
            8,
            "scan should emit the expected number of events"
        );

        let ScanEvent::FileType {
            entity_id,
            ancestors,
            file_name,
            file_size,
            file_type,
        } = &events[0]
        else {
            panic!("first event should be the outer zip file-type event");
        };
        assert_eq!(*entity_id, 0, "outer zip should have root entity id");
        assert_eq!(
            *ancestors,
            Vec::<u64>::new(),
            "outer zip should have no ancestors"
        );
        assert_eq!(
            *file_name,
            Some(zip_file_name.clone()),
            "outer zip file name should match the scanned archive name"
        );
        assert_eq!(
            *file_size, zip_file_size,
            "outer zip size should match fixture size"
        );
        assert_eq!(
            *file_type, "CL_TYPE_ZIP",
            "outer zip file type should be CL_TYPE_ZIP"
        );

        let ScanEvent::PreScan {
            entity_id,
            ancestors,
            sha2_256,
            file_name,
            file_size,
            file_type,
        } = &events[1]
        else {
            panic!("second event should be the outer zip pre-scan event");
        };
        assert_eq!(*entity_id, 0, "outer zip should have root entity id");
        assert_eq!(
            *ancestors,
            Vec::<u64>::new(),
            "outer zip should have no ancestors"
        );
        assert_eq!(
            *sha2_256, zip_sha2_256,
            "outer zip hash should match fixture content"
        );
        assert_eq!(
            *file_name,
            Some(zip_file_name.clone()),
            "outer zip file name should match the scanned archive name"
        );
        assert_eq!(
            *file_size, zip_file_size,
            "outer zip size should match fixture size"
        );
        assert_eq!(
            *file_type, "CL_TYPE_ZIP",
            "outer zip file type should be CL_TYPE_ZIP"
        );

        let ScanEvent::FileType {
            entity_id,
            ancestors,
            file_name,
            file_size,
            file_type,
        } = &events[2]
        else {
            panic!("third event should be the inner file-type event");
        };
        assert_eq!(*entity_id, 1, "inner file should have entity id 1");
        assert_eq!(
            *ancestors,
            vec![0],
            "inner file should have the zip as its ancestor"
        );
        assert_eq!(
            *file_name,
            Some(inner_file_name.clone()),
            "inner file name should match the archive entry name"
        );
        assert_eq!(
            *file_size, inner_file_size,
            "inner file size should match fixture size"
        );
        assert_eq!(
            *file_type, "CL_TYPE_TEXT_ASCII",
            "inner file type should be ASCII text"
        );

        let ScanEvent::PreScan {
            entity_id,
            ancestors,
            sha2_256,
            file_name,
            file_size,
            file_type,
        } = &events[3]
        else {
            panic!("fourth event should be the inner pre-scan event");
        };
        assert_eq!(*entity_id, 1, "inner file should have entity id 1");
        assert_eq!(
            *ancestors,
            vec![0],
            "inner file should have the zip as its ancestor"
        );
        assert_eq!(
            *sha2_256, inner_sha2_256,
            "inner file hash should match fixture content"
        );
        assert_eq!(
            *file_name,
            Some(inner_file_name.clone()),
            "inner file name should match the archive entry name"
        );
        assert_eq!(
            *file_size, inner_file_size,
            "inner file size should match fixture size"
        );
        assert_eq!(
            *file_type, "CL_TYPE_TEXT_ASCII",
            "inner file type should be ASCII text"
        );

        let ScanEvent::MatchFound {
            entity_id,
            ancestors,
            sha2_256,
            file_name,
            file_size,
            file_type,
            match_name,
        } = &events[4]
        else {
            panic!("fifth event should be the inner match event");
        };
        assert_eq!(*entity_id, 1, "inner file should have entity id 1");
        assert_eq!(
            *ancestors,
            vec![0],
            "inner file should have the zip as its ancestor"
        );
        assert_eq!(
            *sha2_256, inner_sha2_256,
            "inner file hash should match fixture content"
        );
        assert_eq!(
            *file_name,
            Some(inner_file_name.clone()),
            "inner file name should match the archive entry name"
        );
        assert_eq!(
            *file_size, inner_file_size,
            "inner file size should match fixture size"
        );
        assert_eq!(
            *file_type, "CL_TYPE_TEXT_ASCII",
            "inner file type should be ASCII text"
        );
        assert_eq!(
            *match_name, "naughty_file.UNOFFICIAL",
            "match name should match the generated test signature"
        );

        let ScanEvent::PostScan {
            entity_id,
            ancestors,
            sha2_256,
            file_name,
            file_size,
            file_type,
        } = &events[5]
        else {
            panic!("sixth event should be the inner post-scan event");
        };
        assert_eq!(*entity_id, 1, "inner file should have entity id 1");
        assert_eq!(
            *ancestors,
            vec![0],
            "inner file should have the zip as its ancestor"
        );
        assert_eq!(
            *sha2_256, inner_sha2_256,
            "inner file hash should match fixture content"
        );
        assert_eq!(
            *file_name,
            Some(inner_file_name.clone()),
            "inner file name should match the archive entry name"
        );
        assert_eq!(
            *file_size, inner_file_size,
            "inner file size should match fixture size"
        );
        assert_eq!(
            *file_type, "CL_TYPE_TEXT_ASCII",
            "inner file type should be ASCII text"
        );

        let ScanEvent::PostScan {
            entity_id,
            ancestors,
            sha2_256,
            file_name,
            file_size,
            file_type,
        } = &events[6]
        else {
            panic!("seventh event should be the outer zip post-scan event");
        };
        assert_eq!(*entity_id, 0, "outer zip should have root entity id");
        assert_eq!(
            *ancestors,
            Vec::<u64>::new(),
            "outer zip should have no ancestors"
        );
        assert_eq!(
            *sha2_256, zip_sha2_256,
            "outer zip hash should match fixture content"
        );
        assert_eq!(
            *file_name,
            Some(zip_file_name.clone()),
            "outer zip file name should match the scanned archive name"
        );
        assert_eq!(
            *file_size, zip_file_size,
            "outer zip size should match fixture size"
        );
        assert_eq!(
            *file_type, "CL_TYPE_ZIP",
            "outer zip file type should be CL_TYPE_ZIP"
        );

        let ScanEvent::Result(result) = &events[7] else {
            panic!("eighth event should be the final scan result");
        };
        match result.as_ref().expect("scan result should be available") {
            ScanResult::MatchFound(name) => assert_eq!(
                name, "naughty_file.UNOFFICIAL",
                "scan should finish with the expected match result"
            ),
            other => panic!("expected a match result, got {other:?}"),
        }

        assert_eq!(
            *file_type_count.lock().unwrap(),
            2,
            "file-type callback should run for the zip and the inner file"
        );
        assert_eq!(
            *pre_scan_count.lock().unwrap(),
            2,
            "pre-scan callback should run for the zip and the inner file"
        );
        assert_eq!(
            *match_count.lock().unwrap(),
            1,
            "match callback should run once for the inner file"
        );
        assert_eq!(
            *post_scan_count.lock().unwrap(),
            2,
            "post-scan callback should run for the inner file and the outer zip"
        );
    }

    // Goal: prove that returning Trust for an inner text layer does not trust the
    // outer archive and therefore leaves the overall scan result with no matches found.
    // Strategy: scan a zip containing a clean text file, return Trust only when
    // the pre-scan callback sees CL_TYPE_TEXT_ASCII, then assert the callback was
    // hit for the inner layer and that the terminal Result event is NothingFound.
    #[tokio::test]
    async fn pre_scan_trust_inner_text_in_zip_returns_clean_result() {
        let hit = Arc::new(Mutex::new(false));
        let inner_fixture_path = "test_data/files/good_file";
        let temp_dir = tempdir().expect("temporary directory creation should succeed");
        let inner_file_path = temp_dir.path().join("good_file");
        let zip_file_path = temp_dir.path().join("good_file.zip");
        let inner_contents = fs::read(inner_fixture_path).expect("fixture should be readable");
        fs::write(&inner_file_path, &inner_contents).expect("inner test file should be written");
        fs::write(
            &zip_file_path,
            stored_zip_bytes("good_file", &inner_contents),
        )
        .expect("zip archive should be written");

        let (zip_file_name, _zip_file_size, _zip_sha2_256) = fixture_metadata(
            zip_file_path
                .to_str()
                .expect("zip path should be valid UTF-8"),
        );

        crate::initialize().expect("initialize should succeed");

        let mut engine = configured_engine().await;
        engine.register_callback(
            EngineCallback::PreScan,
            Box::new({
                let hit = hit.clone();
                move |scan_layer: &mut crate::callback::ScanLayer| {
                    let file_type = scan_layer.type_().expect("file type should be available");
                    if file_type == "CL_TYPE_TEXT_ASCII" {
                        *hit.lock().unwrap() = true;
                        ScanLogicResult::Trust
                    } else {
                        ScanLogicResult::Success
                    }
                }
            }),
        );

        let events = scan_and_collect_events(
            &engine,
            Fmap::try_from(File::open(&zip_file_path).expect("opening zip file should succeed"))
                .expect("file-backed fmap creation should succeed"),
            Some(&zip_file_name),
        )
        .await;

        assert!(
            *hit.lock().unwrap(),
            "pre-scan callback should return Trust for the inner text file"
        );
        assert!(
            matches!(
                events.last(),
                Some(ScanEvent::Result(Ok(ScanResult::NothingFound)))
            ),
            "returning Trust for the inner text file should leave the overall zip scan with no matches found"
        );
    }
}
