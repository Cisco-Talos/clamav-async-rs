# Release Notes

This document summarizes notable changes by release, starting with the first
tagged version of `clamav-async` and ending with the current `v0.4.0` state
represented by the current commit.

## v0.4.0

This release significantly expands the scan callback surface and improves the
observability of libclamav scan layers.

### Major Changes

- Added callback registration through `Engine::register_callback()` for:
  - pre-scan callbacks
  - post-scan callbacks
  - file-type callbacks
  - match callbacks
- Introduced `callback::ScanLayer` as the callback-facing abstraction for the
  current layer of a scanned file which may have nested components (e.g. files
  within an archive, attachments within a document, component parts of a
  complex file format, or normalized versions of a file such as the rendered
  version of a document or the simplified version of a script).
- Callback registration now includes a Rust closure whose return value may be
  used to alter scan behavior such as ignoring a match, trusting the file,
  aborting the scan, or adding a match.
  > Disclaimer: The name of an added match is not configurable in this version
  > and will be given a name depending on which callback returned `Match`.
- Callback closures will receive `&mut ScanLayer` rather than separate primitive
  arguments, allowing callback logic to inspect:
  - entity ids
  - ancestor entity ids
  - file type
  - file name
  - file size
  - SHA2-256
  - mapped layer data
  - the last match name
- As with v0.3.0, event data is also sent by the callbacks including the above
  information, minus the mapped layer data. The entity id, ancestor entity ids,
  and SHA2-256 hash is new in this version, so that a downstream application
  does not need to guess or calculate these values.
- Added `ScanEvent::PostScan` and expanded scan event coverage for nested scans.
- Renamed the language in code and documentation which used "Virus" or "Alert"
  to use "Match" instead, for consistency in semantics and event naming.

### Public API Improvements

- Expanded `fmap::Fmap` with accessors and mutators for:
  - path
  - name
  - file descriptor
  - file size
  - SHA2-256 presence
  - mapped data access
- `ScanLayer` now caches an `Fmap` instead of repeatedly exposing raw libclamav
  pointers.
- Added `clamav_async::debug()` as a safe wrapper around
  `clamav_sys::cl_debug()`.
- Renamed `ScanResult::Clean` to `ScanResult::NothingFound` to avoid implying
  that a file should be trusted when the scan merely found no matches.
- Added public API rustdoc across the major exported types and methods.

### Behavior Changes

- Callback return values now clearly steer scanning behavior:
  - `Abort` stops the scan
  - `Trust` marks the current layer trusted
  - `Success` continues scanning without preserving a rejected match
  - `Match` accepts or creates a match and continues
- Large match-layer data access is now covered and verified for sizes well
  beyond 4 KiB.

### Bug Fixes

- Fixed callback data access by caching the layer fmap inside `ScanLayer`.
- Fixed ancestor traversal so inner-layer ancestor ids contain only parent
  layers, not the current layer.
- Fixed scan-time C string lifetime handling in `Engine::scan()` so file names
  and hints remain valid for the FFI call.
- Removed dead code related to copying scanned content buffers through an older
  path.
- Removed obsolete `layer_attr` support.

### Tests and Examples

- Added extensive callback tests for:
  - pre-scan
  - post-scan
  - file-type
  - match
  - trusted scan-layer behavior
  - nested zip scans
  - callback event ordering
- Added `examples/callback_decisions.rs` as a runnable end-to-end example.
- Updated the README example and validated it against the local ClamAV test
  setup.

### Documentation and Project Metadata

- Added `README.md` with ABI guidance, usage patterns, callback semantics, and
  testing notes.
- Added `SECURITY.md`.
- Added `CONTRIBUTING.md`.
- Added `AGENTS.md` for repository-specific automation and maintenance context.
- Updated package metadata and authorship for the current release line.

## v0.3.0

This release focused on ClamAV 1.4 support and build reliability.

### Major Changes

- Enabled ClamAV 1.4 scan options for:
  - OneNote parsing
  - image fuzzy hash scanning

### Bug Fixes

- Fixed an FFI compatibility issue when building on macOS.

### Tooling and Maintenance

- Added GitHub Actions build and test workflow coverage.

## v0.2.0

This release established the async-oriented foundation of the crate.

### Major Changes

- Imported the async implementation from the earlier `clamav-rs` work.
- Updated the dependency layout and repository linkage around `clamav-sys`.
- Added crate keywords and general project metadata cleanup.

### Bug Fixes and Cleanup

- Renamed `cl_pread` to `pread_cb`.
- Improved the file inspection callback implementation.
- Removed vestigial platform gating and stale comments.
- Addressed a broad set of `clippy::pedantic` warnings.
- Fixed typos and updated copyright notices.

## v0.1.0

Initial tagged release.

### Highlights

- Introduced the first public version of the crate.
- Established the initial async Rust wrapper around `libclamav`.
