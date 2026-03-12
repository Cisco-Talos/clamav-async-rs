# AGENTS.md

This file provides project-specific context for agents working in this
repository.

## Repository Summary

- Crate: `clamav-async`
- Purpose: async-friendly Rust wrapper around `libclamav`
- Main public API modules:
  - `src/lib.rs`
  - `src/engine.rs`
  - `src/callback.rs`
  - `src/fmap.rs`
  - `src/scan_settings.rs`

## Local Build Environment

`clamav-sys` discovers dependencies in this order:

- If `CLAMAV_LIBRARY` and `CLAMAV_INCLUDE` are set, those paths are used.
- Otherwise, `pkg-config` is used on Unix, Linux, and macOS.
- Otherwise, `vcpkg` is used on Windows.
- If `OPENSSL_INCLUDE` is set, it is added to the bindgen header search path.

If manual overrides are needed, use:

```bash
CLAMAV_LIBRARY=/path/to/libclamav.so
CLAMAV_INCLUDE=/path/to/clamav/include
OPENSSL_INCLUDE=/path/to/openssl/include
```

Meaning:

- `CLAMAV_LIBRARY`: path to the ClamAV library file
- `CLAMAV_INCLUDE`: one or more include directories containing `clamav.h`
- `OPENSSL_INCLUDE`: directory containing OpenSSL headers such as `openssl/ssl.h`

Typical compile/test commands:

```bash
env CLAMAV_LIBRARY=/path/to/libclamav.so \
    CLAMAV_INCLUDE=/path/to/clamav/include \
    OPENSSL_INCLUDE=/path/to/openssl/include \
    cargo test --no-run
```

```bash
env CLAMAV_LIBRARY=/path/to/libclamav.so \
    CLAMAV_INCLUDE=/path/to/clamav/include \
    OPENSSL_INCLUDE=/path/to/openssl/include \
    cargo test -- --test-threads=1
```

Run Rust tests serially unless there is a specific reason not to. libclamav
initialization is process-global and several tests use temporary fixtures.

## ABI and Dependency Notes

- This crate is ABI-coupled to the local `libclamav` build used by
  `../clamav-sys`.
- The sibling crate `../clamav-sys` is part of the effective development
  environment. Changes there may be required when ClamAV headers change.
- The local `clamav-sys` build logic has already been adjusted to honor
  `OPENSSL_INCLUDE`.
- If the ClamAV C API changes, expect to rebuild bindings and possibly touch
  both this crate and `../clamav-sys`.

## Public API Landmarks

- `initialize()` in `src/lib.rs`
  - Safe to call multiple times.
  - Must be called before using the engine.
- `debug()` in `src/lib.rs`
  - Wraps `clamav_sys::cl_debug()`.
- `engine::Engine`
  - Create with `Engine::new()`
  - Load databases with `load_databases()`
  - Compile with `compile()`
  - Scan with `scan()`
  - Register callbacks with `register_callback()`
- `callback::ScanLayer`
  - Callback closures receive `&mut ScanLayer`
  - Access metadata via methods instead of separate callback arguments
- `fmap::Fmap`
  - Wraps `cl_fmap_t`
  - Supports file-backed, memory-backed, and borrowed callback-layer fmaps

## Callback Model

- Supported callback hooks:
  - `PreScan`
  - `PostScan`
  - `FileType`
  - `Match`
- Callback closures use:

```rust
Fn(&mut ScanLayer) -> ScanLogicResult
```

- `ScanLogicResult` behavior:
  - `Abort`: stop scanning immediately
  - `Trust`: discard prior matches, stop scanning the current layer and trust the current layer; will continue to scan the rest of the file
  - `Success`: continue scanning; in a match callback this discards the current match
  - `Match`: continue scanning; in a match callback this accepts the current match

## Important Implementation Details

- `ScanLayer` caches its layer fmap as `Option<Fmap>`.
- `ScanLayer::data()` and `Fmap::data()` return borrowed slices into
  libclamav-managed memory. Copy data inside the callback if it is needed later.
- `ScanLayer::ancestor_ids()` is expected to return only parent layer ids, not
  the current layer id.
- Nested scans such as zip archives produce multiple callback events. Do not
  assume only one top-level file event sequence.
- `Engine::scan()` keeps C strings alive until the FFI call completes. Do not
  regress this by taking raw pointers from temporary `CString`s.

## Testing Landmarks

- Callback-heavy tests live in `src/callback.rs`.
- Engine registration tests live in `src/engine.rs`.
- `Fmap` unit tests live in `src/fmap.rs`.
- Fixture files:
  - `test_data/files/good_file`
  - `test_data/files/naughty_file`
- Test databases:
  - `test_data/database/`

Known good targeted test commands:

```bash
env CLAMAV_LIBRARY=/path/to/libclamav.so \
    CLAMAV_INCLUDE=/path/to/clamav/include \
    OPENSSL_INCLUDE=/path/to/openssl/include \
    cargo test callback::tests:: -- --test-threads=1
```

```bash
env CLAMAV_LIBRARY=/path/to/libclamav.so \
    CLAMAV_INCLUDE=/path/to/clamav/include \
    OPENSSL_INCLUDE=/path/to/openssl/include \
    cargo test fmap::tests:: -- --test-threads=1
```

## Examples and Documentation

- Runnable example:
  - `examples/callback_decisions.rs`
- README example was validated end-to-end with:

```bash
env CLAMAV_LIBRARY=/path/to/libclamav.so \
    CLAMAV_INCLUDE=/path/to/clamav/include \
    OPENSSL_INCLUDE=/path/to/openssl/include \
    cargo run --example callback_decisions -- test_data/database test_data/files/good_file
```

- The example must use:

```rust
#[tokio::main(flavor = "current_thread")]
```

because this crate enables Tokio `rt` but not `rt-multi-thread`.

## Documentation Conventions

- Public API docs were added to the major exported types and methods in:
  - `src/callback.rs`
  - `src/engine.rs`
  - `src/fmap.rs`
  - `src/scan_settings.rs`
- Keep future docs focused on ownership, callback lifetime, ABI coupling, and
  scan behavior rather than restating obvious names.

## Repository Docs

- `README.md` describes ABI expectations and recommended usage patterns.
- `SECURITY.md` contains the reporting policy.
- `CONTRIBUTING.md` is repo-specific. Upstream ClamAV does not currently ship a
  top-level `CONTRIBUTING.md`, so do not assume one exists upstream.
