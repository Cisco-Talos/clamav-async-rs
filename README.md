# clamav-async-rs

<p align="center">
  Rust bindings and async helpers for scanning files with ClamAV®.
</p>

`clamav-async-rs` provides a Rust wrapper around `libclamav` for
loading signature databases, configuring an engine, scanning content, and
observing scan-layer callbacks.

## Documentation

This crate wraps the ClamAV C library. For the underlying scanner behavior and
file format support, refer to the ClamAV manual at
[docs.clamav.net](https://docs.clamav.net/).

## ABI Compatibility

This crate is ABI-coupled to the `libclamav` version used to generate and link
the `clamav-sys` bindings.

Recommended rules:

- Build `clamav-sys` against the same ClamAV source tree, build tree, and
  installed headers that you will use at runtime.
- Treat ClamAV upgrades as ABI events. Rebuild this crate and `clamav-sys`
  after upgrading ClamAV, changing compiler toolchains, or changing the target
  platform.
- Do not mix headers from one ClamAV build with a different shared library at
  runtime.
- If you maintain local patches to ClamAV, regenerate bindings after those ABI
  changes land.

Dependency discovery is handled by `clamav-sys` in this order:

- If `CLAMAV_LIBRARY` and `CLAMAV_INCLUDE` are set, those paths are used.
- Otherwise, `pkg-config` is used on Unix, Linux, and macOS.
- Otherwise, `vcpkg` is used on Windows.
- If `OPENSSL_INCLUDE` is set, it is added to the bindgen header search path.

If ClamAV or OpenSSL are installed in non-standard locations, use manual
override variables like:

```bash
CLAMAV_LIBRARY=/path/to/libclamav.so
CLAMAV_INCLUDE=/path/to/clamav/include
OPENSSL_INCLUDE=/path/to/openssl/include
```

`CLAMAV_LIBRARY` should point at the ClamAV library file,
`CLAMAV_INCLUDE` should point at one or more include directories containing
`clamav.h`, and `OPENSSL_INCLUDE` should point at the directory containing
OpenSSL headers such as `openssl/ssl.h`.

## Recommended Usage Patterns

### Initialize once per process

Call `clamav_async::initialize()` before creating engines. The wrapper makes
this safe to call multiple times, but it still represents process-global
libclamav initialization.

If you want libclamav debug logging, call `clamav_async::debug()` after
initialization.

### Compile the engine once

Create an [`Engine`](src/engine.rs), load databases, then compile and reuse that
engine for scans instead of rebuilding it for every file.

### Register callbacks before scanning

If you need scan-layer visibility, register callbacks on the engine before
starting the scan. Callback operations receive a mutable
[`ScanLayer`](src/callback.rs) and can inspect:

- object id
- ancestors
- file type
- file name
- file size
- SHA-256
- mapped file data
- last match name

### Copy callback data you need to keep

`ScanLayer` and `Fmap` expose data borrowed from libclamav-managed scan state.
Do not retain borrowed slices or pointers after the callback returns. If you
need the bytes later, copy them during the callback.

### Expect nested callback ordering

Top-level scans are straightforward, but nested content such as archives may
emit multiple file-type, pre-scan, match, and post-scan callbacks as libclamav
descends into child layers. Write callback logic so it keys off the
`ScanLayer` metadata instead of assuming a single flat file.

### Keep callback logic small

Callbacks run during scanning. Prefer cheap inspection and state capture. If you
need heavier work, copy the relevant metadata or bytes and hand that work off
after the scan completes.

### Use callback return values to steer scanning

Callback return values are not just status codes. They directly affect how
`libclamav` proceeds with the scan.

- `ScanLogicResult::Abort` cancels the scan immediately.
- `ScanLogicResult::Trust` discards any previous matches, cancels the scan, and
  causes the final result to be reported as trusted.
- `ScanLogicResult::Success` continues the scan. If returned from the `Match`
  callback, it discards the current match and scanning continues.
- `ScanLogicResult::Match` continues the scan. If returned from the `Match`
  callback, it accepts the current match. If returned from another callback,
  libclamav records a match named for the current callback.

## Example

```rust
use clamav_async::{
    callback::{EngineCallback, ScanLogicResult},
    engine::{Engine, ScanEvent},
    fmap::Fmap,
    initialize,
    scan_settings::{GeneralFlags, ParseFlags, ScanSettings},
};
use std::fs::File;
use tokio_stream::StreamExt;

fn scan_settings() -> ScanSettings {
    let mut settings = ScanSettings::default();
    settings.set_parse(&ParseFlags::all());
    settings.set_general(&GeneralFlags::CL_SCAN_GENERAL_HEURISTICS);
    settings
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    initialize()?;

    let mut engine = Engine::new();
    engine.register_callback(
        EngineCallback::FileType,
        Box::new(|layer| {
            let file_type = layer.type_().expect("file type should be available");
            let file_size = layer.file_size();

            if file_type == "CL_TYPE_HTML" {
                ScanLogicResult::Match
            } else if file_size < 20 {
                ScanLogicResult::Abort
            } else {
                ScanLogicResult::Success
            }
        }),
    );

    engine.load_databases(&"test_data/database").await?;
    engine.compile().await?;

    let target = Fmap::try_from(File::open("test_data/files/good_file")?)?;
    let mut events = engine.scan(
        target,
        Some("good_file"),
        None,
        None,
        None,
        scan_settings(),
    )?;

    while let Some(event) = events.next().await {
        match event {
            ScanEvent::Result(result) => println!("result: {result:?}"),
            other => println!("event: {other:?}"),
        }
    }

    Ok(())
}
```

The same example is available as [`examples/callback_decisions.rs`](examples/callback_decisions.rs).

### Compiling The Example Program

#### Linux / Unix / macOS

Install the ClamAV development package and OpenSSL headers. If they are
installed in standard system locations, `pkg-config` is usually sufficient.

If ClamAV is installed in a non-standard location, set `CLAMAV_LIBRARY` and
`CLAMAV_INCLUDE`. Set `OPENSSL_INCLUDE` if OpenSSL headers are also outside the
default include paths.

Example in `sh`:

```sh
export CLAMAV_INCLUDE="$HOME/clams/1.5.2/include"
export CLAMAV_LIBRARY="$HOME/clams/1.5.2/lib/libclamav.so"
export OPENSSL_INCLUDE="$HOME/.mussels/install/host-static/include"
export LD_LIBRARY_PATH="$HOME/clams/1.5.2/lib"
cargo run --example callback_decisions -- test_data/database test_data/files/good_file
```

#### Windows using vcpkg

If you use `vcpkg`, set `$env:VCPKG_ROOT` to your `vcpkg` installation and set
`$env:VCPKGRS_DYNAMIC=1` to use dynamic linking. The default method often does
not work because `pdcurses` does not support the `x64-windows-static-md`
triplet.

Install LLVM for `bindgen`, which requires `libclang` on Windows. Set
`$env:LIBCLANG_PATH` to the directory containing `libclang.dll` or `clang.dll`.
For example:

```powershell
$env:LIBCLANG_PATH = "C:\Program Files\LLVM\bin"
```

See the [vcpkg crate's documentation](https://docs.rs/vcpkg) for more details.

#### Windows without vcpkg

If not using vcpkg, you must use the override variables described above so that
`cargo run` can find the required files.

You must also install LLVM for `bindgen`, which requires `libclang` on
Windows. Set `LIBCLANG_PATH` to the directory containing `libclang.dll` or
`clang.dll`.

Example in PowerShell:

```powershell
$env:CLAMAV_LIBRARY = "$env:HOME\Downloads\clamav-1.5.2\clamav.lib"
$env:CLAMAV_INCLUDE = "$env:HOME\Downloads\clamav-1.5.2\include"
$env:OPENSSL_INCLUDE = "$env:HOME\Downloads\openssl\include"
$env:LIBCLANG_PATH = "C:\Program Files\LLVM\bin"
$env:PATH = "$env:HOME\Downloads\clamav-1.5.2;$env:PATH"
cargo run --example callback_decisions -- test_data/database test_data/files/good_file
```

## Testing

### Linux / Unix / macOS

Run tests with the local ClamAV build configuration:

```sh
export CLAMAV_INCLUDE="$HOME/clams/1.5.2/include"
export CLAMAV_LIBRARY="$HOME/clams/1.5.2/lib/libclamav.so"
export OPENSSL_INCLUDE="$HOME/.mussels/install/host-static/include"
export LD_LIBRARY_PATH="$HOME/clams/1.5.2/lib"
cargo test -- --test-threads=1
```

### Windows using vcpkg

Set up `vcpkg`, `VCPKG_ROOT`, `VCPKGRS_DYNAMIC`, and `LIBCLANG_PATH` as
described above for building.

To run tests that load signature databases on Windows, also set
`CLAMAV_CVD_CERTS_DIR` to the ClamAV `certs` directory. The test suite uses
this value to configure `CL_ENGINE_CVDCERTSDIR` before loading databases.

### Windows without vcpkg

Set the ClamAV and OpenSSL override variables as described above for building,
and also set `CLAMAV_CVD_CERTS_DIR` to the ClamAV `certs` directory.

Example in PowerShell:

```powershell
$env:CLAMAV_LIBRARY = "$env:HOME\Downloads\clamav-1.5.2\clamav.lib"
$env:CLAMAV_INCLUDE = "$env:HOME\Downloads\clamav-1.5.2\include"
$env:OPENSSL_INCLUDE = "$env:HOME\Downloads\openssl\include"
$env:CLAMAV_CVD_CERTS_DIR = "$env:HOME\Downloads\clamav-1.5.2\certs"
$env:LIBCLANG_PATH = "C:\Program Files\LLVM\bin"
$env:PATH = "$env:HOME\Downloads\clamav-1.5.2;$env:PATH"
cargo test -- --test-threads=1
```

Serial test execution is recommended because libclamav initialization is
process-global and some integration-style tests use temporary databases and
fixture files.

## Want to make a contribution?

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before
opening a pull request.

If you believe you have found a security issue, do not file a public issue.
Follow [SECURITY.md](SECURITY.md).

## Licensing

`clamav-async-rs` is licensed for public/open source use under the GNU General
Public License, Version 2 (GPLv2).

See [LICENSE](LICENSE) for a copy of the license.

## Acknowledgements

This crate builds on ClamAV and `libclamav`, maintained by the ClamAV Team at
Cisco Talos.
