# Contributing to clamav-async-rs

Thank you for contributing to `clamav-async-rs`.

The maintainers welcome code contributions, tests, bug reports, and
documentation improvements.

## Before you start

- Check whether the issue is already reported.
- If you are fixing behavior that comes from `libclamav`, confirm whether the
  problem belongs in this crate, in `clamav-sys`, or upstream in ClamAV.
- If the issue may be security-sensitive, do not open a public issue. Follow
  [SECURITY.md](SECURITY.md).

## Development setup

This crate inherits dependency discovery from `clamav-sys`:

- If `CLAMAV_LIBRARY` and `CLAMAV_INCLUDE` are set, those paths are used.
- Otherwise, `pkg-config` is used on Unix, Linux, and macOS.
- Otherwise, `vcpkg` is used on Windows.
- If `OPENSSL_INCLUDE` is set, it is added to the bindgen header search path.

If ClamAV or OpenSSL are installed in non-standard locations, set:

```bash
CLAMAV_LIBRARY=/path/to/libclamav.so
CLAMAV_INCLUDE=/path/to/clamav/include
OPENSSL_INCLUDE=/path/to/openssl/include
```

`CLAMAV_LIBRARY` should point at the ClamAV library file,
`CLAMAV_INCLUDE` should point at one or more include directories containing
`clamav.h`, and `OPENSSL_INCLUDE` should point at the directory containing
OpenSSL headers such as `openssl/ssl.h`.

## Recommended workflow

1. Fork the repository and create a focused branch.
2. Make the smallest coherent change that solves the problem.
3. Add or update tests when behavior changes.
4. Run formatting and tests before opening a pull request.

## Testing

Run the test suite with the expected ClamAV environment:

```bash
CLAMAV_LIBRARY=/path/to/libclamav.so \
CLAMAV_INCLUDE=/path/to/clamav/include \
OPENSSL_INCLUDE=/path/to/openssl/include \
cargo test -- --test-threads=1
```

Serial execution is preferred because libclamav initialization is process-wide
and several tests rely on temporary fixtures and temporary signature databases.

## Pull requests

When opening a pull request:

- Explain the user-visible behavior change.
- Include relevant test coverage.
- Note any ABI implications if the change depends on new or patched ClamAV C
  APIs.
- Mention whether downstream users need to rebuild `clamav-sys` or upgrade
  ClamAV.

Small, focused pull requests are easier to review and merge.

## Style

- Keep wrapper APIs explicit about ownership and lifetimes.
- Prefer safe Rust interfaces over exposing raw pointers.
- When callback data is borrowed from libclamav, copy it if it must outlive the
  callback.
- Preserve compatibility assumptions carefully when touching FFI boundaries.

## Reporting bugs

Bug reports are welcome. A good report includes:

- a minimal reproducer
- expected behavior
- actual behavior
- ClamAV version
- Rust version
- platform details
- relevant logs or backtraces

If the bug depends on a specific sample or signature database, provide a safe
way for maintainers to reproduce it.
