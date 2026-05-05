# clamav-async-rs Security Policy

## What constitutes a security issue / vulnerability?

A security issue, or vulnerability, may be any bug that represents a threat to
the security of users of this crate or any issue that a malicious person could
use to cause a Denial of Service (DoS) attack on a network service or
application using `clamav-async-rs` and `libclamav`.

This definition includes issues where untrusted user input such as scanning a
file or loading a signature database may cause a severe memory leak, cause a
crash, cause an infinite loop, or provide any other means to impair or disable
the scanner or the hosting application.

A vulnerability also includes all other traditional security vectors such as
privilege escalation, remote code execution, information disclosure, ABI misuse
that can cause memory corruption, and unsafe wrapper bugs that may expose
unsound behavior to Rust callers.

If you are unsure if your bug is a security issue, please report it as a
security issue.

## Vulnerability reporting best practices

Do not discuss the issue in a public forum, public chat, or public issue
tracker.

Do not create a public GitHub issue with exploit details.

Submit your report by email to `psirt@cisco.com`. Support requests submitted to
Cisco PSIRT that are received via email are typically acknowledged within 48
hours. Cisco PSIRT will work with the ClamAV developers and maintainers of this
crate to confirm or reject the security vulnerability.

If the report is rejected, PSIRT or the maintainers will explain why.

If the report is accepted, the maintainers will craft a fix and may request
your help to verify that you find it satisfactory. Cisco may assign a CVE and
will work with you to identify a disclosure date when the summary will become
public and when it will be safe to discuss in public.

Please allow at least 90 days to craft a fix and publish a patch before you
disclose the issue publicly. This non-disclosure window is critical to the
security of other users and downstream applications.

## How do I submit my vulnerability report?

Security issues should be reported to Cisco PSIRT. The recommended method is to
submit by email to `psirt@cisco.com`. For additional details, see:
https://tools.cisco.com/security/center/resources/security_vulnerability_policy.html

## What should I include in my vulnerability report?

Follow the same best practices used for regular bug reports, but do not submit
them publicly. Include enough detail for maintainers to reproduce and assess the
issue.

First, verify that the bug exists in the latest relevant version of:

- this crate
- `clamav-sys`
- the ClamAV / `libclamav` build you are using

At a minimum include the following:

- Step-by-step instructions for reproducing the issue.
- If the issue is triggered by scanning a specific file:
  - Include the file in an encrypted zip along with the password.
  - Or include instructions to generate a reproducer.
- Describe your working environment:
  - operating system
  - CPU architecture
  - Rust toolchain version
  - ClamAV version
  - whether the ClamAV library is patched locally
  - relevant environment variables such as `CLAMAV_SOURCE`,
    `CLAMAV_BUILD`, and `OPENSSL_INCLUDE`
- If you found the bug with a fuzzer, sanitizer, or custom harness, describe
  that setup and include the reproduction steps.
- If you are reporting a crash, include a backtrace and any sanitizer output if
  available.

## How to obtain a crash backtrace

If the issue involves a crash in a Rust test or binary, run it under `gdb` or
`lldb` and include the backtrace. If the failure occurs inside `libclamav`,
include the native stack frames as well.

For example:

```bash
RUST_BACKTRACE=1 cargo test some_test -- --test-threads=1
```

If you can reproduce the crash in a standalone binary, attach a debugger and
capture a full native backtrace.
