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

#![allow(dead_code)]

use clamav_sys::{
    cl_scan_options, CL_SCAN_DEV_COLLECT_PERFORMANCE_INFO, CL_SCAN_DEV_COLLECT_SHA,
    CL_SCAN_GENERAL_ALLMATCHES, CL_SCAN_GENERAL_COLLECT_METADATA, CL_SCAN_GENERAL_HEURISTICS,
    CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE, CL_SCAN_GENERAL_UNPRIVILEGED, CL_SCAN_HEURISTIC_BROKEN,
    CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE, CL_SCAN_HEURISTIC_ENCRYPTED_DOC,
    CL_SCAN_HEURISTIC_EXCEEDS_MAX, CL_SCAN_HEURISTIC_MACROS, CL_SCAN_HEURISTIC_PARTITION_INTXN,
    CL_SCAN_HEURISTIC_PHISHING_CLOAK, CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH,
    CL_SCAN_HEURISTIC_STRUCTURED, CL_SCAN_HEURISTIC_STRUCTURED_CC,
    CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL, CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED,
    CL_SCAN_MAIL_PARTIAL_MESSAGE, CL_SCAN_PARSE_ARCHIVE, CL_SCAN_PARSE_ELF, CL_SCAN_PARSE_HTML,
    CL_SCAN_PARSE_HWP3, CL_SCAN_PARSE_IMAGE, CL_SCAN_PARSE_IMAGE_FUZZY_HASH, CL_SCAN_PARSE_MAIL,
    CL_SCAN_PARSE_OLE2, CL_SCAN_PARSE_ONENOTE, CL_SCAN_PARSE_PDF, CL_SCAN_PARSE_PE,
    CL_SCAN_PARSE_SWF, CL_SCAN_PARSE_XMLDOCS,
};

use bitflags::bitflags;

bitflags! {
    #[repr(C)]
    pub struct GeneralFlags: u32 {
        /// scan in all-match mode
        const CL_SCAN_GENERAL_ALLMATCHES           = CL_SCAN_GENERAL_ALLMATCHES;
        /// collect metadata (--gen-json)
        const CL_SCAN_GENERAL_COLLECT_METADATA     = CL_SCAN_GENERAL_COLLECT_METADATA;
        /// option to enable heuristic alerts
        const CL_SCAN_GENERAL_HEURISTICS           = CL_SCAN_GENERAL_HEURISTICS;
        /// allow heuristic match to take precedence.
        const CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE = CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE;
        /// scanner will not have read access to files.
        const CL_SCAN_GENERAL_UNPRIVILEGED         = CL_SCAN_GENERAL_UNPRIVILEGED;
    }
}

bitflags! {
    #[repr(C)]
    pub struct ParseFlags : u32 {
        const CL_SCAN_PARSE_ARCHIVE          = CL_SCAN_PARSE_ARCHIVE;
        const CL_SCAN_PARSE_ELF              = CL_SCAN_PARSE_ELF;
        const CL_SCAN_PARSE_PDF              = CL_SCAN_PARSE_PDF;
        const CL_SCAN_PARSE_SWF              = CL_SCAN_PARSE_SWF;
        const CL_SCAN_PARSE_HWP3             = CL_SCAN_PARSE_HWP3;
        const CL_SCAN_PARSE_XMLDOCS          = CL_SCAN_PARSE_XMLDOCS;
        const CL_SCAN_PARSE_MAIL             = CL_SCAN_PARSE_MAIL;
        const CL_SCAN_PARSE_OLE2             = CL_SCAN_PARSE_OLE2;
        const CL_SCAN_PARSE_HTML             = CL_SCAN_PARSE_HTML;
        const CL_SCAN_PARSE_PE               = CL_SCAN_PARSE_PE;
        const CL_SCAN_PARSE_ONENOTE          = CL_SCAN_PARSE_ONENOTE;
        const CL_SCAN_PARSE_IMAGE            = CL_SCAN_PARSE_IMAGE;
        const CL_SCAN_PARSE_IMAGE_FUZZY_HASH = CL_SCAN_PARSE_IMAGE_FUZZY_HASH;
    }
}

bitflags! {
    #[repr(C)]
    pub struct HeuristicFlags : u32 {
        /// alert on broken PE and broken ELF files
        const CL_SCAN_HEURISTIC_BROKEN                  = CL_SCAN_HEURISTIC_BROKEN;
        /// alert when files exceed scan limits (filesize, max scansize, or max recursion depth)
        const CL_SCAN_HEURISTIC_EXCEEDS_MAX             = CL_SCAN_HEURISTIC_EXCEEDS_MAX;
        /// alert on SSL mismatches
        const CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH   = CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH;
        /// alert on cloaked URLs in emails
        const CL_SCAN_HEURISTIC_PHISHING_CLOAK          = CL_SCAN_HEURISTIC_PHISHING_CLOAK;
        /// alert on OLE2 files containing macros
        const CL_SCAN_HEURISTIC_MACROS                  = CL_SCAN_HEURISTIC_MACROS;
        /// alert if archive is encrypted (rar, zip, etc)
        const CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE       = CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE;
        /// alert if a document is encrypted (pdf, docx, etc)
        const CL_SCAN_HEURISTIC_ENCRYPTED_DOC           = CL_SCAN_HEURISTIC_ENCRYPTED_DOC;
        /// alert if partition table size doesn't make sense
        const CL_SCAN_HEURISTIC_PARTITION_INTXN         = CL_SCAN_HEURISTIC_PARTITION_INTXN;
        /// data loss prevention options, i.e. alert when detecting personal information
        const CL_SCAN_HEURISTIC_STRUCTURED              = CL_SCAN_HEURISTIC_STRUCTURED;
        /// alert when detecting social security numbers
        const CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL   = CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL;
        /// alert when detecting stripped social security numbers
        const CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED = CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED;
        /// alert when detecting credit card numbers
        const CL_SCAN_HEURISTIC_STRUCTURED_CC           = CL_SCAN_HEURISTIC_STRUCTURED_CC;
    }
}

bitflags! {
    #[repr(C)]
    pub struct MailFlags : u32 {
        const CL_SCAN_MAIL_PARTIAL_MESSAGE = CL_SCAN_MAIL_PARTIAL_MESSAGE;
    }
}

bitflags! {
    #[repr(C)]
    pub struct DevFlags : u32 {
        /// Enables hash output in sha-collect builds - for internal use only
        const CL_SCAN_DEV_COLLECT_SHA              = CL_SCAN_DEV_COLLECT_SHA;
        /// collect performance timings
        const CL_SCAN_DEV_COLLECT_PERFORMANCE_INFO = CL_SCAN_DEV_COLLECT_PERFORMANCE_INFO;
    }
}

#[derive(Default)]
pub struct ScanSettings {
    pub settings: cl_scan_options,
}

impl ScanSettings {
    #[must_use]
    pub fn general(&self) -> GeneralFlags {
        GeneralFlags::from_bits(self.settings.general).unwrap_or(GeneralFlags::empty())
    }

    pub fn set_general(&mut self, flags: &GeneralFlags) {
        self.settings.general = flags.bits();
    }

    #[must_use]
    pub fn parse(&self) -> ParseFlags {
        ParseFlags::from_bits(self.settings.parse).unwrap_or(ParseFlags::empty())
    }

    pub fn set_parse(&mut self, flags: &ParseFlags) {
        self.settings.parse = flags.bits();
    }

    #[must_use]
    pub fn heuristic(&self) -> HeuristicFlags {
        HeuristicFlags::from_bits(self.settings.heuristic).unwrap_or(HeuristicFlags::empty())
    }

    pub fn set_heuristic(&mut self, flags: &HeuristicFlags) {
        self.settings.heuristic = flags.bits();
    }

    #[must_use]
    pub fn mail(&self) -> MailFlags {
        MailFlags::from_bits(self.settings.mail).unwrap_or(MailFlags::empty())
    }

    pub fn set_mail(&mut self, flags: &MailFlags) {
        self.settings.mail = flags.bits();
    }

    #[must_use]
    pub fn dev(&self) -> DevFlags {
        DevFlags::from_bits(self.settings.dev).unwrap_or(DevFlags::empty())
    }

    pub fn set_dev(&mut self, flags: &DevFlags) {
        self.settings.dev = flags.bits();
    }
}

impl ToString for ScanSettings {
    #[allow(clippy::too_many_lines)]
    fn to_string(&self) -> String {
        let mut flag_names = Vec::<String>::new();

        let general_flags = vec![
            (
                GeneralFlags::CL_SCAN_GENERAL_ALLMATCHES,
                "CL_SCAN_GENERAL_ALLMATCHES",
            ),
            (
                GeneralFlags::CL_SCAN_GENERAL_COLLECT_METADATA,
                "CL_SCAN_GENERAL_COLLECT_METADATA",
            ),
            (
                GeneralFlags::CL_SCAN_GENERAL_HEURISTICS,
                "CL_SCAN_GENERAL_HEURISTICS",
            ),
            (
                GeneralFlags::CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE,
                "CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE",
            ),
            (
                GeneralFlags::CL_SCAN_GENERAL_UNPRIVILEGED,
                "CL_SCAN_GENERAL_UNPRIVILEGED",
            ),
        ];
        let parse_flags = vec![
            (ParseFlags::CL_SCAN_PARSE_ARCHIVE, "CL_SCAN_PARSE_ARCHIVE"),
            (ParseFlags::CL_SCAN_PARSE_ELF, "CL_SCAN_PARSE_ELF"),
            (ParseFlags::CL_SCAN_PARSE_PDF, "CL_SCAN_PARSE_PDF"),
            (ParseFlags::CL_SCAN_PARSE_SWF, "CL_SCAN_PARSE_SWF"),
            (ParseFlags::CL_SCAN_PARSE_HWP3, "CL_SCAN_PARSE_HWP3"),
            (ParseFlags::CL_SCAN_PARSE_XMLDOCS, "CL_SCAN_PARSE_XMLDOCS"),
            (ParseFlags::CL_SCAN_PARSE_MAIL, "CL_SCAN_PARSE_MAIL"),
            (ParseFlags::CL_SCAN_PARSE_OLE2, "CL_SCAN_PARSE_OLE2"),
            (ParseFlags::CL_SCAN_PARSE_HTML, "CL_SCAN_PARSE_HTML"),
            (ParseFlags::CL_SCAN_PARSE_PE, "CL_SCAN_PARSE_PE"),
        ];
        let heuristic_flags = vec![
            (
                HeuristicFlags::CL_SCAN_HEURISTIC_BROKEN,
                "CL_SCAN_HEURISTIC_BROKEN",
            ),
            (
                HeuristicFlags::CL_SCAN_HEURISTIC_EXCEEDS_MAX,
                "CL_SCAN_HEURISTIC_EXCEEDS_MAX",
            ),
            (
                HeuristicFlags::CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH,
                "CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH",
            ),
            (
                HeuristicFlags::CL_SCAN_HEURISTIC_PHISHING_CLOAK,
                "CL_SCAN_HEURISTIC_PHISHING_CLOAK",
            ),
            (
                HeuristicFlags::CL_SCAN_HEURISTIC_MACROS,
                "CL_SCAN_HEURISTIC_MACROS",
            ),
            (
                HeuristicFlags::CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE,
                "CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE",
            ),
            (
                HeuristicFlags::CL_SCAN_HEURISTIC_ENCRYPTED_DOC,
                "CL_SCAN_HEURISTIC_ENCRYPTED_DOC",
            ),
            (
                HeuristicFlags::CL_SCAN_HEURISTIC_PARTITION_INTXN,
                "CL_SCAN_HEURISTIC_PARTITION_INTXN",
            ),
            (
                HeuristicFlags::CL_SCAN_HEURISTIC_STRUCTURED,
                "CL_SCAN_HEURISTIC_STRUCTURED",
            ),
            (
                HeuristicFlags::CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL,
                "CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL",
            ),
            (
                HeuristicFlags::CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED,
                "CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED",
            ),
            (
                HeuristicFlags::CL_SCAN_HEURISTIC_STRUCTURED_CC,
                "CL_SCAN_HEURISTIC_STRUCTURED_CC",
            ),
        ];

        let mail_flags = vec![(
            MailFlags::CL_SCAN_MAIL_PARTIAL_MESSAGE,
            "CL_SCAN_MAIL_PARTIAL_MESSAGE",
        )];

        let dev_flags = vec![
            (DevFlags::CL_SCAN_DEV_COLLECT_SHA, "CL_SCAN_DEV_COLLECT_SHA"),
            (
                DevFlags::CL_SCAN_DEV_COLLECT_PERFORMANCE_INFO,
                "CL_SCAN_DEV_COLLECT_PERFORMANCE_INFO",
            ),
        ];

        for (flag, name) in general_flags {
            if self.general().contains(flag) {
                flag_names.push(name.to_string());
            }
        }
        for (flag, name) in parse_flags {
            if self.parse().contains(flag) {
                flag_names.push(name.to_string());
            }
        }
        for (flag, name) in heuristic_flags {
            if self.heuristic().contains(flag) {
                flag_names.push(name.to_string());
            }
        }
        for (flag, name) in mail_flags {
            if self.mail().contains(flag) {
                flag_names.push(name.to_string());
            }
        }
        for (flag, name) in dev_flags {
            if self.dev().contains(flag) {
                flag_names.push(name.to_string());
            }
        }

        flag_names.join(" ")
    }
}

pub struct Builder {
    current: cl_scan_options,
}

impl Builder {
    #[must_use]
    pub fn new() -> Self {
        Builder {
            current: cl_scan_options::default(),
        }
    }

    #[must_use]
    pub fn build(&self) -> ScanSettings {
        ScanSettings {
            settings: self.current,
        }
    }

    /// Disable support for special files.
    pub fn clear(&mut self) -> &mut Self {
        self.current.parse = 0;
        self
    }

    /// Enable transparent scanning of various archive formats.
    pub fn enable_archive(&mut self) -> &mut Self {
        self.current.parse |= CL_SCAN_PARSE_ARCHIVE;
        self
    }

    /// Enable support for mail files.
    pub fn enable_mail(&mut self) -> &mut Self {
        self.current.parse |= CL_SCAN_PARSE_MAIL;
        self
    }

    /// Enable support for OLE2 containers (used by MS Office and .msi files).
    pub fn enable_ole2(&mut self) -> &mut Self {
        self.current.parse |= CL_SCAN_PARSE_OLE2;
        self
    }

    /// With this flag the library will mark encrypted archives as viruses (Encrypted.Zip, Encrypted.RAR).
    pub fn block_encrypted(&mut self) -> &mut Self {
        self.current.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE;
        self
    }

    /// Enable HTML normalisation (including `ScrEnc` decryption).
    pub fn enable_html(&mut self) -> &mut Self {
        self.current.parse |= CL_SCAN_PARSE_HTML;
        self
    }

    /// Enable deep scanning of Portable Executable files and allows libclamav to unpack executables compressed with run-time unpackers.
    pub fn enable_pe(&mut self) -> &mut Self {
        self.current.parse |= CL_SCAN_PARSE_PE;
        self
    }

    /// Try to detect broken executables and mark them as Broken.Executable.
    pub fn block_broken_executables(&mut self) -> &mut Self {
        self.current.heuristic |= CL_SCAN_HEURISTIC_BROKEN;
        self
    }

    ///  Mark archives as viruses if maxfiles, maxfilesize, or maxreclevel limit is reached.
    pub fn block_max_limit(&mut self) -> &mut Self {
        self.current.heuristic |= CL_SCAN_HEURISTIC_EXCEEDS_MAX;
        self
    }

    /// Enable phishing module: always block SSL mismatches in URLs.
    pub fn enable_phishing_blockssl(&mut self) -> &mut Self {
        self.current.heuristic |= CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH;
        self
    }

    /// Enable phishing module: always block cloaked URLs.
    pub fn enable_phishing_blockcloak(&mut self) -> &mut Self {
        self.current.heuristic |= CL_SCAN_HEURISTIC_PHISHING_CLOAK;
        self
    }

    /// Enable support for ELF files.
    pub fn enable_elf(&mut self) -> &mut Self {
        self.current.parse |= CL_SCAN_PARSE_ELF;
        self
    }

    /// Enable scanning within PDF files.
    pub fn enable_pdf(&mut self) -> &mut Self {
        self.current.parse |= CL_SCAN_PARSE_PDF;
        self
    }

    /// Enable the DLP module which scans for credit card and SSN numbers.
    pub fn enable_structured(&mut self) -> &mut Self {
        self.current.heuristic |= CL_SCAN_HEURISTIC_STRUCTURED;
        self
    }

    /// Enable search for SSNs formatted as xx-yy-zzzz.
    pub fn enable_structured_ssn_normal(&mut self) -> &mut Self {
        self.current.heuristic |= CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL;
        self
    }

    /// Enable search for SSNs formatted as xxyyzzzz.
    pub fn enable_structured_ssn_stripped(&mut self) -> &mut Self {
        self.current.heuristic |= CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED;
        self
    }

    /// Enable scanning of RFC1341 messages split over many emails.
    ///
    /// You will need to periodically clean up $TemporaryDirectory/clamav-partial directory.
    pub fn enable_partial_message(&mut self) -> &mut Self {
        self.current.mail |= CL_SCAN_MAIL_PARTIAL_MESSAGE;
        self
    }

    /// Allow heuristic match to take precedence. When enabled, if a heuristic scan (such
    /// as phishingScan) detects a possible virus/phish it will stop scan immediately.
    ///
    /// Recommended, saves CPU scan-time. When disabled, virus/phish detected by heuristic
    /// scans will be reported only at the end of a scan. If an archive contains both a
    /// heuristically detected virus/phishing, and a real malware, the real malware will be
    /// reported.
    pub fn enable_heuristic_precedence(&mut self) -> &mut Self {
        self.current.general |= CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE;
        self
    }

    /// OLE2 containers, which contain VBA macros will be marked infected (Heuris-tics.OLE2.ContainsMacros).
    pub fn block_macros(&mut self) -> &mut Self {
        self.current.heuristic |= CL_SCAN_HEURISTIC_MACROS;
        self
    }

    /// Enable scanning within SWF files, notably compressed SWF.
    pub fn enable_swf(&mut self) -> &mut Self {
        self.current.parse |= CL_SCAN_PARSE_SWF;
        self
    }

    /// Enable scanning of XML docs.
    pub fn enable_xmldocs(&mut self) -> &mut Self {
        self.current.parse |= CL_SCAN_PARSE_XMLDOCS;
        self
    }

    /// Enable scanning of HWP3 files.
    pub fn enable_hwp3(&mut self) -> &mut Self {
        self.current.parse |= CL_SCAN_PARSE_HWP3;
        self
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_defaults_to_standard_opts() {
        let settings = Builder::new().build();
        assert_eq!(settings.settings, clamav_sys::cl_scan_options::default());
    }

    #[test]
    fn builder_clear_success() {
        let settings = Builder::new().clear().build();
        assert_eq!(settings.settings.general, 0);
        assert_eq!(settings.settings.parse, 0);
        assert_eq!(settings.settings.heuristic, 0);
        assert_eq!(settings.settings.mail, 0);
        assert_eq!(settings.settings.dev, 0);
    }

    #[test]
    fn builder_just_pdf_success() {
        let settings = Builder::new().clear().enable_pdf().build();
        assert_eq!(settings.settings.parse, CL_SCAN_PARSE_PDF);
    }

    #[test]
    fn builder_normal_files_success() {
        let settings = Builder::new()
            .clear()
            .enable_pdf()
            .enable_html()
            .enable_pe()
            .build();
        assert_eq!(
            settings.settings.parse,
            CL_SCAN_PARSE_PDF | CL_SCAN_PARSE_HTML | CL_SCAN_PARSE_PE
        );
    }

    #[test]
    fn display_settings_standard_options_success() {
        let string_settings = ScanSettings::default().to_string();
        assert!(string_settings.contains("CL_SCAN_PARSE_ARCHIVE"));
        assert!(string_settings.contains("CL_SCAN_PARSE_MAIL"));
        assert!(string_settings.contains("CL_SCAN_PARSE_OLE2"));
        assert!(string_settings.contains("CL_SCAN_PARSE_PDF"));
        assert!(string_settings.contains("CL_SCAN_PARSE_HTML"));
        assert!(string_settings.contains("CL_SCAN_PARSE_PE"));
        assert!(string_settings.contains("CL_SCAN_PARSE_ELF"));
        assert!(string_settings.contains("CL_SCAN_PARSE_SWF"));
        assert!(string_settings.contains("CL_SCAN_PARSE_XMLDOCS"));
    }

    #[test]
    fn settings_default_to_standard() {
        let settings: ScanSettings = ScanSettings::default();
        assert_eq!(settings.settings, cl_scan_options::default());
    }
}
