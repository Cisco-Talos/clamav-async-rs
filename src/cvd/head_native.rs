use super::{CvdHeadError, CvdMeta};
use std::{
    borrow::Cow,
    str::{self, FromStr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// CVD files are expected to begin with this string. Note that this constant
/// contains the first colon, as well
const CVD_HEAD_MAGIC: &[u8] = b"ClamAV-VDB:";

/// The non-standard timestamp format used in CVD headers to represent the
/// creation time
const CVD_TIMESTAMP_FMT: &[time::format_description::FormatItem] = time::macros::format_description!(
    "[day padding:zero] [month repr:short] [year] [hour]:[minute] [offset_hour][offset_minute]"
);

pub struct CvdHdr {
    version: usize,
    n_sigs: usize,
    f_level: usize,
    dsig: String,
    builder: String,
    ctime: SystemTime,
    is_old_db: bool,
    ctime_str: String,
    md5_str: String,
}

impl CvdMeta for CvdHdr {
    fn from_header_bytes(bytes: &[u8; 512]) -> Result<Self, CvdHeadError>
    where
        Self: std::marker::Sized,
    {
        let mut fields = bytes
            .strip_prefix(CVD_HEAD_MAGIC)
            .ok_or(CvdHeadError::BadMagic)?
            .split(|b| *b == b':');
        let creation_time_str = fields
            .next()
            .map(str::from_utf8)
            .transpose()?
            .ok_or(CvdHeadError::MissingCreationTime)?;
        let version = fields
            .next()
            .map(str::from_utf8)
            .transpose()?
            .ok_or(CvdHeadError::MissingVersion)?
            .parse()?;
        let n_sigs: usize = fields
            .next()
            .map(str::from_utf8)
            .transpose()?
            .ok_or(CvdHeadError::MissingNumberOfSigs)?
            .parse()?;
        let f_level: usize =
            str::from_utf8(fields.next().ok_or(CvdHeadError::MissingFLevel)?)?.parse()?;
        // Just preserve this verbatim.
        let md5_str = fields
            .next()
            .map(str::from_utf8)
            .transpose()?
            .ok_or(CvdHeadError::MissingMd5)?
            .into();
        let dsig = str::from_utf8(fields.next().ok_or(CvdHeadError::MissingDSig)?)?.into();
        let builder =
            std::str::from_utf8(fields.next().ok_or(CvdHeadError::MissingBuilder)?)?.into();

        // This field is not present in older signature database files.  It
        // should be the last field (and will be padded out with spaces at the
        // end)
        let (ctime, is_old_db) = fields
            // Is it there?
            .next()
            // Try to make it a str
            .map(str::from_utf8)
            // ...and check that that worked (by flipping the Result out of the
            // Option)
            .transpose()?
            // This value is padded to the right with spaces
            .map(str::trim_end)
            // Try to make it a usize
            .map(usize::from_str)
            // ...and check that that worked
            .transpose()?
            .map(|stime| UNIX_EPOCH.checked_add(Duration::from_secs(stime as u64)))
            // ...and check that that worked
            .ok_or(CvdHeadError::STimeTooLarge)?
            // It's there, so this isn't an old DB
            .map(|stime| Ok((stime, false)))
            // Or it wasn't there, so this *is* an old DB
            .unwrap_or_else(|| {
                // Parse the string version, e.g.: "16 Sep 2021 08:32 -0400"
                // Oddly, there are no seconds.  So this is very much a custom format
                time::OffsetDateTime::parse(creation_time_str, CVD_TIMESTAMP_FMT)
                    // And mark this as old-format
                    .map(|odt| (odt.into(), true))
            })?;

        let ctime_str = time::OffsetDateTime::from(ctime)
            .format(CVD_TIMESTAMP_FMT)
            .expect("format timestamp");

        Ok(Self {
            ctime,
            version,
            n_sigs,
            f_level,
            dsig,
            builder,
            is_old_db,
            ctime_str,
            md5_str,
        })
    }

    fn f_level(&self) -> usize {
        self.f_level
    }

    fn n_sigs(&self) -> usize {
        self.n_sigs
    }

    fn time_str(&self) -> std::borrow::Cow<'_, str> {
        // This is returned in the same format as normally appears within the header
        Cow::from(&self.ctime_str)
    }

    fn version(&self) -> usize {
        self.version
    }

    fn md5_str(&self) -> std::borrow::Cow<'_, str> {
        Cow::from(&self.md5_str)
    }

    fn dsig_str(&self) -> std::borrow::Cow<'_, str> {
        Cow::from(&self.dsig)
    }

    fn builder(&self) -> std::borrow::Cow<'_, str> {
        std::borrow::Cow::from(&self.builder)
    }

    fn stime(&self) -> usize {
        self.ctime
            .duration_since(UNIX_EPOCH)
            .expect("compute seconds since epoch")
            .as_secs() as usize
    }
}

impl CvdHdr {
    /// Whether or not this is an old-format DB (no stime field in header)
    pub fn is_old_db(&self) -> bool {
        self.is_old_db
    }
}
