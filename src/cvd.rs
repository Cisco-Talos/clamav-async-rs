use std::{borrow::Cow, fs::File, num::ParseIntError, path::Path, str::Utf8Error};
use thiserror::Error;

#[cfg(not(feature = "native-impl"))]
pub mod head_libclamav;
#[cfg(feature = "native-impl")]
pub mod head_native;

#[cfg(not(feature = "native-impl"))]
pub use head_libclamav::CvdHdr;

#[cfg(feature = "native-impl")]
pub use head_native::CvdHdr;

pub trait CvdMeta {
    /// Load fromm the initial bytes found at the beginning of the CVD/CLD
    fn from_header_bytes(bytes: &[u8; 512]) -> Result<Self, CvdHeadError>
    where
        Self: Sized;

    /// Obtain a CVD/CLD header from an open file
    fn from_file(fh: &mut File) -> Result<Self, CvdHeadError>
    where
        Self: Sized,
    {
        use std::io::Read;

        let mut buf = [0u8; 512];
        fh.read_exact(buf.as_mut_slice())?;
        Self::from_header_bytes(&buf)
    }

    /// Obtain a CVD/CLD header from the specified path
    fn from_path(path: &Path) -> Result<Self, CvdHeadError>
    where
        Self: Sized,
    {
        let mut fh = File::open(path)?;
        Self::from_file(&mut fh)
    }

    /// Database "feature level"
    fn f_level(&self) -> usize;

    /// Number of signatures reported to be within the database
    fn n_sigs(&self) -> usize;

    /// Creation time (as a string)
    fn time_str(&self) -> Cow<'_, str>;

    /// Database version
    fn version(&self) -> usize;

    /// MD5 digest (as a hex string)
    fn md5_str(&self) -> Cow<'_, str>;

    /// Digital signature (as a hex string)
    fn dsig_str(&self) -> Cow<'_, str>;

    /// Database builder's ID
    fn builder(&self) -> Cow<'_, str>;

    /// Creation time as seconds
    fn stime(&self) -> usize;
}

#[derive(Debug, Error)]
pub enum CvdHeadError {
    /// Generic error from the libclamav parser.  Unfortunately, it outputs its
    /// error via a message
    #[error("unable to parse (see log output)")]
    Parse,

    /// An IO error occurred
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),

    /// Header was missing an expected leading signature
    #[error("bad magic")]
    BadMagic,

    /// Header fields ended when expecting creation time
    #[error("missing creation time field")]
    MissingCreationTime,

    /// Header fields ended when expecting version
    #[error("missing version field")]
    MissingVersion,

    /// Header fields ended when expecting number of signatures
    #[error("missing number of signatures field")]
    MissingNumberOfSigs,

    /// Header fields ended when expecting feature level
    #[error("missing f_level field")]
    MissingFLevel,

    /// Header fields ended when expecting database MD5
    #[error("missing md5 field")]
    MissingMd5,

    /// Header fields ended when expecting digital signature
    #[error("missing dsig field")]
    MissingDSig,

    /// Header fields ended when expecting builder identity
    #[error("missing builder field")]
    MissingBuilder,

    /// Header field contains non-UTF-8 content
    #[error("non-UTF-8 contenti: {0}")]
    Utf80(#[from] Utf8Error),

    /// Header field content can't be parsed as number
    #[error("unable to parse integer: {0}")]
    ParseInt(#[from] ParseIntError),

    /// Header field content can't be parsed as a timestamp
    #[error("unable to parse time: {0}")]
    ParseTime(#[from] time::error::Parse),

    /// Value of "stime" header field would overflow a SystemTime representation
    #[error("value of stime would overflow SystemTime")]
    STimeTooLarge,
}
