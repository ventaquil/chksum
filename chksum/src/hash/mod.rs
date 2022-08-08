use std::fmt::{self, Formatter, LowerHex, UpperHex};

pub mod md5;
pub mod sha1;
pub mod sha2;

use std::num::ParseIntError;

use thiserror::Error;

#[derive(Debug, Eq, Error, PartialEq)]
pub enum DigestError {
    #[error("Invalid digest length `{value}`, proper value `{proper}`")]
    InvalidLength { value: usize, proper: usize },
    #[error(transparent)]
    ParseError(#[from] ParseIntError),
}

pub type DigestResult<T> = Result<T, DigestError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashAlgorithm {
    /// MD5 hash function implemented in [`md5`] module.
    MD5,
    /// SHA-1 hash function implemented in [`sha1`] module.
    SHA1,
    /// SHA-2 224 hash function implemented in [`sha2::sha224`] module.
    SHA2_224,
    /// SHA-2 256 hash function implemented in [`sha2::sha256`] module.
    SHA2_256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashDigest {
    /// Digest of MD5 hash function implemented in [`md5`] module.
    MD5(md5::Digest),
    /// Digest of SHA-1 hash function implemented in [`sha1`] module.
    SHA1(sha1::Digest),
    /// Digest of SHA-2 224 hash function implemented in [`sha2::sha224`] module.
    SHA2_224(sha2::sha224::Digest),
    /// Digest of SHA-2 256 hash function implemented in [`sha2::sha256`] module.
    SHA2_256(sha2::sha256::Digest),
}

impl From<md5::Digest> for HashDigest {
    #[cfg_attr(not(debug_assertions), inline)]
    fn from(digest: md5::Digest) -> Self {
        Self::MD5(digest)
    }
}

impl From<sha1::Digest> for HashDigest {
    #[cfg_attr(not(debug_assertions), inline)]
    fn from(digest: sha1::Digest) -> Self {
        Self::SHA1(digest)
    }
}

impl From<sha2::sha224::Digest> for HashDigest {
    #[cfg_attr(not(debug_assertions), inline)]
    fn from(digest: sha2::sha224::Digest) -> Self {
        Self::SHA2_224(digest)
    }
}

impl From<sha2::sha256::Digest> for HashDigest {
    #[cfg_attr(not(debug_assertions), inline)]
    fn from(digest: sha2::sha256::Digest) -> Self {
        Self::SHA2_256(digest)
    }
}

impl LowerHex for HashDigest {
    #[cfg_attr(not(debug_assertions), inline)]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MD5(digest) => LowerHex::fmt(digest, f),
            Self::SHA1(digest) => LowerHex::fmt(digest, f),
            Self::SHA2_224(digest) => LowerHex::fmt(digest, f),
            Self::SHA2_256(digest) => LowerHex::fmt(digest, f),
        }
    }
}

impl UpperHex for HashDigest {
    #[cfg_attr(not(debug_assertions), inline)]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MD5(digest) => UpperHex::fmt(digest, f),
            Self::SHA1(digest) => UpperHex::fmt(digest, f),
            Self::SHA2_224(digest) => UpperHex::fmt(digest, f),
            Self::SHA2_256(digest) => UpperHex::fmt(digest, f),
        }
    }
}
