#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(nightly, feature(optimize_attribute))]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod md5;
pub mod sha1;

#[cfg(feature = "std")]
use std::num::ParseIntError;

#[cfg(feature = "std")]
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Alghorithm {
    MD5,
    SHA1,
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[derive(Debug, Eq, Error, PartialEq)]
pub enum DigestError {
    #[error("Invalid digest length `{value}`, proper value `{proper}`")]
    InvalidLength { value: usize, proper: usize },
    #[error(transparent)]
    ParseError(#[from] ParseIntError),
}

pub trait Digest {
    type Digest;

    fn digest(&mut self) -> Self::Digest;
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub trait Hash<T>: Digest + Reset + Update<T> {}

pub trait Reset {
    fn reset(&mut self);
}

pub trait Update<T> {
    fn update<D: AsRef<[T]>>(&mut self, data: D);
}
