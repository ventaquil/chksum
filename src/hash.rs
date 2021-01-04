use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::result::Result;

pub mod md5;
pub mod sha1;

#[derive(Debug)]
pub struct UnknownAlgorithmError {
    algorithm: String,
}

impl Error for UnknownAlgorithmError {}

impl Display for UnknownAlgorithmError {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "Unknown algorithm '{}'", self.algorithm)
    }
}

pub trait Hash {
    fn digest(&self) -> String;

    fn update(&mut self, data: &[u8]) -> usize;
}

pub trait Process<T, E> {
    fn update(&mut self, data: &T) -> Result<usize, E>;
}

#[inline]
pub fn new(name: &str) -> Result<Context, UnknownAlgorithmError> {
    Context::new(name)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Context {
    MD5(md5::Context),
    SHA1(sha1::Context),
}

impl Context {
    #[inline]
    pub fn new(name: &str) -> Result<Self, UnknownAlgorithmError> {
        match name {
            "MD5" => Ok(Self::MD5(md5::new())),
            "SHA1" | "SHA-1" => Ok(Self::SHA1(sha1::new())),
            &_ => Err(UnknownAlgorithmError { algorithm: String::from(name) }),
        }
    }
}

impl Hash for Context {
    #[inline]
    fn digest(&self) -> String {
        match self {
            Self::MD5(hash) => hash.digest(),
            Self::SHA1(hash) => hash.digest(),
        }
    }

    #[inline]
    fn update(&mut self, data: &[u8]) -> usize {
        match self {
            Self::MD5(hash) => hash.update(data),
            Self::SHA1(hash) => hash.update(data),
        }
    }
}
