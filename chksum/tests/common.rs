use std::str::Utf8Error;
use std::string::FromUtf8Error;
use std::{io, result};

use chksum;
use thiserror::Error;

const ALPHABET: &'static str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Chksum(#[from] chksum::Error),
    #[error(transparent)]
    FromUtf8(#[from] FromUtf8Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Utf8(#[from] Utf8Error),
}

pub type Result = result::Result<(), Error>;

/// Default data sizes.
#[derive(Debug, Eq, PartialEq)]
#[rustfmt::skip]
pub enum Size {
    Empty  =      0,
    Tiny   =      8,
    Small  =     64,
    Medium =    512,
    Big    =  4_096,
    Huge   = 32_768,
}

/// Generate data of given size.
pub fn data_with_size(size: usize) -> Vec<u8> {
    ALPHABET.as_bytes().iter().cloned().cycle().take(size).collect()
}
