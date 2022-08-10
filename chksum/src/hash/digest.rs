use std::num::ParseIntError;
use std::result;

use thiserror::Error;

#[derive(Debug, Eq, Error, PartialEq)]
pub enum Error {
    #[error("Invalid digest length `{value}`, proper value `{proper}`")]
    InvalidLength { value: usize, proper: usize },
    #[error(transparent)]
    ParseError(#[from] ParseIntError),
}

pub type Result<T> = result::Result<T, Error>;
