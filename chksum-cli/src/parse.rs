use std::num::ParseIntError;

use chksum::hash::Alghorithm as HashAlghorithm;
use thiserror::Error;

#[derive(Debug, Eq, Error, PartialEq)]
pub enum Error {
    #[error("Not a valid number")]
    ChunkSizeIsNotANumber(#[from] ParseIntError),
    #[error("Value is zero")]
    ChunkSizeIsZero,
    #[error("Unknown suffix `{0}`")]
    ChunkSizeUnknownSuffix(String),
    #[error("Unknown hash alghorithm")]
    HashAlghorithmUnknown,
}

pub fn chunk_size<V: AsRef<str>>(value: V) -> Result<usize, Error> {
    let value = value.as_ref();
    let value = if let Ok(value) = value.parse::<usize>() {
        value
    } else {
        let length = value.len();
        let (value, suffix) = value.split_at(length - 1);
        let value = value.parse::<usize>()?;
        let multiply = match suffix {
            "k" | "K" => Some(1024),
            "m" | "M" => Some(1024 * 1024),
            "g" | "G" => Some(1024 * 1024 * 1024),
            _ => None,
        };
        let multiply = multiply.ok_or_else(|| Error::ChunkSizeUnknownSuffix(suffix.to_owned()))?;
        value * multiply
    };
    match value {
        _ if value > 0 => Ok(value),
        _ => Err(Error::ChunkSizeIsZero),
    }
}

pub fn hash<V: AsRef<str>>(value: V) -> Result<HashAlghorithm, Error> {
    let value = value.as_ref();
    match value {
        "MD5" => Ok(HashAlghorithm::MD5),
        "SHA1" | "SHA-1" => Ok(HashAlghorithm::SHA1),
        _ => Err(Error::HashAlghorithmUnknown),
    }
}

#[cfg(test)]
mod tests {
    use super::{chunk_size, hash, Error, HashAlghorithm};

    #[test]
    fn test_chunk_size() {
        assert!(
            matches!(chunk_size("2"), Ok(chunk_size) if chunk_size == 2),
            "chunk size is valid"
        );
        assert!(
            matches!(chunk_size("16"), Ok(chunk_size) if chunk_size == 16),
            "chunk size is valid"
        );
        assert!(
            matches!(chunk_size("512"), Ok(chunk_size) if chunk_size == 512),
            "chunk size is valid"
        );
        assert!(
            matches!(chunk_size("1k"), Ok(chunk_size) if chunk_size == 1 * 1024),
            "chunk size is valid"
        );
        assert!(
            matches!(chunk_size("2K"), Ok(chunk_size) if chunk_size == 2 * 1024),
            "chunk size is valid"
        );
        assert!(
            matches!(chunk_size("4m"), Ok(chunk_size) if chunk_size == 4 * 1024 * 1024),
            "chunk size is valid"
        );
        assert!(
            matches!(chunk_size("8M"), Ok(chunk_size) if chunk_size == 8 * 1024 * 1024),
            "chunk size is valid"
        );
        #[cfg(target_pointer_width = "32")]
        assert!(
            matches!(chunk_size("1g"), Ok(chunk_size) if chunk_size == 1 * 1024 * 1024 * 1024),
            "chunk size is valid"
        );
        #[cfg(target_pointer_width = "64")]
        assert!(
            matches!(chunk_size("16g"), Ok(chunk_size) if chunk_size == 16 * 1024 * 1024 * 1024),
            "chunk size is valid"
        );
        #[cfg(target_pointer_width = "32")]
        assert!(
            matches!(chunk_size("2G"), Ok(chunk_size) if chunk_size == 2 * 1024 * 1024 * 1024),
            "chunk size is valid"
        );
        #[cfg(target_pointer_width = "64")]
        assert!(
            matches!(chunk_size("32G"), Ok(chunk_size) if chunk_size == 32 * 1024 * 1024 * 1024),
            "chunk size is valid"
        );
        assert!(
            matches!(chunk_size("0"), Err(Error::ChunkSizeIsZero)),
            "chunk size is zero!"
        );
        assert!(
            matches!(chunk_size("0k"), Err(Error::ChunkSizeIsZero)),
            "chunk size is zero!"
        );
        assert!(
            matches!(chunk_size("0M"), Err(Error::ChunkSizeIsZero)),
            "chunk size is zero!"
        );
        assert!(
            matches!(chunk_size("0g"), Err(Error::ChunkSizeIsZero)),
            "chunk size is zero!"
        );
        assert!(
            matches!(chunk_size("0x0"), Err(Error::ChunkSizeIsNotANumber(_))),
            "chunk size is not a number!"
        );
        assert!(
            matches!(chunk_size("0x0g"), Err(Error::ChunkSizeIsNotANumber(_))),
            "chunk size is not a number!"
        );
        assert!(
            matches!(chunk_size("abc"), Err(Error::ChunkSizeIsNotANumber(_))),
            "chunk size is not a number!"
        );
        assert!(
            matches!(chunk_size("15x"), Err(Error::ChunkSizeUnknownSuffix(_))),
            "suffix is unknown!"
        );
        assert!(
            matches!(chunk_size("15 "), Err(Error::ChunkSizeUnknownSuffix(_))),
            "suffix is unknown!"
        );
    }

    #[test]
    fn test_hash_md5() {
        assert!(
            matches!(hash("MD5"), Ok(HashAlghorithm::MD5)),
            "string is a valid MD5 name!"
        );
        assert!(
            matches!(hash("md5"), Err(Error::HashAlghorithmUnknown)),
            "string is not a valid SHA-1 name!"
        );
        assert!(
            matches!(hash("Md5"), Err(Error::HashAlghorithmUnknown)),
            "string is not a valid SHA-1 name!"
        );
        assert!(
            matches!(hash("MD 5"), Err(Error::HashAlghorithmUnknown)),
            "string is not a valid SHA-1 name!"
        );
    }

    #[test]
    fn test_hash_sha1() {
        assert!(
            matches!(hash("SHA1"), Ok(HashAlghorithm::SHA1)),
            "string is a valid SHA-1 name!"
        );
        assert!(
            matches!(hash("SHA-1"), Ok(HashAlghorithm::SHA1)),
            "string is a valid SHA-1 name!"
        );
        assert!(
            matches!(hash("sha1"), Err(Error::HashAlghorithmUnknown)),
            "string is not a valid SHA-1 name!"
        );
        assert!(
            matches!(hash("Sha1"), Err(Error::HashAlghorithmUnknown)),
            "string is not a valid SHA-1 name!"
        );
        assert!(
            matches!(hash("SHA 1"), Err(Error::HashAlghorithmUnknown)),
            "string is not a valid SHA-1 name!"
        );
    }
}
