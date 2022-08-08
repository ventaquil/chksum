use std::num::ParseIntError;

use chksum::hash::HashAlgorithm;
use thiserror::Error;

/// Possible errors returned by parsing functions.
#[derive(Debug, Eq, Error, PartialEq)]
pub(crate) enum Error {
    #[error("Not a valid number")]
    ChunkSizeIsNotANumber(#[from] ParseIntError),
    #[error("Value is zero")]
    ChunkSizeIsZero,
    #[error("Unknown suffix `{0}`")]
    ChunkSizeUnknownSuffix(String),
    #[error("Unknown hash Algorithm")]
    HashAlgorithmUnknown,
}

/// Parse hash name into [`HashAlgorithm`] variant.
pub(crate) fn hash<T>(value: T) -> Result<HashAlgorithm, Error>
where
    T: AsRef<str>,
{
    let value = value.as_ref();
    match value {
        "MD5" => Ok(HashAlgorithm::MD5),
        "SHA1" | "SHA-1" => Ok(HashAlgorithm::SHA1),
        "SHA256" | "SHA-256" | "SHA2 256" | "SHA-2 256" => Ok(HashAlgorithm::SHA2_256),
        _ => Err(Error::HashAlgorithmUnknown),
    }
}

/// Parse human readable number into machine readable.
pub(crate) fn human_number<T>(value: T) -> Result<usize, Error>
where
    T: AsRef<str>,
{
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_md5() {
        assert!(
            matches!(hash("MD5"), Ok(HashAlgorithm::MD5)),
            "string is a valid MD5 name!"
        );
        assert!(
            matches!(hash("md5"), Err(Error::HashAlgorithmUnknown)),
            "string is not a valid MD5 name!"
        );
        assert!(
            matches!(hash("Md5"), Err(Error::HashAlgorithmUnknown)),
            "string is not a valid MD5 name!"
        );
        assert!(
            matches!(hash("MD 5"), Err(Error::HashAlgorithmUnknown)),
            "string is not a valid MD5 name!"
        );
    }

    #[test]
    fn test_hash_sha1() {
        assert!(
            matches!(hash("SHA1"), Ok(HashAlgorithm::SHA1)),
            "string is a valid SHA-1 name!"
        );
        assert!(
            matches!(hash("SHA-1"), Ok(HashAlgorithm::SHA1)),
            "string is a valid SHA-1 name!"
        );
        assert!(
            matches!(hash("sha1"), Err(Error::HashAlgorithmUnknown)),
            "string is not a valid SHA-1 name!"
        );
        assert!(
            matches!(hash("Sha1"), Err(Error::HashAlgorithmUnknown)),
            "string is not a valid SHA-1 name!"
        );
        assert!(
            matches!(hash("SHA 1"), Err(Error::HashAlgorithmUnknown)),
            "string is not a valid SHA-1 name!"
        );
    }

    #[test]
    fn test_hash_sha2_256() {
        assert!(
            matches!(hash("SHA256"), Ok(HashAlgorithm::SHA2_256)),
            "string is a valid SHA-2 256 name!"
        );
        assert!(
            matches!(hash("SHA-256"), Ok(HashAlgorithm::SHA2_256)),
            "string is a valid SHA-2 256 name!"
        );
        assert!(
            matches!(hash("SHA2 256"), Ok(HashAlgorithm::SHA2_256)),
            "string is a valid SHA-2 256 name!"
        );
        assert!(
            matches!(hash("SHA-2 256"), Ok(HashAlgorithm::SHA2_256)),
            "string is a valid SHA-2 256 name!"
        );
        assert!(
            matches!(hash("sha256"), Err(Error::HashAlgorithmUnknown)),
            "string is not a valid SHA-2 256 name!"
        );
        assert!(
            matches!(hash("Sha256"), Err(Error::HashAlgorithmUnknown)),
            "string is not a valid SHA-2 256 name!"
        );
        assert!(
            matches!(hash("SHA 256"), Err(Error::HashAlgorithmUnknown)),
            "string is not a valid SHA-2 256 name!"
        );
        assert!(
            matches!(hash("sha2 256"), Err(Error::HashAlgorithmUnknown)),
            "string is not a valid SHA-2 256 name!"
        );
        assert!(
            matches!(hash("Sha2 256"), Err(Error::HashAlgorithmUnknown)),
            "string is not a valid SHA-2 256 name!"
        );
        assert!(
            matches!(hash("SHA 2 256"), Err(Error::HashAlgorithmUnknown)),
            "string is not a valid SHA-2 256 name!"
        );
    }

    #[test]
    fn test_human_number() {
        assert!(
            matches!(human_number("2"), Ok(human_number) if human_number == 2),
            "chunk size is valid"
        );
        assert!(
            matches!(human_number("16"), Ok(human_number) if human_number == 16),
            "chunk size is valid"
        );
        assert!(
            matches!(human_number("512"), Ok(human_number) if human_number == 512),
            "chunk size is valid"
        );
        assert!(
            matches!(human_number("1k"), Ok(human_number) if human_number == 1 * 1024),
            "chunk size is valid"
        );
        assert!(
            matches!(human_number("2K"), Ok(human_number) if human_number == 2 * 1024),
            "chunk size is valid"
        );
        assert!(
            matches!(human_number("4m"), Ok(human_number) if human_number == 4 * 1024 * 1024),
            "chunk size is valid"
        );
        assert!(
            matches!(human_number("8M"), Ok(human_number) if human_number == 8 * 1024 * 1024),
            "chunk size is valid"
        );
        #[cfg(target_pointer_width = "32")]
        assert!(
            matches!(human_number("1g"), Ok(human_number) if human_number == 1 * 1024 * 1024 * 1024),
            "chunk size is valid"
        );
        #[cfg(target_pointer_width = "64")]
        assert!(
            matches!(human_number("16g"), Ok(human_number) if human_number == 16 * 1024 * 1024 * 1024),
            "chunk size is valid"
        );
        #[cfg(target_pointer_width = "32")]
        assert!(
            matches!(human_number("2G"), Ok(human_number) if human_number == 2 * 1024 * 1024 * 1024),
            "chunk size is valid"
        );
        #[cfg(target_pointer_width = "64")]
        assert!(
            matches!(human_number("32G"), Ok(human_number) if human_number == 32 * 1024 * 1024 * 1024),
            "chunk size is valid"
        );
        assert!(
            matches!(human_number("0"), Err(Error::ChunkSizeIsZero)),
            "chunk size is zero!"
        );
        assert!(
            matches!(human_number("0k"), Err(Error::ChunkSizeIsZero)),
            "chunk size is zero!"
        );
        assert!(
            matches!(human_number("0M"), Err(Error::ChunkSizeIsZero)),
            "chunk size is zero!"
        );
        assert!(
            matches!(human_number("0g"), Err(Error::ChunkSizeIsZero)),
            "chunk size is zero!"
        );
        assert!(
            matches!(human_number("0x0"), Err(Error::ChunkSizeIsNotANumber(_))),
            "chunk size is not a number!"
        );
        assert!(
            matches!(human_number("0x0g"), Err(Error::ChunkSizeIsNotANumber(_))),
            "chunk size is not a number!"
        );
        assert!(
            matches!(human_number("abc"), Err(Error::ChunkSizeIsNotANumber(_))),
            "chunk size is not a number!"
        );
        assert!(
            matches!(human_number("15x"), Err(Error::ChunkSizeUnknownSuffix(_))),
            "suffix is unknown!"
        );
        assert!(
            matches!(human_number("15 "), Err(Error::ChunkSizeUnknownSuffix(_))),
            "suffix is unknown!"
        );
    }
}
