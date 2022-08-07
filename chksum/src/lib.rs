//! This crate provides basic cryptographic primitives and easy to use interface which allows to calculate checksums.
//!
//! # Examples
//!
//! [`Chksum`] trait is automatically implemented into several structs like [`File`](`std::fs::File`), [`ReadDir`](`std::fs::ReadDir`) or [`Stdin`](`std::io::Stdin`).
//!
//! ## File checksum
//!
//! ```rust,no_run
//! # use std::fs::File;
//! use chksum::prelude::*;
//!
//! # fn wrapper() -> Result<()> {
//! let digest = File::open("path/to/file")?.chksum(HashAlgorithm::MD5)?;
//! println!("digest: {:x}", digest);
//! # Ok(())
//! # }
//! ```
//!
//! ## Directory checksum
//!
//! ```rust,no_run
//! # use std::fs::read_dir;
//! use chksum::prelude::*;
//!
//! # fn wrapper() -> Result<()> {
//! let digest = read_dir("path/to/directory")?.chksum(HashAlgorithm::MD5)?;
//! println!("digest: {:x}", digest);
//! # Ok(())
//! # }
//! ```
//!
//! ## Stdin checksum
//!
//! ```rust,no_run
//! # use std::io::stdin;
//! use chksum::prelude::*;
//!
//! # fn wrapper() -> Result<()> {
//! let digest = stdin().chksum(HashAlgorithm::MD5)?;
//! println!("digest: {:x}", digest);
//! # Ok(())
//! # }
//! ```

#![cfg_attr(nightly, feature(optimize_attribute))]

pub mod hash;
pub mod prelude;

extern crate thiserror;

use std::cmp::Reverse;
use std::collections::VecDeque;
use std::fs::{self, DirEntry, File, ReadDir};
use std::io::{self, Read, Stdin, StdinLock};
use std::path::PathBuf;
use std::result;
use std::str::Utf8Error;
use std::string::FromUtf8Error;

use self::hash::{md5, sha1, HashAlgorithm, HashDigest};

/// Contains informations about hashing process.
///
/// Use [`ConfigBuilder`] when you want to use config_builder to create [`Config`].
///
/// # Examples
///
/// ```rust
/// use chksum::Config;
///
/// let chunk_size = 512;
/// let config = Config::new(chunk_size);
/// println!("{:?}", config);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Maximum size of processed chunk of data.
    pub chunk_size: usize,
}

impl Config {
    /// Default chunk size used by [`Default`] trait.
    pub const DEFAULT_CHUNK_SIZE: usize = 65_536;

    /// Constructs new config with given parameters.
    #[cfg_attr(not(debug_assertions), inline)]
    #[must_use]
    pub const fn new(chunk_size: usize) -> Self {
        Self { chunk_size }
    }
}

impl AsRef<Self> for Config {
    #[cfg_attr(not(debug_assertions), inline)]
    fn as_ref(&self) -> &Self {
        self
    }
}

impl Default for Config {
    #[cfg_attr(not(debug_assertions), inline)]
    fn default() -> Self {
        let chunk_size = Self::DEFAULT_CHUNK_SIZE;
        Self::new(chunk_size)
    }
}

impl From<ConfigBuilder> for Config {
    #[cfg_attr(not(debug_assertions), inline)]
    fn from(config_builder: ConfigBuilder) -> Self {
        config_builder.build()
    }
}

impl From<&ConfigBuilder> for Config {
    #[cfg_attr(not(debug_assertions), inline)]
    fn from(config_builder: &ConfigBuilder) -> Self {
        config_builder.build()
    }
}

impl From<&mut ConfigBuilder> for Config {
    #[cfg_attr(not(debug_assertions), inline)]
    fn from(config_builder: &mut ConfigBuilder) -> Self {
        config_builder.build()
    }
}

/// Builder for [`Config`] structure.
///
/// ```rust
/// use chksum::ConfigBuilder;
///
/// let config = ConfigBuilder::new().chunk_size(512).build();
/// println!("{:?}", config);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigBuilder {
    /// Maximum size of processed chunk of data.
    chunk_size: Option<usize>,
}

impl ConfigBuilder {
    /// Build [`Config`].
    #[cfg_attr(not(debug_assertions), inline)]
    #[must_use]
    pub fn build(&self) -> Config {
        let chunk_size = self.chunk_size.unwrap_or(Config::DEFAULT_CHUNK_SIZE);
        Config::new(chunk_size)
    }

    /// Set maximum size of processed chunk of data.
    #[cfg_attr(not(debug_assertions), inline)]
    pub fn chunk_size(&mut self, chunk_size: usize) -> &mut Self {
        self.chunk_size = Some(chunk_size);
        self
    }

    /// Create new [`ConfigBuilder`] instance.
    #[cfg_attr(not(debug_assertions), inline)]
    #[must_use]
    pub const fn new() -> Self {
        Self { chunk_size: None }
    }
}

impl Default for ConfigBuilder {
    #[cfg_attr(not(debug_assertions), inline)]
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Cannot calculate checksum from interactive stdin")]
    InteractiveStdin,
    #[error("Nether file nor directory: `{path}`")]
    NetherFileNorDirectory { path: PathBuf },
    #[error("Chunk size cannot be equal to zero")]
    ZeroChunkSize,
    #[error(transparent)]
    FromUtf8(#[from] FromUtf8Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Utf8(#[from] Utf8Error),
}

pub type Result<T> = result::Result<T, Error>;

pub trait Chksum {
    /// Calculate digest with given hash and default config.
    #[cfg_attr(not(debug_assertions), inline)]
    fn chksum(&mut self, hash_algorithm: HashAlgorithm) -> Result<HashDigest> {
        let config = Config::default();
        self.chksum_with_config(hash_algorithm, config)
    }

    /// Calculate digest with given hash and given config.
    #[cfg_attr(nightly, optimize(speed))]
    fn chksum_with_config<T>(&mut self, hash_algorithm: HashAlgorithm, config: T) -> Result<HashDigest>
    where
        T: AsRef<Config>;
}

impl Chksum for &[u8] {
    fn chksum_with_config<T>(&mut self, hash_algorithm: HashAlgorithm, config: T) -> Result<HashDigest>
    where
        T: AsRef<Config>,
    {
        let config = config.as_ref();
        if config.chunk_size == 0 {
            let error = Error::ZeroChunkSize;
            return Err(error);
        }

        match hash_algorithm {
            HashAlgorithm::MD5 => {
                let mut buffer = vec![0u8; config.chunk_size];
                let mut hash = md5::Hash::new();
                loop {
                    let count = self.read(&mut buffer)?;
                    hash.update(&buffer[..count]);
                    if count == 0 {
                        break;
                    }
                }
                let digest = hash.pad().digest();
                Ok(digest.into())
            },
            HashAlgorithm::SHA1 => {
                let mut buffer = vec![0u8; config.chunk_size];
                let mut hash = sha1::Hash::new();
                loop {
                    let count = self.read(&mut buffer)?;
                    hash.update(&buffer[..count]);
                    if count == 0 {
                        break;
                    }
                }
                let digest = hash.pad().digest();
                Ok(digest.into())
            },
        }
    }
}

impl Chksum for File {
    fn chksum_with_config<T>(&mut self, hash_algorithm: HashAlgorithm, config: T) -> Result<HashDigest>
    where
        T: AsRef<Config>,
    {
        let config = config.as_ref();
        if config.chunk_size == 0 {
            let error = Error::ZeroChunkSize;
            return Err(error);
        }

        match hash_algorithm {
            HashAlgorithm::MD5 => {
                let mut buffer = vec![0u8; config.chunk_size];
                let mut hash = md5::Hash::new();
                loop {
                    let count = self.read(&mut buffer)?;
                    hash.update(&buffer[..count]);
                    if count == 0 {
                        break;
                    }
                }
                let digest = hash.pad().digest();
                Ok(digest.into())
            },
            HashAlgorithm::SHA1 => {
                let mut buffer = vec![0u8; config.chunk_size];
                let mut hash = sha1::Hash::new();
                loop {
                    let count = self.read(&mut buffer)?;
                    hash.update(&buffer[..count]);
                    if count == 0 {
                        break;
                    }
                }
                let digest = hash.pad().digest();
                Ok(digest.into())
            },
        }
    }
}

impl Chksum for &str {
    fn chksum_with_config<T>(&mut self, hash_algorithm: HashAlgorithm, config: T) -> Result<HashDigest>
    where
        T: AsRef<Config>,
    {
        self.as_bytes().chksum_with_config(hash_algorithm, config)
    }
}

impl Chksum for Stdin {
    fn chksum_with_config<T>(&mut self, hash_algorithm: HashAlgorithm, config: T) -> Result<HashDigest>
    where
        T: AsRef<Config>,
    {
        let config = config.as_ref();
        if config.chunk_size == 0 {
            let error = Error::ZeroChunkSize;
            return Err(error);
        }

        if atty::is(atty::Stream::Stdin) {
            let error = Error::InteractiveStdin;
            return Err(error);
        }

        match hash_algorithm {
            HashAlgorithm::MD5 => {
                let mut buffer = vec![0u8; config.chunk_size];
                let mut hash = md5::Hash::new();
                loop {
                    let count = self.read(&mut buffer)?;
                    hash.update(&buffer[..count]);
                    if count == 0 {
                        break;
                    }
                }
                let digest = hash.pad().digest();
                Ok(digest.into())
            },
            HashAlgorithm::SHA1 => {
                let mut buffer = vec![0u8; config.chunk_size];
                let mut hash = sha1::Hash::new();
                loop {
                    let count = self.read(&mut buffer)?;
                    hash.update(&buffer[..count]);
                    if count == 0 {
                        break;
                    }
                }
                let digest = hash.pad().digest();
                Ok(digest.into())
            },
        }
    }
}

impl<'a> Chksum for StdinLock<'a> {
    fn chksum_with_config<T>(&mut self, hash_algorithm: HashAlgorithm, config: T) -> Result<HashDigest>
    where
        T: AsRef<Config>,
    {
        let config = config.as_ref();
        if config.chunk_size == 0 {
            let error = Error::ZeroChunkSize;
            return Err(error);
        }

        if atty::is(atty::Stream::Stdin) {
            let error = Error::InteractiveStdin;
            return Err(error);
        }

        match hash_algorithm {
            HashAlgorithm::MD5 => {
                let mut buffer = vec![0u8; config.chunk_size];
                let mut hash = md5::Hash::new();
                loop {
                    let count = self.read(&mut buffer)?;
                    hash.update(&buffer[..count]);
                    if count == 0 {
                        break;
                    }
                }
                let digest = hash.pad().digest();
                Ok(digest.into())
            },
            HashAlgorithm::SHA1 => {
                let mut buffer = vec![0u8; config.chunk_size];
                let mut hash = sha1::Hash::new();
                loop {
                    let count = self.read(&mut buffer)?;
                    hash.update(&buffer[..count]);
                    if count == 0 {
                        break;
                    }
                }
                let digest = hash.pad().digest();
                Ok(digest.into())
            },
        }
    }
}

impl Chksum for String {
    fn chksum_with_config<T>(&mut self, hash_algorithm: HashAlgorithm, config: T) -> Result<HashDigest>
    where
        T: AsRef<Config>,
    {
        self.as_bytes().chksum_with_config(hash_algorithm, config)
    }
}

impl Chksum for ReadDir {
    fn chksum_with_config<T>(&mut self, hash_algorithm: HashAlgorithm, config: T) -> Result<HashDigest>
    where
        T: AsRef<Config>,
    {
        let config = config.as_ref();
        if config.chunk_size == 0 {
            let error = Error::ZeroChunkSize;
            return Err(error);
        }
        let entries: io::Result<Vec<_>> = self.collect();
        let mut entries = entries?;
        entries.sort_by_key(DirEntry::path);
        let mut stack: VecDeque<_> = entries.into_iter().collect();
        match hash_algorithm {
            HashAlgorithm::MD5 => {
                let mut buffer = vec![0u8; config.chunk_size];
                let mut hash = md5::Hash::new();
                while let Some(entry) = stack.pop_front() {
                    let path = entry.path();
                    let metadata = entry.metadata()?;
                    if metadata.is_file() {
                        let mut file = File::open(&path)?;
                        loop {
                            let count = file.read(&mut buffer)?;
                            hash.update(&buffer[..count]);
                            if count == 0 {
                                break;
                            }
                        }
                    } else if metadata.is_dir() {
                        let mut entries = fs::read_dir(&path)?.collect::<io::Result<Vec<_>>>()?;
                        entries.sort_by_key(|entry| Reverse(entry.path()));
                        let entries = entries;
                        // entries are pushed in reverse order
                        for entry in entries {
                            stack.push_front(entry);
                        }
                    } else {
                        let error = Error::NetherFileNorDirectory { path };
                        return Err(error);
                    }
                }
                let digest = hash.pad().digest();
                Ok(digest.into())
            },
            HashAlgorithm::SHA1 => {
                let mut buffer = vec![0u8; config.chunk_size];
                let mut hash = sha1::Hash::new();
                while let Some(entry) = stack.pop_front() {
                    let path = entry.path();
                    let metadata = entry.metadata()?;
                    if metadata.is_file() {
                        let mut file = File::open(&path)?;
                        loop {
                            let count = file.read(&mut buffer)?;
                            hash.update(&buffer[..count]);
                            if count == 0 {
                                break;
                            }
                        }
                    } else if metadata.is_dir() {
                        let mut entries = fs::read_dir(&path)?.collect::<io::Result<Vec<_>>>()?;
                        entries.sort_by_key(|entry| Reverse(entry.path()));
                        let entries = entries;
                        // entries are pushed in reverse order
                        for entry in entries {
                            stack.push_front(entry);
                        }
                    } else {
                        let error = Error::NetherFileNorDirectory { path };
                        return Err(error);
                    }
                }
                let digest = hash.pad().digest();
                Ok(digest.into())
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder_default() {
        assert_eq!(ConfigBuilder::default().build(), Config::default());
    }

    #[test]
    fn test_config_builder_chunk_size() {
        let (chunk_size,) = (128,);
        let config = ConfigBuilder::new().chunk_size(chunk_size).build();
        assert_eq!(config.chunk_size, chunk_size);
    }

    #[test]
    fn test_config_as_ref() {
        let (chunk_size,) = (256,);
        let config = Config::new(chunk_size);
        assert_eq!(config.as_ref(), &config);
    }

    #[test]
    fn test_config_from() {
        let (chunk_size,) = (512,);
        let config: Config = ConfigBuilder::new().chunk_size(chunk_size).into();
        assert_eq!(config, ConfigBuilder::new().chunk_size(chunk_size).build());
    }

    #[test]
    fn test_config_new() {
        let (chunk_size,) = (1024,);
        let config = Config::new(chunk_size);
        assert_eq!(config.chunk_size, chunk_size);
    }
}
