#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod arch;
pub mod convert;
pub mod hash;
pub mod num;

use std::fs;
use std::io;
use std::path::Path;

use crate::hash::Hash;

/// Contains informations about hashing process.
///
/// # Examples
///
/// ```rust
/// use chksum::Config;
///
/// let config = Config::default();
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct Config {
    chunk_size: usize,
    with_paths: bool,
}

impl Config {
    pub const DEFAULT_CHUNK_SIZE: usize = 512;
    pub const DEFAULT_WITH_PATHS: bool = false;

    /// Constructs new config with given parameters.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum::Config;
    ///
    /// let config = Config::new(32, false);
    /// ```
    #[must_use] pub const fn new(chunk_size: usize, with_paths: bool) -> Self {
        Self {
            chunk_size,
            with_paths,
        }
    }
}

impl Default for Config {
    /// Creates config with default parameters.
    #[cfg_attr(feature = "inline", inline)]
    fn default() -> Self {
        let chunk_size = Self::DEFAULT_CHUNK_SIZE;
        let with_paths = Self::DEFAULT_WITH_PATHS;
        Self::new(chunk_size, with_paths)
    }
}

impl From<(usize, bool)> for Config {
    /// Converts tuple into `Config`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum::Config;
    ///
    /// let config = (Config::DEFAULT_CHUNK_SIZE, Config::DEFAULT_WITH_PATHS);
    /// let config = Config::from(config);
    /// let (chunk_size, with_paths) = config.into();
    /// assert_eq!(chunk_size, Config::DEFAULT_CHUNK_SIZE);
    /// assert_eq!(with_paths, Config::DEFAULT_WITH_PATHS);
    /// ```
    #[cfg_attr(feature = "inline", inline)]
    fn from(config: (usize, bool)) -> Self {
        let (chunk_size, with_paths) = config;
        Self::new(chunk_size, with_paths)
    }
}

impl From<Config> for (usize, bool) {
    /// Converts `Config` into tuple.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum::Config;
    ///
    /// let config = Config::default();
    /// let (chunk_size, with_paths) = config.into();
    /// assert_eq!(chunk_size, Config::DEFAULT_CHUNK_SIZE);
    /// assert_eq!(with_paths, Config::DEFAULT_WITH_PATHS);
    /// ```
    #[cfg_attr(feature = "inline", inline)]
    fn from(config: Config) -> Self {
        (config.chunk_size, config.with_paths)
    }
}

/// Calculate digest of given path with given hash with default config.
///
/// # Examples
///
/// ```rust,no_run
/// use std::convert::TryFrom;
/// use chksum::arch::x1::Arch;
/// use chksum::chksum;
/// use chksum::hash::{md5::{Digest, Hash}, ToHex};
///
/// let mut hash = Hash::<Arch>::new();
/// if let Ok(digest) = chksum(&mut hash, "path/to/file") {
///     println!("digest: {}", digest.to_hex());
/// }
/// ```
pub fn chksum<H, P>(hash: &mut H, path: P) -> io::Result<H::Digest>
where H: Hash<u8>, P: AsRef<Path> + Copy {
    let config = Config::default();
    chksum_with_config(&config, hash, path)
}

/// Calculate digest of given path with given hash with given config.
///
/// # Examples
///
/// ```rust,no_run
/// use std::convert::TryFrom;
/// use chksum::arch::x1::Arch;
/// use chksum::{chksum_with_config, Config};
/// use chksum::hash::{md5::{Digest, Hash}, ToHex};
///
/// let config = Config::new(1024, true);
/// let mut hash = Hash::<Arch>::new();
/// if let Ok(digest) = chksum_with_config(&config, &mut hash, "path/to/file") {
///     println!("digest: {}", digest.to_hex());
/// }
/// ```
pub fn chksum_with_config<H, P>(config: &Config, hash: &mut H, path: P) -> io::Result<H::Digest>
where H: Hash<u8>, P: AsRef<Path> + Copy {
    let metadata = fs::metadata(path)?;
    if metadata.is_file() {
        file::chksum_with_config(config, hash, path)
    } else if metadata.is_dir() {
        directory::chksum_with_config(config, hash, path)
    } else {
        let error = io::Error::new(io::ErrorKind::InvalidInput, "Nether file nor directory");
        Err(error)
    }
}

fn hash_with_config<H, P>(config: &Config, hash: &mut H, path: P) -> io::Result<()>
where H: Hash<u8>, P: AsRef<Path> + Copy {
    let metadata = fs::metadata(path)?;
    if metadata.is_file() {
        file::hash_with_config(config, hash, path)
    } else if metadata.is_dir() {
        directory::hash_with_config(config, hash, path)
    } else {
        let error = io::Error::new(io::ErrorKind::InvalidInput, "Nether file nor directory");
        Err(error)
    }
}

mod directory {
    use std::io;
    use std::path::Path;

    use crate::hash::Hash;

    use super::Config;

    extern crate walkdir;
    use walkdir::WalkDir;

    pub(super) fn hash_with_config<H, P>(config: &Config, hash: &mut H, path: P) -> io::Result<()>
    where H: Hash<u8>, P: AsRef<Path> + Copy {
        if config.with_paths {
            if let Some(path) = path.as_ref().to_str() {
                hash.update(path.as_bytes());
            }
        }
        Ok(())
    }

    pub(super) fn chksum_with_config<H, P>(config: &Config, hash: &mut H, path: P) -> io::Result<H::Digest>
    where H: Hash<u8>, P: AsRef<Path> + Copy {
        for entry in WalkDir::new(path).sort_by(|a, b| a.path().cmp(b.path())) {
            let entry = entry?;
            let path = entry.path();
            super::hash_with_config(config, hash, path)?;
        }
        let digest = hash.digest();
        Ok(digest)
    }
}

mod file {
    use std::fs::File;
    use std::io::{self, Read};
    use std::path::Path;

    use crate::hash::Hash;

    use super::Config;

    #[allow(
        clippy::unseparated_literal_suffix,
    )]
    pub(super) fn hash_with_config<H, P>(config: &Config, hash: &mut H, path: P) -> io::Result<()>
    where H: Hash<u8>, P: AsRef<Path> + Copy {
        let mut file = File::open(path)?;
        if config.with_paths {
            if let Some(path) = path.as_ref().to_str() {
                hash.update(path.as_bytes());
            }
        }
        let mut buffer = vec![0u8; config.chunk_size];
        loop {
            let count = file.read(&mut buffer)?;
            hash.update(&buffer[..count]);
            if count < buffer.len() {
                break;
            }
        }
        Ok(())
    }

    pub(super) fn chksum_with_config<H, P>(config: &Config, hash: &mut H, path: P) -> io::Result<H::Digest>
    where H: Hash<u8>, P: AsRef<Path> + Copy {
        hash_with_config(config, hash, path)?;
        let digest = hash.digest();
        Ok(digest)
    }
}
