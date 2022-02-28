use std::cmp::Reverse;
use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use chksum_config::Config;
use chksum_hash::Hash;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Cannot get metadata for `{path}`: {source}")]
    Metadata { path: PathBuf, source: io::Error },
    #[error("Nether file nor directory: `{path}`")]
    NetherFileNorDirectory { path: PathBuf },
    #[error("Cannot open `{path}`: {source}")]
    Open { path: PathBuf, source: io::Error },
    #[error("Path `{path}` is not a valid unicode string")]
    PathUnicode { path: PathBuf },
    #[error("Cannot read from `{path}`: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error(transparent)]
    Io { #[from] source: io::Error },
}

pub trait Chksum {
    /// Calculate digest of given path with given hash with default config.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use std::convert::TryFrom;
    ///
    /// use chksum_arch::x1::Arch;
    /// use chksum_hash::md5::Hash;
    /// use chksum_sync::Chksum;
    ///
    /// let mut hash = Hash::<Arch>::new();
    /// if let Ok(digest) = "path/to/file".chksum(&mut hash) {
    ///     println!("digest: {:x}", digest);
    /// }
    /// ```
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn chksum<H>(&mut self, hash: &mut H) -> Result<H::Digest, Error>
    where
        H: Hash<u8>,
    {
        let config = Config::default();
        self.chksum_with_config(hash, config)
    }

    /// Calculate digest of given path with given hash with given config.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use std::convert::TryFrom;
    ///
    /// use chksum_arch::x1::Arch;
    /// use chksum_config::Config;
    /// use chksum_hash::md5::Hash;
    /// use chksum_sync::Chksum;
    ///
    /// let mut hash = Hash::<Arch>::new();
    /// let config = Config::new(1024, true);
    /// if let Ok(digest) = "path/to/file".chksum_with_config(&mut hash, config) {
    ///     println!("digest: {:x}", digest);
    /// }
    /// ```
    fn chksum_with_config<H, C>(&mut self, hash: &mut H, config: C) -> Result<H::Digest, Error>
    where
        H: Hash<u8>,
        C: AsRef<Config>;
}

impl<P: AsRef<Path>> Chksum for P {
    fn chksum_with_config<H, C>(&mut self, hash: &mut H, config: C) -> Result<H::Digest, Error>
    where
        H: Hash<u8>,
        C: AsRef<Config>,
    {
        let path = self.as_ref();
        let path = path.to_path_buf();
        let config = config.as_ref();
        let mut stack: VecDeque<PathBuf> = [path].into();
        while let Some(path) = stack.pop_front() {
            if config.with_paths {
                let path = path.to_str().ok_or_else(|| Error::PathUnicode { path: path.clone() })?;
                hash.update(path);
            }
            let metadata = fs::metadata(&path).map_err(|error| {
                Error::Metadata {
                    path: path.clone(),
                    source: error,
                }
            })?;
            if metadata.is_file() {
                let mut file = File::open(&path).map_err(|error| {
                    Error::Open {
                        path: path.clone(),
                        source: error,
                    }
                })?;
                let mut buffer = vec![0u8; config.chunk_size];
                loop {
                    let count = file.read(&mut buffer).map_err(|error| {
                        Error::Read {
                            path: path.clone(),
                            source: error,
                        }
                    })?;
                    hash.update(&buffer[..count]);
                    if count == 0 {
                        break;
                    }
                }
            } else if metadata.is_dir() {
                let mut entries = fs::read_dir(&path)
                    .map_err(|error| {
                        Error::Read {
                            path: path.clone(),
                            source: error,
                        }
                    })?
                    .collect::<io::Result<Vec<_>>>()?;
                entries.sort_by_key(|entry| Reverse(entry.path()));
                let entries = entries;
                // entries are pushed in reverse order
                for entry in entries {
                    let path = entry.path();
                    stack.push_front(path);
                }
            } else {
                let error = Error::NetherFileNorDirectory { path };
                return Err(error);
            }
        }
        let digest = hash.digest();
        Ok(digest)
    }
}
