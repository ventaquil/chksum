use std::fs;
use std::io::Read as _;
use std::path;
use std::result::Result;

use crate::hash::{Context as HashContext, Process};

extern crate walkdir;
use walkdir::WalkDir;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Context {
    pub chunk_size: usize,
    pub process_pathnames: bool,
}

impl Default for Context {
    #[inline]
    fn default() -> Context {
        Context {
            chunk_size: 512,
            process_pathnames: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct File {
    context: Context,
    pathname: String,
}

impl File {
    #[inline]
    pub fn new(pathname: &str, context: Context) -> Result<File, String> {
        let path = path::Path::new(pathname);

        if !path.exists() {
            Err(format!("path {} not exists", pathname))
        } else if path.is_file() {
            Ok(File {
                context,
                pathname: pathname.to_string(),
            })
        } else {
            Err(format!("there is no file under path {}", pathname))
        }
    }

    #[inline]
    pub fn pathname(&self) -> &str {
        &self.pathname
    }
}

impl Process for File {
    #[inline]
    fn process<Block, Digest>(
        &self,
        hash: &mut dyn HashContext<Block, Digest>,
    ) -> Result<Digest, String> {
        if self.context.process_pathnames {
            hash.update(self.pathname.as_bytes()); // todo check output
        }

        fs::File::open(self.pathname())
            .and_then(|mut file| {
                fs::metadata(self.pathname()).and_then(|metadata| {
                    let length: usize = metadata.len() as usize;
                    for _ in (0..length).step_by(self.context.chunk_size) {
                        let mut buffer = vec![0; self.context.chunk_size];
                        let read = file.read(&mut buffer)?;
                        if read != hash.update(&buffer[0..read]) {
                            // todo return error
                        }
                    }
                    Ok(hash.digest())
                })
            })
            .map_err(|error| error.to_string()) // change every io.Error into String
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Directory {
    context: Context,
    pathname: String,
}

impl Directory {
    #[inline]
    pub fn new(pathname: &str, context: Context) -> Result<Directory, String> {
        let path = path::Path::new(pathname);

        if !path.exists() {
            Err(format!("path {} not exists", pathname))
        } else if path.is_dir() {
            Ok(Directory {
                context,
                pathname: pathname.to_string(),
            })
        } else {
            Err(format!("there is no directory under path {}", pathname))
        }
    }

    #[inline]
    pub fn pathname(&self) -> &str {
        &self.pathname
    }
}

impl Process for Directory {
    #[inline]
    fn process<Block, Digest>(
        &self,
        hash: &mut dyn HashContext<Block, Digest>,
    ) -> Result<Digest, String> {
        let pathnames = WalkDir::new(self.pathname()) // todo control min and max depth and follow links option
            .into_iter()
            .map(|entry| {
                entry
                    .map(|entry| {
                        let path = entry.into_path();
                        let pathname = path.to_string_lossy();
                        String::from(pathname)
                    })
                    .map_err(|error| error.to_string()) // change every walkdir.Error into String
            });
        for pathname in pathnames {
            let pathname = pathname?;
            if let Ok(file) = File::new(&pathname, self.context) {
                file.process(hash)?;
            } else if self.context.process_pathnames {
                // for directories only process pathnames if this option is enabled
                hash.update(pathname.as_bytes()); // todo check output
            }
        }
        Ok(hash.digest())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Path {
    File(File),
    Directory(Directory),
}

impl Path {
    #[inline]
    pub fn new(pathname: &str, context: Context) -> Result<Path, String> {
        let path = path::Path::new(pathname);

        if !path.exists() {
            Err(format!("path {} not exists", pathname))
        } else if path.is_file() {
            let file = File::new(pathname, context)?;
            let file = Self::File(file);
            Ok(file)
        } else if path.is_dir() {
            let directory = Directory::new(pathname, context)?;
            let directory = Self::Directory(directory);
            Ok(directory)
        } else {
            Err(format!("undefined type of {}", pathname))
        }
    }

    #[inline]
    pub fn pathname(&self) -> &str {
        match self {
            Self::File(file) => file.pathname(),
            Self::Directory(directory) => directory.pathname(),
        }
    }
}

impl Process for Path {
    #[inline]
    fn process<Block, Digest>(
        &self,
        hash: &mut dyn HashContext<Block, Digest>,
    ) -> Result<Digest, String> {
        match self {
            Self::File(file) => file.process(hash),
            Self::Directory(directory) => directory.process(hash),
        }
    }
}
