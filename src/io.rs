use std::fs;
use std::io::Read as _;
use std::path;
use std::result::Result;

use crate::hash::{Context as HashContext, Process};

extern crate walkdir;
use walkdir::WalkDir;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct File {
    chunk_size: usize,
    pathname: String,
    process_pathname: bool,
}

impl File {
    pub fn new(pathname: &str, chunk_size: usize, process_pathname: bool) -> Result<File, String> {
        let path = path::Path::new(pathname);

        if !path.exists() {
            Err(format!("path {} not exists", pathname))
        } else if path.is_file() {
            Ok(File {
                chunk_size,
                pathname: pathname.to_string(),
                process_pathname,
            })
        } else {
            Err(format!("there is no file under path {}", pathname))
        }
    }
}

impl Process for File {
    fn process<Block, Digest>(&self, hash: &mut dyn HashContext<Block, Digest>) -> Result<(), String> {
        if self.process_pathname {
            hash.update(self.pathname.as_bytes()); // todo check output
        }

        fs::File::open(&self.pathname).and_then(|mut file| {
            fs::metadata(&self.pathname).and_then(|metadata| {
                let length: usize = metadata.len() as usize;
                for _ in (0..length).step_by(self.chunk_size) {
                    let mut buffer = vec![0; self.chunk_size];
                    let read = file.read(&mut buffer)?;
                    if read != hash.update(&buffer[0..read]) {
                        // todo return error
                    }
                }
                Ok(())
            })
        })
        .or_else(|error| Err(error.to_string())) // change every io.Error into String
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Directory {
    chunk_size: usize,
    pathname: String,
    process_pathnames: bool,
}

impl Directory {
    pub fn new(pathname: &str, chunk_size: usize, process_pathnames: bool) -> Result<Directory, String> {
        let path = path::Path::new(pathname);

        if !path.exists() {
            Err(format!("path {} not exists", pathname))
        } else if path.is_dir() {
            Ok(Directory {
                chunk_size,
                pathname: pathname.to_string(),
                process_pathnames,
            })
        } else {
            Err(format!("there is no directory under path {}", pathname))
        }
    }
}

impl Process for Directory {
    fn process<Block, Digest>(&self, hash: &mut dyn HashContext<Block, Digest>) -> Result<(), String> {
        let pathnames = WalkDir::new(&self.pathname) // todo control min and max depth and follow links option
                                .into_iter()
                                .map(|entry| {
                                    entry.and_then(|entry| {
                                             let path = entry.into_path();
                                             let pathname = path.to_string_lossy();
                                             let pathname = String::from(pathname);
                                             Ok(pathname)
                                         })
                                         .or_else(|error| Err(error.to_string())) // change every walkdir.Error into String
                                });
        for pathname in pathnames {
            let pathname = pathname?;
            if let Ok(file) = File::new(&pathname, self.chunk_size, self.process_pathnames) {
                file.process(hash)?;
            } else if self.process_pathnames { // for directories only process pathnames if this option is enabled
                hash.update(pathname.as_bytes()); // todo check output
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Path {
    File(File),
    Directory(Directory),
}

impl Path {
    pub fn new(pathname: &str, chunk_size: usize, process_pathname: bool) -> Result<Path, String> {
        let path = path::Path::new(pathname);

        if !path.exists() {
            Err(format!("path {} not exists", pathname))
        } else if path.is_file() {
            let file = File::new(pathname, chunk_size, process_pathname)?;
            let file = Self::File(file);
            Ok(file)
        } else if path.is_dir() {
            let directory = Directory::new(pathname, chunk_size, process_pathname)?;
            let directory = Self::Directory(directory);
            Ok(directory)
        } else {
            Err(format!("undefined type of {}", pathname))
        }
    }
}

impl Process for Path {
    fn process<Block, Digest>(&self, hash: &mut dyn HashContext<Block, Digest>) -> Result<(), String> {
        match self {
            Self::File(file) => file.process(hash),
            Self::Directory(directory) => directory.process(hash),
        }
    }
}
