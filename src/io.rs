use std::fs;
use std::io::{self, Read as _};
use std::path::MAIN_SEPARATOR as PATH_SEPARATOR;

use crate::hash::{self, Context as Hash, Process};

#[inline]
pub fn new(chunk_size: usize, with_pathnames: bool) -> Context {
    Context::new(chunk_size, with_pathnames)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Context {
    chunk_size: usize,
    with_pathnames: bool,
}

impl Context {
    #[inline]
    pub fn new(chunk_size: usize, with_pathnames: bool) -> Self {
        Self {
            chunk_size,
            with_pathnames,
        }
    }
}

impl Default for Context {
    #[inline]
    fn default() -> Self {
        Self {
            chunk_size: 512,
            with_pathnames: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Directory {
    context: Context,
    pathname: String,
}

impl Directory {
    #[inline]
    pub fn new(pathname: &str, context: Context) -> Result<Directory, io::Error> {
        fs::metadata(pathname).and_then(|metadata| {
            if metadata.file_type().is_dir() {
                Ok(Self {
                    context,
                    pathname: pathname.trim_end_matches(PATH_SEPARATOR).to_string(),
                })
            } else {
                Err(io::Error::new(io::ErrorKind::Other, "Not a directory"))
            }
        })
    }
}

impl Process<Directory, io::Error> for Hash {
    #[inline]
    fn update(&mut self, data: &Directory) -> Result<usize, io::Error> {
        let mut entries = fs::read_dir(&data.pathname)?.map(|result| result.map(|entry| entry.path())).collect::<Result<Vec<_>, io::Error>>()?;
        entries.sort();
        let mut processed = 0;
        if data.context.with_pathnames {
            processed += hash::Hash::update(self, data.pathname.as_bytes());
        }
        for entry in entries {
            let entry = entry.to_string_lossy(); // todo what with non-ASCII strings?
            let entry = Path::new(&entry, data.context)?;
            processed += Process::update(self, &entry)?;
        }
        Ok(processed)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct File {
    context: Context,
    pathname: String,
}

impl File {
    #[inline]
    pub fn new(pathname: &str, context: Context) -> Result<File, io::Error> {
        fs::metadata(pathname).and_then(|metadata| {
            if metadata.file_type().is_file() {
                Ok(Self {
                    context,
                    pathname: pathname.to_string(),
                })
            } else {
                Err(io::Error::new(io::ErrorKind::Other, "Not a file"))
            }
        })
    }
}

impl Process<File, io::Error> for Hash {
    #[inline]
    fn update(&mut self, data: &File) -> Result<usize, io::Error> {
        let mut file = fs::File::open(&data.pathname)?;
        let length = fs::metadata(&data.pathname).map(|metadata| metadata.len())? as usize;
        let mut processed = 0;
        if data.context.with_pathnames {
            processed += hash::Hash::update(self, data.pathname.as_bytes());
        }
        for _ in (0..length).step_by(data.context.chunk_size) {
            let mut buffer = vec![0; data.context.chunk_size];
            let read = file.read(&mut buffer)?;
            processed += hash::Hash::update(self, &buffer[..read]);
        }
        Ok(processed)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Path {
    Directory(Directory),
    File(File),
}

impl Path {
    #[inline]
    pub fn new(pathname: &str, context: Context) -> Result<Path, io::Error> {
        fs::metadata(pathname).and_then(|metadata| {
            let file_type = metadata.file_type();
            if file_type.is_dir() {
                let directory = Directory::new(pathname, context)?;
                let directory = Self::Directory(directory);
                Ok(directory)
            } else if file_type.is_file() {
                let file = File::new(pathname, context)?;
                let file = Self::File(file);
                Ok(file)
            } else {
                Err(io::Error::new(io::ErrorKind::Other, "Unknown type"))
            }
        })
    }
}

impl Process<Path, io::Error> for Hash {
    #[inline]
    fn update(&mut self, data: &Path) -> Result<usize, io::Error> {
        match data {
            Path::Directory(directory) => Process::<Directory, io::Error>::update(self, directory),
            Path::File(file) => Process::<File, io::Error>::update(self, file),
        }
    }
}
