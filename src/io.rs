use std::cmp::min;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use std::result::Result;

use super::hash::{Context as HashContext, Hash};

pub struct Processor {
    chunk_size: usize,
    hash: Hash,
    process_pathnames: bool,
}

impl Processor {
    pub fn new(chunk_size: usize, hash: Hash, process_pathnames: bool) -> Processor {
        Processor { chunk_size: chunk_size, hash: hash, process_pathnames: process_pathnames }
    }

    pub fn process(&self, path: &Path) -> Result<Vec<u8>, String> {
        let mut hash: Box<dyn HashContext> = self.hash.into();
        match self.process_path(&path, &mut hash) {
            Ok(_) => Ok(hash.digest()),
            Err(error) => Err(error),
        }
    }

    fn process_path(&self, path: &Path, hash: &mut Box<dyn HashContext>) -> Result<(), String> {
        if self.process_pathnames {
            let path = path.to_str().unwrap(); // fixme catch unwrap
            let path = path.as_bytes();
            let path: Vec<u8> = path.to_vec();
            hash.update(path);
        }

        if path.is_file() {
            self.process_file(path, hash)
        } else if path.is_dir() {
            self.process_directory(path, hash)
        } else {
            Err(String::from("Undefined type of path"))
        }
    }

    fn process_directory(&self, path: &Path, hash: &mut Box<dyn HashContext>) -> Result<(), String> {
        let mut entries = path.read_dir()
                              .unwrap() // fixme catch unwrap
                              .map(|entries| entries.map(|entry| entry.path()))
                              .collect::<Result<Vec<_>, io::Error>>()
                              .unwrap(); // fixme catch unwrap
        entries.sort();
        for entry in entries { // fixme catch unwrap
            let path = Path::new(&entry);
            self.process_path(&path, hash); // fixme use Result
        }

        Ok(())
    }

    fn process_file(&self, path: &Path, hash: &mut Box<dyn HashContext>) -> Result<(), String> {
        let mut file = File::open(path).unwrap(); // fixme catch unwrap
        let metadata = fs::metadata(path).unwrap(); // fixme catch unwrap
        let mut length: usize = metadata.len() as usize;
        loop {
            let buffer = min(self.chunk_size, length);
            length -= buffer;
            let mut buffer = vec![0; buffer];
            file.read(&mut buffer).unwrap(); // fixme catch unwrap
            hash.update(buffer);

            if length == 0 {
                break;
            }
        }

        Ok(())
    }
}
