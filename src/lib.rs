use std::cmp::min;
use std::collections::HashMap;
use std::thread;

pub mod hash;
use hash::{Context as HashContext, Hash, Process as _, md5, sha1};
pub mod io;
use io::Path;

pub fn new(chunk_size: usize, hash: hash::Hash, jobs: usize, pathnames: Vec<String>, process_pathnames: bool) -> Context {
    Context::new(chunk_size, hash, jobs, pathnames, process_pathnames)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Context {
    chunk_size: usize,
    hash: hash::Hash,
    jobs: usize,
    pathnames: Vec<String>,
    process_pathnames: bool,
}

impl Context {
    pub fn new(chunk_size: usize, hash: hash::Hash, jobs: usize, pathnames: Vec<String>, process_pathnames: bool) -> Context {
        Context {
            chunk_size,
            hash,
            jobs,
            pathnames,
            process_pathnames
        }
    }

    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    pub fn hash(&self) -> hash::Hash {
        self.hash
    }

    pub fn jobs(&self) -> usize {
        self.jobs
    }

    pub fn pathnames(&self) -> &Vec<String> {
        &self.pathnames
    }

    pub fn process_pathnames(&self) -> bool {
        self.process_pathnames
    }

    pub fn process(&self) -> thread::Result<HashMap<String, Result<String, String>>> {
        let mut digests = HashMap::new();

        for i in (0..self.pathnames.len()).step_by(self.jobs) {
            let j = min(i + self.jobs, self.pathnames.len());
            let mut threads: Vec<thread::JoinHandle<Result<_, String>>> = Vec::new();
            for pathname in &self.pathnames[i..j] {
                let chunk_size = self.chunk_size;
                let hash = self.hash;
                let process_pathnames = self.process_pathnames;
                let pathname = pathname.clone();
                let thread = thread::spawn(move || {
                    let path = Path::new(&pathname, chunk_size, process_pathnames)?;
                    let digest = match hash {
                        Hash::MD5 => {
                            let mut hash = md5::new();
                            path.process(&mut hash)?;
                            hash.digest()
                                .hex()
                        },
                        Hash::SHA1 => {
                            let mut hash = sha1::new();
                            path.process(&mut hash)?;
                            hash.digest()
                                .hex()
                        },
                    };
                    Ok(digest)
                });
                threads.push(thread);
            }

            for (j, thread) in threads.into_iter()
                                      .enumerate() {
                let pathname = self.pathnames[i + j].to_string();
                match thread.join()? {
                    Ok(digest) => digests.insert(pathname, Ok(digest)),
                    Err(error) => digests.insert(pathname, Err(error)),
                };
            }
        }

        Ok(digests)
    }
}
