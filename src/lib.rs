use std::cmp::min;
use std::collections::HashMap;
use std::thread;

pub mod hash;
use hash::{md5, sha1, Context as HashContext, Hash, Process as _};
pub mod io;
use io::{Context as IOContext, Path};

#[inline]
pub fn new(hash: hash::Hash, io: IOContext, jobs: usize, pathnames: Vec<String>) -> Context {
    Context::new(hash, io, jobs, pathnames)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Context {
    hash: hash::Hash,
    io: IOContext,
    jobs: usize,
    pathnames: Vec<String>,
}

impl Context {
    #[inline]
    pub fn new(hash: hash::Hash, io: IOContext, jobs: usize, pathnames: Vec<String>) -> Context {
        Context {
            hash,
            io,
            jobs,
            pathnames,
        }
    }

    #[inline]
    pub fn hash(&self) -> hash::Hash {
        self.hash
    }

    #[inline]
    pub fn io(&self) -> IOContext {
        self.io
    }

    #[inline]
    pub fn jobs(&self) -> usize {
        self.jobs
    }

    #[inline]
    pub fn pathnames(&self) -> &Vec<String> {
        &self.pathnames
    }

    #[inline]
    pub fn process(&self) -> thread::Result<HashMap<String, Result<String, String>>> {
        let mut digests = HashMap::new();

        for i in (0..self.pathnames.len()).step_by(self.jobs) {
            let j = min(i + self.jobs, self.pathnames.len());
            let mut threads: Vec<thread::JoinHandle<Result<_, String>>> = Vec::new();
            for pathname in &self.pathnames[i..j] {
                let hash = self.hash;
                let io = self.io;
                let pathname = pathname.clone();
                let thread = thread::spawn(move || {
                    let path = Path::new(&pathname, io)?;
                    let digest = match hash {
                        Hash::MD5 => {
                            let mut hash = md5::new();
                            path.process(&mut hash)?;
                            hash.digest().hex()
                        }
                        Hash::SHA1 => {
                            let mut hash = sha1::new();
                            path.process(&mut hash)?;
                            hash.digest().hex()
                        }
                    };
                    Ok(digest)
                });
                threads.push(thread);
            }

            for (j, thread) in threads.into_iter().enumerate() {
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
