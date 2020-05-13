pub mod hash;
pub mod io;

pub fn new(chunk_size: usize, hash: hash::Hash, jobs: usize, pathnames: Vec<String>, process_pathnames: bool) -> Context {
    Context {
        chunk_size: chunk_size,
        hash: hash,
        jobs: jobs,
        pathnames: pathnames,
        process_pathnames: process_pathnames
    }
}

#[derive(Debug)]
pub struct Context {
    pub chunk_size: usize,
    pub hash: hash::Hash,
    pub jobs: usize,
    pub pathnames: Vec<String>,
    pub process_pathnames: bool,
}
