pub mod hash;
use hash::{Context as Hash, Hash as _};
pub mod io;
use io::{Context as IO, Path};

#[inline]
pub fn new(hash: Hash, io: IO) -> Context {
    Context::new(hash, io)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Context {
    hash: Hash,
    io: IO,
}

impl Context {
    #[inline]
    pub fn new(hash: Hash, io: IO) -> Context {
        Context {
            hash,
            io,
        }
    }

    #[inline]
    pub fn chksum(&self, pathname: &str) -> Result<String, std::io::Error> {
        let path = Path::new(pathname, self.io)?;
        let mut hash = self.hash.clone();
        hash::Process::update(&mut hash, &path)?;
        Ok(hash.digest())
    }
}
