use std::result::Result;

pub mod md5;
pub mod sha1;

pub trait Context<Block, Digest> {
    fn digest(&self) -> Digest;

    fn update(&mut self, data: &[u8]) -> usize;

    fn process_block(&mut self, block: &Block);

    fn finalize(&mut self);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Hash {
    MD5,
    SHA1,
}

pub trait Process {
    fn process<Block, Digest>(
        &self,
        hash: &mut dyn Context<Block, Digest>,
    ) -> Result<Digest, String>;
}
