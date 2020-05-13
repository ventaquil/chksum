use std::str::FromStr;

pub mod md5;

pub trait Context {
    fn block_size(&self) -> usize;

    fn update(&mut self, data: Vec<u8>);

    fn finalize(&mut self);

    fn digest(&self) -> Vec<u8>;
}

#[derive(Copy, Clone, Debug)]
pub enum Hash {
    MD5,
}

impl FromStr for Hash {
    type Err = (); // fixme change this type

    fn from_str(s: &str) -> Result<Hash, ()> {
        match s {
            "MD5" => Ok(Hash::MD5),
            _ => Err(()),
        }
    }
}

impl Into<Box<dyn Context>> for Hash {
    fn into(self) -> Box<dyn Context> {
        Box::new(match self {
            Hash::MD5 => md5::new(),
        })
    }
}

pub fn hashes() -> Vec<&'static str> {
    vec![
        "MD5",
    ]
}
