pub mod md5;
pub mod sha1;

pub trait Digest {
    type Digest;

    fn digest(&mut self) -> Self::Digest;
}

pub trait Hash<T>: Digest + Reset + Update<T> {}

pub trait Reset {
    fn reset(&mut self);
}

pub trait ToHex {
    fn to_hex(&self) -> String;
}

pub trait Update<T> {
    fn update(&mut self, data: &[T]);
}
