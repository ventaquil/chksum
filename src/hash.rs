pub mod md5;

pub trait Data<T> {
    fn data(&self) -> T;
}

pub trait Digest {
    type Digest;

    fn digest(&self) -> Self::Digest;
}

pub trait Finalize {
    fn finalize(&mut self);
}

pub trait Hash<T>: Digest + Finalize + Reset + Update<T> {
    type Padding;
    
    fn processed(&self) -> usize;
}

pub trait Padding<T>: Data<Vec<T>> + Finalize + Reset + Update<T> {}

pub trait Reset {
    fn reset(&mut self);
}

pub trait Update<T> {
    fn update(&mut self, data: &[T]);
}
