const ALPHABET: &'static str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Default data sizes.
#[derive(Debug, Eq, PartialEq)]
#[rustfmt::skip]
pub enum Size {
    Empty  =      0,
    Tiny   =      8,
    Small  =     64,
    Medium =    512,
    Big    =  4_096,
    Huge   = 32_768,
}

/// Generate data of given size.
pub fn data_with_size(size: usize) -> Vec<u8> {
    ALPHABET.as_bytes().iter().cloned().cycle().take(size).collect()
}
