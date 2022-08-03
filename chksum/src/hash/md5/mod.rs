//! Implementation of MD5 hash function based on [RFC 1321: The MD5 Message-Digest Algorithm](https://tools.ietf.org/html/rfc1321).

mod block;
mod digest;
mod hash;
mod padding;
mod state;

pub use digest::Digest;
pub use hash::Hash;
pub use state::State;
