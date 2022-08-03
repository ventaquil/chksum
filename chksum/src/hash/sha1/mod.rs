//! Implementation of SHA-1 hash function based on [RFC 3174: US Secure Hash Algorithm 1 (SHA1)](https://tools.ietf.org/html/rfc3174).

mod block;
mod digest;
mod hash;
mod padding;
mod state;

pub use digest::Digest;
pub use hash::Hash;
pub use state::State;
