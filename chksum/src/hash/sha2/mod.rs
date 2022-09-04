//! Implementation of SHA-2 hash function based on [FIPS PUB 180-4: Secure Hash Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).

#[cfg(feature = "sha2_224")]
pub mod sha224;
#[cfg(feature = "sha2_256")]
pub mod sha256;
#[cfg(feature = "sha2_384")]
pub mod sha384;
#[cfg(feature = "sha2_512")]
pub mod sha512;
