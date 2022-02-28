//! Implementation of SHA-1 hash function based on [RFC 3174: US Secure Hash Algorithm 1 (SHA1)](https://tools.ietf.org/html/rfc3174).
//!
//! # Examples
//!
//! ```rust
//! use chksum_hash::sha1::State;
//!
//! let mut state = State::<u32>::new();
//! assert_eq!(
//!     state.digest(),
//!     [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
//! );
//! let data = [
//!     u32::from_be_bytes([0x80, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//! ];
//! state.update(data);
//! assert_eq!(
//!     state.digest(),
//!     [0xDA39A3EE, 0x5E6B4B0D, 0x3255BFEF, 0x95601890, 0xAFD80709]
//! );
//! ```
//!
//! ```rust
//! use chksum_hash::sha1::State;
//!
//! let mut state = State::<u32>::new();
//! assert_eq!(
//!     state.digest(),
//!     [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
//! );
//! let data = [
//!     u32::from_be_bytes([0x31, 0x32, 0x33, 0x34]),
//!     u32::from_be_bytes([0x35, 0x36, 0x37, 0x38]),
//!     u32::from_be_bytes([0x39, 0x30, 0x31, 0x32]),
//!     u32::from_be_bytes([0x33, 0x34, 0x35, 0x36]),
//!     u32::from_be_bytes([0x37, 0x38, 0x39, 0x30]),
//!     u32::from_be_bytes([0x31, 0x32, 0x33, 0x34]),
//!     u32::from_be_bytes([0x35, 0x36, 0x37, 0x38]),
//!     u32::from_be_bytes([0x39, 0x30, 0x31, 0x32]),
//!     u32::from_be_bytes([0x33, 0x34, 0x35, 0x36]),
//!     u32::from_be_bytes([0x37, 0x38, 0x39, 0x30]),
//!     u32::from_be_bytes([0x31, 0x32, 0x33, 0x34]),
//!     u32::from_be_bytes([0x35, 0x36, 0x37, 0x38]),
//!     u32::from_be_bytes([0x39, 0x30, 0x31, 0x32]),
//!     u32::from_be_bytes([0x33, 0x34, 0x35, 0x36]),
//!     u32::from_be_bytes([0x37, 0x38, 0x39, 0x30]),
//!     u32::from_be_bytes([0x31, 0x32, 0x33, 0x34]),
//! ];
//! state.update(data);
//! let data = [
//!     u32::from_be_bytes([0x35, 0x36, 0x37, 0x38]),
//!     u32::from_be_bytes([0x39, 0x30, 0x31, 0x32]),
//!     u32::from_be_bytes([0x33, 0x34, 0x35, 0x36]),
//!     u32::from_be_bytes([0x37, 0x38, 0x39, 0x30]),
//!     u32::from_be_bytes([0x80, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x02, 0x80]),
//! ];
//! state.update(data);
//! assert_eq!(
//!     state.digest(),
//!     [0x50ABF570, 0x6A150990, 0xA08B2C5E, 0xA40FA0E5, 0x85554732]
//! );
//! ```

#[cfg(not(feature = "std"))]
use core::fmt::{self, Debug, Formatter};
#[cfg(not(feature = "std"))]
use core::ops::{BitAnd, BitOr, BitXor, Not, Shl, Shr};
#[cfg(feature = "std")]
use std::fmt::{self, Debug, Formatter};
#[cfg(feature = "std")]
use std::ops::{BitAnd, BitOr, BitXor, Not, Shl, Shr};

#[cfg(feature = "std")]
use chksum_arch::Arch;
#[cfg(feature = "std")]
use chksum_traits::convert::{From1, FromBeBytes, ToBeBytes};
use chksum_traits::num::WrappingAdd;

#[cfg(feature = "std")]
use super::DigestError;

pub const BLOCK_LENGTH_BITS: usize = 512;
pub const BLOCK_LENGTH_BYTES: usize = BLOCK_LENGTH_BITS / 8;
pub const BLOCK_LENGTH_WORDS: usize = BLOCK_LENGTH_BYTES / 2;
pub const BLOCK_LENGTH_DWORDS: usize = BLOCK_LENGTH_WORDS / 2;

pub const DIGEST_LENGTH_BITS: usize = 160;
pub const DIGEST_LENGTH_BYTES: usize = DIGEST_LENGTH_BITS / 8;
pub const DIGEST_LENGTH_WORDS: usize = DIGEST_LENGTH_BYTES / 2;
pub const DIGEST_LENGTH_DWORDS: usize = DIGEST_LENGTH_WORDS / 2;
pub const DIGEST_LENGTH_HEX: usize = DIGEST_LENGTH_BYTES * 2;

#[allow(clippy::unreadable_literal)]
const A: u32 = 0x67452301;
#[allow(clippy::unreadable_literal)]
const B: u32 = 0xEFCDAB89;
#[allow(clippy::unreadable_literal)]
const C: u32 = 0x98BADCFE;
#[allow(clippy::unreadable_literal)]
const D: u32 = 0x10325476;
#[allow(clippy::unreadable_literal)]
const E: u32 = 0xC3D2E1F0;

#[allow(clippy::unreadable_literal)]
const CONSTS: [u32; 4] = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6];

#[allow(clippy::unreadable_literal)]
const SHIFTS: [u32; 6] = [0x01, 0x1F, 0x05, 0x1B, 0x1E, 0x02];

#[cfg(feature = "std")]
const PADDING: [u8; BLOCK_LENGTH_BYTES] = [
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[cfg_attr(docsrs, doc(hidden))]
pub trait FFunc: BitAnd<Output = Self> + BitOr<Output = Self> + Copy + Not<Output = Self> {}

impl<T> FFunc for T where T: BitAnd<Output = Self> + BitOr<Output = Self> + Copy + Not<Output = Self> {}

#[cfg_attr(docsrs, doc(hidden))]
pub trait FFFunc: FFunc + Shl<Output = Self> + Shr<Output = Self> + WrappingAdd<Output = Self> {}

impl<T> FFFunc for T where T: FFunc + Shl<Output = Self> + Shr<Output = Self> + WrappingAdd<Output = Self> {}

#[cfg_attr(docsrs, doc(hidden))]
pub trait GFunc: BitXor<Output = Self> + Sized {}

impl<T> GFunc for T where T: BitXor<Output = Self> + Sized {}

#[cfg_attr(docsrs, doc(hidden))]
pub trait GGFunc:
    BitOr<Output = Self> + GFunc + Copy + Shl<Output = Self> + Shr<Output = Self> + WrappingAdd<Output = Self>
{
}

impl<T> GGFunc for T where
    T: BitOr<Output = Self> + GFunc + Copy + Shl<Output = Self> + Shr<Output = Self> + WrappingAdd<Output = Self>
{
}

#[cfg_attr(docsrs, doc(hidden))]
pub trait HFunc: BitAnd<Output = Self> + BitOr<Output = Self> + Copy {}

impl<T> HFunc for T where T: BitAnd<Output = Self> + BitOr<Output = Self> + Copy {}

#[cfg_attr(docsrs, doc(hidden))]
pub trait HHFunc: HFunc + Shl<Output = Self> + Shr<Output = Self> + WrappingAdd<Output = Self> {}

impl<T> HHFunc for T where T: HFunc + Shl<Output = Self> + Shr<Output = Self> + WrappingAdd<Output = Self> {}

#[cfg_attr(docsrs, doc(hidden))]
pub trait IFunc: BitXor<Output = Self> + Sized {}

impl<T> IFunc for T where T: BitXor<Output = Self> + Sized {}

#[cfg_attr(docsrs, doc(hidden))]
pub trait IIFunc:
    BitOr<Output = Self> + IFunc + Copy + Shl<Output = Self> + Shr<Output = Self> + WrappingAdd<Output = Self>
{
}

impl<T> IIFunc for T where
    T: BitOr<Output = Self> + IFunc + Copy + Shl<Output = Self> + Shr<Output = Self> + WrappingAdd<Output = Self>
{
}

/// Low-level struct for manual manipulation of hash state.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct State<T> {
    a: T,
    b: T,
    c: T,
    d: T,
    e: T,
    consts: [T; 4],
    shifts: [T; 6],
}

impl<T> State<T>
where
    T: FFFunc + GGFunc + HHFunc + IIFunc + From<u32>,
{
    /// Create new state instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum_hash::sha1::State;
    ///
    /// let state = State::<u32>::new();
    /// ```
    #[cfg_attr(not(debug_assertions), inline(always))]
    #[must_use]
    pub fn new() -> Self {
        Self::from_raw(T::from(A), T::from(B), T::from(C), T::from(D), T::from(E))
    }

    #[allow(clippy::many_single_char_names)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    #[must_use]
    pub fn from_raw(a: T, b: T, c: T, d: T, e: T) -> Self {
        Self {
            a, b, c, d, e,
            consts: [
                T::from(CONSTS[0]),
                T::from(CONSTS[1]),
                T::from(CONSTS[2]),
                T::from(CONSTS[3]),
            ],
            shifts: [
                T::from(SHIFTS[0]),
                T::from(SHIFTS[1]),
                T::from(SHIFTS[2]),
                T::from(SHIFTS[3]),
                T::from(SHIFTS[4]),
                T::from(SHIFTS[5]),
            ],
        }
    }

    /// Update state with block of data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum_hash::sha1::State;
    ///
    /// let mut state = State::<u32>::new();
    /// let data = [0x00; 16];
    /// state.update(data);
    /// ```
    #[allow(
        clippy::items_after_statements,
        clippy::too_many_lines,
        clippy::shadow_unrelated,
        clippy::many_single_char_names,
    )]
    #[cfg_attr(nightly, optimize(speed))]
    pub fn update(&mut self, block: [T; BLOCK_LENGTH_DWORDS]) {
        let mut block = [
            block[0x0], block[0x1], block[0x2], block[0x3],
            block[0x4], block[0x5], block[0x6], block[0x7],
            block[0x8], block[0x9], block[0xA], block[0xB],
            block[0xC], block[0xD], block[0xE], block[0xF],
            T::from(0), T::from(0), T::from(0), T::from(0),
            T::from(0), T::from(0), T::from(0), T::from(0),
            T::from(0), T::from(0), T::from(0), T::from(0),
            T::from(0), T::from(0), T::from(0), T::from(0),
            T::from(0), T::from(0), T::from(0), T::from(0),
            T::from(0), T::from(0), T::from(0), T::from(0),
            T::from(0), T::from(0), T::from(0), T::from(0),
            T::from(0), T::from(0), T::from(0), T::from(0),
            T::from(0), T::from(0), T::from(0), T::from(0),
            T::from(0), T::from(0), T::from(0), T::from(0),
            T::from(0), T::from(0), T::from(0), T::from(0),
            T::from(0), T::from(0), T::from(0), T::from(0),
            T::from(0), T::from(0), T::from(0), T::from(0),
            T::from(0), T::from(0), T::from(0), T::from(0),
            T::from(0), T::from(0), T::from(0), T::from(0),
            T::from(0), T::from(0), T::from(0), T::from(0),
        ];
        block[16] = block[13] ^ block[8] ^ block[2] ^ block[0];
        block[16] = (block[16] << self.shifts[0]) | (block[16] >> self.shifts[1]);
        block[17] = block[14] ^ block[9] ^ block[3] ^ block[1];
        block[17] = (block[17] << self.shifts[0]) | (block[17] >> self.shifts[1]);
        block[18] = block[15] ^ block[10] ^ block[4] ^ block[2];
        block[18] = (block[18] << self.shifts[0]) | (block[18] >> self.shifts[1]);
        block[19] = block[16] ^ block[11] ^ block[5] ^ block[3];
        block[19] = (block[19] << self.shifts[0]) | (block[19] >> self.shifts[1]);
        block[20] = block[17] ^ block[12] ^ block[6] ^ block[4];
        block[20] = (block[20] << self.shifts[0]) | (block[20] >> self.shifts[1]);
        block[21] = block[18] ^ block[13] ^ block[7] ^ block[5];
        block[21] = (block[21] << self.shifts[0]) | (block[21] >> self.shifts[1]);
        block[22] = block[19] ^ block[14] ^ block[8] ^ block[6];
        block[22] = (block[22] << self.shifts[0]) | (block[22] >> self.shifts[1]);
        block[23] = block[20] ^ block[15] ^ block[9] ^ block[7];
        block[23] = (block[23] << self.shifts[0]) | (block[23] >> self.shifts[1]);
        block[24] = block[21] ^ block[16] ^ block[10] ^ block[8];
        block[24] = (block[24] << self.shifts[0]) | (block[24] >> self.shifts[1]);
        block[25] = block[22] ^ block[17] ^ block[11] ^ block[9];
        block[25] = (block[25] << self.shifts[0]) | (block[25] >> self.shifts[1]);
        block[26] = block[23] ^ block[18] ^ block[12] ^ block[10];
        block[26] = (block[26] << self.shifts[0]) | (block[26] >> self.shifts[1]);
        block[27] = block[24] ^ block[19] ^ block[13] ^ block[11];
        block[27] = (block[27] << self.shifts[0]) | (block[27] >> self.shifts[1]);
        block[28] = block[25] ^ block[20] ^ block[14] ^ block[12];
        block[28] = (block[28] << self.shifts[0]) | (block[28] >> self.shifts[1]);
        block[29] = block[26] ^ block[21] ^ block[15] ^ block[13];
        block[29] = (block[29] << self.shifts[0]) | (block[29] >> self.shifts[1]);
        block[30] = block[27] ^ block[22] ^ block[16] ^ block[14];
        block[30] = (block[30] << self.shifts[0]) | (block[30] >> self.shifts[1]);
        block[31] = block[28] ^ block[23] ^ block[17] ^ block[15];
        block[31] = (block[31] << self.shifts[0]) | (block[31] >> self.shifts[1]);
        block[32] = block[29] ^ block[24] ^ block[18] ^ block[16];
        block[32] = (block[32] << self.shifts[0]) | (block[32] >> self.shifts[1]);
        block[33] = block[30] ^ block[25] ^ block[19] ^ block[17];
        block[33] = (block[33] << self.shifts[0]) | (block[33] >> self.shifts[1]);
        block[34] = block[31] ^ block[26] ^ block[20] ^ block[18];
        block[34] = (block[34] << self.shifts[0]) | (block[34] >> self.shifts[1]);
        block[35] = block[32] ^ block[27] ^ block[21] ^ block[19];
        block[35] = (block[35] << self.shifts[0]) | (block[35] >> self.shifts[1]);
        block[36] = block[33] ^ block[28] ^ block[22] ^ block[20];
        block[36] = (block[36] << self.shifts[0]) | (block[36] >> self.shifts[1]);
        block[37] = block[34] ^ block[29] ^ block[23] ^ block[21];
        block[37] = (block[37] << self.shifts[0]) | (block[37] >> self.shifts[1]);
        block[38] = block[35] ^ block[30] ^ block[24] ^ block[22];
        block[38] = (block[38] << self.shifts[0]) | (block[38] >> self.shifts[1]);
        block[39] = block[36] ^ block[31] ^ block[25] ^ block[23];
        block[39] = (block[39] << self.shifts[0]) | (block[39] >> self.shifts[1]);
        block[40] = block[37] ^ block[32] ^ block[26] ^ block[24];
        block[40] = (block[40] << self.shifts[0]) | (block[40] >> self.shifts[1]);
        block[41] = block[38] ^ block[33] ^ block[27] ^ block[25];
        block[41] = (block[41] << self.shifts[0]) | (block[41] >> self.shifts[1]);
        block[42] = block[39] ^ block[34] ^ block[28] ^ block[26];
        block[42] = (block[42] << self.shifts[0]) | (block[42] >> self.shifts[1]);
        block[43] = block[40] ^ block[35] ^ block[29] ^ block[27];
        block[43] = (block[43] << self.shifts[0]) | (block[43] >> self.shifts[1]);
        block[44] = block[41] ^ block[36] ^ block[30] ^ block[28];
        block[44] = (block[44] << self.shifts[0]) | (block[44] >> self.shifts[1]);
        block[45] = block[42] ^ block[37] ^ block[31] ^ block[29];
        block[45] = (block[45] << self.shifts[0]) | (block[45] >> self.shifts[1]);
        block[46] = block[43] ^ block[38] ^ block[32] ^ block[30];
        block[46] = (block[46] << self.shifts[0]) | (block[46] >> self.shifts[1]);
        block[47] = block[44] ^ block[39] ^ block[33] ^ block[31];
        block[47] = (block[47] << self.shifts[0]) | (block[47] >> self.shifts[1]);
        block[48] = block[45] ^ block[40] ^ block[34] ^ block[32];
        block[48] = (block[48] << self.shifts[0]) | (block[48] >> self.shifts[1]);
        block[49] = block[46] ^ block[41] ^ block[35] ^ block[33];
        block[49] = (block[49] << self.shifts[0]) | (block[49] >> self.shifts[1]);
        block[50] = block[47] ^ block[42] ^ block[36] ^ block[34];
        block[50] = (block[50] << self.shifts[0]) | (block[50] >> self.shifts[1]);
        block[51] = block[48] ^ block[43] ^ block[37] ^ block[35];
        block[51] = (block[51] << self.shifts[0]) | (block[51] >> self.shifts[1]);
        block[52] = block[49] ^ block[44] ^ block[38] ^ block[36];
        block[52] = (block[52] << self.shifts[0]) | (block[52] >> self.shifts[1]);
        block[53] = block[50] ^ block[45] ^ block[39] ^ block[37];
        block[53] = (block[53] << self.shifts[0]) | (block[53] >> self.shifts[1]);
        block[54] = block[51] ^ block[46] ^ block[40] ^ block[38];
        block[54] = (block[54] << self.shifts[0]) | (block[54] >> self.shifts[1]);
        block[55] = block[52] ^ block[47] ^ block[41] ^ block[39];
        block[55] = (block[55] << self.shifts[0]) | (block[55] >> self.shifts[1]);
        block[56] = block[53] ^ block[48] ^ block[42] ^ block[40];
        block[56] = (block[56] << self.shifts[0]) | (block[56] >> self.shifts[1]);
        block[57] = block[54] ^ block[49] ^ block[43] ^ block[41];
        block[57] = (block[57] << self.shifts[0]) | (block[57] >> self.shifts[1]);
        block[58] = block[55] ^ block[50] ^ block[44] ^ block[42];
        block[58] = (block[58] << self.shifts[0]) | (block[58] >> self.shifts[1]);
        block[59] = block[56] ^ block[51] ^ block[45] ^ block[43];
        block[59] = (block[59] << self.shifts[0]) | (block[59] >> self.shifts[1]);
        block[60] = block[57] ^ block[52] ^ block[46] ^ block[44];
        block[60] = (block[60] << self.shifts[0]) | (block[60] >> self.shifts[1]);
        block[61] = block[58] ^ block[53] ^ block[47] ^ block[45];
        block[61] = (block[61] << self.shifts[0]) | (block[61] >> self.shifts[1]);
        block[62] = block[59] ^ block[54] ^ block[48] ^ block[46];
        block[62] = (block[62] << self.shifts[0]) | (block[62] >> self.shifts[1]);
        block[63] = block[60] ^ block[55] ^ block[49] ^ block[47];
        block[63] = (block[63] << self.shifts[0]) | (block[63] >> self.shifts[1]);
        block[64] = block[61] ^ block[56] ^ block[50] ^ block[48];
        block[64] = (block[64] << self.shifts[0]) | (block[64] >> self.shifts[1]);
        block[65] = block[62] ^ block[57] ^ block[51] ^ block[49];
        block[65] = (block[65] << self.shifts[0]) | (block[65] >> self.shifts[1]);
        block[66] = block[63] ^ block[58] ^ block[52] ^ block[50];
        block[66] = (block[66] << self.shifts[0]) | (block[66] >> self.shifts[1]);
        block[67] = block[64] ^ block[59] ^ block[53] ^ block[51];
        block[67] = (block[67] << self.shifts[0]) | (block[67] >> self.shifts[1]);
        block[68] = block[65] ^ block[60] ^ block[54] ^ block[52];
        block[68] = (block[68] << self.shifts[0]) | (block[68] >> self.shifts[1]);
        block[69] = block[66] ^ block[61] ^ block[55] ^ block[53];
        block[69] = (block[69] << self.shifts[0]) | (block[69] >> self.shifts[1]);
        block[70] = block[67] ^ block[62] ^ block[56] ^ block[54];
        block[70] = (block[70] << self.shifts[0]) | (block[70] >> self.shifts[1]);
        block[71] = block[68] ^ block[63] ^ block[57] ^ block[55];
        block[71] = (block[71] << self.shifts[0]) | (block[71] >> self.shifts[1]);
        block[72] = block[69] ^ block[64] ^ block[58] ^ block[56];
        block[72] = (block[72] << self.shifts[0]) | (block[72] >> self.shifts[1]);
        block[73] = block[70] ^ block[65] ^ block[59] ^ block[57];
        block[73] = (block[73] << self.shifts[0]) | (block[73] >> self.shifts[1]);
        block[74] = block[71] ^ block[66] ^ block[60] ^ block[58];
        block[74] = (block[74] << self.shifts[0]) | (block[74] >> self.shifts[1]);
        block[75] = block[72] ^ block[67] ^ block[61] ^ block[59];
        block[75] = (block[75] << self.shifts[0]) | (block[75] >> self.shifts[1]);
        block[76] = block[73] ^ block[68] ^ block[62] ^ block[60];
        block[76] = (block[76] << self.shifts[0]) | (block[76] >> self.shifts[1]);
        block[77] = block[74] ^ block[69] ^ block[63] ^ block[61];
        block[77] = (block[77] << self.shifts[0]) | (block[77] >> self.shifts[1]);
        block[78] = block[75] ^ block[70] ^ block[64] ^ block[62];
        block[78] = (block[78] << self.shifts[0]) | (block[78] >> self.shifts[1]);
        block[79] = block[76] ^ block[71] ^ block[65] ^ block[63];
        block[79] = (block[79] << self.shifts[0]) | (block[79] >> self.shifts[1]);

        let (a, b, c, d, e) = (self.a, self.b, self.c, self.d, self.e);

        // Step 1

        #[cfg_attr(not(debug_assertions), inline(always))]
        fn f<T>(x: T, y: T, z: T) -> T
        where
            T: FFunc,
        {
            (x & y) | (!x & z)
        }

        #[allow(clippy::similar_names, clippy::many_single_char_names, clippy::too_many_arguments)]
        #[cfg_attr(not(debug_assertions), inline(always))]
        fn ff<T>(a: T, b: T, c: T, d: T, e: T, data: T, shl: T, shr: T, constant: T) -> T
        where
            T: FFFunc,
        {
            ((a << shl) | (a >> shr))
                .wrapping_add(f(b, c, d))
                .wrapping_add(e)
                .wrapping_add(data)
                .wrapping_add(constant)
        }

        let (a, b, c, d, e) = (
            ff(a, b, c, d, e, block[0], self.shifts[2], self.shifts[3], self.consts[0]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ff(a, b, c, d, e, block[1], self.shifts[2], self.shifts[3], self.consts[0]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ff(a, b, c, d, e, block[2], self.shifts[2], self.shifts[3], self.consts[0]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ff(a, b, c, d, e, block[3], self.shifts[2], self.shifts[3], self.consts[0]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ff(a, b, c, d, e, block[4], self.shifts[2], self.shifts[3], self.consts[0]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ff(a, b, c, d, e, block[5], self.shifts[2], self.shifts[3], self.consts[0]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ff(a, b, c, d, e, block[6], self.shifts[2], self.shifts[3], self.consts[0]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ff(a, b, c, d, e, block[7], self.shifts[2], self.shifts[3], self.consts[0]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ff(a, b, c, d, e, block[8], self.shifts[2], self.shifts[3], self.consts[0]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ff(a, b, c, d, e, block[9], self.shifts[2], self.shifts[3], self.consts[0]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ff(a, b, c, d, e, block[10], self.shifts[2], self.shifts[3], self.consts[0]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ff(a, b, c, d, e, block[11], self.shifts[2], self.shifts[3], self.consts[0]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ff(a, b, c, d, e, block[12], self.shifts[2], self.shifts[3], self.consts[0]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ff(a, b, c, d, e, block[13], self.shifts[2], self.shifts[3], self.consts[0]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ff(a, b, c, d, e, block[14], self.shifts[2], self.shifts[3], self.consts[0]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ff(a, b, c, d, e, block[15], self.shifts[2], self.shifts[3], self.consts[0]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ff(a, b, c, d, e, block[16], self.shifts[2], self.shifts[3], self.consts[0]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ff(a, b, c, d, e, block[17], self.shifts[2], self.shifts[3], self.consts[0]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ff(a, b, c, d, e, block[18], self.shifts[2], self.shifts[3], self.consts[0]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ff(a, b, c, d, e, block[19], self.shifts[2], self.shifts[3], self.consts[0]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );

        // Step 2

        #[cfg_attr(not(debug_assertions), inline(always))]
        fn g<T>(x: T, y: T, z: T) -> T
        where
            T: GFunc,
        {
            x ^ y ^ z
        }

        #[allow(clippy::similar_names, clippy::many_single_char_names, clippy::too_many_arguments)]
        #[cfg_attr(not(debug_assertions), inline(always))]
        fn gg<T>(a: T, b: T, c: T, d: T, e: T, data: T, shl: T, shr: T, constant: T) -> T
        where
            T: GGFunc,
        {
            ((a << shl) | (a >> shr))
                .wrapping_add(g(b, c, d))
                .wrapping_add(e)
                .wrapping_add(data)
                .wrapping_add(constant)
        }

        let (a, b, c, d, e) = (
            gg(a, b, c, d, e, block[20], self.shifts[2], self.shifts[3], self.consts[1]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            gg(a, b, c, d, e, block[21], self.shifts[2], self.shifts[3], self.consts[1]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            gg(a, b, c, d, e, block[22], self.shifts[2], self.shifts[3], self.consts[1]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            gg(a, b, c, d, e, block[23], self.shifts[2], self.shifts[3], self.consts[1]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            gg(a, b, c, d, e, block[24], self.shifts[2], self.shifts[3], self.consts[1]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            gg(a, b, c, d, e, block[25], self.shifts[2], self.shifts[3], self.consts[1]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            gg(a, b, c, d, e, block[26], self.shifts[2], self.shifts[3], self.consts[1]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            gg(a, b, c, d, e, block[27], self.shifts[2], self.shifts[3], self.consts[1]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            gg(a, b, c, d, e, block[28], self.shifts[2], self.shifts[3], self.consts[1]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            gg(a, b, c, d, e, block[29], self.shifts[2], self.shifts[3], self.consts[1]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            gg(a, b, c, d, e, block[30], self.shifts[2], self.shifts[3], self.consts[1]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            gg(a, b, c, d, e, block[31], self.shifts[2], self.shifts[3], self.consts[1]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            gg(a, b, c, d, e, block[32], self.shifts[2], self.shifts[3], self.consts[1]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            gg(a, b, c, d, e, block[33], self.shifts[2], self.shifts[3], self.consts[1]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            gg(a, b, c, d, e, block[34], self.shifts[2], self.shifts[3], self.consts[1]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            gg(a, b, c, d, e, block[35], self.shifts[2], self.shifts[3], self.consts[1]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            gg(a, b, c, d, e, block[36], self.shifts[2], self.shifts[3], self.consts[1]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            gg(a, b, c, d, e, block[37], self.shifts[2], self.shifts[3], self.consts[1]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            gg(a, b, c, d, e, block[38], self.shifts[2], self.shifts[3], self.consts[1]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            gg(a, b, c, d, e, block[39], self.shifts[2], self.shifts[3], self.consts[1]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );

        // Step 3

        #[cfg_attr(not(debug_assertions), inline(always))]
        fn h<T>(x: T, y: T, z: T) -> T
        where
            T: HFunc,
        {
            (x & y) | (x & z) | (y & z)
        }

        #[allow(clippy::similar_names, clippy::many_single_char_names, clippy::too_many_arguments)]
        #[cfg_attr(not(debug_assertions), inline(always))]
        fn hh<T>(a: T, b: T, c: T, d: T, e: T, data: T, shl: T, shr: T, constant: T) -> T
        where
            T: HHFunc,
        {
            ((a << shl) | (a >> shr))
                .wrapping_add(h(b, c, d))
                .wrapping_add(e)
                .wrapping_add(data)
                .wrapping_add(constant)
        }

        let (a, b, c, d, e) = (
            hh(a, b, c, d, e, block[40], self.shifts[2], self.shifts[3], self.consts[2]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            hh(a, b, c, d, e, block[41], self.shifts[2], self.shifts[3], self.consts[2]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            hh(a, b, c, d, e, block[42], self.shifts[2], self.shifts[3], self.consts[2]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            hh(a, b, c, d, e, block[43], self.shifts[2], self.shifts[3], self.consts[2]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            hh(a, b, c, d, e, block[44], self.shifts[2], self.shifts[3], self.consts[2]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            hh(a, b, c, d, e, block[45], self.shifts[2], self.shifts[3], self.consts[2]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            hh(a, b, c, d, e, block[46], self.shifts[2], self.shifts[3], self.consts[2]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            hh(a, b, c, d, e, block[47], self.shifts[2], self.shifts[3], self.consts[2]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            hh(a, b, c, d, e, block[48], self.shifts[2], self.shifts[3], self.consts[2]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            hh(a, b, c, d, e, block[49], self.shifts[2], self.shifts[3], self.consts[2]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            hh(a, b, c, d, e, block[50], self.shifts[2], self.shifts[3], self.consts[2]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            hh(a, b, c, d, e, block[51], self.shifts[2], self.shifts[3], self.consts[2]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            hh(a, b, c, d, e, block[52], self.shifts[2], self.shifts[3], self.consts[2]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            hh(a, b, c, d, e, block[53], self.shifts[2], self.shifts[3], self.consts[2]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            hh(a, b, c, d, e, block[54], self.shifts[2], self.shifts[3], self.consts[2]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            hh(a, b, c, d, e, block[55], self.shifts[2], self.shifts[3], self.consts[2]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            hh(a, b, c, d, e, block[56], self.shifts[2], self.shifts[3], self.consts[2]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            hh(a, b, c, d, e, block[57], self.shifts[2], self.shifts[3], self.consts[2]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            hh(a, b, c, d, e, block[58], self.shifts[2], self.shifts[3], self.consts[2]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            hh(a, b, c, d, e, block[59], self.shifts[2], self.shifts[3], self.consts[2]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );

        // Step 4

        #[cfg_attr(not(debug_assertions), inline(always))]
        fn i<T>(x: T, y: T, z: T) -> T
        where
            T: IFunc,
        {
            x ^ y ^ z
        }

        #[allow(clippy::similar_names, clippy::many_single_char_names, clippy::too_many_arguments)]
        #[cfg_attr(not(debug_assertions), inline(always))]
        fn ii<T>(a: T, b: T, c: T, d: T, e: T, data: T, shl: T, shr: T, constant: T) -> T
        where
            T: IIFunc,
        {
            ((a << shl) | (a >> shr))
                .wrapping_add(i(b, c, d))
                .wrapping_add(e)
                .wrapping_add(data)
                .wrapping_add(constant)
        }

        let (a, b, c, d, e) = (
            ii(a, b, c, d, e, block[60], self.shifts[2], self.shifts[3], self.consts[3]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ii(a, b, c, d, e, block[61], self.shifts[2], self.shifts[3], self.consts[3]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ii(a, b, c, d, e, block[62], self.shifts[2], self.shifts[3], self.consts[3]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ii(a, b, c, d, e, block[63], self.shifts[2], self.shifts[3], self.consts[3]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ii(a, b, c, d, e, block[64], self.shifts[2], self.shifts[3], self.consts[3]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ii(a, b, c, d, e, block[65], self.shifts[2], self.shifts[3], self.consts[3]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ii(a, b, c, d, e, block[66], self.shifts[2], self.shifts[3], self.consts[3]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ii(a, b, c, d, e, block[67], self.shifts[2], self.shifts[3], self.consts[3]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ii(a, b, c, d, e, block[68], self.shifts[2], self.shifts[3], self.consts[3]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ii(a, b, c, d, e, block[69], self.shifts[2], self.shifts[3], self.consts[3]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ii(a, b, c, d, e, block[70], self.shifts[2], self.shifts[3], self.consts[3]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ii(a, b, c, d, e, block[71], self.shifts[2], self.shifts[3], self.consts[3]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ii(a, b, c, d, e, block[72], self.shifts[2], self.shifts[3], self.consts[3]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ii(a, b, c, d, e, block[73], self.shifts[2], self.shifts[3], self.consts[3]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ii(a, b, c, d, e, block[74], self.shifts[2], self.shifts[3], self.consts[3]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ii(a, b, c, d, e, block[75], self.shifts[2], self.shifts[3], self.consts[3]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ii(a, b, c, d, e, block[76], self.shifts[2], self.shifts[3], self.consts[3]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ii(a, b, c, d, e, block[77], self.shifts[2], self.shifts[3], self.consts[3]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ii(a, b, c, d, e, block[78], self.shifts[2], self.shifts[3], self.consts[3]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );
        let (a, b, c, d, e) = (
            ii(a, b, c, d, e, block[79], self.shifts[2], self.shifts[3], self.consts[3]),
            a,
            (b << self.shifts[4]) | (b >> self.shifts[5]),
            c,
            d,
        );

        // Update state

        self.a = self.a.wrapping_add(a);
        self.b = self.b.wrapping_add(b);
        self.c = self.c.wrapping_add(c);
        self.d = self.d.wrapping_add(d);
        self.e = self.e.wrapping_add(e);
    }

    /// Return state digest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum_hash::sha1::State;
    ///
    /// let mut state = State::<u32>::new();
    /// assert_eq!(
    ///     state.digest(),
    ///     [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    /// );
    /// ```
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn digest(&self) -> [T; 5] {
        [self.a, self.b, self.c, self.d, self.e]
    }
}

impl<T: Debug> Debug for State<T> {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("State")
            .field("a", &self.a)
            .field("b", &self.b)
            .field("c", &self.c)
            .field("d", &self.d)
            .field("e", &self.e)
            .finish()
    }
}

impl<T> Default for State<T>
where
    T: FFFunc + GGFunc + HHFunc + IIFunc + From<u32>,
{
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn default() -> Self {
        Self::new()
    }
}

impl<T: From<u32>> super::Reset for State<T> {
    /// Reset state.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum_hash::sha1::State;
    /// use chksum_hash::Reset;
    ///
    /// let mut state = State::<u32>::new();
    /// let data = [0x00; 16];
    /// state.update(data);
    /// assert_ne!(
    ///     state.digest(),
    ///     [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    /// );
    /// state.reset();
    /// assert_eq!(
    ///     state.digest(),
    ///     [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    /// );
    /// ```
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn reset(&mut self) {
        self.a = T::from(A);
        self.b = T::from(B);
        self.c = T::from(C);
        self.d = T::from(D);
        self.e = T::from(E);
    }
}

/// Represents hash digest.
///
/// # Examples
///
/// ```rust
/// use chksum_hash::sha1::Digest;
///
/// let digest = Digest::try_from("da39a3ee5e6b4b0d3255bfef95601890afd80709").unwrap();
/// println!("digest {:?}", digest);
/// println!("digest {:x}", digest);
/// println!("digest {:X}", digest);
/// ```
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Digest<T>([T; DIGEST_LENGTH_BYTES]);

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl fmt::LowerHex for Digest<u8> {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let digest = format!(
            "{:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}",
            self.0[0x00], self.0[0x01], self.0[0x02], self.0[0x03],
            self.0[0x04], self.0[0x05], self.0[0x06], self.0[0x07],
            self.0[0x08], self.0[0x09], self.0[0x0A], self.0[0x0B],
            self.0[0x0C], self.0[0x0D], self.0[0x0E], self.0[0x0F],
            self.0[0x10], self.0[0x11], self.0[0x12], self.0[0x13],
        );
        if formatter.alternate() {
            formatter.pad_integral(true, "0x", &digest)
        } else {
            formatter.pad(&digest)
        }
    }
}

#[cfg(feature = "std")]
impl fmt::UpperHex for Digest<u8> {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let digest = format!(
            "{:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}",
            self.0[0x00], self.0[0x01], self.0[0x02], self.0[0x03],
            self.0[0x04], self.0[0x05], self.0[0x06], self.0[0x07],
            self.0[0x08], self.0[0x09], self.0[0x0A], self.0[0x0B],
            self.0[0x0C], self.0[0x0D], self.0[0x0E], self.0[0x0F],
            self.0[0x10], self.0[0x11], self.0[0x12], self.0[0x13],
        );
        if formatter.alternate() {
            formatter.pad_integral(true, "0X", &digest)
        } else {
            formatter.pad(&digest)
        }
    }
}

#[cfg(feature = "std")]
impl<T, U> From<[U; DIGEST_LENGTH_DWORDS]> for Digest<T>
where
    T: Copy,
    U: ToBeBytes<T, 4>,
{
    #[allow(clippy::many_single_char_names)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(digest: [U; DIGEST_LENGTH_DWORDS]) -> Self {
        let [a, b, c, d, e] = digest;
        let [a, b, c, d, e] = [
            a.to_be_bytes(),
            b.to_be_bytes(),
            c.to_be_bytes(),
            d.to_be_bytes(),
            e.to_be_bytes(),
        ];
        Self([
            a[0], a[1], a[2], a[3],
            b[0], b[1], b[2], b[3],
            c[0], c[1], c[2], c[3],
            d[0], d[1], d[2], d[3],
            e[0], e[1], e[2], e[3],
        ])
    }
}

#[cfg(feature = "std")]
impl<T, U> From<State<U>> for Digest<T>
where
    T: Copy,
    U: ToBeBytes<T, 4>,
{
    #[allow(clippy::many_single_char_names)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(state: State<U>) -> Self {
        let (a, b, c, d, e) = (state.a, state.b, state.c, state.d, state.e);
        Self::from([a, b, c, d, e])
    }
}

#[cfg(feature = "std")]
impl<T> From<Digest<T>> for [T; DIGEST_LENGTH_BYTES] {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(digest: Digest<T>) -> Self {
        digest.0
    }
}

#[cfg(feature = "std")]
impl TryFrom<&str> for Digest<u8> {
    type Error = DigestError;

    #[allow(clippy::many_single_char_names, clippy::shadow_unrelated)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn try_from(digest: &str) -> Result<Self, Self::Error> {
        if digest.len() != DIGEST_LENGTH_HEX {
            let error = DigestError::InvalidLength {
                value: digest.len(),
                proper: DIGEST_LENGTH_HEX,
            };
            return Err(error);
        }
        let (a, b, c, d, e) = (
            u32::from_str_radix(&digest[0x00..0x08], 16)?,
            u32::from_str_radix(&digest[0x08..0x10], 16)?,
            u32::from_str_radix(&digest[0x10..0x18], 16)?,
            u32::from_str_radix(&digest[0x18..0x20], 16)?,
            u32::from_str_radix(&digest[0x20..0x28], 16)?,
        );
        let digest = [a, b, c, d, e];
        let digest = Self::from(digest);
        Ok(digest)
    }
}

/// Hash struct with internal buffer which allows to process input data.
#[cfg(feature = "std")]
#[cfg_attr(docsrs, cfg(feature = "std"))]
#[derive(Clone)]
pub struct Hash<T: Arch>
where
    T::u8: Copy,
{
    state: State<T::u32>,
    buffer: Vec<T::u8>,
    counter: usize,
    padding: [T::u8; BLOCK_LENGTH_BYTES],
}

#[cfg(feature = "std")]
impl<T> Hash<T>
where
    T: Arch,
    T::u8: Copy + From<u8>,
    T::u32: FFFunc + GGFunc + HHFunc + IIFunc + From<u32> + From1<u8> + FromBeBytes<T::u8, 4> + ToBeBytes<T::u8, 4>,
{
    /// Create new hash instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum_arch::x1::Arch;
    /// use chksum_hash::sha1::Hash;
    ///
    /// let hash = Hash::<Arch>::new();
    /// ```
    #[cfg_attr(not(debug_assertions), inline(always))]
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: State::new(),
            buffer: Vec::new(),
            counter: 0,
            padding: [
                T::u8::from(PADDING[0x00]), T::u8::from(PADDING[0x01]), T::u8::from(PADDING[0x02]), T::u8::from(PADDING[0x03]),
                T::u8::from(PADDING[0x04]), T::u8::from(PADDING[0x05]), T::u8::from(PADDING[0x06]), T::u8::from(PADDING[0x07]),
                T::u8::from(PADDING[0x08]), T::u8::from(PADDING[0x09]), T::u8::from(PADDING[0x0A]), T::u8::from(PADDING[0x0B]),
                T::u8::from(PADDING[0x0C]), T::u8::from(PADDING[0x0D]), T::u8::from(PADDING[0x0E]), T::u8::from(PADDING[0x0F]),
                T::u8::from(PADDING[0x10]), T::u8::from(PADDING[0x11]), T::u8::from(PADDING[0x12]), T::u8::from(PADDING[0x13]),
                T::u8::from(PADDING[0x14]), T::u8::from(PADDING[0x15]), T::u8::from(PADDING[0x16]), T::u8::from(PADDING[0x17]),
                T::u8::from(PADDING[0x18]), T::u8::from(PADDING[0x19]), T::u8::from(PADDING[0x1A]), T::u8::from(PADDING[0x1B]),
                T::u8::from(PADDING[0x1C]), T::u8::from(PADDING[0x1D]), T::u8::from(PADDING[0x1E]), T::u8::from(PADDING[0x1F]),
                T::u8::from(PADDING[0x20]), T::u8::from(PADDING[0x21]), T::u8::from(PADDING[0x22]), T::u8::from(PADDING[0x23]),
                T::u8::from(PADDING[0x24]), T::u8::from(PADDING[0x25]), T::u8::from(PADDING[0x26]), T::u8::from(PADDING[0x27]),
                T::u8::from(PADDING[0x28]), T::u8::from(PADDING[0x29]), T::u8::from(PADDING[0x2A]), T::u8::from(PADDING[0x2B]),
                T::u8::from(PADDING[0x2C]), T::u8::from(PADDING[0x2D]), T::u8::from(PADDING[0x2E]), T::u8::from(PADDING[0x2F]),
                T::u8::from(PADDING[0x30]), T::u8::from(PADDING[0x31]), T::u8::from(PADDING[0x32]), T::u8::from(PADDING[0x33]),
                T::u8::from(PADDING[0x34]), T::u8::from(PADDING[0x35]), T::u8::from(PADDING[0x36]), T::u8::from(PADDING[0x37]),
                T::u8::from(PADDING[0x38]), T::u8::from(PADDING[0x39]), T::u8::from(PADDING[0x3A]), T::u8::from(PADDING[0x3B]),
                T::u8::from(PADDING[0x3C]), T::u8::from(PADDING[0x3D]), T::u8::from(PADDING[0x3E]), T::u8::from(PADDING[0x3F]),
            ],
        }
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn create_block(data: [T::u8; BLOCK_LENGTH_BYTES]) -> [T::u32; BLOCK_LENGTH_DWORDS] {
        [
            T::u32::from_be_bytes([data[0x00], data[0x01], data[0x02], data[0x03]]),
            T::u32::from_be_bytes([data[0x04], data[0x05], data[0x06], data[0x07]]),
            T::u32::from_be_bytes([data[0x08], data[0x09], data[0x0A], data[0x0B]]),
            T::u32::from_be_bytes([data[0x0C], data[0x0D], data[0x0E], data[0x0F]]),
            T::u32::from_be_bytes([data[0x10], data[0x11], data[0x12], data[0x13]]),
            T::u32::from_be_bytes([data[0x14], data[0x15], data[0x16], data[0x17]]),
            T::u32::from_be_bytes([data[0x18], data[0x19], data[0x1A], data[0x1B]]),
            T::u32::from_be_bytes([data[0x1C], data[0x1D], data[0x1E], data[0x1F]]),
            T::u32::from_be_bytes([data[0x20], data[0x21], data[0x22], data[0x23]]),
            T::u32::from_be_bytes([data[0x24], data[0x25], data[0x26], data[0x27]]),
            T::u32::from_be_bytes([data[0x28], data[0x29], data[0x2A], data[0x2B]]),
            T::u32::from_be_bytes([data[0x2C], data[0x2D], data[0x2E], data[0x2F]]),
            T::u32::from_be_bytes([data[0x30], data[0x31], data[0x32], data[0x33]]),
            T::u32::from_be_bytes([data[0x34], data[0x35], data[0x36], data[0x37]]),
            T::u32::from_be_bytes([data[0x38], data[0x39], data[0x3A], data[0x3B]]),
            T::u32::from_be_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]),
        ]
    }

    /// Update hash with data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum_arch::x1::Arch;
    /// use chksum_hash::sha1::Hash;
    ///
    /// let mut hash = Hash::<Arch>::new();
    /// let data = [0, 1, 2, 3];
    /// hash.update(data);
    /// let data = "string";
    /// hash.update(data);
    /// ```
    #[cfg_attr(nightly, optimize(speed))]
    pub fn update<D: AsRef<[T::u8]>>(&mut self, data: D) {
        let data = data.as_ref();
        self.counter = self.counter.wrapping_add(data.len());
        let mut data = data;
        if self.buffer.is_empty() {
            // if buffer is empty parse as many blocks as it is possible
            while data.len() >= BLOCK_LENGTH_BYTES {
                let block = data[..BLOCK_LENGTH_BYTES].try_into().unwrap();
                data = &data[BLOCK_LENGTH_BYTES..];
                let block = Self::create_block(block);
                self.state.update(block);
            }
        } else if ((self.buffer.len() % BLOCK_LENGTH_BYTES) + data.len()) > BLOCK_LENGTH_BYTES {
            // if buffer is not empty fill buffer with missing data that the buffer's length will be multiple of block's length
            let buffer_length = self.buffer.len() % BLOCK_LENGTH_BYTES;
            if buffer_length > 0 {
                let buffer_missing = BLOCK_LENGTH_BYTES - buffer_length;
                let buffer = &data[..buffer_missing];
                data = &data[buffer_missing..];
                self.buffer.extend_from_slice(buffer);
            }
            // create as many blocks from buffer as it is possible
            while self.buffer.len() >= BLOCK_LENGTH_BYTES {
                let block = self.buffer.drain(..BLOCK_LENGTH_BYTES).as_slice().try_into().unwrap();
                let block = Self::create_block(block);
                self.state.update(block);
            }
            // create as many blocks from data as it is possible
            while data.len() >= BLOCK_LENGTH_BYTES {
                let block = data[..BLOCK_LENGTH_BYTES].try_into().unwrap();
                data = &data[BLOCK_LENGTH_BYTES..];
                let block = Self::create_block(block);
                self.state.update(block);
            }
        }
        if !data.is_empty() {
            // update buffer with rest of data
            self.buffer.extend_from_slice(data);
        }
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn padding(&self) -> Vec<T::u8> {
        let length = self.counter as u64;
        let length = length * 8; // convert byte-length into bits-length
        let length = length.to_be_bytes();
        let length = [
            T::u8::from(length[0]),
            T::u8::from(length[1]),
            T::u8::from(length[2]),
            T::u8::from(length[3]),
            T::u8::from(length[4]),
            T::u8::from(length[5]),
            T::u8::from(length[6]),
            T::u8::from(length[7]),
        ];

        let counter = self.counter % BLOCK_LENGTH_BYTES;
        let counter = counter + 1 + length.len();

        let padding = if counter > BLOCK_LENGTH_BYTES {
            2 * BLOCK_LENGTH_BYTES
        } else {
            BLOCK_LENGTH_BYTES
        };
        let padding = padding - counter + 1;
        let mut padding: Vec<_> = self.padding[..padding].to_vec();
        padding.extend_from_slice(&length);
        padding
    }

    /// Get final digest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::convert::TryFrom;
    ///
    /// use chksum_arch::x1::Arch;
    /// use chksum_hash::sha1::{Digest, Hash};
    ///
    /// let mut hash = Hash::<Arch>::new();
    /// let digest = Digest::try_from("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709").unwrap();
    /// assert_eq!(hash.digest(), digest);
    /// ```
    #[cfg_attr(nightly, optimize(speed))]
    pub fn digest(&self) -> Digest<T::u8> {
        let mut state = self.state;
        if self.buffer.is_empty() {
            let mut padding = self.padding();
            while padding.len() >= BLOCK_LENGTH_BYTES {
                let block = padding.drain(..BLOCK_LENGTH_BYTES).as_slice().try_into().unwrap();
                let block = Self::create_block(block);
                state.update(block);
            }
        } else {
            let mut buffer = self.buffer.clone();
            let mut padding = self.padding();
            buffer.append(&mut padding);
            while buffer.len() >= BLOCK_LENGTH_BYTES {
                let block = buffer.drain(..BLOCK_LENGTH_BYTES).as_slice().try_into().unwrap();
                let block = Self::create_block(block);
                state.update(block);
            }
        }
        state.into()
    }
}

#[cfg(feature = "std")]
impl<T: Arch + Debug> Debug for Hash<T>
where
    T::u8: Copy + Debug,
    T::u32: Debug,
{
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hash")
            .field("state", &self.state)
            .field("buffer", &self.buffer)
            .field("counter", &self.counter)
            .finish()
    }
}

#[cfg(feature = "std")]
impl<T> Default for Hash<T>
where
    T: Arch,
    T::u8: Copy + From<u8>,
    T::u32: FFFunc + GGFunc + HHFunc + IIFunc + From<u32> + From1<u8> + FromBeBytes<T::u8, 4> + ToBeBytes<T::u8, 4>,
{
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
impl<T: Arch> super::Digest for Hash<T>
where
    T::u8: Copy + From<u8>,
    T::u32: FFFunc + GGFunc + HHFunc + IIFunc + From<u32> + From1<u8> + FromBeBytes<T::u8, 4> + ToBeBytes<T::u8, 4>,
{
    type Digest = Digest<T::u8>;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn digest(&mut self) -> Self::Digest {
        Hash::digest(self)
    }
}

#[cfg(feature = "std")]
impl<T: Arch> super::Hash<T::u8> for Hash<T>
where
    T::u8: Copy + From<u8>,
    T::u32: FFFunc + GGFunc + HHFunc + IIFunc + From<u32> + From1<u8> + FromBeBytes<T::u8, 4> + ToBeBytes<T::u8, 4>,
{
}

#[cfg(feature = "std")]
impl<T: Arch> super::Update<T::u8> for Hash<T>
where
    T::u8: Copy + From<u8>,
    T::u32: FFFunc + GGFunc + HHFunc + IIFunc + From<u32> + From1<u8> + FromBeBytes<T::u8, 4> + ToBeBytes<T::u8, 4>,
{
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn update<D: AsRef<[T::u8]>>(&mut self, data: D) {
        Hash::update(self, data);
    }
}

#[cfg(feature = "std")]
impl<R: Copy, S: From<u32>, T: Arch<u8 = R, u32 = S>> super::Reset for Hash<T> {
    /// Reset hash.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::convert::TryFrom;
    ///
    /// use chksum_arch::x1::Arch;
    /// use chksum_hash::sha1::{Digest, Hash};
    /// use chksum_hash::Reset;
    ///
    /// let mut hash = Hash::<Arch>::new();
    /// let data = [0x00u8; 16];
    /// hash.update(&data[..]);
    /// let digest = Digest::try_from("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709").unwrap();
    /// assert_ne!(hash.digest(), digest);
    /// hash.reset();
    /// assert_eq!(hash.digest(), digest);
    /// ```
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn reset(&mut self) {
        self.state.reset();
        self.buffer.clear();
        self.counter = 0;
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    use chksum_arch::x1::Arch;

    #[cfg(feature = "std")]
    use super::{Digest, DigestError, Hash};
    use super::State;

    #[test]
    fn state_new() {
        let state = State::<u32>::new();
        assert_eq!(
            state.digest(),
            [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        );
    }

    #[test]
    fn state_empty() {
        let mut state = State::<u32>::new();
        state.update([
            0x80000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000,
        ]);
        assert_eq!(
            state.digest(),
            [0xDA39A3EE, 0x5E6B4B0D, 0x3255BFEF, 0x95601890, 0xAFD80709]
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn digest_format() {
        let digest = Digest::try_from("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709").unwrap();
        assert_eq!(format!("{digest:x}"), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(format!("{digest:#x}"), "0xda39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(format!("{digest:48x}"), "da39a3ee5e6b4b0d3255bfef95601890afd80709        ");
        assert_eq!(format!("{digest:>48x}"), "        da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(format!("{digest:^48x}"), "    da39a3ee5e6b4b0d3255bfef95601890afd80709    ");
        assert_eq!(format!("{digest:<48x}"), "da39a3ee5e6b4b0d3255bfef95601890afd80709        ");
        assert_eq!(format!("{digest:.^48x}"), "....da39a3ee5e6b4b0d3255bfef95601890afd80709....");
        assert_eq!(format!("{digest:.8x}"), "da39a3ee");
        assert_eq!(format!("{digest:X}"), "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
        assert_eq!(format!("{digest:#X}"), "0XDA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
        assert_eq!(format!("{digest:48X}"), "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709        ");
        assert_eq!(format!("{digest:>48X}"), "        DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
        assert_eq!(format!("{digest:^48X}"), "    DA39A3EE5E6B4B0D3255BFEF95601890AFD80709    ");
        assert_eq!(format!("{digest:<48X}"), "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709        ");
        assert_eq!(format!("{digest:.^48X}"), "....DA39A3EE5E6B4B0D3255BFEF95601890AFD80709....");
        assert_eq!(format!("{digest:.8X}"), "DA39A3EE");
    }

    #[cfg(feature = "std")]
    #[test]
    fn digest_tryfrom() {
        assert_eq!(Digest::try_from("da39a3ee5e6b4b0d3255bfef95601890afd80709"), Digest::try_from("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"));
        assert_eq!(Digest::try_from("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"), Ok(Digest([0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55, 0xBF, 0xEF, 0x95, 0x60, 0x18, 0x90, 0xAF, 0xD8, 0x07, 0x09])));
        assert!(matches!(Digest::try_from("D4"), Err(DigestError::InvalidLength { value: _, proper: _ })));
        assert!(matches!(Digest::try_from("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709XX"), Err(DigestError::InvalidLength { value: _, proper: _ })));
        assert!(matches!(Digest::try_from("DA39A3EE5E6B4B0D3255BFEF95601890AFD807XX"), Err(DigestError::ParseError(_))));
    }

    #[cfg(feature = "std")]
    #[test]
    fn hash_new() {
        let hash = Hash::<Arch>::new();
        let digest = Digest::try_from("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709").unwrap();
        assert_eq!(hash.digest(), digest);
    }

    #[cfg(feature = "std")]
    #[test]
    fn hash_hello_world() {
        let mut hash = Hash::<Arch>::new();
        let data = "Hello World";
        hash.update(data);
        let digest = Digest::try_from("0A4D55A8D778E5022FAB701977C5D840BBC486D0").unwrap();
        assert_eq!(hash.digest(), digest);
    }

    #[cfg(feature = "std")]
    #[test]
    fn hash_hello_world_by_chunks() {
        let mut hash = Hash::<Arch>::new();
        let data = "Hello";
        hash.update(data);
        let data = " ";
        hash.update(data);
        let data = "World";
        hash.update(data);
        let digest = Digest::try_from("0A4D55A8D778E5022FAB701977C5D840BBC486D0").unwrap();
        assert_eq!(hash.digest(), digest);
    }
}
