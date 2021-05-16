//! Implementation of SHA-1 hash function based on [RFC 3174: US Secure Hash Algorithm 1 (SHA1)](https://tools.ietf.org/html/rfc3174).
//!
//! # Examples
//!
//! ```rust
//! use chksum::hash::sha1::State;
//!
//! let mut state = State::<u32>::new();
//! assert_eq!(state.digest(), [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]);
//! let data = [u32::from_be_bytes([0x80, 0x00, 0x00, 0x00]), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
//! state.update(data);
//! assert_eq!(state.digest(), [0xDA39A3EE, 0x5E6B4B0D, 0x3255BFEF, 0x95601890, 0xAFD80709]);
//! ```
//!
//! ```rust
//! use chksum::hash::sha1::State;
//!
//! let mut state = State::<u32>::new();
//! assert_eq!(state.digest(), [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]);
//! let data = [u32::from_be_bytes([0x31, 0x32, 0x33, 0x34]), u32::from_be_bytes([0x35, 0x36, 0x37, 0x38]), u32::from_be_bytes([0x39, 0x30, 0x31, 0x32]), u32::from_be_bytes([0x33, 0x34, 0x35, 0x36]), u32::from_be_bytes([0x37, 0x38, 0x39, 0x30]), u32::from_be_bytes([0x31, 0x32, 0x33, 0x34]), u32::from_be_bytes([0x35, 0x36, 0x37, 0x38]), u32::from_be_bytes([0x39, 0x30, 0x31, 0x32]), u32::from_be_bytes([0x33, 0x34, 0x35, 0x36]), u32::from_be_bytes([0x37, 0x38, 0x39, 0x30]), u32::from_be_bytes([0x31, 0x32, 0x33, 0x34]), u32::from_be_bytes([0x35, 0x36, 0x37, 0x38]), u32::from_be_bytes([0x39, 0x30, 0x31, 0x32]), u32::from_be_bytes([0x33, 0x34, 0x35, 0x36]), u32::from_be_bytes([0x37, 0x38, 0x39, 0x30]), u32::from_be_bytes([0x31, 0x32, 0x33, 0x34])];
//! state.update(data);
//! let data = [u32::from_be_bytes([0x35, 0x36, 0x37, 0x38]), u32::from_be_bytes([0x39, 0x30, 0x31, 0x32]), u32::from_be_bytes([0x33, 0x34, 0x35, 0x36]), u32::from_be_bytes([0x37, 0x38, 0x39, 0x30]), u32::from_be_bytes([0x80, 0x00, 0x00, 0x00]), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, u32::from_le_bytes([0x80, 0x02, 0x00, 0x00])];
//! state.update(data);
//! assert_eq!(state.digest(), [0x50ABF570, 0x6A150990, 0xA08B2C5E, 0xA40FA0E5, 0x85554732]);
//! ```

use std::convert::{From, TryFrom, TryInto};
use std::fmt::{self, Debug, Formatter};
use std::ops::{BitAnd, BitOr, BitXor, Not, Shl, Shr};

use crate::arch::Arch;
use crate::convert::{arch::From1, FromBeBytes, ToBeBytes};
use crate::num::WrappingAdd;

const BLOCK_LENGTH_BITS: usize = 512;
const BLOCK_LENGTH_BYTES: usize = BLOCK_LENGTH_BITS / 8;
const BLOCK_LENGTH_WORDS: usize = BLOCK_LENGTH_BYTES / 2;
const BLOCK_LENGTH_DWORDS: usize = BLOCK_LENGTH_WORDS / 2;

const DIGEST_LENGTH_BITS: usize = 160;
const DIGEST_LENGTH_BYTES: usize = DIGEST_LENGTH_BITS / 8;
const DIGEST_LENGTH_WORDS: usize = DIGEST_LENGTH_BYTES / 2;
const DIGEST_LENGTH_DWORDS: usize = DIGEST_LENGTH_WORDS / 2;
const DIGEST_LENGTH_HEX: usize = DIGEST_LENGTH_BYTES * 2;

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
const CONSTS: [u32; 4] = [
    0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6,
];

#[allow(clippy::unreadable_literal)]
const SHIFTS: [u32; 6] = [
    0x01, 0x1F, 0x05, 0x1B, 0x1E, 0x02,
];

const PADDING: [u8; BLOCK_LENGTH_BYTES] = [
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// State
#[derive(Clone, Copy)]
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
where T: BitAnd<Output = T> + BitOr<Output = T> + BitXor<Output = T> + Copy + From<u32> + Not<Output = T> + Shl<Output = T> + Shr<Output = T> + WrappingAdd<Output = T> + WrappingAdd<u32, Output = T> {
    /// Create new state instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum::hash::sha1::State;
    ///
    /// let state = State::<u32>::new();
    /// ```
    #[cfg_attr(feature = "inline", inline)]
    #[must_use] pub fn new() -> Self {
        Self {
            a: T::from(A),
            b: T::from(B),
            c: T::from(C),
            d: T::from(D),
            e: T::from(E),
            consts: [
                T::from(CONSTS[0]), T::from(CONSTS[1]), T::from(CONSTS[2]), T::from(CONSTS[3]),
            ],
            shifts: [
                T::from(SHIFTS[0]), T::from(SHIFTS[1]), T::from(SHIFTS[2]), T::from(SHIFTS[3]), T::from(SHIFTS[4]), T::from(SHIFTS[5]),
            ],
        }
    }

    /// Update state with block of data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum::hash::sha1::State;
    ///
    /// let mut state = State::<u32>::new();
    /// let data = [0x00; 16];
    /// state.update(data);
    /// ```
    #[allow(
        clippy::items_after_statements,
        clippy::too_many_lines,
        clippy::shadow_unrelated,
    )]
    pub fn update(&mut self, block: [T; BLOCK_LENGTH_DWORDS]) {
        let mut block = [
             block[ 0],  block[ 1],  block[ 2],  block[ 3],
             block[ 4],  block[ 5],  block[ 6],  block[ 7],
             block[ 8],  block[ 9],  block[10],  block[11],
             block[12],  block[13],  block[14],  block[15],
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
        block[16] = block[13] ^ block[ 8] ^ block[ 2] ^ block[ 0];
        block[16] = (block[16] << self.shifts[0]) | (block[16] >> self.shifts[1]);
        block[17] = block[14] ^ block[ 9] ^ block[ 3] ^ block[ 1];
        block[17] = (block[17] << self.shifts[0]) | (block[17] >> self.shifts[1]);
        block[18] = block[15] ^ block[10] ^ block[ 4] ^ block[ 2];
        block[18] = (block[18] << self.shifts[0]) | (block[18] >> self.shifts[1]);
        block[19] = block[16] ^ block[11] ^ block[ 5] ^ block[ 3];
        block[19] = (block[19] << self.shifts[0]) | (block[19] >> self.shifts[1]);
        block[20] = block[17] ^ block[12] ^ block[ 6] ^ block[ 4];
        block[20] = (block[20] << self.shifts[0]) | (block[20] >> self.shifts[1]);
        block[21] = block[18] ^ block[13] ^ block[ 7] ^ block[ 5];
        block[21] = (block[21] << self.shifts[0]) | (block[21] >> self.shifts[1]);
        block[22] = block[19] ^ block[14] ^ block[ 8] ^ block[ 6];
        block[22] = (block[22] << self.shifts[0]) | (block[22] >> self.shifts[1]);
        block[23] = block[20] ^ block[15] ^ block[ 9] ^ block[ 7];
        block[23] = (block[23] << self.shifts[0]) | (block[23] >> self.shifts[1]);
        block[24] = block[21] ^ block[16] ^ block[10] ^ block[ 8];
        block[24] = (block[24] << self.shifts[0]) | (block[24] >> self.shifts[1]);
        block[25] = block[22] ^ block[17] ^ block[11] ^ block[ 9];
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

        #[cfg_attr(feature = "inline", inline)]
        fn f<T>(x: T, y: T, z: T) -> T
        where T: BitAnd<Output = T> + BitOr<Output = T> + Copy + Not<Output = T> + Shl<Output = T> + Shr<Output = T> + WrappingAdd<Output = T> {
            (x & y) | (!x & z)
        }

        #[allow(
            clippy::similar_names,
            clippy::many_single_char_names,
            clippy::too_many_arguments,
        )]
        #[cfg_attr(feature = "inline", inline)]
        fn ff<T>(a: T, b: T, c: T, d: T, e: T, data: T, shl: T, shr: T, constant: T) -> T
        where T: BitAnd<Output = T> + BitOr<Output = T> + Copy + Not<Output = T> + Shl<Output = T> + Shr<Output = T> + WrappingAdd<Output = T> {
            ((a << shl) | (a >> shr))
                .wrapping_add(f(b, c, d))
                .wrapping_add(e)
                .wrapping_add(data)
                .wrapping_add(constant)
        }

        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[ 0], self.shifts[2], self.shifts[3], self.consts[0]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[ 1], self.shifts[2], self.shifts[3], self.consts[0]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[ 2], self.shifts[2], self.shifts[3], self.consts[0]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[ 3], self.shifts[2], self.shifts[3], self.consts[0]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[ 4], self.shifts[2], self.shifts[3], self.consts[0]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[ 5], self.shifts[2], self.shifts[3], self.consts[0]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[ 6], self.shifts[2], self.shifts[3], self.consts[0]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[ 7], self.shifts[2], self.shifts[3], self.consts[0]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[ 8], self.shifts[2], self.shifts[3], self.consts[0]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[ 9], self.shifts[2], self.shifts[3], self.consts[0]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[10], self.shifts[2], self.shifts[3], self.consts[0]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[11], self.shifts[2], self.shifts[3], self.consts[0]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[12], self.shifts[2], self.shifts[3], self.consts[0]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[13], self.shifts[2], self.shifts[3], self.consts[0]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[14], self.shifts[2], self.shifts[3], self.consts[0]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[15], self.shifts[2], self.shifts[3], self.consts[0]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[16], self.shifts[2], self.shifts[3], self.consts[0]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[17], self.shifts[2], self.shifts[3], self.consts[0]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[18], self.shifts[2], self.shifts[3], self.consts[0]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[19], self.shifts[2], self.shifts[3], self.consts[0]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);

        // Step 2

        #[cfg_attr(feature = "inline", inline)]
        fn g<T>(x: T, y: T, z: T) -> T
        where T: BitXor<Output = T> {
            x ^ y ^ z
        }

        #[allow(
            clippy::similar_names,
            clippy::many_single_char_names,
            clippy::too_many_arguments,
        )]
        #[cfg_attr(feature = "inline", inline)]
        fn gg<T>(a: T, b: T, c: T, d: T, e: T, data: T, shl: T, shr: T, constant: T) -> T
        where T: BitOr<Output = T> + BitXor<Output = T> + Copy + Shl<Output = T> + Shr<Output = T> + WrappingAdd<Output = T> {
            ((a << shl) | (a >> shr))
             .wrapping_add(g(b, c, d))
             .wrapping_add(e)
             .wrapping_add(data)
             .wrapping_add(constant)
        }

        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[20], self.shifts[2], self.shifts[3], self.consts[1]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[21], self.shifts[2], self.shifts[3], self.consts[1]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[22], self.shifts[2], self.shifts[3], self.consts[1]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[23], self.shifts[2], self.shifts[3], self.consts[1]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[24], self.shifts[2], self.shifts[3], self.consts[1]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[25], self.shifts[2], self.shifts[3], self.consts[1]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[26], self.shifts[2], self.shifts[3], self.consts[1]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[27], self.shifts[2], self.shifts[3], self.consts[1]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[28], self.shifts[2], self.shifts[3], self.consts[1]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[29], self.shifts[2], self.shifts[3], self.consts[1]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[30], self.shifts[2], self.shifts[3], self.consts[1]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[31], self.shifts[2], self.shifts[3], self.consts[1]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[32], self.shifts[2], self.shifts[3], self.consts[1]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[33], self.shifts[2], self.shifts[3], self.consts[1]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[34], self.shifts[2], self.shifts[3], self.consts[1]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[35], self.shifts[2], self.shifts[3], self.consts[1]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[36], self.shifts[2], self.shifts[3], self.consts[1]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[37], self.shifts[2], self.shifts[3], self.consts[1]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[38], self.shifts[2], self.shifts[3], self.consts[1]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[39], self.shifts[2], self.shifts[3], self.consts[1]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);

        // Step 3

        #[cfg_attr(feature = "inline", inline)]
        fn h<T>(x: T, y: T, z: T) -> T
        where T: BitAnd<Output = T> + BitOr<Output = T> + Copy {
            (x & y) | (x & z) | (y & z)
        }

        #[allow(
            clippy::similar_names,
            clippy::many_single_char_names,
            clippy::too_many_arguments,
        )]
        #[cfg_attr(feature = "inline", inline)]
        fn hh<T>(a: T, b: T, c: T, d: T, e: T, data: T, shl: T, shr: T, constant: T) -> T
        where T: BitAnd<Output = T> + BitOr<Output = T> + Copy + Shl<Output = T> + Shr<Output = T> + WrappingAdd<Output = T> {
            ((a << shl) | (a >> shr))
             .wrapping_add(h(b, c, d))
             .wrapping_add(e)
             .wrapping_add(data)
             .wrapping_add(constant)
        }

        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[40], self.shifts[2], self.shifts[3], self.consts[2]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[41], self.shifts[2], self.shifts[3], self.consts[2]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[42], self.shifts[2], self.shifts[3], self.consts[2]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[43], self.shifts[2], self.shifts[3], self.consts[2]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[44], self.shifts[2], self.shifts[3], self.consts[2]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[45], self.shifts[2], self.shifts[3], self.consts[2]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[46], self.shifts[2], self.shifts[3], self.consts[2]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[47], self.shifts[2], self.shifts[3], self.consts[2]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[48], self.shifts[2], self.shifts[3], self.consts[2]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[49], self.shifts[2], self.shifts[3], self.consts[2]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[50], self.shifts[2], self.shifts[3], self.consts[2]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[51], self.shifts[2], self.shifts[3], self.consts[2]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[52], self.shifts[2], self.shifts[3], self.consts[2]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[53], self.shifts[2], self.shifts[3], self.consts[2]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[54], self.shifts[2], self.shifts[3], self.consts[2]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[55], self.shifts[2], self.shifts[3], self.consts[2]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[56], self.shifts[2], self.shifts[3], self.consts[2]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[57], self.shifts[2], self.shifts[3], self.consts[2]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[58], self.shifts[2], self.shifts[3], self.consts[2]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[59], self.shifts[2], self.shifts[3], self.consts[2]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);

        // Step 4

        #[cfg_attr(feature = "inline", inline)]
        fn i<T>(x: T, y: T, z: T) -> T
        where T: BitXor<Output = T> + Copy {
            x ^ y ^ z
        }

        #[allow(
            clippy::similar_names,
            clippy::many_single_char_names,
            clippy::too_many_arguments,
        )]
        #[cfg_attr(feature = "inline", inline)]
        fn ii<T>(a: T, b: T, c: T, d: T, e: T, data: T, shl: T, shr: T, constant: T) -> T
        where T: BitOr<Output = T> + BitXor<Output = T> + Copy + Shl<Output = T> + Shr<Output = T> + WrappingAdd<Output = T> {
            ((a << shl) | (a >> shr))
             .wrapping_add(i(b, c, d))
             .wrapping_add(e)
             .wrapping_add(data)
             .wrapping_add(constant)
        }

        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[60], self.shifts[2], self.shifts[3], self.consts[3]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[61], self.shifts[2], self.shifts[3], self.consts[3]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[62], self.shifts[2], self.shifts[3], self.consts[3]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[63], self.shifts[2], self.shifts[3], self.consts[3]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[64], self.shifts[2], self.shifts[3], self.consts[3]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[65], self.shifts[2], self.shifts[3], self.consts[3]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[66], self.shifts[2], self.shifts[3], self.consts[3]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[67], self.shifts[2], self.shifts[3], self.consts[3]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[68], self.shifts[2], self.shifts[3], self.consts[3]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[69], self.shifts[2], self.shifts[3], self.consts[3]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[70], self.shifts[2], self.shifts[3], self.consts[3]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[71], self.shifts[2], self.shifts[3], self.consts[3]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[72], self.shifts[2], self.shifts[3], self.consts[3]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[73], self.shifts[2], self.shifts[3], self.consts[3]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[74], self.shifts[2], self.shifts[3], self.consts[3]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[75], self.shifts[2], self.shifts[3], self.consts[3]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[76], self.shifts[2], self.shifts[3], self.consts[3]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[77], self.shifts[2], self.shifts[3], self.consts[3]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[78], self.shifts[2], self.shifts[3], self.consts[3]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[79], self.shifts[2], self.shifts[3], self.consts[3]), a, (b << self.shifts[4]) | (b >> self.shifts[5]), c, d);

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
    /// use chksum::hash::sha1::State;
    ///
    /// let mut state = State::<u32>::new();
    /// assert_eq!(state.digest(), [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]);
    /// ```
    #[cfg_attr(feature = "inline", inline)]
    pub fn digest(&self) -> [T; 5] {
        [self.a, self.b, self.c, self.d, self.e]
    }
}

impl<T: Debug> Debug for State<T> {
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

impl<T: From<u32>> super::Reset for State<T> {
    /// Reset state.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum::hash::Reset;
    /// use chksum::hash::sha1::State;
    ///
    /// let mut state = State::<u32>::new();
    /// let data = [0x00; 16];
    /// state.update(data);
    /// assert_ne!(state.digest(), [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]);
    /// state.reset();
    /// assert_eq!(state.digest(), [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]);
    /// ```
    #[cfg_attr(feature = "inline", inline)]
    fn reset(&mut self) {
        self.a = T::from(A);
        self.b = T::from(B);
        self.c = T::from(C);
        self.d = T::from(D);
        self.e = T::from(E);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Digest<T>([T; DIGEST_LENGTH_BYTES]);

impl super::ToHex for Digest<u8> {
    #[cfg_attr(feature = "inline", inline)]
    fn to_hex(&self) -> String {
        format!(
            "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.0[ 0], self.0[ 1], self.0[ 2], self.0[ 3],
            self.0[ 4], self.0[ 5], self.0[ 6], self.0[ 7],
            self.0[ 8], self.0[ 9], self.0[10], self.0[11],
            self.0[12], self.0[13], self.0[14], self.0[15],
            self.0[16], self.0[17], self.0[18], self.0[19],
        )
    }
}

impl<T, U> From<[U; DIGEST_LENGTH_DWORDS]> for Digest<T>
where T: Copy, U: ToBeBytes<T, 4> {
    #[cfg_attr(feature = "inline", inline)]
    fn from(digest: [U; DIGEST_LENGTH_DWORDS]) -> Self {
        let [a, b, c, d, e] = digest;
        let [a, b, c, d, e] = [a.to_be_bytes(), b.to_be_bytes(), c.to_be_bytes(), d.to_be_bytes(), e.to_be_bytes()];
        Self(
            [
                a[0], a[1], a[2], a[3],
                b[0], b[1], b[2], b[3],
                c[0], c[1], c[2], c[3],
                d[0], d[1], d[2], d[3],
                e[0], e[1], e[2], e[3],
            ],
        )
    }
}

impl<T, U> From<State<U>> for Digest<T>
where T: Copy, U: ToBeBytes<T, 4> {
    #[cfg_attr(feature = "inline", inline)]
    fn from(state: State<U>) -> Self {
        let (a, b, c, d, e) = (state.a, state.b, state.c, state.d, state.e);
        Self::from([a, b, c, d, e])
    }
}

impl TryFrom<&str> for Digest<u8> {
    type Error = &'static str;

    #[allow(clippy::shadow_unrelated)]
    #[cfg_attr(feature = "inline", inline)]
    fn try_from(digest: &str) -> Result<Self, Self::Error> {
        if digest.len() != DIGEST_LENGTH_HEX {
            // todo
        }
        let (a, b, c, d, e) = (
            u32::from_str_radix(&digest[ 0.. 8], 16).unwrap(), // todo fix unwrapping
            u32::from_str_radix(&digest[ 8..16], 16).unwrap(), // todo fix unwrapping
            u32::from_str_radix(&digest[16..24], 16).unwrap(), // todo fix unwrapping
            u32::from_str_radix(&digest[24..32], 16).unwrap(), // todo fix unwrapping
            u32::from_str_radix(&digest[32..40], 16).unwrap(), // todo fix unwrapping
        );
        let digest = [a, b, c, d, e];
        let digest = Self::from(digest);
        Ok(digest)
    }
}

#[derive(Clone)]
pub struct Hash<T: Arch>
where T::u8: Copy {
    state: State<T::u32>,
    buffer: Vec<T::u8>,
    counter: usize,
    padding: [T::u8; BLOCK_LENGTH_BYTES],
}

impl<T> Hash<T>
where T: Arch, T::u8: Copy + From<u8>, T::u32: BitAnd<Output = T::u32> + BitOr<Output = T::u32> + BitXor<Output = T::u32> + Copy + From<u32> + From1<u8> + FromBeBytes<T::u8, 4> + Not<Output = T::u32> + Shl<Output = T::u32> + Shr<Output = T::u32> + ToBeBytes<T::u8, 4> + WrappingAdd<Output = T::u32> + WrappingAdd<u32, Output = T::u32> {
    /// Create new hash instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum::arch::x1::Arch;
    /// use chksum::hash::sha1::Hash;
    ///
    /// let hash = Hash::<Arch>::new();
    /// ```
    #[cfg_attr(feature = "inline", inline)]
    #[must_use] pub fn new() -> Self {
        Self {
            state: State::new(),
            buffer: Vec::new(),
            counter: 0,
            padding: [
                T::u8::from(PADDING[ 0]), T::u8::from(PADDING[ 1]), T::u8::from(PADDING[ 2]), T::u8::from(PADDING[ 3]), T::u8::from(PADDING[ 4]), T::u8::from(PADDING[ 5]), T::u8::from(PADDING[ 6]), T::u8::from(PADDING[ 7]),
                T::u8::from(PADDING[ 8]), T::u8::from(PADDING[ 9]), T::u8::from(PADDING[10]), T::u8::from(PADDING[11]), T::u8::from(PADDING[12]), T::u8::from(PADDING[13]), T::u8::from(PADDING[14]), T::u8::from(PADDING[15]),
                T::u8::from(PADDING[16]), T::u8::from(PADDING[17]), T::u8::from(PADDING[18]), T::u8::from(PADDING[19]), T::u8::from(PADDING[20]), T::u8::from(PADDING[21]), T::u8::from(PADDING[22]), T::u8::from(PADDING[23]),
                T::u8::from(PADDING[24]), T::u8::from(PADDING[25]), T::u8::from(PADDING[26]), T::u8::from(PADDING[27]), T::u8::from(PADDING[28]), T::u8::from(PADDING[29]), T::u8::from(PADDING[30]), T::u8::from(PADDING[31]),
                T::u8::from(PADDING[32]), T::u8::from(PADDING[33]), T::u8::from(PADDING[34]), T::u8::from(PADDING[35]), T::u8::from(PADDING[36]), T::u8::from(PADDING[37]), T::u8::from(PADDING[38]), T::u8::from(PADDING[39]),
                T::u8::from(PADDING[40]), T::u8::from(PADDING[41]), T::u8::from(PADDING[42]), T::u8::from(PADDING[43]), T::u8::from(PADDING[44]), T::u8::from(PADDING[45]), T::u8::from(PADDING[46]), T::u8::from(PADDING[47]),
                T::u8::from(PADDING[48]), T::u8::from(PADDING[49]), T::u8::from(PADDING[50]), T::u8::from(PADDING[51]), T::u8::from(PADDING[52]), T::u8::from(PADDING[53]), T::u8::from(PADDING[54]), T::u8::from(PADDING[55]),
                T::u8::from(PADDING[56]), T::u8::from(PADDING[57]), T::u8::from(PADDING[58]), T::u8::from(PADDING[59]), T::u8::from(PADDING[60]), T::u8::from(PADDING[61]), T::u8::from(PADDING[62]), T::u8::from(PADDING[63]),
            ],
        }
    }

    #[cfg_attr(feature = "inline", inline)]
    fn create_block(data: [T::u8; BLOCK_LENGTH_BYTES]) -> [T::u32; BLOCK_LENGTH_DWORDS] {
        [
            T::u32::from_be_bytes([data[ 0], data[ 1], data[ 2], data[ 3]]),
            T::u32::from_be_bytes([data[ 4], data[ 5], data[ 6], data[ 7]]),
            T::u32::from_be_bytes([data[ 8], data[ 9], data[10], data[11]]),
            T::u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
            T::u32::from_be_bytes([data[16], data[17], data[18], data[19]]),
            T::u32::from_be_bytes([data[20], data[21], data[22], data[23]]),
            T::u32::from_be_bytes([data[24], data[25], data[26], data[27]]),
            T::u32::from_be_bytes([data[28], data[29], data[30], data[31]]),
            T::u32::from_be_bytes([data[32], data[33], data[34], data[35]]),
            T::u32::from_be_bytes([data[36], data[37], data[38], data[39]]),
            T::u32::from_be_bytes([data[40], data[41], data[42], data[43]]),
            T::u32::from_be_bytes([data[44], data[45], data[46], data[47]]),
            T::u32::from_be_bytes([data[48], data[49], data[50], data[51]]),
            T::u32::from_be_bytes([data[52], data[53], data[54], data[55]]),
            T::u32::from_be_bytes([data[56], data[57], data[58], data[59]]),
            T::u32::from_be_bytes([data[60], data[61], data[62], data[63]]),
        ]
    }

    /// Update hash with data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum::arch::x1::Arch;
    /// use chksum::hash::sha1::Hash;
    ///
    /// let mut hash = Hash::<Arch>::new();
    /// hash.update(&[0, 1, 2, 3]);
    /// ```
    pub fn update(&mut self, data: &[T::u8]) {
        self.counter = self.counter.wrapping_add(data.len());
        let mut data = data;
        if self.buffer.is_empty() {
            // if buffer is empty parse as many blocks as it is possible and update buffer
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

    #[cfg_attr(feature = "inline", inline)]
    fn padding(&self) -> Vec<T::u8> {
        let length = self.counter as u64;
        let length = length * 8; // convert byte-length into bits-length
        let length = length.to_be_bytes(); // fixme verify endianness
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
        } - counter + 1;
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
    /// use chksum::arch::x1::Arch;
    /// use chksum::hash::sha1::{Digest, Hash};
    ///
    /// let mut hash = Hash::<Arch>::new();
    /// let digest = Digest::try_from("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709").unwrap();
    /// assert_eq!(hash.digest(), digest);
    /// ```
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
        let digest = state.into();
        digest
    }
}

impl<T: Arch + Debug> Debug for Hash<T>
where T::u8: Copy + Debug, T::u32: Debug {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hash")
         .field("state", &self.state)
         .field("buffer", &self.buffer)
         .field("counter", &self.counter)
         .finish()
    }
}

impl<T: Arch> super::Digest for Hash<T>
where T::u8: Copy + From<u8>, T::u32: BitAnd<Output = T::u32> + BitOr<Output = T::u32> + BitXor<Output = T::u32> + Copy + From<u32> + From1<u8> + FromBeBytes<T::u8, 4> + Not<Output = T::u32> + Shl<Output = T::u32> + Shr<Output = T::u32> + ToBeBytes<T::u8, 4> + WrappingAdd<Output = T::u32> + WrappingAdd<u32, Output = T::u32> {
    type Digest = Digest<T::u8>;

    #[cfg_attr(feature = "inline", inline)]
    fn digest(&mut self) -> Self::Digest {
        Hash::digest(self)
    }
}

impl<T: Arch> super::Hash<T::u8> for Hash<T>
where T::u8: Copy + From<u8>, T::u32: BitAnd<Output = T::u32> + BitOr<Output = T::u32> + BitXor<Output = T::u32> + Copy + From<u32> + From1<u8> + FromBeBytes<T::u8, 4> + Not<Output = T::u32> + Shl<Output = T::u32> + Shr<Output = T::u32> + ToBeBytes<T::u8, 4> + WrappingAdd<Output = T::u32> + WrappingAdd<u32, Output = T::u32> {}

impl<T: Arch> super::Update<T::u8> for Hash<T>
where T::u8: Copy + From<u8>, T::u32: BitAnd<Output = T::u32> + BitOr<Output = T::u32> + BitXor<Output = T::u32> + Copy + From<u32> + From1<u8> + FromBeBytes<T::u8, 4> + Not<Output = T::u32> + Shl<Output = T::u32> + Shr<Output = T::u32> + ToBeBytes<T::u8, 4> + WrappingAdd<Output = T::u32> + WrappingAdd<u32, Output = T::u32> {
    #[cfg_attr(feature = "inline", inline)]
    fn update(&mut self, data: &[T::u8]) {
        Hash::update(self, data);
    }
}

impl<R: Copy, S: From<u32>, T: Arch<u8 = R, u32 = S>> super::Reset for Hash<T> {
    /// Reset hash.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::convert::TryFrom;
    /// use chksum::arch::x1::Arch;
    /// use chksum::hash::Reset;
    /// use chksum::hash::sha1::{Digest, Hash};
    ///
    /// let mut hash = Hash::<Arch>::new();
    /// let data = [0x00u8; 16];
    /// hash.update(&data[..]);
    /// let digest = Digest::try_from("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709").unwrap();
    /// assert_ne!(hash.digest(), digest);
    /// hash.reset();
    /// assert_eq!(hash.digest(), digest);
    /// ```
    #[cfg_attr(feature = "inline", inline)]
    fn reset(&mut self) {
        self.state.reset();
        self.buffer.clear();
        self.counter = 0;
    }
}

#[cfg(test)]
pub mod tests {
    use std::convert::TryFrom;

    use crate::arch::x1::Arch;

    use super::{Digest, Hash, State};

    #[test]
    fn state_new() {
        let state = State::<u32>::new();
        assert_eq!(state.digest(), [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]);
    }

    #[test]
    fn state_empty() {
        let mut state = State::<u32>::new();
        state.update(
            [
                0x80000000, 0x00000000, 0x00000000, 0x00000000,
                0x00000000, 0x00000000, 0x00000000, 0x00000000,
                0x00000000, 0x00000000, 0x00000000, 0x00000000,
                0x00000000, 0x00000000, 0x00000000, 0x00000000,
            ]
        );
        assert_eq!(state.digest(), [0xDA39A3EE, 0x5E6B4B0D, 0x3255BFEF, 0x95601890, 0xAFD80709]);
    }

    #[test]
    fn hash_new() {
        let hash = Hash::<Arch>::new();
        let digest = Digest::try_from("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709").unwrap();
        assert_eq!(hash.digest(), digest);
    }

    #[test]
    fn hash_hello_world() {
        let mut hash = Hash::<Arch>::new();
        let data = "Hello World".as_bytes();
        hash.update(data);
        let digest = Digest::try_from("0A4D55A8D778E5022FAB701977C5D840BBC486D0").unwrap();
        assert_eq!(hash.digest(), digest);
    }

    #[test]
    fn hash_hello_world_by_chunks() {
        let mut hash = Hash::<Arch>::new();
        let data = "Hello".as_bytes();
        hash.update(data);
        let data = " ".as_bytes();
        hash.update(data);
        let data = "World".as_bytes();
        hash.update(data);
        let digest = Digest::try_from("0A4D55A8D778E5022FAB701977C5D840BBC486D0").unwrap();
        assert_eq!(hash.digest(), digest);
    }
}
