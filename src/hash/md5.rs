//! Implementation of MD5 hash function based on [RFC 1321: The MD5 Message-Digest Algorithm](https://tools.ietf.org/html/rfc1321).
//!
//! # Examples
//!
//! ```rust
//! use chksum::hash::md5::State;
//!
//! let mut state = State::<u32>::new();
//! assert_eq!(state.digest(), [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]);
//! let data = [u32::from_le_bytes([0x80, 0x00, 0x00, 0x00]), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
//! state.update(data);
//! assert_eq!(state.digest(), [0xD98C1DD4, 0x04B2008F, 0x980980E9, 0x7E42f8EC]);
//! ```
//!
//! ```rust
//! use chksum::hash::md5::State;
//!
//! let mut state = State::<u32>::new();
//! assert_eq!(state.digest(), [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]);
//! let data = [u32::from_le_bytes([0x31, 0x32, 0x33, 0x34]), u32::from_le_bytes([0x35, 0x36, 0x37, 0x38]), u32::from_le_bytes([0x39, 0x30, 0x31, 0x32]), u32::from_le_bytes([0x33, 0x34, 0x35, 0x36]), u32::from_le_bytes([0x37, 0x38, 0x39, 0x30]), u32::from_le_bytes([0x31, 0x32, 0x33, 0x34]), u32::from_le_bytes([0x35, 0x36, 0x37, 0x38]), u32::from_le_bytes([0x39, 0x30, 0x31, 0x32]), u32::from_le_bytes([0x33, 0x34, 0x35, 0x36]), u32::from_le_bytes([0x37, 0x38, 0x39, 0x30]), u32::from_le_bytes([0x31, 0x32, 0x33, 0x34]), u32::from_le_bytes([0x35, 0x36, 0x37, 0x38]), u32::from_le_bytes([0x39, 0x30, 0x31, 0x32]), u32::from_le_bytes([0x33, 0x34, 0x35, 0x36]), u32::from_le_bytes([0x37, 0x38, 0x39, 0x30]), u32::from_le_bytes([0x31, 0x32, 0x33, 0x34])];
//! state.update(data);
//! let data = [u32::from_le_bytes([0x35, 0x36, 0x37, 0x38]), u32::from_le_bytes([0x39, 0x30, 0x31, 0x32]), u32::from_le_bytes([0x33, 0x34, 0x35, 0x36]), u32::from_le_bytes([0x37, 0x38, 0x39, 0x30]), u32::from_le_bytes([0x80, 0x00, 0x00, 0x00]), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, u32::from_le_bytes([0x80, 0x02, 0x00, 0x00]), 0x00];
//! state.update(data);
//! assert_eq!(state.digest(), [0xA2F4ED57, 0x55C9E32B, 0x2EDA49AC, 0x7AB60721]);
//! ```

use std::convert::{From, TryFrom, TryInto};
use std::fmt::{self, Debug, Formatter};
use std::ops::{BitAnd, BitOr, BitXor, Not, Shl, Shr};

use crate::arch::Arch;
use crate::convert::{arch::From1, FromLeBytes, ToLeBytes};
use crate::num::WrappingAdd;

const BLOCK_LENGTH_BITS: usize = 512;
const BLOCK_LENGTH_BYTES: usize = BLOCK_LENGTH_BITS / 8;
const BLOCK_LENGTH_WORDS: usize = BLOCK_LENGTH_BYTES / 2;
const BLOCK_LENGTH_DWORDS: usize = BLOCK_LENGTH_WORDS / 2;

const DIGEST_LENGTH_BITS: usize = 128;
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
const CONSTS: [u32; 64] = [
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE, 0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C, 0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1, 0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
];

#[allow(clippy::unreadable_literal)]
const SHIFTS: [u8; 32] = [
    0x07, 0x19, 0x0C, 0x14, 0x11, 0x0F, 0x16, 0x0A,
    0x05, 0x1B, 0x09, 0x17, 0x0E, 0x12, 0x14, 0x0C,
    0x04, 0x1C, 0x0B, 0x15, 0x10, 0x10, 0x17, 0x09,
    0x06, 0x1A, 0x0A, 0x16, 0x0F, 0x11, 0x15, 0x0B,
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
    consts: [T; 64],
    shifts: [T; 32],
}

impl<T> State<T>
where T: BitAnd<Output = T> + BitOr<Output = T> + BitXor<Output = T> + Copy + From<u32> + From1<u8> + Not<Output = T> + Shl<Output = T> + Shr<Output = T> + WrappingAdd<Output = T> + WrappingAdd<u32, Output = T> {
    /// Create new state instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum::hash::md5::State;
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
            consts: [
                T::from(CONSTS[ 0]), T::from(CONSTS[ 1]), T::from(CONSTS[ 2]), T::from(CONSTS[ 3]), T::from(CONSTS[ 4]), T::from(CONSTS[ 5]), T::from(CONSTS[ 6]), T::from(CONSTS[ 7]),
                T::from(CONSTS[ 8]), T::from(CONSTS[ 9]), T::from(CONSTS[10]), T::from(CONSTS[11]), T::from(CONSTS[12]), T::from(CONSTS[13]), T::from(CONSTS[14]), T::from(CONSTS[15]),
                T::from(CONSTS[16]), T::from(CONSTS[17]), T::from(CONSTS[18]), T::from(CONSTS[19]), T::from(CONSTS[20]), T::from(CONSTS[21]), T::from(CONSTS[22]), T::from(CONSTS[23]),
                T::from(CONSTS[24]), T::from(CONSTS[25]), T::from(CONSTS[26]), T::from(CONSTS[27]), T::from(CONSTS[28]), T::from(CONSTS[29]), T::from(CONSTS[30]), T::from(CONSTS[31]),
                T::from(CONSTS[32]), T::from(CONSTS[33]), T::from(CONSTS[34]), T::from(CONSTS[35]), T::from(CONSTS[36]), T::from(CONSTS[37]), T::from(CONSTS[38]), T::from(CONSTS[39]),
                T::from(CONSTS[40]), T::from(CONSTS[41]), T::from(CONSTS[42]), T::from(CONSTS[43]), T::from(CONSTS[44]), T::from(CONSTS[45]), T::from(CONSTS[46]), T::from(CONSTS[47]),
                T::from(CONSTS[48]), T::from(CONSTS[49]), T::from(CONSTS[50]), T::from(CONSTS[51]), T::from(CONSTS[52]), T::from(CONSTS[53]), T::from(CONSTS[54]), T::from(CONSTS[55]),
                T::from(CONSTS[56]), T::from(CONSTS[57]), T::from(CONSTS[58]), T::from(CONSTS[59]), T::from(CONSTS[60]), T::from(CONSTS[61]), T::from(CONSTS[62]), T::from(CONSTS[63]),
            ],
            shifts: [
                T::from1(SHIFTS[ 0]), T::from1(SHIFTS[ 1]), T::from1(SHIFTS[ 2]), T::from1(SHIFTS[ 3]), T::from1(SHIFTS[ 4]), T::from1(SHIFTS[ 5]), T::from1(SHIFTS[ 6]), T::from1(SHIFTS[ 7]),
                T::from1(SHIFTS[ 8]), T::from1(SHIFTS[ 9]), T::from1(SHIFTS[10]), T::from1(SHIFTS[11]), T::from1(SHIFTS[12]), T::from1(SHIFTS[13]), T::from1(SHIFTS[14]), T::from1(SHIFTS[15]),
                T::from1(SHIFTS[16]), T::from1(SHIFTS[17]), T::from1(SHIFTS[18]), T::from1(SHIFTS[19]), T::from1(SHIFTS[20]), T::from1(SHIFTS[21]), T::from1(SHIFTS[22]), T::from1(SHIFTS[23]),
                T::from1(SHIFTS[24]), T::from1(SHIFTS[25]), T::from1(SHIFTS[26]), T::from1(SHIFTS[27]), T::from1(SHIFTS[28]), T::from1(SHIFTS[29]), T::from1(SHIFTS[30]), T::from1(SHIFTS[31]),
            ],
        }
    }

    /// Update state with block of data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum::hash::md5::State;
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
        let (a, b, c, d) = (self.a, self.b, self.c, self.d);

        // Round 1

        #[cfg_attr(feature = "inline", inline)]
        fn f<T>(x: T, y: T, z: T) -> T
        where T: BitAnd<Output = T> + BitOr<Output = T> + Copy + Not<Output = T> {
            (x & y) | (!x & z)
        }

        #[allow(
            clippy::similar_names,
            clippy::many_single_char_names,
            clippy::too_many_arguments,
        )]
        #[cfg_attr(feature = "inline", inline)]
        fn ff<T>(a: T, b: T, c: T, d: T, data: T, shl: T, shr: T, constant: T) -> T
        where T: BitAnd<Output = T> + BitOr<Output = T> + Copy + Not<Output = T> + Shl<Output = T> + Shr<Output = T> + WrappingAdd<Output = T> + WrappingAdd<u32, Output = T> {
            let x = a.wrapping_add(f(b, c, d)).wrapping_add(data).wrapping_add(constant);
            ((x << shl) | (x >> shr)).wrapping_add(b)
        }

        let a = ff(a, b, c, d, block[0x0], self.shifts[0x0], self.shifts[0x1], self.consts[0x00]);
        let d = ff(d, a, b, c, block[0x1], self.shifts[0x2], self.shifts[0x3], self.consts[0x01]);
        let c = ff(c, d, a, b, block[0x2], self.shifts[0x4], self.shifts[0x5], self.consts[0x02]);
        let b = ff(b, c, d, a, block[0x3], self.shifts[0x6], self.shifts[0x7], self.consts[0x03]);
        let a = ff(a, b, c, d, block[0x4], self.shifts[0x0], self.shifts[0x1], self.consts[0x04]);
        let d = ff(d, a, b, c, block[0x5], self.shifts[0x2], self.shifts[0x3], self.consts[0x05]);
        let c = ff(c, d, a, b, block[0x6], self.shifts[0x4], self.shifts[0x5], self.consts[0x06]);
        let b = ff(b, c, d, a, block[0x7], self.shifts[0x6], self.shifts[0x7], self.consts[0x07]);
        let a = ff(a, b, c, d, block[0x8], self.shifts[0x0], self.shifts[0x1], self.consts[0x08]);
        let d = ff(d, a, b, c, block[0x9], self.shifts[0x2], self.shifts[0x3], self.consts[0x09]);
        let c = ff(c, d, a, b, block[0xA], self.shifts[0x4], self.shifts[0x5], self.consts[0x0A]);
        let b = ff(b, c, d, a, block[0xB], self.shifts[0x6], self.shifts[0x7], self.consts[0x0B]);
        let a = ff(a, b, c, d, block[0xC], self.shifts[0x0], self.shifts[0x1], self.consts[0x0C]);
        let d = ff(d, a, b, c, block[0xD], self.shifts[0x2], self.shifts[0x3], self.consts[0x0D]);
        let c = ff(c, d, a, b, block[0xE], self.shifts[0x4], self.shifts[0x5], self.consts[0x0E]);
        let b = ff(b, c, d, a, block[0xF], self.shifts[0x6], self.shifts[0x7], self.consts[0x0F]);

        // Round 2

        #[cfg_attr(feature = "inline", inline)]
        fn g<T>(x: T, y: T, z: T) -> T
        where T: BitAnd<Output = T> + BitOr<Output = T> + Copy + Not<Output = T> {
            (x & z) | (y & !z)
        }

        #[allow(
            clippy::similar_names,
            clippy::many_single_char_names,
            clippy::too_many_arguments,
        )]
        #[cfg_attr(feature = "inline", inline)]
        fn gg<T>(a: T, b: T, c: T, d: T, data: T, shl: T, shr: T, constant: T) -> T
        where T: BitAnd<Output = T> + BitOr<Output = T> + Copy + Not<Output = T> + Shl<Output = T> + Shr<Output = T> + WrappingAdd<Output = T> + WrappingAdd<u32, Output = T> {
            let x = a.wrapping_add(g(b, c, d)).wrapping_add(data).wrapping_add(constant);
            ((x << shl) | (x >> shr)).wrapping_add(b)
        }

        let a = gg(a, b, c, d, block[0x1], self.shifts[0x08], self.shifts[0x09], self.consts[0x10]);
        let d = gg(d, a, b, c, block[0x6], self.shifts[0x0A], self.shifts[0x0B], self.consts[0x11]);
        let c = gg(c, d, a, b, block[0xB], self.shifts[0x0C], self.shifts[0x0D], self.consts[0x12]);
        let b = gg(b, c, d, a, block[0x0], self.shifts[0x0E], self.shifts[0x0F], self.consts[0x13]);
        let a = gg(a, b, c, d, block[0x5], self.shifts[0x08], self.shifts[0x09], self.consts[0x14]);
        let d = gg(d, a, b, c, block[0xA], self.shifts[0x0A], self.shifts[0x0B], self.consts[0x15]);
        let c = gg(c, d, a, b, block[0xF], self.shifts[0x0C], self.shifts[0x0D], self.consts[0x16]);
        let b = gg(b, c, d, a, block[0x4], self.shifts[0x0E], self.shifts[0x0F], self.consts[0x17]);
        let a = gg(a, b, c, d, block[0x9], self.shifts[0x08], self.shifts[0x09], self.consts[0x18]);
        let d = gg(d, a, b, c, block[0xE], self.shifts[0x0A], self.shifts[0x0B], self.consts[0x19]);
        let c = gg(c, d, a, b, block[0x3], self.shifts[0x0C], self.shifts[0x0D], self.consts[0x1A]);
        let b = gg(b, c, d, a, block[0x8], self.shifts[0x0E], self.shifts[0x0F], self.consts[0x1B]);
        let a = gg(a, b, c, d, block[0xD], self.shifts[0x08], self.shifts[0x09], self.consts[0x1C]);
        let d = gg(d, a, b, c, block[0x2], self.shifts[0x0A], self.shifts[0x0B], self.consts[0x1D]);
        let c = gg(c, d, a, b, block[0x7], self.shifts[0x0C], self.shifts[0x0D], self.consts[0x1E]);
        let b = gg(b, c, d, a, block[0xC], self.shifts[0x0E], self.shifts[0x0F], self.consts[0x1F]);

        // Round 3

        #[cfg_attr(feature = "inline", inline)]
        fn h<T>(x: T, y: T, z: T) -> T
        where T: BitXor<Output = T> + Copy {
            x ^ y ^ z
        }

        #[allow(
            clippy::similar_names,
            clippy::many_single_char_names,
            clippy::too_many_arguments,
        )]
        #[cfg_attr(feature = "inline", inline)]
        fn hh<T>(a: T, b: T, c: T, d: T, data: T, shl: T, shr: T, constant: T) -> T
        where T: BitOr<Output = T> + BitXor<Output = T> + Copy + Shl<Output = T> + Shr<Output = T> + WrappingAdd<Output = T> + WrappingAdd<u32, Output = T> {
            let x = a.wrapping_add(h(b, c, d)).wrapping_add(data).wrapping_add(constant);
            ((x << shl) | (x >> shr)).wrapping_add(b)
        }

        let a = hh(a, b, c, d, block[0x5], self.shifts[0x10], self.shifts[0x11], self.consts[0x20]);
        let d = hh(d, a, b, c, block[0x8], self.shifts[0x12], self.shifts[0x13], self.consts[0x21]);
        let c = hh(c, d, a, b, block[0xB], self.shifts[0x14], self.shifts[0x15], self.consts[0x22]);
        let b = hh(b, c, d, a, block[0xE], self.shifts[0x16], self.shifts[0x17], self.consts[0x23]);
        let a = hh(a, b, c, d, block[0x1], self.shifts[0x10], self.shifts[0x11], self.consts[0x24]);
        let d = hh(d, a, b, c, block[0x4], self.shifts[0x12], self.shifts[0x13], self.consts[0x25]);
        let c = hh(c, d, a, b, block[0x7], self.shifts[0x14], self.shifts[0x15], self.consts[0x26]);
        let b = hh(b, c, d, a, block[0xA], self.shifts[0x16], self.shifts[0x17], self.consts[0x27]);
        let a = hh(a, b, c, d, block[0xD], self.shifts[0x10], self.shifts[0x11], self.consts[0x28]);
        let d = hh(d, a, b, c, block[0x0], self.shifts[0x12], self.shifts[0x13], self.consts[0x29]);
        let c = hh(c, d, a, b, block[0x3], self.shifts[0x14], self.shifts[0x15], self.consts[0x2A]);
        let b = hh(b, c, d, a, block[0x6], self.shifts[0x16], self.shifts[0x17], self.consts[0x2B]);
        let a = hh(a, b, c, d, block[0x9], self.shifts[0x10], self.shifts[0x11], self.consts[0x2C]);
        let d = hh(d, a, b, c, block[0xC], self.shifts[0x12], self.shifts[0x13], self.consts[0x2D]);
        let c = hh(c, d, a, b, block[0xF], self.shifts[0x14], self.shifts[0x15], self.consts[0x2E]);
        let b = hh(b, c, d, a, block[0x2], self.shifts[0x16], self.shifts[0x17], self.consts[0x2F]);

        // Round 4

        #[cfg_attr(feature = "inline", inline)]
        fn i<T>(x: T, y: T, z: T) -> T
        where T: BitOr<Output = T> + BitXor<Output = T> + Copy + Not<Output = T> {
            y ^ (x | !z)
        }

        #[allow(
            clippy::similar_names,
            clippy::many_single_char_names,
            clippy::too_many_arguments,
        )]
        #[cfg_attr(feature = "inline", inline)]
        fn ii<T>(a: T, b: T, c: T, d: T, data: T, shl: T, shr: T, constant: T) -> T
        where T: BitOr<Output = T> + BitXor<Output = T> + Copy + Not<Output = T> + Shl<Output = T> + Shr<Output = T> + WrappingAdd<Output = T> + WrappingAdd<u32, Output = T> {
            let x = a.wrapping_add(i(b, c, d)).wrapping_add(data).wrapping_add(constant);
            ((x << shl) | (x >> shr)).wrapping_add(b)
        }

        let a = ii(a, b, c, d, block[0x0], self.shifts[0x18], self.shifts[0x19], self.consts[0x30]);
        let d = ii(d, a, b, c, block[0x7], self.shifts[0x1A], self.shifts[0x1B], self.consts[0x31]);
        let c = ii(c, d, a, b, block[0xE], self.shifts[0x1C], self.shifts[0x1D], self.consts[0x32]);
        let b = ii(b, c, d, a, block[0x5], self.shifts[0x1E], self.shifts[0x1F], self.consts[0x33]);
        let a = ii(a, b, c, d, block[0xC], self.shifts[0x18], self.shifts[0x19], self.consts[0x34]);
        let d = ii(d, a, b, c, block[0x3], self.shifts[0x1A], self.shifts[0x1B], self.consts[0x35]);
        let c = ii(c, d, a, b, block[0xA], self.shifts[0x1C], self.shifts[0x1D], self.consts[0x36]);
        let b = ii(b, c, d, a, block[0x1], self.shifts[0x1E], self.shifts[0x1F], self.consts[0x37]);
        let a = ii(a, b, c, d, block[0x8], self.shifts[0x18], self.shifts[0x19], self.consts[0x38]);
        let d = ii(d, a, b, c, block[0xF], self.shifts[0x1A], self.shifts[0x1B], self.consts[0x39]);
        let c = ii(c, d, a, b, block[0x6], self.shifts[0x1C], self.shifts[0x1D], self.consts[0x3A]);
        let b = ii(b, c, d, a, block[0xD], self.shifts[0x1E], self.shifts[0x1F], self.consts[0x3B]);
        let a = ii(a, b, c, d, block[0x4], self.shifts[0x18], self.shifts[0x19], self.consts[0x3C]);
        let d = ii(d, a, b, c, block[0xB], self.shifts[0x1A], self.shifts[0x1B], self.consts[0x3D]);
        let c = ii(c, d, a, b, block[0x2], self.shifts[0x1C], self.shifts[0x1D], self.consts[0x3E]);
        let b = ii(b, c, d, a, block[0x9], self.shifts[0x1E], self.shifts[0x1F], self.consts[0x3F]);

        // Update state

        self.a = self.a.wrapping_add(a);
        self.b = self.b.wrapping_add(b);
        self.c = self.c.wrapping_add(c);
        self.d = self.d.wrapping_add(d);
    }

    /// Return state digest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum::hash::md5::State;
    ///
    /// let mut state = State::<u32>::new();
    /// assert_eq!(state.digest(), [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]);
    /// ```
    #[cfg_attr(feature = "inline", inline)]
    pub fn digest(&self) -> [T; 4] {
        [self.a, self.b, self.c, self.d]
    }
}

impl<T: Debug> Debug for State<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("State")
         .field("a", &self.a)
         .field("b", &self.b)
         .field("c", &self.c)
         .field("d", &self.d)
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
    /// use chksum::hash::md5::State;
    ///
    /// let mut state = State::<u32>::new();
    /// let data = [0x00; 16];
    /// state.update(data);
    /// assert_ne!(state.digest(), [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]);
    /// state.reset();
    /// assert_eq!(state.digest(), [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]);
    /// ```
    #[cfg_attr(feature = "inline", inline)]
    fn reset(&mut self) {
        self.a = T::from(A);
        self.b = T::from(B);
        self.c = T::from(C);
        self.d = T::from(D);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Digest<T>([T; DIGEST_LENGTH_BYTES]);

impl super::ToHex for Digest<u8> {
    #[cfg_attr(feature = "inline", inline)]
    fn to_hex(&self) -> String {
        format!(
            "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.0[ 0], self.0[ 1], self.0[ 2], self.0[ 3],
            self.0[ 4], self.0[ 5], self.0[ 6], self.0[ 7],
            self.0[ 8], self.0[ 9], self.0[10], self.0[11],
            self.0[12], self.0[13], self.0[14], self.0[15],
        )
    }
}

impl<T, U> From<[U; DIGEST_LENGTH_DWORDS]> for Digest<T>
where T: Copy, U: ToLeBytes<T, 4> {
    #[cfg_attr(feature = "inline", inline)]
    fn from(digest: [U; DIGEST_LENGTH_DWORDS]) -> Self {
        let [a, b, c, d] = digest;
        let [a, b, c, d] = [a.to_le_bytes(), b.to_le_bytes(), c.to_le_bytes(), d.to_le_bytes()];
        Self(
            [
                a[0], a[1], a[2], a[3],
                b[0], b[1], b[2], b[3],
                c[0], c[1], c[2], c[3],
                d[0], d[1], d[2], d[3],
            ],
        )
    }
}

impl<T, U> From<State<U>> for Digest<T>
where T: Copy, U: ToLeBytes<T, 4> {
    #[cfg_attr(feature = "inline", inline)]
    fn from(state: State<U>) -> Self {
        let (a, b, c, d) = (state.a, state.b, state.c, state.d);
        Self::from([a, b, c, d])
    }
}

impl TryFrom<&str> for Digest<u8> {
    type Error = &'static str;

    #[allow(clippy::shadow_unrelated)]
    #[cfg_attr(feature = "inline", inline)]
    fn try_from(digest: &str) -> Result<Self, Self::Error> {
        if digest.len() != DIGEST_LENGTH_HEX {
            // fixme panic or not to panic?
        }
        let (a, b, c, d) = (
            u32::from_str_radix(&digest[ 0.. 8], 16).unwrap(), // todo fix unwrapping
            u32::from_str_radix(&digest[ 8..16], 16).unwrap(), // todo fix unwrapping
            u32::from_str_radix(&digest[16..24], 16).unwrap(), // todo fix unwrapping
            u32::from_str_radix(&digest[24..32], 16).unwrap(), // todo fix unwrapping
        );
        let (a, b, c, d) = (
            a.swap_bytes(),
            b.swap_bytes(),
            c.swap_bytes(),
            d.swap_bytes(),
        );
        let digest = [a, b, c, d];
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
where T: Arch, T::u8: Copy + From<u8>, T::u32: BitAnd<Output = T::u32> + BitOr<Output = T::u32> + BitXor<Output = T::u32> + Copy + From<u32> + From1<u8> + FromLeBytes<T::u8, 4> + Not<Output = T::u32> + Shl<Output = T::u32> + Shr<Output = T::u32> + ToLeBytes<T::u8, 4> + WrappingAdd<Output = T::u32> + WrappingAdd<u32, Output = T::u32> {
    /// Create new hash instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum::arch::x1::Arch;
    /// use chksum::hash::md5::Hash;
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
            T::u32::from_le_bytes([data[ 0], data[ 1], data[ 2], data[ 3]]),
            T::u32::from_le_bytes([data[ 4], data[ 5], data[ 6], data[ 7]]),
            T::u32::from_le_bytes([data[ 8], data[ 9], data[10], data[11]]),
            T::u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            T::u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            T::u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            T::u32::from_le_bytes([data[24], data[25], data[26], data[27]]),
            T::u32::from_le_bytes([data[28], data[29], data[30], data[31]]),
            T::u32::from_le_bytes([data[32], data[33], data[34], data[35]]),
            T::u32::from_le_bytes([data[36], data[37], data[38], data[39]]),
            T::u32::from_le_bytes([data[40], data[41], data[42], data[43]]),
            T::u32::from_le_bytes([data[44], data[45], data[46], data[47]]),
            T::u32::from_le_bytes([data[48], data[49], data[50], data[51]]),
            T::u32::from_le_bytes([data[52], data[53], data[54], data[55]]),
            T::u32::from_le_bytes([data[56], data[57], data[58], data[59]]),
            T::u32::from_le_bytes([data[60], data[61], data[62], data[63]]),
        ]
    }

    /// Update hash with data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum::arch::x1::Arch;
    /// use chksum::hash::md5::Hash;
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
        let length = length.to_le_bytes(); // fixme verify endianness
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
    /// use chksum::hash::md5::{Digest, Hash};
    ///
    /// let mut hash = Hash::<Arch>::new();
    /// let digest = Digest::try_from("D41D8CD98F00B204E9800998ECF8427E").unwrap();
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
where T::u8: Copy + From<u8>, T::u32: BitAnd<Output = T::u32> + BitOr<Output = T::u32> + BitXor<Output = T::u32> + Copy + From<u32> + From1<u8> + FromLeBytes<T::u8, 4> + Not<Output = T::u32> + Shl<Output = T::u32> + Shr<Output = T::u32> + ToLeBytes<T::u8, 4> + WrappingAdd<Output = T::u32> + WrappingAdd<u32, Output = T::u32> {
    type Digest = Digest<T::u8>;

    #[cfg_attr(feature = "inline", inline)]
    fn digest(&mut self) -> Self::Digest {
        Hash::digest(self)
    }
}

impl<T: Arch> super::Hash<T::u8> for Hash<T>
where T::u8: Copy + From<u8>, T::u32: BitAnd<Output = T::u32> + BitOr<Output = T::u32> + BitXor<Output = T::u32> + Copy + From<u32> + From1<u8> + FromLeBytes<T::u8, 4> + Not<Output = T::u32> + Shl<Output = T::u32> + Shr<Output = T::u32> + ToLeBytes<T::u8, 4> + WrappingAdd<Output = T::u32> + WrappingAdd<u32, Output = T::u32> {}

impl<T: Arch> super::Update<T::u8> for Hash<T>
where T::u8: Copy + From<u8>, T::u32: BitAnd<Output = T::u32> + BitOr<Output = T::u32> + BitXor<Output = T::u32> + Copy + From<u32> + From1<u8> + FromLeBytes<T::u8, 4> + Not<Output = T::u32> + Shl<Output = T::u32> + Shr<Output = T::u32> + ToLeBytes<T::u8, 4> + WrappingAdd<Output = T::u32> + WrappingAdd<u32, Output = T::u32> {
    #[cfg_attr(feature = "inline", inline)]
    fn update(&mut self, data: &[T::u8]) {
        Hash::update(self, data);
    }
}

impl<T> super::Reset for Hash<T>
where T: Arch, T::u8: Copy, T::u32: From<u32> {
    /// Reset hash.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::convert::TryFrom;
    /// use chksum::arch::x1::Arch;
    /// use chksum::hash::Reset;
    /// use chksum::hash::md5::{Digest, Hash};
    ///
    /// let mut hash = Hash::<Arch>::new();
    /// let data = [0x00u8; 16];
    /// hash.update(&data[..]);
    /// let digest = Digest::try_from("D41D8CD98F00B204E9800998ECF8427E").unwrap();
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
        assert_eq!(state.digest(), [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]);
    }

    #[test]
    fn state_empty() {
        let mut state = State::<u32>::new();
        state.update(
            [
                0x80, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]
        );
        assert_eq!(state.digest(), [0xD98C1DD4, 0x04B2008F, 0x980980E9, 0x7E42f8EC]);
    }

    #[test]
    fn hash_new() {
        let hash = Hash::<Arch>::new();
        let digest = Digest::try_from("D41D8CD98F00B204E9800998ECF8427E").unwrap();
        assert_eq!(hash.digest(), digest);
    }

    #[test]
    fn hash_hello_world() {
        let mut hash = Hash::<Arch>::new();
        let data = "Hello World".as_bytes();
        hash.update(data);
        let digest = Digest::try_from("B10A8DB164E0754105B7A99BE72E3FE5").unwrap();
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
        let digest = Digest::try_from("B10A8DB164E0754105B7A99BE72E3FE5").unwrap();
        assert_eq!(hash.digest(), digest);
    }
}
