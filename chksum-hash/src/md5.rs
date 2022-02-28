//! Implementation of MD5 hash function based on [RFC 1321: The MD5 Message-Digest Algorithm](https://tools.ietf.org/html/rfc1321).
//!
//! # Examples
//!
//! ```rust
//! use chksum_hash::md5::State;
//!
//! let mut state = State::<u32>::new();
//! assert_eq!(state.digest(), [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]);
//! let data = [
//!     u32::from_le_bytes([0x80, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//! ];
//! state.update(data);
//! assert_eq!(state.digest(), [0xD98C1DD4, 0x04B2008F, 0x980980E9, 0x7E42F8EC]);
//! ```
//!
//! ```rust
//! use chksum_hash::md5::State;
//!
//! let mut state = State::<u32>::new();
//! assert_eq!(state.digest(), [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]);
//! let data = [
//!     u32::from_le_bytes([0x31, 0x32, 0x33, 0x34]),
//!     u32::from_le_bytes([0x35, 0x36, 0x37, 0x38]),
//!     u32::from_le_bytes([0x39, 0x30, 0x31, 0x32]),
//!     u32::from_le_bytes([0x33, 0x34, 0x35, 0x36]),
//!     u32::from_le_bytes([0x37, 0x38, 0x39, 0x30]),
//!     u32::from_le_bytes([0x31, 0x32, 0x33, 0x34]),
//!     u32::from_le_bytes([0x35, 0x36, 0x37, 0x38]),
//!     u32::from_le_bytes([0x39, 0x30, 0x31, 0x32]),
//!     u32::from_le_bytes([0x33, 0x34, 0x35, 0x36]),
//!     u32::from_le_bytes([0x37, 0x38, 0x39, 0x30]),
//!     u32::from_le_bytes([0x31, 0x32, 0x33, 0x34]),
//!     u32::from_le_bytes([0x35, 0x36, 0x37, 0x38]),
//!     u32::from_le_bytes([0x39, 0x30, 0x31, 0x32]),
//!     u32::from_le_bytes([0x33, 0x34, 0x35, 0x36]),
//!     u32::from_le_bytes([0x37, 0x38, 0x39, 0x30]),
//!     u32::from_le_bytes([0x31, 0x32, 0x33, 0x34]),
//! ];
//! state.update(data);
//! let data = [
//!     u32::from_le_bytes([0x35, 0x36, 0x37, 0x38]),
//!     u32::from_le_bytes([0x39, 0x30, 0x31, 0x32]),
//!     u32::from_le_bytes([0x33, 0x34, 0x35, 0x36]),
//!     u32::from_le_bytes([0x37, 0x38, 0x39, 0x30]),
//!     u32::from_le_bytes([0x80, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//!     u32::from_le_bytes([0x80, 0x02, 0x00, 0x00]),
//!     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
//! ];
//! state.update(data);
//! assert_eq!(state.digest(), [0xA2F4ED57, 0x55C9E32B, 0x2EDA49AC, 0x7AB60721]);
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
use chksum_traits::convert::From1;
#[cfg(feature = "std")]
use chksum_traits::convert::{FromLeBytes, ToLeBytes};
use chksum_traits::num::WrappingAdd;

#[cfg(feature = "std")]
use super::DigestError;

pub const BLOCK_LENGTH_BITS: usize = 512;
pub const BLOCK_LENGTH_BYTES: usize = BLOCK_LENGTH_BITS / 8;
pub const BLOCK_LENGTH_WORDS: usize = BLOCK_LENGTH_BYTES / 2;
pub const BLOCK_LENGTH_DWORDS: usize = BLOCK_LENGTH_WORDS / 2;

pub const DIGEST_LENGTH_BITS: usize = 128;
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
#[rustfmt::skip]
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
#[rustfmt::skip]
const SHIFTS: [u8; 32] = [
    0x07, 0x19, 0x0C, 0x14, 0x11, 0x0F, 0x16, 0x0A, 0x05, 0x1B, 0x09, 0x17, 0x0E, 0x12, 0x14, 0x0C,
    0x04, 0x1C, 0x0B, 0x15, 0x10, 0x10, 0x17, 0x09, 0x06, 0x1A, 0x0A, 0x16, 0x0F, 0x11, 0x15, 0x0B,
];

#[cfg(feature = "std")]
#[rustfmt::skip]
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
pub trait FFFunc:
    FFunc + Shl<Output = Self> + Shr<Output = Self> + WrappingAdd<Output = Self> + WrappingAdd<u32, Output = Self>
{
}

impl<T> FFFunc for T where
    T: FFunc + Shl<Output = Self> + Shr<Output = Self> + WrappingAdd<Output = Self> + WrappingAdd<u32, Output = Self>
{
}

#[cfg_attr(docsrs, doc(hidden))]
pub trait GFunc: BitAnd<Output = Self> + BitOr<Output = Self> + Copy + Not<Output = Self> {}

impl<T> GFunc for T where T: BitAnd<Output = Self> + BitOr<Output = Self> + Copy + Not<Output = Self> {}

#[cfg_attr(docsrs, doc(hidden))]
pub trait GGFunc:
    GFunc + Shl<Output = Self> + Shr<Output = Self> + WrappingAdd<Output = Self> + WrappingAdd<u32, Output = Self>
{
}

impl<T> GGFunc for T where
    T: GFunc + Shl<Output = Self> + Shr<Output = Self> + WrappingAdd<Output = Self> + WrappingAdd<u32, Output = Self>
{
}

#[cfg_attr(docsrs, doc(hidden))]
pub trait HFunc: BitXor<Output = Self> + Copy {}

impl<T> HFunc for T where T: BitXor<Output = Self> + Copy {}

#[cfg_attr(docsrs, doc(hidden))]
pub trait HHFunc:
    BitOr<Output = Self>
    + HFunc
    + Shl<Output = Self>
    + Shr<Output = Self>
    + WrappingAdd<Output = Self>
    + WrappingAdd<u32, Output = Self>
{
}

impl<T> HHFunc for T where
    T: BitOr<Output = Self>
        + HFunc
        + Shl<Output = Self>
        + Shr<Output = Self>
        + WrappingAdd<Output = Self>
        + WrappingAdd<u32, Output = Self>
{
}

#[cfg_attr(docsrs, doc(hidden))]
pub trait IFunc: BitOr<Output = Self> + BitXor<Output = Self> + Copy + Not<Output = Self> {}

impl<T> IFunc for T where T: BitOr<Output = Self> + BitXor<Output = Self> + Copy + Not<Output = Self> {}

#[cfg_attr(docsrs, doc(hidden))]
pub trait IIFunc:
    IFunc + Shl<Output = Self> + Shr<Output = Self> + WrappingAdd<Output = Self> + WrappingAdd<u32, Output = Self>
{
}

impl<T> IIFunc for T where
    T: IFunc + Shl<Output = Self> + Shr<Output = Self> + WrappingAdd<Output = Self> + WrappingAdd<u32, Output = Self>
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
    consts: [T; 64],
    shifts: [T; 32],
}

impl<T> State<T>
where
    T: FFFunc + GGFunc + HHFunc + IIFunc + From<u32> + From1<u8>,
{
    /// Create new state instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum_hash::md5::State;
    ///
    /// let state = State::<u32>::new();
    /// ```
    #[cfg_attr(not(debug_assertions), inline(always))]
    #[must_use]
    pub fn new() -> Self {
        Self::from_raw(T::from(A), T::from(B), T::from(C), T::from(D))
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    #[must_use]
    #[rustfmt::skip]
    pub fn from_raw(a: T, b: T, c: T, d: T) -> Self {
        Self {
            a, b, c, d,
            consts: [
                T::from(CONSTS[0x00]), T::from(CONSTS[0x01]), T::from(CONSTS[0x02]), T::from(CONSTS[0x03]),
                T::from(CONSTS[0x04]), T::from(CONSTS[0x05]), T::from(CONSTS[0x06]), T::from(CONSTS[0x07]),
                T::from(CONSTS[0x08]), T::from(CONSTS[0x09]), T::from(CONSTS[0x0A]), T::from(CONSTS[0x0B]),
                T::from(CONSTS[0x0C]), T::from(CONSTS[0x0D]), T::from(CONSTS[0x0E]), T::from(CONSTS[0x0F]),
                T::from(CONSTS[0x10]), T::from(CONSTS[0x11]), T::from(CONSTS[0x12]), T::from(CONSTS[0x13]),
                T::from(CONSTS[0x14]), T::from(CONSTS[0x15]), T::from(CONSTS[0x16]), T::from(CONSTS[0x17]),
                T::from(CONSTS[0x18]), T::from(CONSTS[0x19]), T::from(CONSTS[0x1A]), T::from(CONSTS[0x1B]),
                T::from(CONSTS[0x1C]), T::from(CONSTS[0x1D]), T::from(CONSTS[0x1E]), T::from(CONSTS[0x1F]),
                T::from(CONSTS[0x20]), T::from(CONSTS[0x21]), T::from(CONSTS[0x22]), T::from(CONSTS[0x23]),
                T::from(CONSTS[0x24]), T::from(CONSTS[0x25]), T::from(CONSTS[0x26]), T::from(CONSTS[0x27]),
                T::from(CONSTS[0x28]), T::from(CONSTS[0x29]), T::from(CONSTS[0x2A]), T::from(CONSTS[0x2B]),
                T::from(CONSTS[0x2C]), T::from(CONSTS[0x2D]), T::from(CONSTS[0x2E]), T::from(CONSTS[0x2F]),
                T::from(CONSTS[0x30]), T::from(CONSTS[0x31]), T::from(CONSTS[0x32]), T::from(CONSTS[0x33]),
                T::from(CONSTS[0x34]), T::from(CONSTS[0x35]), T::from(CONSTS[0x36]), T::from(CONSTS[0x37]),
                T::from(CONSTS[0x38]), T::from(CONSTS[0x39]), T::from(CONSTS[0x3A]), T::from(CONSTS[0x3B]),
                T::from(CONSTS[0x3C]), T::from(CONSTS[0x3D]), T::from(CONSTS[0x3E]), T::from(CONSTS[0x3F]),
            ],
            shifts: [
                T::from1(SHIFTS[0x00]), T::from1(SHIFTS[0x01]), T::from1(SHIFTS[0x02]), T::from1(SHIFTS[0x03]),
                T::from1(SHIFTS[0x04]), T::from1(SHIFTS[0x05]), T::from1(SHIFTS[0x06]), T::from1(SHIFTS[0x07]),
                T::from1(SHIFTS[0x08]), T::from1(SHIFTS[0x09]), T::from1(SHIFTS[0x0A]), T::from1(SHIFTS[0x0B]),
                T::from1(SHIFTS[0x0C]), T::from1(SHIFTS[0x0D]), T::from1(SHIFTS[0x0E]), T::from1(SHIFTS[0x0F]),
                T::from1(SHIFTS[0x10]), T::from1(SHIFTS[0x11]), T::from1(SHIFTS[0x12]), T::from1(SHIFTS[0x13]),
                T::from1(SHIFTS[0x14]), T::from1(SHIFTS[0x15]), T::from1(SHIFTS[0x16]), T::from1(SHIFTS[0x17]),
                T::from1(SHIFTS[0x18]), T::from1(SHIFTS[0x19]), T::from1(SHIFTS[0x1A]), T::from1(SHIFTS[0x1B]),
                T::from1(SHIFTS[0x1C]), T::from1(SHIFTS[0x1D]), T::from1(SHIFTS[0x1E]), T::from1(SHIFTS[0x1F]),
            ],
        }
    }

    /// Update state with block of data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum_hash::md5::State;
    ///
    /// let mut state = State::<u32>::new();
    /// let data = [0x00; 16];
    /// state.update(data);
    /// ```
    #[allow(clippy::items_after_statements, clippy::too_many_lines, clippy::shadow_unrelated)]
    pub fn update(&mut self, block: [T; BLOCK_LENGTH_DWORDS]) {
        let (a, b, c, d) = (self.a, self.b, self.c, self.d);

        // Round 1

        #[cfg_attr(not(debug_assertions), inline(always))]
        fn f<T>(x: T, y: T, z: T) -> T
        where
            T: FFunc,
        {
            (x & y) | (!x & z)
        }

        #[allow(clippy::similar_names, clippy::many_single_char_names, clippy::too_many_arguments)]
        #[cfg_attr(not(debug_assertions), inline(always))]
        fn ff<T>(a: T, b: T, c: T, d: T, data: T, shl: T, shr: T, constant: T) -> T
        where
            T: FFFunc,
        {
            let x = a.wrapping_add(f(b, c, d)).wrapping_add(data).wrapping_add(constant);
            ((x << shl) | (x >> shr)).wrapping_add(b)
        }

        let a = ff(
            a,
            b,
            c,
            d,
            block[0x0],
            self.shifts[0x0],
            self.shifts[0x1],
            self.consts[0x00],
        );
        let d = ff(
            d,
            a,
            b,
            c,
            block[0x1],
            self.shifts[0x2],
            self.shifts[0x3],
            self.consts[0x01],
        );
        let c = ff(
            c,
            d,
            a,
            b,
            block[0x2],
            self.shifts[0x4],
            self.shifts[0x5],
            self.consts[0x02],
        );
        let b = ff(
            b,
            c,
            d,
            a,
            block[0x3],
            self.shifts[0x6],
            self.shifts[0x7],
            self.consts[0x03],
        );
        let a = ff(
            a,
            b,
            c,
            d,
            block[0x4],
            self.shifts[0x0],
            self.shifts[0x1],
            self.consts[0x04],
        );
        let d = ff(
            d,
            a,
            b,
            c,
            block[0x5],
            self.shifts[0x2],
            self.shifts[0x3],
            self.consts[0x05],
        );
        let c = ff(
            c,
            d,
            a,
            b,
            block[0x6],
            self.shifts[0x4],
            self.shifts[0x5],
            self.consts[0x06],
        );
        let b = ff(
            b,
            c,
            d,
            a,
            block[0x7],
            self.shifts[0x6],
            self.shifts[0x7],
            self.consts[0x07],
        );
        let a = ff(
            a,
            b,
            c,
            d,
            block[0x8],
            self.shifts[0x0],
            self.shifts[0x1],
            self.consts[0x08],
        );
        let d = ff(
            d,
            a,
            b,
            c,
            block[0x9],
            self.shifts[0x2],
            self.shifts[0x3],
            self.consts[0x09],
        );
        let c = ff(
            c,
            d,
            a,
            b,
            block[0xA],
            self.shifts[0x4],
            self.shifts[0x5],
            self.consts[0x0A],
        );
        let b = ff(
            b,
            c,
            d,
            a,
            block[0xB],
            self.shifts[0x6],
            self.shifts[0x7],
            self.consts[0x0B],
        );
        let a = ff(
            a,
            b,
            c,
            d,
            block[0xC],
            self.shifts[0x0],
            self.shifts[0x1],
            self.consts[0x0C],
        );
        let d = ff(
            d,
            a,
            b,
            c,
            block[0xD],
            self.shifts[0x2],
            self.shifts[0x3],
            self.consts[0x0D],
        );
        let c = ff(
            c,
            d,
            a,
            b,
            block[0xE],
            self.shifts[0x4],
            self.shifts[0x5],
            self.consts[0x0E],
        );
        let b = ff(
            b,
            c,
            d,
            a,
            block[0xF],
            self.shifts[0x6],
            self.shifts[0x7],
            self.consts[0x0F],
        );

        // Round 2

        #[cfg_attr(not(debug_assertions), inline(always))]
        fn g<T>(x: T, y: T, z: T) -> T
        where
            T: GFunc,
        {
            (x & z) | (y & !z)
        }

        #[allow(clippy::similar_names, clippy::many_single_char_names, clippy::too_many_arguments)]
        #[cfg_attr(not(debug_assertions), inline(always))]
        fn gg<T>(a: T, b: T, c: T, d: T, data: T, shl: T, shr: T, constant: T) -> T
        where
            T: GGFunc,
        {
            let x = a.wrapping_add(g(b, c, d)).wrapping_add(data).wrapping_add(constant);
            ((x << shl) | (x >> shr)).wrapping_add(b)
        }

        let a = gg(
            a,
            b,
            c,
            d,
            block[0x1],
            self.shifts[0x08],
            self.shifts[0x09],
            self.consts[0x10],
        );
        let d = gg(
            d,
            a,
            b,
            c,
            block[0x6],
            self.shifts[0x0A],
            self.shifts[0x0B],
            self.consts[0x11],
        );
        let c = gg(
            c,
            d,
            a,
            b,
            block[0xB],
            self.shifts[0x0C],
            self.shifts[0x0D],
            self.consts[0x12],
        );
        let b = gg(
            b,
            c,
            d,
            a,
            block[0x0],
            self.shifts[0x0E],
            self.shifts[0x0F],
            self.consts[0x13],
        );
        let a = gg(
            a,
            b,
            c,
            d,
            block[0x5],
            self.shifts[0x08],
            self.shifts[0x09],
            self.consts[0x14],
        );
        let d = gg(
            d,
            a,
            b,
            c,
            block[0xA],
            self.shifts[0x0A],
            self.shifts[0x0B],
            self.consts[0x15],
        );
        let c = gg(
            c,
            d,
            a,
            b,
            block[0xF],
            self.shifts[0x0C],
            self.shifts[0x0D],
            self.consts[0x16],
        );
        let b = gg(
            b,
            c,
            d,
            a,
            block[0x4],
            self.shifts[0x0E],
            self.shifts[0x0F],
            self.consts[0x17],
        );
        let a = gg(
            a,
            b,
            c,
            d,
            block[0x9],
            self.shifts[0x08],
            self.shifts[0x09],
            self.consts[0x18],
        );
        let d = gg(
            d,
            a,
            b,
            c,
            block[0xE],
            self.shifts[0x0A],
            self.shifts[0x0B],
            self.consts[0x19],
        );
        let c = gg(
            c,
            d,
            a,
            b,
            block[0x3],
            self.shifts[0x0C],
            self.shifts[0x0D],
            self.consts[0x1A],
        );
        let b = gg(
            b,
            c,
            d,
            a,
            block[0x8],
            self.shifts[0x0E],
            self.shifts[0x0F],
            self.consts[0x1B],
        );
        let a = gg(
            a,
            b,
            c,
            d,
            block[0xD],
            self.shifts[0x08],
            self.shifts[0x09],
            self.consts[0x1C],
        );
        let d = gg(
            d,
            a,
            b,
            c,
            block[0x2],
            self.shifts[0x0A],
            self.shifts[0x0B],
            self.consts[0x1D],
        );
        let c = gg(
            c,
            d,
            a,
            b,
            block[0x7],
            self.shifts[0x0C],
            self.shifts[0x0D],
            self.consts[0x1E],
        );
        let b = gg(
            b,
            c,
            d,
            a,
            block[0xC],
            self.shifts[0x0E],
            self.shifts[0x0F],
            self.consts[0x1F],
        );

        // Round 3

        #[cfg_attr(not(debug_assertions), inline(always))]
        fn h<T>(x: T, y: T, z: T) -> T
        where
            T: HFunc,
        {
            x ^ y ^ z
        }

        #[allow(clippy::similar_names, clippy::many_single_char_names, clippy::too_many_arguments)]
        #[cfg_attr(not(debug_assertions), inline(always))]
        fn hh<T>(a: T, b: T, c: T, d: T, data: T, shl: T, shr: T, constant: T) -> T
        where
            T: HHFunc,
        {
            let x = a.wrapping_add(h(b, c, d)).wrapping_add(data).wrapping_add(constant);
            ((x << shl) | (x >> shr)).wrapping_add(b)
        }

        let a = hh(
            a,
            b,
            c,
            d,
            block[0x5],
            self.shifts[0x10],
            self.shifts[0x11],
            self.consts[0x20],
        );
        let d = hh(
            d,
            a,
            b,
            c,
            block[0x8],
            self.shifts[0x12],
            self.shifts[0x13],
            self.consts[0x21],
        );
        let c = hh(
            c,
            d,
            a,
            b,
            block[0xB],
            self.shifts[0x14],
            self.shifts[0x15],
            self.consts[0x22],
        );
        let b = hh(
            b,
            c,
            d,
            a,
            block[0xE],
            self.shifts[0x16],
            self.shifts[0x17],
            self.consts[0x23],
        );
        let a = hh(
            a,
            b,
            c,
            d,
            block[0x1],
            self.shifts[0x10],
            self.shifts[0x11],
            self.consts[0x24],
        );
        let d = hh(
            d,
            a,
            b,
            c,
            block[0x4],
            self.shifts[0x12],
            self.shifts[0x13],
            self.consts[0x25],
        );
        let c = hh(
            c,
            d,
            a,
            b,
            block[0x7],
            self.shifts[0x14],
            self.shifts[0x15],
            self.consts[0x26],
        );
        let b = hh(
            b,
            c,
            d,
            a,
            block[0xA],
            self.shifts[0x16],
            self.shifts[0x17],
            self.consts[0x27],
        );
        let a = hh(
            a,
            b,
            c,
            d,
            block[0xD],
            self.shifts[0x10],
            self.shifts[0x11],
            self.consts[0x28],
        );
        let d = hh(
            d,
            a,
            b,
            c,
            block[0x0],
            self.shifts[0x12],
            self.shifts[0x13],
            self.consts[0x29],
        );
        let c = hh(
            c,
            d,
            a,
            b,
            block[0x3],
            self.shifts[0x14],
            self.shifts[0x15],
            self.consts[0x2A],
        );
        let b = hh(
            b,
            c,
            d,
            a,
            block[0x6],
            self.shifts[0x16],
            self.shifts[0x17],
            self.consts[0x2B],
        );
        let a = hh(
            a,
            b,
            c,
            d,
            block[0x9],
            self.shifts[0x10],
            self.shifts[0x11],
            self.consts[0x2C],
        );
        let d = hh(
            d,
            a,
            b,
            c,
            block[0xC],
            self.shifts[0x12],
            self.shifts[0x13],
            self.consts[0x2D],
        );
        let c = hh(
            c,
            d,
            a,
            b,
            block[0xF],
            self.shifts[0x14],
            self.shifts[0x15],
            self.consts[0x2E],
        );
        let b = hh(
            b,
            c,
            d,
            a,
            block[0x2],
            self.shifts[0x16],
            self.shifts[0x17],
            self.consts[0x2F],
        );

        // Round 4

        #[cfg_attr(not(debug_assertions), inline(always))]
        fn i<T>(x: T, y: T, z: T) -> T
        where
            T: IFunc,
        {
            y ^ (x | !z)
        }

        #[allow(clippy::similar_names, clippy::many_single_char_names, clippy::too_many_arguments)]
        #[cfg_attr(not(debug_assertions), inline(always))]
        fn ii<T>(a: T, b: T, c: T, d: T, data: T, shl: T, shr: T, constant: T) -> T
        where
            T: IIFunc,
        {
            let x = a.wrapping_add(i(b, c, d)).wrapping_add(data).wrapping_add(constant);
            ((x << shl) | (x >> shr)).wrapping_add(b)
        }

        let a = ii(
            a,
            b,
            c,
            d,
            block[0x0],
            self.shifts[0x18],
            self.shifts[0x19],
            self.consts[0x30],
        );
        let d = ii(
            d,
            a,
            b,
            c,
            block[0x7],
            self.shifts[0x1A],
            self.shifts[0x1B],
            self.consts[0x31],
        );
        let c = ii(
            c,
            d,
            a,
            b,
            block[0xE],
            self.shifts[0x1C],
            self.shifts[0x1D],
            self.consts[0x32],
        );
        let b = ii(
            b,
            c,
            d,
            a,
            block[0x5],
            self.shifts[0x1E],
            self.shifts[0x1F],
            self.consts[0x33],
        );
        let a = ii(
            a,
            b,
            c,
            d,
            block[0xC],
            self.shifts[0x18],
            self.shifts[0x19],
            self.consts[0x34],
        );
        let d = ii(
            d,
            a,
            b,
            c,
            block[0x3],
            self.shifts[0x1A],
            self.shifts[0x1B],
            self.consts[0x35],
        );
        let c = ii(
            c,
            d,
            a,
            b,
            block[0xA],
            self.shifts[0x1C],
            self.shifts[0x1D],
            self.consts[0x36],
        );
        let b = ii(
            b,
            c,
            d,
            a,
            block[0x1],
            self.shifts[0x1E],
            self.shifts[0x1F],
            self.consts[0x37],
        );
        let a = ii(
            a,
            b,
            c,
            d,
            block[0x8],
            self.shifts[0x18],
            self.shifts[0x19],
            self.consts[0x38],
        );
        let d = ii(
            d,
            a,
            b,
            c,
            block[0xF],
            self.shifts[0x1A],
            self.shifts[0x1B],
            self.consts[0x39],
        );
        let c = ii(
            c,
            d,
            a,
            b,
            block[0x6],
            self.shifts[0x1C],
            self.shifts[0x1D],
            self.consts[0x3A],
        );
        let b = ii(
            b,
            c,
            d,
            a,
            block[0xD],
            self.shifts[0x1E],
            self.shifts[0x1F],
            self.consts[0x3B],
        );
        let a = ii(
            a,
            b,
            c,
            d,
            block[0x4],
            self.shifts[0x18],
            self.shifts[0x19],
            self.consts[0x3C],
        );
        let d = ii(
            d,
            a,
            b,
            c,
            block[0xB],
            self.shifts[0x1A],
            self.shifts[0x1B],
            self.consts[0x3D],
        );
        let c = ii(
            c,
            d,
            a,
            b,
            block[0x2],
            self.shifts[0x1C],
            self.shifts[0x1D],
            self.consts[0x3E],
        );
        let b = ii(
            b,
            c,
            d,
            a,
            block[0x9],
            self.shifts[0x1E],
            self.shifts[0x1F],
            self.consts[0x3F],
        );

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
    /// use chksum_hash::md5::State;
    ///
    /// let mut state = State::<u32>::new();
    /// assert_eq!(state.digest(), [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]);
    /// ```
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn digest(&self) -> [T; 4] {
        [self.a, self.b, self.c, self.d]
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
            .finish()
    }
}

impl<T> Default for State<T>
where
    T: FFFunc + GGFunc + HHFunc + IIFunc + From<u32> + From1<u8>,
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
    /// use chksum_hash::md5::State;
    /// use chksum_hash::Reset;
    ///
    /// let mut state = State::<u32>::new();
    /// let data = [0x00; 16];
    /// state.update(data);
    /// assert_ne!(state.digest(), [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]);
    /// state.reset();
    /// assert_eq!(state.digest(), [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]);
    /// ```
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn reset(&mut self) {
        self.a = T::from(A);
        self.b = T::from(B);
        self.c = T::from(C);
        self.d = T::from(D);
    }
}

/// Represents hash digest.
///
/// # Examples
///
/// ```rust
/// use chksum_hash::md5::Digest;
///
/// let digest = Digest::try_from("d41d8cd98f00b204e9800998ecf8427e").unwrap();
/// println!("digest {:?}", digest);
/// println!("digest {:x}", digest);
/// println!("digest {:X}", digest);
/// ```
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Digest<T>([T; DIGEST_LENGTH_BYTES]);

#[cfg(feature = "std")]
impl fmt::LowerHex for Digest<u8> {
    #[cfg_attr(not(debug_assertions), inline(always))]
    #[rustfmt::skip]
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let digest = format!(
            "{:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}",
            self.0[0x0], self.0[0x1], self.0[0x2], self.0[0x3],
            self.0[0x4], self.0[0x5], self.0[0x6], self.0[0x7],
            self.0[0x8], self.0[0x9], self.0[0xA], self.0[0xB],
            self.0[0xC], self.0[0xD], self.0[0xE], self.0[0xF],
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
    #[rustfmt::skip]
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let digest = format!(
            "{:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}",
            self.0[0x0], self.0[0x1], self.0[0x2], self.0[0x3],
            self.0[0x4], self.0[0x5], self.0[0x6], self.0[0x7],
            self.0[0x8], self.0[0x9], self.0[0xA], self.0[0xB],
            self.0[0xC], self.0[0xD], self.0[0xE], self.0[0xF],
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
    U: ToLeBytes<T, 4>,
{
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(digest: [U; DIGEST_LENGTH_DWORDS]) -> Self {
        let [a, b, c, d] = digest;
        let [a, b, c, d] = [a.to_le_bytes(), b.to_le_bytes(), c.to_le_bytes(), d.to_le_bytes()];
        Self([
            a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3], c[0], c[1], c[2], c[3], d[0], d[1], d[2], d[3],
        ])
    }
}

#[cfg(feature = "std")]
impl<T, U> From<State<U>> for Digest<T>
where
    T: Copy,
    U: ToLeBytes<T, 4>,
{
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(state: State<U>) -> Self {
        let (a, b, c, d) = (state.a, state.b, state.c, state.d);
        Self::from([a, b, c, d])
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

    #[allow(clippy::shadow_unrelated)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn try_from(digest: &str) -> Result<Self, Self::Error> {
        if digest.len() != DIGEST_LENGTH_HEX {
            let error = DigestError::InvalidLength {
                value: digest.len(),
                proper: DIGEST_LENGTH_HEX,
            };
            return Err(error);
        }
        let (a, b, c, d) = (
            u32::from_str_radix(&digest[0x00..0x08], 16)?,
            u32::from_str_radix(&digest[0x08..0x10], 16)?,
            u32::from_str_radix(&digest[0x10..0x18], 16)?,
            u32::from_str_radix(&digest[0x18..0x20], 16)?,
        );
        let (a, b, c, d) = (a.swap_bytes(), b.swap_bytes(), c.swap_bytes(), d.swap_bytes());
        let digest = [a, b, c, d];
        let digest = Self::from(digest);
        Ok(digest)
    }
}

/// Hash struct with internal buffer which allows to process input data.
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
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
    T::u32: FFFunc + GGFunc + HHFunc + IIFunc + From<u32> + From1<u8> + FromLeBytes<T::u8, 4> + ToLeBytes<T::u8, 4>,
{
    /// Create new hash instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum_arch::x1::Arch;
    /// use chksum_hash::md5::Hash;
    ///
    /// let hash = Hash::<Arch>::new();
    /// ```
    #[cfg_attr(not(debug_assertions), inline(always))]
    #[must_use]
    #[rustfmt::skip]
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
            T::u32::from_le_bytes([data[0x00], data[0x01], data[0x02], data[0x03]]),
            T::u32::from_le_bytes([data[0x04], data[0x05], data[0x06], data[0x07]]),
            T::u32::from_le_bytes([data[0x08], data[0x09], data[0x0A], data[0x0B]]),
            T::u32::from_le_bytes([data[0x0C], data[0x0D], data[0x0E], data[0x0F]]),
            T::u32::from_le_bytes([data[0x10], data[0x11], data[0x12], data[0x13]]),
            T::u32::from_le_bytes([data[0x14], data[0x15], data[0x16], data[0x17]]),
            T::u32::from_le_bytes([data[0x18], data[0x19], data[0x1A], data[0x1B]]),
            T::u32::from_le_bytes([data[0x1C], data[0x1D], data[0x1E], data[0x1F]]),
            T::u32::from_le_bytes([data[0x20], data[0x21], data[0x22], data[0x23]]),
            T::u32::from_le_bytes([data[0x24], data[0x25], data[0x26], data[0x27]]),
            T::u32::from_le_bytes([data[0x28], data[0x29], data[0x2A], data[0x2B]]),
            T::u32::from_le_bytes([data[0x2C], data[0x2D], data[0x2E], data[0x2F]]),
            T::u32::from_le_bytes([data[0x30], data[0x31], data[0x32], data[0x33]]),
            T::u32::from_le_bytes([data[0x34], data[0x35], data[0x36], data[0x37]]),
            T::u32::from_le_bytes([data[0x38], data[0x39], data[0x3A], data[0x3B]]),
            T::u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]),
        ]
    }

    /// Update hash with data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum_arch::x1::Arch;
    /// use chksum_hash::md5::Hash;
    ///
    /// let mut hash = Hash::<Arch>::new();
    /// let data = [0, 1, 2, 3];
    /// hash.update(data);
    /// let data = "string";
    /// hash.update(data);
    /// ```
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
        let length = length.to_le_bytes();
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
    /// use chksum_hash::md5::{Digest, Hash};
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
    T::u32: FFFunc + GGFunc + HHFunc + IIFunc + From<u32> + From1<u8> + FromLeBytes<T::u8, 4> + ToLeBytes<T::u8, 4>,
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
    T::u32: FFFunc + GGFunc + HHFunc + IIFunc + From<u32> + From1<u8> + FromLeBytes<T::u8, 4> + ToLeBytes<T::u8, 4>,
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
    T::u32: FFFunc + GGFunc + HHFunc + IIFunc + From<u32> + From1<u8> + FromLeBytes<T::u8, 4> + ToLeBytes<T::u8, 4>,
{
}

#[cfg(feature = "std")]
impl<T: Arch> super::Update<T::u8> for Hash<T>
where
    T::u8: Copy + From<u8>,
    T::u32: BitAnd<Output = T::u32>
        + BitOr<Output = T::u32>
        + BitXor<Output = T::u32>
        + Copy
        + From<u32>
        + From1<u8>
        + FromLeBytes<T::u8, 4>
        + Not<Output = T::u32>
        + Shl<Output = T::u32>
        + Shr<Output = T::u32>
        + ToLeBytes<T::u8, 4>
        + WrappingAdd<Output = T::u32>
        + WrappingAdd<u32, Output = T::u32>,
{
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn update<D: AsRef<[T::u8]>>(&mut self, data: D) {
        Hash::update(self, data);
    }
}

#[cfg(feature = "std")]
impl<T> super::Reset for Hash<T>
where
    T: Arch,
    T::u8: Copy,
    T::u32: From<u32>,
{
    /// Reset hash.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::convert::TryFrom;
    ///
    /// use chksum_arch::x1::Arch;
    /// use chksum_hash::md5::{Digest, Hash};
    /// use chksum_hash::Reset;
    ///
    /// let mut hash = Hash::<Arch>::new();
    /// let data = [0x00u8; 16];
    /// hash.update(&data[..]);
    /// let digest = Digest::try_from("D41D8CD98F00B204E9800998ECF8427E").unwrap();
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
#[rustfmt::skip]
mod tests {
    #[cfg(feature = "std")]
    use chksum_arch::x1::Arch;

    #[cfg(feature = "std")]
    use super::{Digest, DigestError, Hash};
    use super::State;

    #[test]
    fn state_new() {
        let state = State::<u32>::new();
        assert_eq!(state.digest(), [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]);
    }

    #[test]
    fn state_empty() {
        let mut state = State::<u32>::new();
        state.update([
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        assert_eq!(state.digest(), [0xD98C1DD4, 0x04B2008F, 0x980980E9, 0x7E42F8EC]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn digest_format() {
        let digest = Digest::try_from("D41D8CD98F00B204E9800998ECF8427E").unwrap();
        assert_eq!(format!("{digest:x}"), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(format!("{digest:#x}"), "0xd41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(format!("{digest:40x}"), "d41d8cd98f00b204e9800998ecf8427e        ");
        assert_eq!(format!("{digest:>40x}"), "        d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(format!("{digest:^40x}"), "    d41d8cd98f00b204e9800998ecf8427e    ");
        assert_eq!(format!("{digest:<40x}"), "d41d8cd98f00b204e9800998ecf8427e        ");
        assert_eq!(format!("{digest:.^40x}"), "....d41d8cd98f00b204e9800998ecf8427e....");
        assert_eq!(format!("{digest:.8x}"), "d41d8cd9");
        assert_eq!(format!("{digest:X}"), "D41D8CD98F00B204E9800998ECF8427E");
        assert_eq!(format!("{digest:#X}"), "0XD41D8CD98F00B204E9800998ECF8427E");
        assert_eq!(format!("{digest:40X}"), "D41D8CD98F00B204E9800998ECF8427E        ");
        assert_eq!(format!("{digest:>40X}"), "        D41D8CD98F00B204E9800998ECF8427E");
        assert_eq!(format!("{digest:^40X}"), "    D41D8CD98F00B204E9800998ECF8427E    ");
        assert_eq!(format!("{digest:<40X}"), "D41D8CD98F00B204E9800998ECF8427E        ");
        assert_eq!(format!("{digest:.^40X}"), "....D41D8CD98F00B204E9800998ECF8427E....");
        assert_eq!(format!("{digest:.8X}"), "D41D8CD9");
    }

    #[cfg(feature = "std")]
    #[test]
    fn digest_tryfrom() {
        assert_eq!(Digest::try_from("d41d8cd98f00b204e9800998ecf8427e"), Digest::try_from("D41D8CD98F00B204E9800998ECF8427E"));
        assert_eq!(Digest::try_from("D41D8CD98F00B204E9800998ECF8427E"), Ok(Digest([0xD4, 0x1D, 0x8C, 0xD9, 0x8F, 0x00, 0xB2, 0x04, 0xE9, 0x80, 0x09, 0x98, 0xEC, 0xF8, 0x42, 0x7E])));
        assert!(matches!(Digest::try_from("D4"), Err(DigestError::InvalidLength { value: _, proper: _ })));
        assert!(matches!(Digest::try_from("D41D8CD98F00B204E9800998ECF8427EXX"), Err(DigestError::InvalidLength { value: _, proper: _ })));
        assert!(matches!(Digest::try_from("D41D8CD98F00B204E9800998ECF842XX"), Err(DigestError::ParseError(_))));
    }

    #[cfg(feature = "std")]
    #[test]
    fn hash_new() {
        let hash = Hash::<Arch>::new();
        let digest = Digest::try_from("D41D8CD98F00B204E9800998ECF8427E").unwrap();
        assert_eq!(hash.digest(), digest);
    }

    #[cfg(feature = "std")]
    #[test]
    fn hash_hello_world() {
        let mut hash = Hash::<Arch>::new();
        let data = "Hello World";
        hash.update(data);
        let digest = Digest::try_from("B10A8DB164E0754105B7A99BE72E3FE5").unwrap();
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
        let digest = Digest::try_from("B10A8DB164E0754105B7A99BE72E3FE5").unwrap();
        assert_eq!(hash.digest(), digest);
    }
}
