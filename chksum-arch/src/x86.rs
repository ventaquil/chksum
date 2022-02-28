#[cfg(target_feature = "sse4.1")]
use std::arch::x86::_mm_extract_epi32;
#[cfg(target_feature = "sse")]
use std::arch::x86::{__m128i, _mm_cmpeq_epi32, _mm_extract_epi8, _mm_set_epi8};
#[cfg(target_feature = "sse2")]
use std::arch::x86::{
    _mm_add_epi32,
    _mm_and_si128,
    _mm_or_si128,
    _mm_set1_epi32,
    _mm_set_epi32,
    _mm_sll_epi32,
    _mm_srl_epi32,
    _mm_xor_si128,
};
use std::cmp::{Eq, PartialEq};
use std::convert::From;
use std::fmt;
use std::ops::{Add, BitAnd, BitOr, BitXor, Not, Shl, Shr};

use chksum_traits::convert::{From1, FromBeBytes, FromLeBytes, ToBeBytes, ToLeBytes};
use chksum_traits::num::WrappingAdd;

#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
#[cfg(target_feature = "sse")]
pub struct u8x4 {
    m128: __m128i,
}

#[cfg(target_feature = "sse2")]
impl BitOr for u8x4 {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn bitor(self, rhs: Self) -> Self::Output {
        unsafe {
            Self {
                m128: _mm_or_si128(self.m128, rhs.m128),
            }
        }
    }
}

impl BitOr<u8> for u8x4 {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn bitor(self, rhs: u8) -> Self::Output {
        self | Self::from(rhs)
    }
}

impl fmt::Debug for u8x4 {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m128: (u8, u8, u8, u8) = self.into();
        f.debug_tuple("u8x4")
            .field(&m128.0)
            .field(&m128.1)
            .field(&m128.2)
            .field(&m128.3)
            .finish()
    }
}

impl From<u8> for u8x4 {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(number: u8) -> Self {
        Self::from([number, number, number, number])
    }
}

#[cfg(target_feature = "sse")]
impl From<[u8; 4]> for u8x4 {
    #[allow(clippy::unseparated_literal_suffix, clippy::cast_possible_wrap)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(numbers: [u8; 4]) -> Self {
        unsafe {
            Self {
                #[cfg(target_endian = "big")]
                m128: _mm_set_epi8(
                    0i8,
                    0i8,
                    0i8,
                    numbers[0] as i8,
                    0i8,
                    0i8,
                    0i8,
                    numbers[1] as i8,
                    0i8,
                    0i8,
                    0i8,
                    numbers[2] as i8,
                    0i8,
                    0i8,
                    0i8,
                    numbers[3] as i8,
                ),
                #[cfg(target_endian = "little")]
                m128: _mm_set_epi8(
                    0i8,
                    0i8,
                    0i8,
                    numbers[3] as i8,
                    0i8,
                    0i8,
                    0i8,
                    numbers[2] as i8,
                    0i8,
                    0i8,
                    0i8,
                    numbers[1] as i8,
                    0i8,
                    0i8,
                    0i8,
                    numbers[0] as i8,
                ),
            }
        }
    }
}

#[cfg(target_feature = "sse")]
impl From<(u8, u8, u8, u8)> for u8x4 {
    #[allow(clippy::unseparated_literal_suffix, clippy::cast_possible_wrap)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(numbers: (u8, u8, u8, u8)) -> Self {
        unsafe {
            Self {
                #[cfg(target_endian = "big")]
                m128: _mm_set_epi8(
                    0i8,
                    0i8,
                    0i8,
                    numbers.0 as i8,
                    0i8,
                    0i8,
                    0i8,
                    numbers.1 as i8,
                    0i8,
                    0i8,
                    0i8,
                    numbers.2 as i8,
                    0i8,
                    0i8,
                    0i8,
                    numbers.3 as i8,
                ),
                #[cfg(target_endian = "little")]
                m128: _mm_set_epi8(
                    0i8,
                    0i8,
                    0i8,
                    numbers.3 as i8,
                    0i8,
                    0i8,
                    0i8,
                    numbers.2 as i8,
                    0i8,
                    0i8,
                    0i8,
                    numbers.1 as i8,
                    0i8,
                    0i8,
                    0i8,
                    numbers.0 as i8,
                ),
            }
        }
    }
}

impl From<u32x4> for u8x4 {
    #[allow(clippy::unseparated_literal_suffix)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(numbers: u32x4) -> Self {
        Self {
            m128: (numbers & 0xFFu8).m128,
        }
    }
}

#[cfg(target_feature = "sse")]
impl From1<u8> for u8x4 {
    #[allow(clippy::unseparated_literal_suffix, clippy::cast_possible_wrap)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from1(number: u8) -> Self {
        unsafe {
            Self {
                #[cfg(target_endian = "big")]
                m128: _mm_set_epi8(
                    0i8,
                    0i8,
                    0i8,
                    number as i8,
                    0i8,
                    0i8,
                    0i8,
                    0i8,
                    0i8,
                    0i8,
                    0i8,
                    0i8,
                    0i8,
                    0i8,
                    0i8,
                    0i8,
                ),
                #[cfg(target_endian = "little")]
                m128: _mm_set_epi8(
                    0i8,
                    0i8,
                    0i8,
                    0i8,
                    0i8,
                    0i8,
                    0i8,
                    0i8,
                    0i8,
                    0i8,
                    0i8,
                    0i8,
                    0i8,
                    0i8,
                    0i8,
                    number as i8,
                ),
            }
        }
    }
}

#[cfg(target_feature = "sse")]
impl From<u8x4> for (u8, u8, u8, u8) {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(number: u8x4) -> (u8, u8, u8, u8) {
        unsafe {
            (
                _mm_extract_epi8::<0x0>(number.m128) as u8,
                _mm_extract_epi8::<0x4>(number.m128) as u8,
                _mm_extract_epi8::<0x8>(number.m128) as u8,
                _mm_extract_epi8::<0xC>(number.m128) as u8,
            )
        }
    }
}

#[cfg(target_feature = "sse")]
impl From<&u8x4> for (u8, u8, u8, u8) {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(number: &u8x4) -> (u8, u8, u8, u8) {
        unsafe {
            (
                _mm_extract_epi8::<0x0>(number.m128) as u8,
                _mm_extract_epi8::<0x4>(number.m128) as u8,
                _mm_extract_epi8::<0x8>(number.m128) as u8,
                _mm_extract_epi8::<0xC>(number.m128) as u8,
            )
        }
    }
}

#[cfg(target_feature = "sse")]
impl From<u8x4> for [u8; 4] {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(number: u8x4) -> [u8; 4] {
        unsafe {
            [
                _mm_extract_epi8::<0x0>(number.m128) as u8,
                _mm_extract_epi8::<0x4>(number.m128) as u8,
                _mm_extract_epi8::<0x8>(number.m128) as u8,
                _mm_extract_epi8::<0xC>(number.m128) as u8,
            ]
        }
    }
}

#[cfg(target_feature = "sse")]
impl From<&u8x4> for [u8; 4] {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(number: &u8x4) -> [u8; 4] {
        unsafe {
            [
                _mm_extract_epi8::<0x0>(number.m128) as u8,
                _mm_extract_epi8::<0x4>(number.m128) as u8,
                _mm_extract_epi8::<0x8>(number.m128) as u8,
                _mm_extract_epi8::<0xC>(number.m128) as u8,
            ]
        }
    }
}

#[cfg(target_feature = "sse2")]
impl Shl for u8x4 {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn shl(self, rhs: Self) -> Self::Output {
        unsafe {
            Self {
                m128: _mm_sll_epi32(self.m128, rhs.m128),
            }
        }
    }
}

#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
#[cfg(target_feature = "sse")]
pub struct u32x4 {
    m128: __m128i,
}

#[cfg(target_feature = "sse2")]
impl Add for u32x4 {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn add(self, rhs: Self) -> Self::Output {
        unsafe {
            Self {
                m128: _mm_add_epi32(self.m128, rhs.m128),
            }
        }
    }
}

impl Add<u32> for u32x4 {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn add(self, rhs: u32) -> Self::Output {
        self + Self::from(rhs)
    }
}

#[cfg(target_feature = "sse2")]
impl BitAnd for u32x4 {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn bitand(self, rhs: Self) -> Self::Output {
        unsafe {
            Self {
                m128: _mm_and_si128(self.m128, rhs.m128),
            }
        }
    }
}

impl BitAnd<u8> for u32x4 {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn bitand(self, rhs: u8) -> Self::Output {
        self & u32::from(rhs)
    }
}

impl BitAnd<u32> for u32x4 {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn bitand(self, rhs: u32) -> Self::Output {
        self & Self::from(rhs)
    }
}

#[cfg(target_feature = "sse2")]
impl BitOr for u32x4 {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn bitor(self, rhs: Self) -> Self::Output {
        unsafe {
            Self {
                m128: _mm_or_si128(self.m128, rhs.m128),
            }
        }
    }
}

impl BitOr<u32> for u32x4 {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn bitor(self, rhs: u32) -> Self::Output {
        self | Self::from(rhs)
    }
}

#[cfg(target_feature = "sse2")]
impl BitXor for u32x4 {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn bitxor(self, rhs: Self) -> Self::Output {
        unsafe {
            Self {
                m128: _mm_xor_si128(self.m128, rhs.m128),
            }
        }
    }
}

impl BitXor<u32> for u32x4 {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn bitxor(self, rhs: u32) -> Self::Output {
        self ^ u32x4::from(rhs)
    }
}

impl fmt::Debug for u32x4 {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m128: (u32, u32, u32, u32) = self.into();
        f.debug_tuple("u32x4")
            .field(&m128.0)
            .field(&m128.1)
            .field(&m128.2)
            .field(&m128.3)
            .finish()
    }
}

impl Eq for u32x4 {}

#[cfg(target_feature = "sse2")]
impl From<u32> for u32x4 {
    #[allow(clippy::cast_possible_wrap)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(number: u32) -> Self {
        unsafe {
            Self {
                m128: _mm_set1_epi32(number as i32),
            }
        }
    }
}

impl From<u8x4> for u32x4 {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(number: u8x4) -> Self {
        Self { m128: number.m128 }
    }
}

#[cfg(target_feature = "sse2")]
impl From<[u32; 4]> for u32x4 {
    #[allow(clippy::cast_possible_wrap)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(numbers: [u32; 4]) -> Self {
        unsafe {
            Self {
                #[cfg(target_endian = "big")]
                m128: _mm_set_epi32(
                    numbers[0] as i32,
                    numbers[1] as i32,
                    numbers[2] as i32,
                    numbers[3] as i32,
                ),
                #[cfg(target_endian = "little")]
                m128: _mm_set_epi32(
                    numbers[3] as i32,
                    numbers[2] as i32,
                    numbers[1] as i32,
                    numbers[0] as i32,
                ),
            }
        }
    }
}

#[cfg(target_feature = "sse2")]
impl From<(u32, u32, u32, u32)> for u32x4 {
    #[allow(clippy::cast_possible_wrap)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(numbers: (u32, u32, u32, u32)) -> Self {
        unsafe {
            Self {
                #[cfg(target_endian = "big")]
                m128: _mm_set_epi32(numbers.0 as i32, numbers.1 as i32, numbers.2 as i32, numbers.3 as i32),
                #[cfg(target_endian = "little")]
                m128: _mm_set_epi32(numbers.3 as i32, numbers.2 as i32, numbers.1 as i32, numbers.0 as i32),
            }
        }
    }
}

#[cfg(target_feature = "sse2")]
impl From1<u8> for u32x4 {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from1(number: u8) -> Self {
        let number = u32::from(number);
        Self::from1(number)
    }
}

#[cfg(target_feature = "sse2")]
impl From1<u32> for u32x4 {
    #[allow(clippy::unseparated_literal_suffix, clippy::cast_possible_wrap)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from1(number: u32) -> Self {
        unsafe {
            Self {
                #[cfg(target_endian = "big")]
                m128: _mm_set_epi32(number as i32, 0i32, 0i32, 0i32),
                #[cfg(target_endian = "little")]
                m128: _mm_set_epi32(0i32, 0i32, 0i32, number as i32),
            }
        }
    }
}

impl FromBeBytes<u8x4, 4> for u32x4 {
    #[allow(clippy::unseparated_literal_suffix)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from_be_bytes(bytes: [u8x4; 4]) -> Self {
        // todo verify endianness
        #[cfg(target_endian = "big")]
        let data = (bytes[3] << u8x4::from1(0x18u8))
            | (bytes[2] << u8x4::from1(0x10u8))
            | (bytes[1] << u8x4::from1(0x08u8))
            | (bytes[0] << u8x4::from1(0x00u8));
        #[cfg(target_endian = "little")]
        let data = (bytes[0] << u8x4::from1(0x00u8))
            | (bytes[1] << u8x4::from1(0x08u8))
            | (bytes[2] << u8x4::from1(0x10u8))
            | (bytes[3] << u8x4::from1(0x18u8));
        Self { m128: data.m128 }
    }
}

impl FromLeBytes<u8x4, 4> for u32x4 {
    #[allow(clippy::unseparated_literal_suffix)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from_le_bytes(bytes: [u8x4; 4]) -> Self {
        // todo verify endianness
        #[cfg(target_endian = "big")]
        let data = (bytes[0] << u8x4::from1(0x00u8))
            | (bytes[1] << u8x4::from1(0x08u8))
            | (bytes[2] << u8x4::from1(0x10u8))
            | (bytes[3] << u8x4::from1(0x18u8));
        #[cfg(target_endian = "little")]
        let data = (bytes[3] << u8x4::from1(0x18u8))
            | (bytes[2] << u8x4::from1(0x10u8))
            | (bytes[1] << u8x4::from1(0x08u8))
            | (bytes[0] << u8x4::from1(0x00u8));
        Self { m128: data.m128 }
    }
}

#[cfg(target_feature = "sse4.1")]
impl From<u32x4> for (u32, u32, u32, u32) {
    #[allow(clippy::cast_sign_loss)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(number: u32x4) -> (u32, u32, u32, u32) {
        unsafe {
            (
                _mm_extract_epi32::<0>(number.m128) as u32,
                _mm_extract_epi32::<1>(number.m128) as u32,
                _mm_extract_epi32::<2>(number.m128) as u32,
                _mm_extract_epi32::<3>(number.m128) as u32,
            )
        }
    }
}

#[cfg(target_feature = "sse4.1")]
impl From<&u32x4> for (u32, u32, u32, u32) {
    #[allow(clippy::cast_sign_loss)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(number: &u32x4) -> (u32, u32, u32, u32) {
        unsafe {
            (
                _mm_extract_epi32::<0>(number.m128) as u32,
                _mm_extract_epi32::<1>(number.m128) as u32,
                _mm_extract_epi32::<2>(number.m128) as u32,
                _mm_extract_epi32::<3>(number.m128) as u32,
            )
        }
    }
}

#[cfg(target_feature = "sse4.1")]
impl From<u32x4> for [u32; 4] {
    #[allow(clippy::cast_sign_loss)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(number: u32x4) -> [u32; 4] {
        unsafe {
            [
                _mm_extract_epi32::<0>(number.m128) as u32,
                _mm_extract_epi32::<1>(number.m128) as u32,
                _mm_extract_epi32::<2>(number.m128) as u32,
                _mm_extract_epi32::<3>(number.m128) as u32,
            ]
        }
    }
}

impl Not for u32x4 {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn not(self) -> Self::Output {
        self ^ u32::MAX
    }
}

#[cfg(target_feature = "sse")]
impl PartialEq for u32x4 {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn eq(&self, other: &Self) -> bool {
        let cmp = unsafe {
            Self {
                m128: _mm_cmpeq_epi32(self.m128, other.m128),
            }
        };
        let cmp: (u32, u32, u32, u32) = cmp.into();
        cmp == (u32::MAX, u32::MAX, u32::MAX, u32::MAX)
    }
}

#[cfg(target_feature = "sse2")]
impl Shl for u32x4 {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn shl(self, rhs: Self) -> Self::Output {
        unsafe {
            Self {
                m128: _mm_sll_epi32(self.m128, rhs.m128),
            }
        }
    }
}

#[cfg(target_feature = "sse2")]
impl Shr for u32x4 {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn shr(self, rhs: Self) -> Self::Output {
        unsafe {
            Self {
                m128: _mm_srl_epi32(self.m128, rhs.m128),
            }
        }
    }
}

#[cfg(target_feature = "sse2")]
impl Shr<u8x4> for u32x4 {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn shr(self, rhs: u8x4) -> Self::Output {
        unsafe {
            Self {
                m128: _mm_srl_epi32(self.m128, rhs.m128),
            }
        }
    }
}

impl ToBeBytes<u8x4, 4> for u32x4 {
    #[allow(clippy::unseparated_literal_suffix)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn to_be_bytes(self) -> [u8x4; 4] {
        // todo verify endianness
        [
            u8x4::from(self >> u8x4::from1(0x18u8)),
            u8x4::from(self >> u8x4::from1(0x10u8)),
            u8x4::from(self >> u8x4::from1(0x08u8)),
            u8x4::from(self >> u8x4::from1(0x00u8)),
        ]
    }
}

impl ToLeBytes<u8x4, 4> for u32x4 {
    #[allow(clippy::unseparated_literal_suffix)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn to_le_bytes(self) -> [u8x4; 4] {
        // todo verify endianness
        [
            u8x4::from(self >> u8x4::from1(0x00u8)),
            u8x4::from(self >> u8x4::from1(0x08u8)),
            u8x4::from(self >> u8x4::from1(0x10u8)),
            u8x4::from(self >> u8x4::from1(0x18u8)),
        ]
    }
}

impl WrappingAdd for u32x4 {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn wrapping_add(self, rhs: Self) -> Self {
        self + rhs
    }
}

impl WrappingAdd<u32> for u32x4 {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn wrapping_add(self, rhs: u32) -> Self {
        self + rhs
    }
}

#[cfg(test)]
mod tests {
    mod u8x4 {
        use chksum_traits::convert::From1;

        use super::super::u8x4;

        #[test]
        fn test_bitor() {
            let left = (u8::MAX, u8::MAX, u8::MAX, u8::MAX);
            let right = (0u8, 1u8, 2u8, 3u8);
            assert_eq!(
                {
                    let left = u8x4::from(left);
                    let right = u8x4::from(right);
                    <(u8, u8, u8, u8)>::from(left | right)
                },
                (left.0 | right.0, left.1 | right.1, left.2 | right.2, left.3 | right.3)
            );
            let right = 0xABu8;
            assert_eq!(
                {
                    let left = u8x4::from(left);
                    let right = u8x4::from(right);
                    <(u8, u8, u8, u8)>::from(left | right)
                },
                (left.0 | right, left.1 | right, left.2 | right, left.3 | right)
            );
        }

        #[test]
        fn test_from_into() {
            let numbers = (0u8, 1u8, 2u8, 3u8);
            assert_eq!(<(u8, u8, u8, u8)>::from(u8x4::from(numbers)), numbers);
            let number = u8::MAX;
            let numbers = (number, 0u8, 0u8, 0u8);
            assert_eq!(<(u8, u8, u8, u8)>::from(u8x4::from1(number)), numbers);
        }

        #[test]
        fn test_shl() {
            let numbers = (u8::MAX, u8::MAX, u8::MAX, u8::MAX);
            for shift in [0u8, 1u8, 2u8, 3u8] {
                assert_eq!(
                    {
                        let numbers = u8x4::from(numbers);
                        let shift = u8x4::from1(shift);
                        <(u8, u8, u8, u8)>::from(numbers << shift)
                    },
                    (
                        numbers.0 << shift,
                        numbers.1 << shift,
                        numbers.2 << shift,
                        numbers.3 << shift
                    )
                );
            }
        }
    }

    mod u32x4 {
        use super::super::u32x4;

        #[test]
        fn test_from_into() {
            let numbers = (0u32, 1u32, 2u32, 3u32);
            assert_eq!(<(u32, u32, u32, u32)>::from(u32x4::from(numbers)), numbers);
        }
    }
}
