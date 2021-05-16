use std::arch::x86::{__m128i, _mm_add_epi32, _mm_and_si128, _mm_cmpeq_epi32, _mm_extract_epi8, _mm_extract_epi32, _mm_or_si128, _mm_set_epi8, _mm_set_epi32, _mm_set1_epi32, _mm_sll_epi32, _mm_srl_epi32, _mm_xor_si128};
use std::cmp::{Eq, PartialEq};
use std::convert::{From, Into};
use std::fmt;
use std::ops::{Add, BitAnd, BitOr, BitXor, Not, Shl, Shr};

use crate::convert::{arch::From1, FromBeBytes, FromLeBytes, ToBeBytes, ToLeBytes};
use crate::num::WrappingAdd;

#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub struct u8x4 {
    m128: __m128i,
}

#[cfg(target_feature = "sse2")]
impl BitOr for u8x4 {
    type Output = Self;

    #[cfg_attr(feature = "inline", inline)]
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

    #[cfg_attr(feature = "inline", inline)]
    fn bitor(self, rhs: u8) -> Self::Output {
        self | Self::from(rhs)
    }
}

impl fmt::Debug for u8x4 {
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
    #[cfg_attr(feature = "inline", inline)]
    fn from(number: u8) -> Self {
        Self::from([number, number, number, number])
    }
}

impl From<[u8; 4]> for u8x4 {
    #[allow(
        clippy::unseparated_literal_suffix,
        clippy::cast_possible_wrap,
    )]
    #[cfg_attr(feature = "inline", inline)]
    fn from(numbers: [u8; 4]) -> Self {
        unsafe {
            Self {
                #[cfg(target_endian = "big")]
                m128: _mm_set_epi8(0i8, 0i8, 0i8, numbers[0] as i8,
                                   0i8, 0i8, 0i8, numbers[1] as i8,
                                   0i8, 0i8, 0i8, numbers[2] as i8,
                                   0i8, 0i8, 0i8, numbers[3] as i8),
                #[cfg(target_endian = "little")]
                m128: _mm_set_epi8(0i8, 0i8, 0i8, numbers[3] as i8,
                                   0i8, 0i8, 0i8, numbers[2] as i8,
                                   0i8, 0i8, 0i8, numbers[1] as i8,
                                   0i8, 0i8, 0i8, numbers[0] as i8),
            }
        }
    }
}

impl From<(u8, u8, u8, u8)> for u8x4 {
    #[allow(
        clippy::unseparated_literal_suffix,
        clippy::cast_possible_wrap,
    )]
    #[cfg_attr(feature = "inline", inline)]
    fn from(numbers: (u8, u8, u8, u8)) -> Self {
        unsafe {
            Self {
                #[cfg(target_endian = "big")]
                m128: _mm_set_epi8(0i8, 0i8, 0i8, numbers.0 as i8,
                                   0i8, 0i8, 0i8, numbers.1 as i8,
                                   0i8, 0i8, 0i8, numbers.2 as i8,
                                   0i8, 0i8, 0i8, numbers.3 as i8),
                #[cfg(target_endian = "little")]
                m128: _mm_set_epi8(0i8, 0i8, 0i8, numbers.3 as i8,
                                   0i8, 0i8, 0i8, numbers.2 as i8,
                                   0i8, 0i8, 0i8, numbers.1 as i8,
                                   0i8, 0i8, 0i8, numbers.0 as i8),
            }
        }
    }
}

impl From<u32x4> for u8x4 {
    #[allow(
        clippy::unseparated_literal_suffix,
    )]
    #[cfg_attr(feature = "inline", inline)]
    fn from(numbers: u32x4) -> Self {
        Self {
            m128: (numbers & 0xFFu8).m128,
        }
    }
}

impl From1<u8> for u8x4 {
    #[allow(
        clippy::unseparated_literal_suffix,
        clippy::cast_possible_wrap,
    )]
    #[cfg_attr(feature = "inline", inline)]
    fn from1(number: u8) -> Self {
        unsafe {
            Self {
                #[cfg(target_endian = "big")]
                m128: _mm_set_epi8(0i8, 0i8, 0i8, number as i8,
                                   0i8, 0i8, 0i8, 0i8,
                                   0i8, 0i8, 0i8, 0i8,
                                   0i8, 0i8, 0i8, 0i8),
                #[cfg(target_endian = "little")]
                m128: _mm_set_epi8(0i8, 0i8, 0i8, 0i8,
                                   0i8, 0i8, 0i8, 0i8,
                                   0i8, 0i8, 0i8, 0i8,
                                   0i8, 0i8, 0i8, number as i8),
            }
        }
    }
}

impl Into<(u8, u8, u8, u8)> for u8x4 {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
    )]
    #[cfg_attr(feature = "inline", inline)]
    fn into(self) -> (u8, u8, u8, u8) {
        unsafe {
            (
                _mm_extract_epi8::< 0>(self.m128) as u8,
                _mm_extract_epi8::< 4>(self.m128) as u8,
                _mm_extract_epi8::< 8>(self.m128) as u8,
                _mm_extract_epi8::<12>(self.m128) as u8,
            )
        }
    }
}

impl Into<(u8, u8, u8, u8)> for &u8x4 {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
    )]
    #[cfg_attr(feature = "inline", inline)]
    fn into(self) -> (u8, u8, u8, u8) {
        unsafe {
            (
                _mm_extract_epi8::< 0>(self.m128) as u8,
                _mm_extract_epi8::< 4>(self.m128) as u8,
                _mm_extract_epi8::< 8>(self.m128) as u8,
                _mm_extract_epi8::<12>(self.m128) as u8,
            )
        }
    }
}

impl Into<[u8; 4]> for u8x4 {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
    )]
    #[cfg_attr(feature = "inline", inline)]
    fn into(self) -> [u8; 4] {
        unsafe {
            [
                _mm_extract_epi8::< 0>(self.m128) as u8,
                _mm_extract_epi8::< 4>(self.m128) as u8,
                _mm_extract_epi8::< 8>(self.m128) as u8,
                _mm_extract_epi8::<12>(self.m128) as u8,
            ]
        }
    }
}

impl Into<[u8; 4]> for &u8x4 {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
    )]
    #[cfg_attr(feature = "inline", inline)]
    fn into(self) -> [u8; 4] {
        unsafe {
            [
                _mm_extract_epi8::< 0>(self.m128) as u8,
                _mm_extract_epi8::< 4>(self.m128) as u8,
                _mm_extract_epi8::< 8>(self.m128) as u8,
                _mm_extract_epi8::<12>(self.m128) as u8,
            ]
        }
    }
}

#[cfg(target_feature = "sse2")]
impl Shl for u8x4 {
    type Output = Self;

    #[cfg_attr(feature = "inline", inline)]
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

    #[cfg_attr(feature = "inline", inline)]
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

    #[cfg_attr(feature = "inline", inline)]
    fn add(self, rhs: u32) -> Self::Output {
        self + Self::from(rhs)
    }
}

#[cfg(target_feature = "sse2")]
impl BitAnd for u32x4 {
    type Output = Self;

    #[cfg_attr(feature = "inline", inline)]
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

    #[cfg_attr(feature = "inline", inline)]
    fn bitand(self, rhs: u8) -> Self::Output {
        self & u32::from(rhs)
    }
}

impl BitAnd<u32> for u32x4 {
    type Output = Self;

    #[cfg_attr(feature = "inline", inline)]
    fn bitand(self, rhs: u32) -> Self::Output {
        self & Self::from(rhs)
    }
}

#[cfg(target_feature = "sse2")]
impl BitOr for u32x4 {
    type Output = Self;

    #[cfg_attr(feature = "inline", inline)]
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

    #[cfg_attr(feature = "inline", inline)]
    fn bitor(self, rhs: u32) -> Self::Output {
        self | Self::from(rhs)
    }
}

#[cfg(target_feature = "sse2")]
impl BitXor for u32x4 {
    type Output = Self;

    #[cfg_attr(feature = "inline", inline)]
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

    #[cfg_attr(feature = "inline", inline)]
    fn bitxor(self, rhs: u32) -> Self::Output {
        self ^ u32x4::from(rhs)
    }
}

impl fmt::Debug for u32x4 {
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
    #[allow(
        clippy::cast_possible_wrap,
    )]
    #[cfg_attr(feature = "inline", inline)]
    fn from(number: u32) -> Self {
        unsafe {
            Self {
                m128: _mm_set1_epi32(number as i32),
            }
        }
    }
}

impl From<u8x4> for u32x4 {
    #[cfg_attr(feature = "inline", inline)]
    fn from(number: u8x4) -> Self {
        Self {
            m128: number.m128,
        }
    }
}

#[cfg(target_feature = "sse2")]
impl From<[u32; 4]> for u32x4 {
    #[allow(
        clippy::cast_possible_wrap,
    )]
    #[cfg_attr(feature = "inline", inline)]
    fn from(numbers: [u32; 4]) -> Self {
        unsafe {
            Self {
                #[cfg(target_endian = "big")]
                m128: _mm_set_epi32(numbers[0] as i32, numbers[1] as i32, numbers[2] as i32, numbers[3] as i32),
                #[cfg(target_endian = "little")]
                m128: _mm_set_epi32(numbers[3] as i32, numbers[2] as i32, numbers[1] as i32, numbers[0] as i32),
            }
        }
    }
}

#[cfg(target_feature = "sse2")]
impl From<(u32, u32, u32, u32)> for u32x4 {
    #[allow(
        clippy::cast_possible_wrap,
    )]
    #[cfg_attr(feature = "inline", inline)]
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
    #[cfg_attr(feature = "inline", inline)]
    fn from1(number: u8) -> Self {
        let number = u32::from(number);
        Self::from1(number)
    }
}

#[cfg(target_feature = "sse2")]
impl From1<u32> for u32x4 {
    #[allow(
        clippy::unseparated_literal_suffix,
        clippy::cast_possible_wrap,
    )]
    #[cfg_attr(feature = "inline", inline)]
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
    #[allow(
        clippy::unseparated_literal_suffix,
    )]
    #[cfg_attr(feature = "inline", inline)]
    fn from_be_bytes(bytes: [u8x4; 4]) -> Self {
        // fixme verify endianness
        Self {
            #[cfg(target_endian = "big")]
            m128: (
                (bytes[3] << u8x4::from1(24u8)) |
                (bytes[2] << u8x4::from1(16u8)) |
                (bytes[1] << u8x4::from1( 8u8)) |
                (bytes[0] << u8x4::from1( 0u8))
            ).m128,
            #[cfg(target_endian = "little")]
            m128: (
                (bytes[0] << u8x4::from1( 0u8)) |
                (bytes[1] << u8x4::from1( 8u8)) |
                (bytes[2] << u8x4::from1(16u8)) |
                (bytes[3] << u8x4::from1(24u8))
            ).m128,
        }
    }
}

impl FromLeBytes<u8x4, 4> for u32x4 {
    #[allow(
        clippy::unseparated_literal_suffix,
    )]
    #[cfg_attr(feature = "inline", inline)]
    fn from_le_bytes(bytes: [u8x4; 4]) -> Self {
        // fixme verify endianness
        Self {
            #[cfg(target_endian = "big")]
            m128: (
                (bytes[0] << u8x4::from1( 0u8)) |
                (bytes[1] << u8x4::from1( 8u8)) |
                (bytes[2] << u8x4::from1(16u8)) |
                (bytes[3] << u8x4::from1(24u8))
            ).m128,
            #[cfg(target_endian = "little")]
            m128: (
                (bytes[3] << u8x4::from1(24u8)) |
                (bytes[2] << u8x4::from1(16u8)) |
                (bytes[1] << u8x4::from1( 8u8)) |
                (bytes[0] << u8x4::from1( 0u8))
            ).m128,
        }
    }
}

#[cfg(target_feature = "sse4.1")]
impl Into<(u32, u32, u32, u32)> for u32x4 {
    #[allow(
        clippy::cast_sign_loss,
    )]
    #[cfg_attr(feature = "inline", inline)]
    fn into(self) -> (u32, u32, u32, u32) {
        unsafe {
            (
                _mm_extract_epi32::<0>(self.m128) as u32,
                _mm_extract_epi32::<1>(self.m128) as u32,
                _mm_extract_epi32::<2>(self.m128) as u32,
                _mm_extract_epi32::<3>(self.m128) as u32,
            )
        }
    }
}

#[cfg(target_feature = "sse4.1")]
impl Into<(u32, u32, u32, u32)> for &u32x4 {
    #[allow(
        clippy::cast_sign_loss,
    )]
    #[cfg_attr(feature = "inline", inline)]
    fn into(self) -> (u32, u32, u32, u32) {
        unsafe {
            (
                _mm_extract_epi32::<0>(self.m128) as u32,
                _mm_extract_epi32::<1>(self.m128) as u32,
                _mm_extract_epi32::<2>(self.m128) as u32,
                _mm_extract_epi32::<3>(self.m128) as u32,
            )
        }
    }
}

#[cfg(target_feature = "sse4.1")]
impl Into<[u32; 4]> for u32x4 {
    #[allow(
        clippy::cast_sign_loss,
    )]
    #[cfg_attr(feature = "inline", inline)]
    fn into(self) -> [u32; 4] {
        unsafe {
            [
                _mm_extract_epi32::<0>(self.m128) as u32,
                _mm_extract_epi32::<1>(self.m128) as u32,
                _mm_extract_epi32::<2>(self.m128) as u32,
                _mm_extract_epi32::<3>(self.m128) as u32,
            ]
        }
    }
}

#[cfg(target_feature = "sse4.1")]
impl Into<[u32; 4]> for &u32x4 {
    #[allow(
        clippy::cast_sign_loss,
    )]
    #[cfg_attr(feature = "inline", inline)]
    fn into(self) -> [u32; 4] {
        unsafe {
            [
                _mm_extract_epi32::<0>(self.m128) as u32,
                _mm_extract_epi32::<1>(self.m128) as u32,
                _mm_extract_epi32::<2>(self.m128) as u32,
                _mm_extract_epi32::<3>(self.m128) as u32,
            ]
        }
    }
}

impl Not for u32x4 {
    type Output = Self;

    #[cfg_attr(feature = "inline", inline)]
    fn not(self) -> Self::Output {
        self ^ u32::MAX
    }
}

impl PartialEq for u32x4 {
    #[cfg_attr(feature = "inline", inline)]
    fn eq(&self, other: &Self) -> bool {
        let cmp =  unsafe {
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

    #[cfg_attr(feature = "inline", inline)]
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

    #[cfg_attr(feature = "inline", inline)]
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

    #[cfg_attr(feature = "inline", inline)]
    fn shr(self, rhs: u8x4) -> Self::Output {
        unsafe {
            Self {
                m128: _mm_srl_epi32(self.m128, rhs.m128),
            }
        }
    }
}

impl ToBeBytes<u8x4, 4> for u32x4 {
    #[allow(
        clippy::unseparated_literal_suffix,
    )]
    #[cfg_attr(feature = "inline", inline)]
    fn to_be_bytes(self) -> [u8x4; 4] {
        // fixme verify endianness
        [
            u8x4::from(self >> u8x4::from1(24u8)),
            u8x4::from(self >> u8x4::from1(16u8)),
            u8x4::from(self >> u8x4::from1( 8u8)),
            u8x4::from(self >> u8x4::from1( 0u8)),
        ]
    }
}

impl ToLeBytes<u8x4, 4> for u32x4 {
    #[allow(
        clippy::unseparated_literal_suffix,
    )]
    #[cfg_attr(feature = "inline", inline)]
    fn to_le_bytes(self) -> [u8x4; 4] {
        // fixme verify endianness
        [
            u8x4::from(self >> u8x4::from1( 0u8)),
            u8x4::from(self >> u8x4::from1( 8u8)),
            u8x4::from(self >> u8x4::from1(16u8)),
            u8x4::from(self >> u8x4::from1(24u8)),
        ]
    }
}

impl WrappingAdd for u32x4 {
    #[cfg_attr(feature = "inline", inline)]
    fn wrapping_add(self, rhs: Self) -> Self {
        self + rhs
    }
}

impl WrappingAdd<u32> for u32x4 {
    #[cfg_attr(feature = "inline", inline)]
    fn wrapping_add(self, rhs: u32) -> Self {
        self + rhs
    }
}

#[cfg(test)]
pub mod tests {
    pub mod u8x4 {
        use super::super::u8x4;

        #[test]
        fn test_from_into() {
            let x: (u8, u8, u8, u8) = (0, 1, 2, 3);
            let y = u8x4::from(x);
            let z: (u8, u8, u8, u8) = y.into();
            assert_eq!(x, z);
        }
    }

    pub mod u32x4 {
        use super::super::u32x4;

        #[test]
        fn test_add() {
            let (a, b, c, d) = (0u32, 1u32, 2u32, 3u32);
            let x = (a, b, c, d);
            let x = u32x4::from(x);
            let y = u32x4::from(u32::MAX);
            let z = x + y;
            let z = z.into();
            let x = (
                a.wrapping_add(u32::MAX),
                b.wrapping_add(u32::MAX),
                c.wrapping_add(u32::MAX),
                d.wrapping_add(u32::MAX),
            );
            assert_eq!(x, z);
        }

        #[test]
        fn test_from_into() {
            let x: (u32, u32, u32, u32) = (0, 1, 2, 3);
            let y = u32x4::from(x);
            let z: (u32, u32, u32, u32) = y.into();
            assert_eq!(x, z);
        }
    }
}
