use std::arch::x86_64::{__m128i, _mm_add_epi32, _mm_and_si128, _mm_cmpeq_epi32, _mm_extract_epi8, _mm_extract_epi32, _mm_or_si128, _mm_set_epi8, _mm_set_epi32, _mm_set1_epi32, _mm_sll_epi32, _mm_srl_epi32, _mm_xor_si128};
use std::cmp::{Eq, PartialEq};
use std::convert::{From, Into};
use std::fmt;
use std::ops::{Add, BitAnd, BitOr, BitXor, Not, Shl, Shr};

use crate::convert::{arch::From1, FromLeBytes, ToLeBytes};
use crate::num::WrappingAdd;

#[derive(Clone,Copy)]
#[allow(non_camel_case_types)]
pub struct u8x4 {
    m128: __m128i,
}

#[cfg(target_feature = "sse2")]
impl BitOr for u8x4 {
    type Output = Self;

    #[inline]
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

    #[inline]
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
    #[inline]
    fn from(number: u8) -> Self {
        Self::from([number, number, number, number])
    }
}

impl From<[u8; 4]> for u8x4 {
    #[inline]
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

impl From<u32x4> for u8x4 {
    #[inline]
    fn from(numbers: u32x4) -> Self {
        Self {
            m128: (numbers & 0xFFu8).m128,
        }
    }
}

impl From1<u8> for u8x4 {
    #[inline]
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
    #[inline]
    fn into(self) -> (u8, u8, u8, u8) {
        unsafe {
            (
                _mm_extract_epi8(self.m128,  0) as u8,
                _mm_extract_epi8(self.m128,  4) as u8,
                _mm_extract_epi8(self.m128,  8) as u8,
                _mm_extract_epi8(self.m128, 12) as u8,
            )
        }
    }
}

impl Into<(u8, u8, u8, u8)> for &u8x4 {
    #[inline]
    fn into(self) -> (u8, u8, u8, u8) {
        unsafe {
            (
                _mm_extract_epi8(self.m128,  0) as u8,
                _mm_extract_epi8(self.m128,  4) as u8,
                _mm_extract_epi8(self.m128,  8) as u8,
                _mm_extract_epi8(self.m128, 12) as u8,
            )
        }
    }
}

impl Into<[u8; 4]> for u8x4 {
    #[inline]
    fn into(self) -> [u8; 4] {
        unsafe {
            [
                _mm_extract_epi8(self.m128,  0) as u8,
                _mm_extract_epi8(self.m128,  4) as u8,
                _mm_extract_epi8(self.m128,  8) as u8,
                _mm_extract_epi8(self.m128, 12) as u8,
            ]
        }
    }
}

impl Into<[u8; 4]> for &u8x4 {
    #[inline]
    fn into(self) -> [u8; 4] {
        unsafe {
            [
                _mm_extract_epi8(self.m128,  0) as u8,
                _mm_extract_epi8(self.m128,  4) as u8,
                _mm_extract_epi8(self.m128,  8) as u8,
                _mm_extract_epi8(self.m128, 12) as u8,
            ]
        }
    }
}

#[cfg(target_feature = "sse2")]
impl Shl for u8x4 {
    type Output = Self;

    #[inline]
    fn shl(self, rhs: Self) -> Self::Output {
        unsafe {
            Self {
                m128: _mm_sll_epi32(self.m128, rhs.m128),
            }
        }
    }
}

// #[derive(Clone,Copy,Debug)]
// #[allow(non_camel_case_types)]
// pub struct u8x16 {
//     m128: __m128i,
// }

// impl From<u8> for u8x16 {
//     #[inline]
//     fn from(number: u8) -> Self {
//         Self::from([
//             number, number, number, number, number, number, number, number,
//             number, number, number, number, number, number, number, number,
//         ])
//     }
// }

// impl From<[u8; 16]> for u8x16 {
//     #[inline]
//     fn from(numbers: [u8; 16]) -> Self {
//         #[cfg(target_endian = "big")]
//         unsafe {
//             Self {
//                 m128: _mm_set_epi8(numbers[ 0] as i8, numbers[ 1] as i8, numbers[ 2] as i8, numbers[ 3] as i8,
//                                    numbers[ 4] as i8, numbers[ 5] as i8, numbers[ 6] as i8, numbers[ 7] as i8,
//                                    numbers[ 8] as i8, numbers[ 9] as i8, numbers[10] as i8, numbers[11] as i8,
//                                    numbers[12] as i8, numbers[13] as i8, numbers[14] as i8, numbers[15] as i8),
//             }
//         }
//         #[cfg(target_endian = "little")]
//         unsafe {
//             Self {
//                 m128: _mm_set_epi8(numbers[12] as i8, numbers[13] as i8, numbers[14] as i8, numbers[15] as i8,
//                                    numbers[ 8] as i8, numbers[ 9] as i8, numbers[10] as i8, numbers[11] as i8,
//                                    numbers[ 4] as i8, numbers[ 5] as i8, numbers[ 6] as i8, numbers[ 7] as i8,
//                                    numbers[ 0] as i8, numbers[ 1] as i8, numbers[ 2] as i8, numbers[ 3] as i8),
//             }
//         }
//     }
// }

// impl From<u8x4> for u8x16 {
//     #[inline]
//     fn from(numbers: u8x4) -> Self {
//         Self {
//             m128: numbers.m128,
//         }
//     }
// }

// impl Into<[u8; 16]> for u8x16 {
//     #[inline]
//     fn into(self) -> [u8; 16] {
//         unsafe {
//             [
//                 _mm_extract_epi8(self.m128,  0) as u8,
//                 _mm_extract_epi8(self.m128,  1) as u8,
//                 _mm_extract_epi8(self.m128,  2) as u8,
//                 _mm_extract_epi8(self.m128,  3) as u8,
//                 _mm_extract_epi8(self.m128,  4) as u8,
//                 _mm_extract_epi8(self.m128,  5) as u8,
//                 _mm_extract_epi8(self.m128,  6) as u8,
//                 _mm_extract_epi8(self.m128,  7) as u8,
//                 _mm_extract_epi8(self.m128,  8) as u8,
//                 _mm_extract_epi8(self.m128,  9) as u8,
//                 _mm_extract_epi8(self.m128, 10) as u8,
//                 _mm_extract_epi8(self.m128, 11) as u8,
//                 _mm_extract_epi8(self.m128, 12) as u8,
//                 _mm_extract_epi8(self.m128, 13) as u8,
//                 _mm_extract_epi8(self.m128, 14) as u8,
//                 _mm_extract_epi8(self.m128, 15) as u8,
//             ]
//         }
//     }
// }

#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
#[cfg(target_feature = "sse")]
pub struct u32x4 {
    m128: __m128i,
}

#[cfg(target_feature = "sse2")]
impl Add for u32x4 {
    type Output = Self;

    #[inline]
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

    #[inline]
    fn add(self, rhs: u32) -> Self::Output {
        self + Self::from(rhs)
    }
}

#[cfg(target_feature = "sse2")]
impl BitAnd for u32x4 {
    type Output = Self;

    #[inline]
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

    #[inline]
    fn bitand(self, rhs: u8) -> Self::Output {
        self & (rhs as u32)
    }
}

impl BitAnd<u32> for u32x4 {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: u32) -> Self::Output {
        self & Self::from(rhs)
    }
}

#[cfg(target_feature = "sse2")]
impl BitOr for u32x4 {
    type Output = Self;

    #[inline]
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

    #[inline]
    fn bitor(self, rhs: u32) -> Self::Output {
        self | Self::from(rhs)
    }
}

#[cfg(target_feature = "sse2")]
impl BitXor for u32x4 {
    type Output = Self;

    #[inline]
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

    #[inline]
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
    #[inline]
    fn from(number: u32) -> Self {
        unsafe {
            Self {
                m128: _mm_set1_epi32(number as i32),
            }
        }
    }
}

impl From<u8x4> for u32x4 {
    #[inline]
    fn from(number: u8x4) -> Self {
        Self {
            m128: number.m128,
        }
    }
}

#[cfg(target_feature = "sse2")]
impl From<[u32; 4]> for u32x4 {
    #[inline]
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
    #[inline]
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
    #[inline]
    fn from1(number: u8) -> Self {
        Self::from1(number as u32)
    }
}

#[cfg(target_feature = "sse2")]
impl From1<u32> for u32x4 {
    #[inline]
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

impl FromLeBytes<[u8x4; 4]> for u32x4 {
    #[inline]
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
    #[inline]
    fn into(self) -> (u32, u32, u32, u32) {
        unsafe {
            (
                _mm_extract_epi32(self.m128, 0) as u32,
                _mm_extract_epi32(self.m128, 1) as u32,
                _mm_extract_epi32(self.m128, 2) as u32,
                _mm_extract_epi32(self.m128, 3) as u32,
            )
        }
    }
}

#[cfg(target_feature = "sse4.1")]
impl Into<(u32, u32, u32, u32)> for &u32x4 {
    #[inline]
    fn into(self) -> (u32, u32, u32, u32) {
        unsafe {
            (
                _mm_extract_epi32(self.m128, 0) as u32,
                _mm_extract_epi32(self.m128, 1) as u32,
                _mm_extract_epi32(self.m128, 2) as u32,
                _mm_extract_epi32(self.m128, 3) as u32,
            )
        }
    }
}

#[cfg(target_feature = "sse4.1")]
impl Into<[u32; 4]> for u32x4 {
    #[inline]
    fn into(self) -> [u32; 4] {
        unsafe {
            [
                _mm_extract_epi32(self.m128, 0) as u32,
                _mm_extract_epi32(self.m128, 1) as u32,
                _mm_extract_epi32(self.m128, 2) as u32,
                _mm_extract_epi32(self.m128, 3) as u32,
            ]
        }
    }
}

#[cfg(target_feature = "sse4.1")]
impl Into<[u32; 4]> for &u32x4 {
    #[inline]
    fn into(self) -> [u32; 4] {
        unsafe {
            [
                _mm_extract_epi32(self.m128, 0) as u32,
                _mm_extract_epi32(self.m128, 1) as u32,
                _mm_extract_epi32(self.m128, 2) as u32,
                _mm_extract_epi32(self.m128, 3) as u32,
            ]
        }
    }
}

impl Not for u32x4 {
    type Output = Self;

    #[inline]
    fn not(self) -> Self::Output {
        self ^ u32::MAX
    }
}

impl PartialEq for u32x4 {
    #[inline]
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

    #[inline]
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

    #[inline]
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

    #[inline]
    fn shr(self, rhs: u8x4) -> Self::Output {
        unsafe {
            Self {
                m128: _mm_srl_epi32(self.m128, rhs.m128),
            }
        }
    }
}

impl ToLeBytes<[u8x4; 4]> for u32x4 {
    #[inline]
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
    #[inline]
    fn wrapping_add(self, rhs: Self) -> Self {
        self + rhs
    }
}

impl WrappingAdd<u32> for u32x4 {
    #[inline]
    fn wrapping_add(self, rhs: u32) -> Self {
        self + rhs
    }
}

#[cfg(test)]
pub mod tests {
    use super::u32x4;

    // #[test]
    // fn test_add() {
    //     let (a, b, c, d) = (0u32, 1u32, 2u32, 3u32);
    //     let x = (a, b, c, d);
    //     let x = u32x4::from(x);
    //     let y = u32x4::from(u32::MAX);
    //     let z = x + y;
    //     let z = z.into();
    //     let x = (
    //         a.wrapping_add(u32::MAX),
    //         b.wrapping_add(u32::MAX),
    //         c.wrapping_add(u32::MAX),
    //         d.wrapping_add(u32::MAX),
    //     );
    //     assert_eq!(x, z);
    // }

    // #[test]
    // fn test_from_into() {
    //     let x: (u32, u32, u32, u32) = (0, 1, 2, 3);
    //     let y = u32x4::from(x);
    //     let z: (u32, u32, u32, u32) = y.into();
    //     assert_eq!(x, z);
    // }

    // use std::arch::x86_64::{/*__m128i, _mm_add_epi32, _mm_and_si128, _mm_cmpeq_epi32,*/ _mm_extract_epi32, /*_mm_or_si128, _mm_set_epi32,*/ _mm_set1_epi32, _mm_sll_epi32/*, _mm_srl_epi32, _mm_xor_si128, _mm_slli_epi32*/};

    // #[test]
    // fn test_shift_left() {
    //     // let (a, b, c, d): (u32, u32, u32, u32) = (0x01, 0xAB, 0xFFFF, 0xFFFFFF);
    //     // let x = (a, b, c, d);
    //     // let y = u32x4::from(x);
    //     // let z = y << 1;
    //     // let z = z.into();
    //     // let x = (
    //     //     a << 1,
    //     //     b << 1,
    //     //     c << 1,
    //     //     d << 1,
    //     // );
    //     // assert_eq!(x, z);
    //     unsafe {
    //         let x = _mm_set1_epi32(9_i32);
    //         let y = _mm_set1_epi32(1_i32);
    //         let z = _mm_sll_epi32(x, y);
    //         // const y: i32 = 1;
    //         // let z = _mm_slli_epi32(x, y);
    //         assert_eq!(9 << 1, _mm_extract_epi32(z, 0));
    //     }
    // }
}
