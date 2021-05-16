use std::arch::x86::{__m128i, _mm_add_epi32, _mm_and_si128, _mm_cmpeq_epi32, _mm_extract_epi32, _mm_or_si128, _mm_set_epi32, _mm_set1_epi32, _mm_xor_si128};
use std::cmp::{Eq, PartialEq};
use std::fmt;
use std::num::Wrapping;
use std::ops::{Add, AddAssign, BitAnd, BitOr, BitXor, Not};

#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
#[cfg(target_feature = "sse")]
pub struct u32x4 {
    m128: __m128i,
}

impl PartialEq for u32x4 {
    fn eq(&self, other: &Self) -> bool {
        let cmp =  unsafe {
            u32x4 {
                m128: _mm_cmpeq_epi32(self.m128, other.m128),
            }
        };
        let cmp: (u32, u32, u32, u32) = cmp.into();
        cmp == (u32::MAX, u32::MAX, u32::MAX, u32::MAX)
    }
}
impl Eq for u32x4 {}

#[cfg(target_feature = "sse2")]
impl From<u32> for u32x4 {
    #[inline]
    fn from(number: u32) -> Self {
        // u32x4::from((number, number, number, number))
        unsafe {
            u32x4 {
                m128: _mm_set1_epi32(number as i32),
            }
        }
    }
}

use std::arch::x86_64::_mm_set_epi8;
#[cfg(target_feature = "sse2")]
impl From<(u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8)> for u32x4 {
    #[inline]
    fn from(numbers: (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8)) -> Self {
        #[cfg(target_endian = "big")]
        unsafe {
            u32x4 {
                m128: _mm_set_epi8(numbers. 0 as i8, numbers. 1 as i8, numbers. 2 as i8, numbers. 3 as i8,
                                   numbers. 4 as i8, numbers. 5 as i8, numbers. 6 as i8, numbers. 7 as i8,
                                   numbers. 8 as i8, numbers. 9 as i8, numbers.10 as i8, numbers.11 as i8,
                                   numbers.12 as i8, numbers.13 as i8, numbers.14 as i8, numbers.15 as i8),
            }
        }
        #[cfg(target_endian = "little")]
        unsafe {
            u32x4 {
                m128: _mm_set_epi8(numbers.12 as i8, numbers.13 as i8, numbers.14 as i8, numbers.15 as i8,
                                   numbers. 8 as i8, numbers. 9 as i8, numbers.10 as i8, numbers.11 as i8,
                                   numbers. 4 as i8, numbers. 5 as i8, numbers. 6 as i8, numbers. 7 as i8,
                                   numbers. 0 as i8, numbers. 1 as i8, numbers. 2 as i8, numbers. 3 as i8),
            }
        }
    }
}

#[cfg(target_feature = "sse2")]
impl From<(u32, u32, u32, u32)> for u32x4 {
    #[inline]
    fn from(numbers: (u32, u32, u32, u32)) -> Self {
        #[cfg(target_endian = "big")]
        unsafe {
            u32x4 {
                m128: _mm_set_epi32(numbers.0 as i32, numbers.1 as i32, numbers.2 as i32, numbers.3 as i32),
            }
        }
        #[cfg(target_endian = "little")]
        unsafe {
            u32x4 {
                m128: _mm_set_epi32(numbers.3 as i32, numbers.2 as i32, numbers.1 as i32, numbers.0 as i32),
            }
        }
    }
}

#[cfg(target_feature = "sse2")]
impl From<[u32; 4]> for u32x4 {
    #[inline]
    fn from(numbers: [u32; 4]) -> Self {
        #[cfg(target_endian = "big")]
        unsafe {
            u32x4 {
                m128: _mm_set_epi32(numbers[0] as i32, numbers[1] as i32, numbers[2] as i32, numbers[3] as i32),
            }
        }
        #[cfg(target_endian = "little")]
        unsafe {
            u32x4 {
                m128: _mm_set_epi32(numbers[3] as i32, numbers[2] as i32, numbers[1] as i32, numbers[0] as i32),
            }
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

#[cfg(target_feature = "sse2")]
impl Add for u32x4 {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        unsafe {
            u32x4 {
                m128: _mm_add_epi32(self.m128, rhs.m128),
            }
        }
    }
}


impl Add<u32> for u32x4 {
    type Output = Self;

    #[inline]
    fn add(self, rhs: u32) -> Self::Output {
        self + u32x4::from(rhs)
    }
}

#[cfg(target_feature = "sse2")]
impl AddAssign for u32x4 {
    #[inline]
    fn add_assign(&mut self, other: Self) {
        unsafe {
            self.m128 = _mm_add_epi32(self.m128, other.m128);
        }
    }
}

#[cfg(target_feature = "sse2")]
impl BitAnd for u32x4 {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        unsafe {
            u32x4 {
                m128: _mm_and_si128(self.m128, rhs.m128),
            }
        }
    }
}

impl BitAnd<u32> for u32x4 {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: u32) -> Self::Output {
        self & u32x4::from(rhs)
    }
}

#[cfg(target_feature = "sse2")]
impl BitOr for u32x4 {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        unsafe {
            u32x4 {
                m128: _mm_or_si128(self.m128, rhs.m128),
            }
        }
    }
}

impl BitOr<u32> for u32x4 {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: u32) -> Self::Output {
        self | u32x4::from(rhs)
    }
}

#[cfg(target_feature = "sse2")]
impl BitXor for u32x4 {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        unsafe {
            u32x4 {
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

#[cfg(target_feature = "sse2")]
impl Not for u32x4 {
    type Output = Self;

    #[inline]
    fn not(self) -> Self::Output {
        self ^ u32::MAX
    }
}

#[cfg(test)]
pub mod tests {
    use super::u32x4;

    #[test]
    fn test_add() {
        let (a, b, c, d): (u32, u32, u32, u32) = (0, 1, 2, 3);
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
