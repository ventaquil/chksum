use std::convert::{From, TryInto};
// use std::fmt::{self,Formatter,LowerHex,UpperHex};
// use std::marker::PhantomData;
use std::ops::{BitAnd, BitOr, BitXor, Not, Shl, Shr};

use crate::arch::Arch;
use crate::convert::{arch::From1, FromLeBytes, ToLeBytes};
use crate::num::WrappingAdd;
use super::Data as _;

const A: u32 = 0x67452301;
const B: u32 = 0xEFCDAB89;
const C: u32 = 0x98BADCFE;
const D: u32 = 0x10325476;

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

const SHIFTS: [u8; 32] = [
    0x07, 0x19, 0x0C, 0x14, 0x11, 0x0F, 0x16, 0x0A, 
    0x05, 0x1B, 0x09, 0x17, 0x0E, 0x12, 0x14, 0x0C, 
    0x04, 0x1C, 0x0B, 0x15, 0x10, 0x10, 0x17, 0x09, 
    0x06, 0x1A, 0x0A, 0x16, 0x0F, 0x11, 0x15, 0x0B,
];

#[derive(Clone,Copy,Debug)]
pub struct State<T> { // fixme exclude consts and shifts from debug output
    a: T,
    b: T,
    c: T,
    d: T,
    consts: [T; 64],
    shifts: [T; 32],
}

impl<T: WrappingAdd<Output = T> + WrappingAdd<u32, Output = T> + BitAnd<Output = T> + BitOr<Output = T> + BitXor<Output = T> + Copy + From<u32> + From1<u8> + Not<Output = T> + Shl<Output = T> + Shr<Output = T>> State<T> {
    #[inline]
    pub fn new() -> Self {
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

    pub fn update(&mut self, block: [T; 16]) {
        let (a, b, c, d) = (self.a, self.b, self.c, self.d);

        // Round 1

        #[inline]
        fn f<T>(x: T, y: T, z: T) -> T
        where T: BitAnd<Output = T> + BitOr<Output = T> + Copy + Not<Output = T> {
            (x & y) | (!x & z)
        }

        #[inline]
        #[allow(clippy::many_single_char_names,clippy::too_many_arguments)]
        fn ff<T>(a: T, b: T, c: T, d: T, data: T, shl: T, shr: T, constant: T) -> T
        where T: WrappingAdd<Output = T> + WrappingAdd<u32, Output = T> + BitAnd<Output = T> + BitOr<Output = T> + Copy + Not<Output = T> + Shl<Output = T> + Shr<Output = T> {
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

        #[inline]
        fn g<T>(x: T, y: T, z: T) -> T
        where T: BitAnd<Output = T> + BitOr<Output = T> + Copy + Not<Output = T> {
            (x & z) | (y & !z)
        }

        #[inline]
        #[allow(clippy::many_single_char_names,clippy::too_many_arguments)]
        fn gg<T>(a: T, b: T, c: T, d: T, data: T, shl: T, shr: T, constant: T) -> T 
        where T: WrappingAdd<Output = T> + WrappingAdd<u32, Output = T> + BitAnd<Output = T> + BitOr<Output = T> + Copy + Not<Output = T> + Shl<Output = T> + Shr<Output = T> {
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

        #[inline]
        fn h<T>(x: T, y: T, z: T) -> T
        where T: BitXor<Output = T> + Copy {
            x ^ y ^ z
        }

        #[inline]
        #[allow(clippy::many_single_char_names,clippy::too_many_arguments)]
        fn hh<T>(a: T, b: T, c: T, d: T, data: T, shl: T, shr: T, constant: T) -> T
        where T: WrappingAdd<Output = T> + WrappingAdd<u32, Output = T> + BitOr<Output = T> + BitXor<Output = T> + Copy + Shl<Output = T> + Shr<Output = T> {
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

        #[inline]
        fn i<T>(x: T, y: T, z: T) -> T
        where T: BitOr<Output = T> + BitXor<Output = T> + Copy + Not<Output = T> {
            y ^ (x | !z)
        }

        #[inline]
        #[allow(clippy::many_single_char_names,clippy::too_many_arguments)]
        fn ii<T>(a: T, b: T, c: T, d: T, data: T, shl: T, shr: T, constant: T) -> T
        where T: WrappingAdd<Output = T> + WrappingAdd<u32, Output = T> + BitOr<Output = T> + BitXor<Output = T> + Copy + Not<Output = T> + Shl<Output = T> + Shr<Output = T> {
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
}

impl<T: From<u32>> super::Reset for State<T> {
    #[inline]
    fn reset(&mut self) {
        self.a = T::from(A);
        self.b = T::from(B);
        self.c = T::from(C);
        self.d = T::from(D);
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Padding { // <T: Copy>
    processed: usize,
    // data: PhantomData<T>,
}

// impl<T: Copy> Padding<T> {
impl Padding {
    #[inline]
    pub fn new() -> Self {
        Self {
            processed: 0,
            // data: PhantomData,
        }
    }

    // #[inline]
    // pub fn update<T>(&mut self, data: &[T]) {
    //     self.processed += data.len()
    // }

    // #[inline]
    // pub fn finalize<T>(&self) -> Vec<T> 
    // where T: Clone + From<u8> {
    //     const BLOCK_LENGTH: usize = 64;
    //
    //     let length = self.processed as u64;
    //     let length = length * 8; // convert byte-length into bits-length
    //     let length = length.to_le_bytes(); // fixme verify endianness
    //     let length = [
    //         T::from(length[0]),
    //         T::from(length[1]),
    //         T::from(length[2]),
    //         T::from(length[3]),
    //         T::from(length[4]),
    //         T::from(length[5]),
    //         T::from(length[6]),
    //         T::from(length[7]),
    //     ];
    //
    //     let processed = self.processed % BLOCK_LENGTH;
    //
    //     let mut padding = vec![T::from(0x80u8)];
    //     if (processed + 1 + length.len()) > BLOCK_LENGTH {
    //         padding.extend(vec![T::from(0x00u8); (2 * BLOCK_LENGTH) - (processed + 1 + length.len())]);
    //     } else {
    //         padding.extend(vec![T::from(0x00u8); BLOCK_LENGTH - (processed + 1 + length.len())]);
    //     }
    //     padding.extend_from_slice(&length[..]);
    //     padding
    // }
}

impl<T: Copy + From<u8>> super::Data<Vec<T>> for Padding {
    #[inline]
    fn data(&self) -> Vec<T> {
        const BLOCK_LENGTH: usize = 64;
    
        let length = self.processed as u64;
        let length = length * 8; // convert byte-length into bits-length
        let length = length.to_le_bytes(); // fixme verify endianness
        let length = [
            T::from(length[0]),
            T::from(length[1]),
            T::from(length[2]),
            T::from(length[3]),
            T::from(length[4]),
            T::from(length[5]),
            T::from(length[6]),
            T::from(length[7]),
        ];
    
        let processed = self.processed % BLOCK_LENGTH;
    
        let mut padding = vec![T::from(0x80u8)];
        if (processed + 1 + length.len()) > BLOCK_LENGTH {
            padding.extend(vec![T::from(0x00u8); (2 * BLOCK_LENGTH) - (processed + 1 + length.len())]);
        } else {
            padding.extend(vec![T::from(0x00u8); BLOCK_LENGTH - (processed + 1 + length.len())]);
        }
        padding.extend_from_slice(&length[..]);
        padding
    }
}

impl super::Finalize for Padding {
    #[inline]
    fn finalize(&mut self) {}
}

impl<T: Copy + From<u8>> super::Padding<T> for Padding {}

impl super::Reset for Padding {
    #[inline]
    fn reset(&mut self) {
        self.processed = 0;
    }
}

impl<T> super::Update<T> for Padding {
    #[inline]
    fn update(&mut self, data: &[T]) {
        self.processed += data.len()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Digest<T>(T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T);

impl<T: Copy, U: ToLeBytes<[T; 4]>> From<State<U>> for Digest<T> {
    #[inline]
    fn from(state: State<U>) -> Self {
        let (a, b, c, d) = (state.a, state.b, state.c, state.d);
        let (a, b, c, d) = (a.to_le_bytes(), b.to_le_bytes(), c.to_le_bytes(), d.to_le_bytes());
        Digest(a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3], c[0], c[1], c[2], c[3], d[0], d[1], d[2], d[3])
    }
}

impl<T> From<(T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T)> for Digest<T> {
    #[inline]
    fn from(digest: (T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T)) -> Self {
        Digest(digest.0, digest.1, digest.2, digest.3, digest.4, digest.5, digest.6, digest.7, digest.8, digest.9, digest.10, digest.11, digest.12, digest.13, digest.14, digest.15)
    }
}

// impl<T> From<[T; 16]> for Digest<T> {
//     #[inline]
//     fn from(digest: [T; 16]) -> Self {
//         Digest(digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7], digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14], digest[15])
//     }
// }

// impl<T> From<Digest<T>> for (T, T, T, T, T, T, T, T, T, T, T, T, T, T, T, T) {
//     #[inline]
//     fn from(digest: Digest<T>) -> Self {
//         let digest: 
//         (digest.0, digest.1, digest.2, digest.3, digest.4, digest.5, digest.6, digest.7, digest.8, digest.9, digest.10, digest.11, digest.12, digest.13, digest.14, digest.15)
//     }
// }

// impl LowerHex for Digest<u32> {
//     fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
//         let Self(a, b, c, d) = self;
//         // let a = LowerHex::fmt(&a, f);
//         // let b = LowerHex::fmt(&b, f);
//         // let c = LowerHex::fmt(&c, f);
//         // let d = LowerHex::fmt(&d, f);
//         write!(f, "{:x}{:x}{:x}{:x}", a, b, c, d)
//     }
// }

// impl UpperHex for Digest<u32> {
//     fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
//         Ok(())
//     }
// }

impl<T> Into<[T; 16]> for Digest<T> {
    #[inline]
    fn into(self) -> [T; 16] {
        [self.0, self.1, self.2, self.3, self.4, self.5, self.6, self.7, self.8, self.9, self.10, self.11, self.12, self.13, self.14, self.15]
    }
}

impl<T> super::Digest for Digest<T> {
    type Digest = Vec<T>;

    fn digest(&self) -> Self::Digest {
        Vec::new()
    }
}

#[derive(Clone, Debug)]
pub struct Hash<T: Arch>
where T::u8: Copy {
    state: State<T::u32>,
    buffer: Vec<T::u8>,
    padding: Padding,
}

impl<R: Copy, S: WrappingAdd<Output = S> + WrappingAdd<u32, Output = S> + BitAnd<Output = S> + BitOr<Output = S> + BitXor<Output = S> + Copy + From<u32> + From1<u8> + Not<Output = S> + Shl<Output = S> + Shr<Output = S>, T: Arch<u8 = R, u32 = S>> Hash<T> {
    #[inline]
    pub fn new() -> Self {
        Self {
            state: State::new(),
            buffer: Vec::new(),
            padding: Padding::new(),
        }
    }

    #[inline]
    pub fn padding(&self) -> Padding {
        self.padding
    }
}

impl<R: Copy, S: Copy + ToLeBytes<[R; 4]>, T: Arch<u8 = R, u32 = S>> super::Digest for Hash<T>
where Digest<R>: From<State<S>> {
    type Digest = Digest<T::u8>;

    #[inline]
    fn digest(&self) -> Self::Digest {
        Digest::from(self.state)
    }
}

impl<R: Copy + Clone + From<u8>, S: WrappingAdd<Output = S> + WrappingAdd<u32, Output = S> + BitAnd<Output = S> + BitOr<Output = S> + BitXor<Output = S> + Copy + From<u32> + From1<u8> + FromLeBytes<[R; 4]> + Not<Output = S> + Shl<Output = S> + Shr<Output = S> + ToLeBytes<[R; 4]>, T: Arch<u8 = R, u32 = S>> super::Finalize for Hash<T>
where Digest<R>: From<State<S>> {
    fn finalize(&mut self) {
        self.padding.finalize();
        let padding = self.padding.data();

        let mut data = Vec::new();
        data.extend_from_slice(&self.buffer[..]);
        data.extend_from_slice(&padding[..]);
        let mut data = &data[..];

        const BLOCK_LENGTH: usize = 64;
        
        let block: [T::u32; 16] = [
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
        ];
        data = &data[BLOCK_LENGTH..];
        self.state.update(block);
        if !data.is_empty() {
            let block: [T::u32; 16] = [
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
            ];
            self.state.update(block);
        }
    }
}

impl<R: Copy + Clone + From<u8>, S: WrappingAdd<Output = S> + WrappingAdd<u32, Output = S> + BitAnd<Output = S> + BitOr<Output = S> + BitXor<Output = S> + Copy + From<u32> + From1<u8> + FromLeBytes<[R; 4]> + Not<Output = S> + Shl<Output = S> + Shr<Output = S> + ToLeBytes<[R; 4]>, T: Arch<u8 = R, u32 = S>> super::Hash<T::u8> for Hash<T>
where Digest<R>: From<State<S>> {
    type Padding = Padding;
    
    #[inline]
    fn processed(&self) -> usize {
        self.padding.processed
    }    
}

impl<R: Copy, S: From<u32>, T: Arch<u8 = R, u32 = S>> super::Reset for Hash<T> {
    #[inline]
    fn reset(&mut self) {
        self.state.reset();
        self.buffer.clear();
        self.padding.reset();
    }
}

impl<R: Clone + Copy, S: WrappingAdd<Output = S> + WrappingAdd<u32, Output = S> + BitAnd<Output = S> + BitOr<Output = S> + BitXor<Output = S> + Copy + From<u32> + From1<u8> + FromLeBytes<[R; 4]> + Not<Output = S> + Shl<Output = S> + Shr<Output = S>, T: Arch<u8 = R, u32 = S>> super::Update<T::u8> for Hash<T> {
    fn update(&mut self, data: &[T::u8]) {
        self.padding.update(data);

        const BLOCK_LENGTH: usize = 64;

        // fixme rewrite
        // if buffer is not empty try to create one block
        // try to create as many blocks as you can
        // update buffer

        if self.buffer.is_empty() && (data.len() >= BLOCK_LENGTH) {
            let mut data = data;
            while data.len() >= BLOCK_LENGTH {
                let block: [T::u32; 16] = [
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
                ];
                data = &data[BLOCK_LENGTH..];
                self.state.update(block);
            }
            self.buffer.extend_from_slice(data);
        } else {
            self.buffer.extend_from_slice(data);
            while self.buffer.len() >= BLOCK_LENGTH {
                let data: [T::u8; 64] = self.buffer[..BLOCK_LENGTH].try_into().unwrap();
                let block: [T::u32; 16] = [
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
                ];
                self.buffer = self.buffer.drain(BLOCK_LENGTH..).collect();
                self.state.update(block);
            }
        }
    }
}
