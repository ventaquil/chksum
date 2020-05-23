//! Implementation of MD5 hash function based on [RFC 1321: The MD5 Message-Digest Algorithm](https://tools.ietf.org/html/rfc1321).

use std::cmp::min;
use std::fmt::{Debug, Formatter, Result as FmtResult};

#[derive(Clone, Copy)]
pub struct Block {
    block: [u8; 64],
    length: usize,
}

impl Block {
    pub const LENGTH: usize = 64;

    #[inline]
    pub fn new() -> Block {
        Self {
            block: [0u8; Self::LENGTH],
            length: 0,
        }
    }

    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.block[..]
    }

    #[inline]
    pub fn length(&self) -> usize {
        self.length
    }

    #[inline]
    pub fn empty(&self) -> bool {
        self.length == 0
    }

    #[inline]
    pub fn full(&self) -> bool {
        self.length == Self::LENGTH
    }

    #[inline]
    pub fn add(&mut self, data: &[u8]) -> usize {
        let start = self.length;
        let end = min(start + data.len(), Self::LENGTH);
        let block = &mut self.block[start..end];
        let length = end - start;
        assert!(block.len() == length);
        assert!(data.len() >= length);
        block.clone_from_slice(&data[..length]);
        self.length += length;
        length
    }

    #[inline]
    pub fn fill(&mut self, data: &[u8]) -> usize {
        self.clear();
        self.add(data)
    }

    #[inline]
    pub fn clear(&mut self) {
        self.block = [0u8; Self::LENGTH];
        self.length = 0;
    }
}

impl Debug for Block {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "Block {{ data: {:?}, length: {:?} }}", &self.block[..], self.length)
    }
}

impl Default for Block {
    fn default() -> Self {
        Self::new()
    }
}

impl Eq for Block {}

impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        (self.block[..] == other.block[..]) && (self.length == other.length)
    }

}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Digest {
    digest: [u8; 16],
}

impl Digest {
    pub const LENGTH: usize = 16;

    #[inline]
    pub fn new(digest: [u8; 16]) -> Digest {
        Digest {
            digest,
        }
    }

    #[inline]
    pub fn digest(&self) -> [u8; 16] {
        self.digest
    }

    #[inline]
    pub fn hex(&self) -> String {
        self.digest.iter()
                   .map(|digit| format!("{:02x}", digit))
                   .collect::<String>()
    }
}

#[inline]
pub fn new() -> Context {
    Context::new()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Context {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    length: usize,
    block: Block,
}

impl Context {
    #[inline]
    #[allow(clippy::unreadable_literal)]
    pub fn new() -> Context {
        Context {
            a: 0x67452301,
            b: 0xEFCDAB89,
            c: 0x98BADCFE,
            d: 0x10325476,
            length: 0,
            block: Block::new(),
        }
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

impl super::Context<Block, Digest> for Context {
    #[inline]
    fn digest(&self) -> Digest {
        let mut context = self.clone();
        context.finalize();
        let mut digest = [0u8; Digest::LENGTH];
        digest[ 0.. 4].clone_from_slice(&context.a.to_le_bytes());
        digest[ 4.. 8].clone_from_slice(&context.b.to_le_bytes());
        digest[ 8..12].clone_from_slice(&context.c.to_le_bytes());
        digest[12..16].clone_from_slice(&context.d.to_le_bytes());
        Digest::new(digest)
    }

    #[inline]
    fn update(&mut self, data: &[u8]) -> usize {
        let mut data = &data[..];

        let mut processed: usize = 0;

        let chunk = self.block.add(&data);
        processed += chunk;
        if self.block.full() {
            data = &data[chunk..];

            let block = self.block.clone(); // todo why need to clone?
            self.process_block(&block);

            // let iterations = data.len() / Block::LENGTH;
            let iterations = data.len() >> 6; // faster than divide by Block::LENGTH
            for _ in 0..iterations {
                let chunk = &data[..Block::LENGTH];
                processed += self.block.fill(&chunk);
                let block = self.block.clone(); // todo why need to clone?
                self.process_block(&block);
                data = &data[Block::LENGTH..];
            }

            processed += self.block.fill(&data);
        }
        processed
    }

    #[inline]
    #[allow(clippy::unreadable_literal)]
    fn process_block(&mut self, block: &Block) {
        let block = block.data();
        let block = [
            u32::from_le_bytes([block[ 0], block[ 1], block[ 2], block[ 3]]),
            u32::from_le_bytes([block[ 4], block[ 5], block[ 6], block[ 7]]),
            u32::from_le_bytes([block[ 8], block[ 9], block[10], block[11]]),
            u32::from_le_bytes([block[12], block[13], block[14], block[15]]),
            u32::from_le_bytes([block[16], block[17], block[18], block[19]]),
            u32::from_le_bytes([block[20], block[21], block[22], block[23]]),
            u32::from_le_bytes([block[24], block[25], block[26], block[27]]),
            u32::from_le_bytes([block[28], block[29], block[30], block[31]]),
            u32::from_le_bytes([block[32], block[33], block[34], block[35]]),
            u32::from_le_bytes([block[36], block[37], block[38], block[39]]),
            u32::from_le_bytes([block[40], block[41], block[42], block[43]]),
            u32::from_le_bytes([block[44], block[45], block[46], block[47]]),
            u32::from_le_bytes([block[48], block[49], block[50], block[51]]),
            u32::from_le_bytes([block[52], block[53], block[54], block[55]]),
            u32::from_le_bytes([block[56], block[57], block[58], block[59]]),
            u32::from_le_bytes([block[60], block[61], block[62], block[63]]),
        ];

        let (a, b, c, d) = (self.a, self.b, self.c, self.d);

        // round 1

        #[inline]
        fn f(x: u32, y: u32, z: u32) -> u32 {
            (x & y) | (!x & z)
        }

        #[inline]
        fn ff(a: u32, b: u32, c: u32, d: u32, data: u32, rotation: u32, constant: u32) -> u32 {
            a.wrapping_add(f(b, c, d))
             .wrapping_add(data)
             .wrapping_add(constant)
             .rotate_left(rotation)
             .wrapping_add(b)
        }

        let a = ff(a, b, c, d, block[ 0],  7, 0xD76AA478);
        let d = ff(d, a, b, c, block[ 1], 12, 0xE8C7B756);
        let c = ff(c, d, a, b, block[ 2], 17, 0x242070DB);
        let b = ff(b, c, d, a, block[ 3], 22, 0xC1BDCEEE);
        let a = ff(a, b, c, d, block[ 4],  7, 0xF57C0FAF);
        let d = ff(d, a, b, c, block[ 5], 12, 0x4787C62A);
        let c = ff(c, d, a, b, block[ 6], 17, 0xA8304613);
        let b = ff(b, c, d, a, block[ 7], 22, 0xFD469501);
        let a = ff(a, b, c, d, block[ 8],  7, 0x698098D8);
        let d = ff(d, a, b, c, block[ 9], 12, 0x8B44F7AF);
        let c = ff(c, d, a, b, block[10], 17, 0xFFFF5BB1);
        let b = ff(b, c, d, a, block[11], 22, 0x895CD7BE);
        let a = ff(a, b, c, d, block[12],  7, 0x6B901122);
        let d = ff(d, a, b, c, block[13], 12, 0xFD987193);
        let c = ff(c, d, a, b, block[14], 17, 0xA679438E);
        let b = ff(b, c, d, a, block[15], 22, 0x49B40821);

        // round 2

        #[inline]
        fn g(x: u32, y: u32, z: u32) -> u32 {
            (x & z) | (y & !z)
        }

        #[inline]
        fn gg(a: u32, b: u32, c: u32, d: u32, data: u32, rotation: u32, constant: u32) -> u32 {
            a.wrapping_add(g(b, c, d))
             .wrapping_add(data)
             .wrapping_add(constant)
             .rotate_left(rotation)
             .wrapping_add(b)
        }

        let a = gg(a, b, c, d, block[ 1],  5, 0xF61E2562);
        let d = gg(d, a, b, c, block[ 6],  9, 0xC040B340);
        let c = gg(c, d, a, b, block[11], 14, 0x265E5A51);
        let b = gg(b, c, d, a, block[ 0], 20, 0xE9B6C7AA);
        let a = gg(a, b, c, d, block[ 5],  5, 0xD62F105D);
        let d = gg(d, a, b, c, block[10],  9, 0x02441453);
        let c = gg(c, d, a, b, block[15], 14, 0xD8A1E681);
        let b = gg(b, c, d, a, block[ 4], 20, 0xE7D3FBC8);
        let a = gg(a, b, c, d, block[ 9],  5, 0x21E1CDE6);
        let d = gg(d, a, b, c, block[14],  9, 0xC33707D6);
        let c = gg(c, d, a, b, block[ 3], 14, 0xF4D50D87);
        let b = gg(b, c, d, a, block[ 8], 20, 0x455A14ED);
        let a = gg(a, b, c, d, block[13],  5, 0xA9E3E905);
        let d = gg(d, a, b, c, block[ 2],  9, 0xFCEFA3F8);
        let c = gg(c, d, a, b, block[ 7], 14, 0x676F02D9);
        let b = gg(b, c, d, a, block[12], 20, 0x8D2A4C8A);

        // round 3

        #[inline]
        fn h(x: u32, y: u32, z: u32) -> u32 {
            x ^ y ^ z
        }

        #[inline]
        fn hh(a: u32, b: u32, c: u32, d: u32, data: u32, rotation: u32, constant: u32) -> u32 {
            a.wrapping_add(h(b, c, d))
             .wrapping_add(data)
             .wrapping_add(constant)
             .rotate_left(rotation)
             .wrapping_add(b)
        }

        let a = hh(a, b, c, d, block[ 5],  4, 0xFFFA3942);
        let d = hh(d, a, b, c, block[ 8], 11, 0x8771F681);
        let c = hh(c, d, a, b, block[11], 16, 0x6D9D6122);
        let b = hh(b, c, d, a, block[14], 23, 0xFDE5380C);
        let a = hh(a, b, c, d, block[ 1],  4, 0xA4BEEA44);
        let d = hh(d, a, b, c, block[ 4], 11, 0x4BDECFA9);
        let c = hh(c, d, a, b, block[ 7], 16, 0xF6BB4B60);
        let b = hh(b, c, d, a, block[10], 23, 0xBEBFBC70);
        let a = hh(a, b, c, d, block[13],  4, 0x289B7EC6);
        let d = hh(d, a, b, c, block[ 0], 11, 0xEAA127FA);
        let c = hh(c, d, a, b, block[ 3], 16, 0xD4EF3085);
        let b = hh(b, c, d, a, block[ 6], 23, 0x04881D05);
        let a = hh(a, b, c, d, block[ 9],  4, 0xD9D4D039);
        let d = hh(d, a, b, c, block[12], 11, 0xE6DB99E5);
        let c = hh(c, d, a, b, block[15], 16, 0x1FA27CF8);
        let b = hh(b, c, d, a, block[ 2], 23, 0xC4AC5665);

        // round 4

        #[inline]
        fn i(x: u32, y: u32, z: u32) -> u32 {
            y ^ (x | !z)
        }

        #[inline]
        fn ii(a: u32, b: u32, c: u32, d: u32, data: u32, rotation: u32, constant: u32) -> u32 {
            a.wrapping_add(i(b, c, d))
             .wrapping_add(data)
             .wrapping_add(constant)
             .rotate_left(rotation)
             .wrapping_add(b)
        }

        let a = ii(a, b, c, d, block[ 0],  6, 0xF4292244);
        let d = ii(d, a, b, c, block[ 7], 10, 0x432AFF97);
        let c = ii(c, d, a, b, block[14], 15, 0xAB9423A7);
        let b = ii(b, c, d, a, block[ 5], 21, 0xFC93A039);
        let a = ii(a, b, c, d, block[12],  6, 0x655B59C3);
        let d = ii(d, a, b, c, block[ 3], 10, 0x8F0CCC92);
        let c = ii(c, d, a, b, block[10], 15, 0xFFEFF47D);
        let b = ii(b, c, d, a, block[ 1], 21, 0x85845DD1);
        let a = ii(a, b, c, d, block[ 8],  6, 0x6FA87E4F);
        let d = ii(d, a, b, c, block[15], 10, 0xFE2CE6E0);
        let c = ii(c, d, a, b, block[ 6], 15, 0xA3014314);
        let b = ii(b, c, d, a, block[13], 21, 0x4E0811A1);
        let a = ii(a, b, c, d, block[ 4],  6, 0xF7537E82);
        let d = ii(d, a, b, c, block[11], 10, 0xBD3AF235);
        let c = ii(c, d, a, b, block[ 2], 15, 0x2AD7D2BB);
        let b = ii(b, c, d, a, block[ 9], 21, 0xEB86D391);

        // Update state

        self.a = self.a.wrapping_add(a);
        self.b = self.b.wrapping_add(b);
        self.c = self.c.wrapping_add(c);
        self.d = self.d.wrapping_add(d);

        // Update length

        self.length += Block::LENGTH;
    }

    #[inline]
    fn finalize(&mut self) {
        #[inline]
        fn padding_length(length: usize) -> [u8; 64] {
            let length = length as u64;
            // let length = length * 8; // convert byte-length into bits-length
            let length = length << 3; // faster than multiply by 8
            let length = length.to_le_bytes();

            let mut data = [0u8; Block::LENGTH];
            data[(Block::LENGTH - 8)..].clone_from_slice(&length);
            data
        }

        #[inline]
        fn padding_index(index: usize, length: usize) -> [u8; 64] {
            let mut data = padding_length(length);
            data[index] = 0x80;
            data
        }

        #[inline]
        fn padding(length: usize) -> [u8; 64] {
            padding_index(0, length)
        }

        let block_filling_data_length = self.block.length();
        let processed_data_length = self.length + block_filling_data_length;
        if self.block.full() { // should never happen?
            // create new full padding block

            let mut block = self.block.clone();
            self.process_block(&block);

            let padding = padding(processed_data_length);
            block.fill(&padding);
            self.process_block(&block);
        } else if (block_filling_data_length + 1) > (Block::LENGTH - 8) {
            // create new partial padding block

            let padding = [0x80u8];
            let mut block = self.block.clone();
            block.add(&padding);
            self.process_block(&block);

            let padding = padding_length(processed_data_length);
            block.fill(&padding);
            self.process_block(&block);
        } else {
            // fill existing block with padding

            let padding = padding_index(block_filling_data_length, processed_data_length);
            let mut block = self.block.clone();
            block.add(&padding[block_filling_data_length..]);
            self.process_block(&block);
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::Block;

    #[test]
    fn block_new() {
        let block = Block::new();
        assert_eq!(true, block.empty());
        assert_eq!(false, block.full());
        assert_eq!(0, block.length());
        let data = [0u8; Block::LENGTH];
        assert_eq!(&data[..], block.data());
    }

    #[test]
    fn block_single_add() {
        let mut block = Block::new();
        let data = [0, 1, 2, 3];
        assert_eq!(4, block.add(&data));
        assert_eq!(false, block.empty());
        assert_eq!(false, block.full());
        assert_eq!(4, block.length());
        assert_eq!(data, block.data()[..4]);
        let data = [0u8; Block::LENGTH - 4];
        assert_eq!(data[..], block.data()[4..]);
    }

    #[test]
    fn block_multiple_add() {
        let mut block = Block::new();
        let data = [0, 1, 2, 3];
        assert_eq!(4, block.add(&data));
        let data = [0x0, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF];
        assert_eq!(7, block.add(&data));
        assert_eq!(false, block.empty());
        assert_eq!(false, block.full());
        assert_eq!(11, block.length());
        let data = [0, 1, 2, 3, 0x0, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF];
        assert_eq!(data, block.data()[..11]);
        let data = [0u8; Block::LENGTH - 11];
        assert_eq!(data[..], block.data()[11..]);
    }

    #[test]
    fn block_overflow_add() {
        let mut block = Block::new();
        let data = [1; Block::LENGTH + 1];
        assert_eq!(Block::LENGTH, block.add(&data));
        assert_eq!(false, block.empty());
        assert_eq!(true, block.full());
        assert_eq!(Block::LENGTH, block.length());
        assert_eq!(&data[..Block::LENGTH], block.data());
    }

    #[test]
    fn block_clear() {
        let mut block = Block::new();
        let data = [0, 1, 2, 3];
        assert_eq!(4, block.add(&data));
        block.clear();
        let data = [0u8; Block::LENGTH];
        assert_eq!(true, block.empty());
        assert_eq!(false, block.full());
        assert_eq!(0, block.length());
        assert_eq!(&data[..], block.data());
    }

    #[test]
    fn block_fill_empty() {
        let mut block = Block::new();
        let data = [0, 1, 2, 3];
        assert_eq!(4, block.fill(&data));
        assert_eq!(false, block.empty());
        assert_eq!(false, block.full());
        assert_eq!(4, block.length());
        assert_eq!(data, block.data()[..4]);
        let data = [0u8; Block::LENGTH - 4];
        assert_eq!(data[..], block.data()[4..]);
    }

    #[test]
    fn block_fill_less() {
        let mut block = Block::new();
        let data = [0, 1, 2, 3];
        assert_eq!(4, block.add(&data));
        let data = [2, 3, 5];
        assert_eq!(3, block.fill(&data));
        assert_eq!(false, block.empty());
        assert_eq!(false, block.full());
        assert_eq!(3, block.length());
        assert_eq!(data, block.data()[..3]);
        let data = [0u8; Block::LENGTH - 3];
        assert_eq!(data[..], block.data()[3..]);
    }

    #[test]
    fn block_fill_more() {
        let mut block = Block::new();
        let data = [0, 1, 2, 3];
        assert_eq!(4, block.add(&data));
        let data = [2, 3, 5, 7, 11, 13, 17, 19, 23];
        assert_eq!(9, block.fill(&data));
        assert_eq!(false, block.empty());
        assert_eq!(false, block.full());
        assert_eq!(9, block.length());
        assert_eq!(data, block.data()[..9]);
        let data = [0u8; Block::LENGTH - 9];
        assert_eq!(data[..], block.data()[9..]);
    }

    #[test]
    fn block_fill_overflow() {
        let mut block = Block::new();
        let data = [1u8; Block::LENGTH + 1];
        assert_eq!(Block::LENGTH, block.fill(&data));
        assert_eq!(false, block.empty());
        assert_eq!(true, block.full());
        assert_eq!(Block::LENGTH, block.length());
        assert_eq!(&data[..Block::LENGTH], block.data());
    }

    use super::Digest;

    #[test]
    fn digest_new() {
        let digest = Digest::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                  0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], digest.digest());
        assert_eq!("00112233445566778899aabbccddeeff", digest.hex());
    }

    use super::super::Context;

    #[test]
    fn md5_empty() {
        let context = super::new();
        assert_eq!(Digest::new([0xD4, 0x1D, 0x8C, 0xD9, 0x8F, 0x00, 0xB2, 0x04,
                                0xE9, 0x80, 0x09, 0x98, 0xEC, 0xF8, 0x42, 0x7E]), context.digest());
    }

    #[test]
    fn md5_hello_world() {
        let mut context = super::new();
        let text = "Hello World".as_bytes();
        assert_eq!(text.len(), context.update(text));
        assert_eq!(Digest::new([0xB1, 0x0A, 0x8D, 0xB1, 0x64, 0xE0, 0x75, 0x41,
                                0x05, 0xB7, 0xA9, 0x9B, 0xE7, 0x2E, 0x3F, 0xE5]), context.digest());
    }

    #[test]
    fn md5_hello_world_by_parts() {
        let mut context = super::new();
        let text = "Hello".as_bytes();
        assert_eq!(text.len(), context.update(text));
        let text = " ".as_bytes();
        assert_eq!(text.len(), context.update(text));
        let text = "World".as_bytes();
        assert_eq!(text.len(), context.update(text));
        assert_eq!(Digest::new([0xB1, 0x0A, 0x8D, 0xB1, 0x64, 0xE0, 0x75, 0x41,
                                0x05, 0xB7, 0xA9, 0x9B, 0xE7, 0x2E, 0x3F, 0xE5]), context.digest());
    }

    #[test]
    fn md5_lorem_ipsum() {
        let mut context = super::new();
        let text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus eget imperdiet libero. Quisque pulvinar lacinia turpis ac luctus. Suspendisse ut dui vehicula libero porttitor consectetur a quis felis. Praesent finibus efficitur justo a iaculis. Suspendisse rutrum sem sit amet lacus consequat ultrices. Duis blandit congue iaculis. Quisque eget quam enim. Cras tempor justo neque, dictum cursus mi facilisis nec. Donec tincidunt, felis non eleifend condimentum, mi tellus scelerisque nulla, vitae sagittis arcu libero vitae purus. Pellentesque pretium sem eu varius accumsan. Nullam vestibulum lacinia nisi, ac consequat erat volutpat et. Pellentesque eu imperdiet lorem. Vestibulum placerat condimentum sapien, a eleifend libero rutrum a. Cras eros tellus, consectetur vel ante et, pretium lacinia tortor. Quisque hendrerit orci neque, sed faucibus quam interdum quis.".as_bytes();
        assert_eq!(text.len(), context.update(text));
        assert_eq!(Digest::new([0xB1, 0x32, 0xF2, 0x8A, 0xF8, 0x82, 0xB0, 0x65,
                                0x6A, 0x1F, 0x30, 0x97, 0xA1, 0x75, 0xEB, 0x72]), context.digest());
    }
}
