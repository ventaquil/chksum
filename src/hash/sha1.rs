//! Implementation of SHA-1 hash function based on [RFC 3174: US Secure Hash Algorithm 1 (SHA1)](https://tools.ietf.org/html/rfc3174).

use super::md5::Block;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Digest {
    digest: [u8; 20],
}

impl Digest {
    pub const LENGTH: usize = 20;

    #[inline]
    pub fn new(digest: [u8; 20]) -> Digest {
        Digest {
            digest,
        }
    }

    #[inline]
    pub fn digest(&self) -> [u8; 20] {
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
    e: u32,
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
            e: 0xC3D2E1F0,
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
        digest[ 0.. 4].clone_from_slice(&context.a.to_be_bytes());
        digest[ 4.. 8].clone_from_slice(&context.b.to_be_bytes());
        digest[ 8..12].clone_from_slice(&context.c.to_be_bytes());
        digest[12..16].clone_from_slice(&context.d.to_be_bytes());
        digest[16..20].clone_from_slice(&context.e.to_be_bytes());
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
    #[allow(clippy::many_single_char_names, clippy::unreadable_literal)]
    fn process_block(&mut self, block: &Block) {
        let block = block.data();
        let mut block = [
            u32::from_be_bytes([block[ 0], block[ 1], block[ 2], block[ 3]]),
            u32::from_be_bytes([block[ 4], block[ 5], block[ 6], block[ 7]]),
            u32::from_be_bytes([block[ 8], block[ 9], block[10], block[11]]),
            u32::from_be_bytes([block[12], block[13], block[14], block[15]]),
            u32::from_be_bytes([block[16], block[17], block[18], block[19]]),
            u32::from_be_bytes([block[20], block[21], block[22], block[23]]),
            u32::from_be_bytes([block[24], block[25], block[26], block[27]]),
            u32::from_be_bytes([block[28], block[29], block[30], block[31]]),
            u32::from_be_bytes([block[32], block[33], block[34], block[35]]),
            u32::from_be_bytes([block[36], block[37], block[38], block[39]]),
            u32::from_be_bytes([block[40], block[41], block[42], block[43]]),
            u32::from_be_bytes([block[44], block[45], block[46], block[47]]),
            u32::from_be_bytes([block[48], block[49], block[50], block[51]]),
            u32::from_be_bytes([block[52], block[53], block[54], block[55]]),
            u32::from_be_bytes([block[56], block[57], block[58], block[59]]),
            u32::from_be_bytes([block[60], block[61], block[62], block[63]]),
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        block[16] = (block[13] ^ block[ 8] ^ block[ 2] ^ block[ 0]).rotate_left(1);
        block[17] = (block[14] ^ block[ 9] ^ block[ 3] ^ block[ 1]).rotate_left(1);
        block[18] = (block[15] ^ block[10] ^ block[ 4] ^ block[ 2]).rotate_left(1);
        block[19] = (block[16] ^ block[11] ^ block[ 5] ^ block[ 3]).rotate_left(1);
        block[20] = (block[17] ^ block[12] ^ block[ 6] ^ block[ 4]).rotate_left(1);
        block[21] = (block[18] ^ block[13] ^ block[ 7] ^ block[ 5]).rotate_left(1);
        block[22] = (block[19] ^ block[14] ^ block[ 8] ^ block[ 6]).rotate_left(1);
        block[23] = (block[20] ^ block[15] ^ block[ 9] ^ block[ 7]).rotate_left(1);
        block[24] = (block[21] ^ block[16] ^ block[10] ^ block[ 8]).rotate_left(1);
        block[25] = (block[22] ^ block[17] ^ block[11] ^ block[ 9]).rotate_left(1);
        block[26] = (block[23] ^ block[18] ^ block[12] ^ block[10]).rotate_left(1);
        block[27] = (block[24] ^ block[19] ^ block[13] ^ block[11]).rotate_left(1);
        block[28] = (block[25] ^ block[20] ^ block[14] ^ block[12]).rotate_left(1);
        block[29] = (block[26] ^ block[21] ^ block[15] ^ block[13]).rotate_left(1);
        block[30] = (block[27] ^ block[22] ^ block[16] ^ block[14]).rotate_left(1);
        block[31] = (block[28] ^ block[23] ^ block[17] ^ block[15]).rotate_left(1);
        block[32] = (block[29] ^ block[24] ^ block[18] ^ block[16]).rotate_left(1);
        block[33] = (block[30] ^ block[25] ^ block[19] ^ block[17]).rotate_left(1);
        block[34] = (block[31] ^ block[26] ^ block[20] ^ block[18]).rotate_left(1);
        block[35] = (block[32] ^ block[27] ^ block[21] ^ block[19]).rotate_left(1);
        block[36] = (block[33] ^ block[28] ^ block[22] ^ block[20]).rotate_left(1);
        block[37] = (block[34] ^ block[29] ^ block[23] ^ block[21]).rotate_left(1);
        block[38] = (block[35] ^ block[30] ^ block[24] ^ block[22]).rotate_left(1);
        block[39] = (block[36] ^ block[31] ^ block[25] ^ block[23]).rotate_left(1);
        block[40] = (block[37] ^ block[32] ^ block[26] ^ block[24]).rotate_left(1);
        block[41] = (block[38] ^ block[33] ^ block[27] ^ block[25]).rotate_left(1);
        block[42] = (block[39] ^ block[34] ^ block[28] ^ block[26]).rotate_left(1);
        block[43] = (block[40] ^ block[35] ^ block[29] ^ block[27]).rotate_left(1);
        block[44] = (block[41] ^ block[36] ^ block[30] ^ block[28]).rotate_left(1);
        block[45] = (block[42] ^ block[37] ^ block[31] ^ block[29]).rotate_left(1);
        block[46] = (block[43] ^ block[38] ^ block[32] ^ block[30]).rotate_left(1);
        block[47] = (block[44] ^ block[39] ^ block[33] ^ block[31]).rotate_left(1);
        block[48] = (block[45] ^ block[40] ^ block[34] ^ block[32]).rotate_left(1);
        block[49] = (block[46] ^ block[41] ^ block[35] ^ block[33]).rotate_left(1);
        block[50] = (block[47] ^ block[42] ^ block[36] ^ block[34]).rotate_left(1);
        block[51] = (block[48] ^ block[43] ^ block[37] ^ block[35]).rotate_left(1);
        block[52] = (block[49] ^ block[44] ^ block[38] ^ block[36]).rotate_left(1);
        block[53] = (block[50] ^ block[45] ^ block[39] ^ block[37]).rotate_left(1);
        block[54] = (block[51] ^ block[46] ^ block[40] ^ block[38]).rotate_left(1);
        block[55] = (block[52] ^ block[47] ^ block[41] ^ block[39]).rotate_left(1);
        block[56] = (block[53] ^ block[48] ^ block[42] ^ block[40]).rotate_left(1);
        block[57] = (block[54] ^ block[49] ^ block[43] ^ block[41]).rotate_left(1);
        block[58] = (block[55] ^ block[50] ^ block[44] ^ block[42]).rotate_left(1);
        block[59] = (block[56] ^ block[51] ^ block[45] ^ block[43]).rotate_left(1);
        block[60] = (block[57] ^ block[52] ^ block[46] ^ block[44]).rotate_left(1);
        block[61] = (block[58] ^ block[53] ^ block[47] ^ block[45]).rotate_left(1);
        block[62] = (block[59] ^ block[54] ^ block[48] ^ block[46]).rotate_left(1);
        block[63] = (block[60] ^ block[55] ^ block[49] ^ block[47]).rotate_left(1);
        block[64] = (block[61] ^ block[56] ^ block[50] ^ block[48]).rotate_left(1);
        block[65] = (block[62] ^ block[57] ^ block[51] ^ block[49]).rotate_left(1);
        block[66] = (block[63] ^ block[58] ^ block[52] ^ block[50]).rotate_left(1);
        block[67] = (block[64] ^ block[59] ^ block[53] ^ block[51]).rotate_left(1);
        block[68] = (block[65] ^ block[60] ^ block[54] ^ block[52]).rotate_left(1);
        block[69] = (block[66] ^ block[61] ^ block[55] ^ block[53]).rotate_left(1);
        block[70] = (block[67] ^ block[62] ^ block[56] ^ block[54]).rotate_left(1);
        block[71] = (block[68] ^ block[63] ^ block[57] ^ block[55]).rotate_left(1);
        block[72] = (block[69] ^ block[64] ^ block[58] ^ block[56]).rotate_left(1);
        block[73] = (block[70] ^ block[65] ^ block[59] ^ block[57]).rotate_left(1);
        block[74] = (block[71] ^ block[66] ^ block[60] ^ block[58]).rotate_left(1);
        block[75] = (block[72] ^ block[67] ^ block[61] ^ block[59]).rotate_left(1);
        block[76] = (block[73] ^ block[68] ^ block[62] ^ block[60]).rotate_left(1);
        block[77] = (block[74] ^ block[69] ^ block[63] ^ block[61]).rotate_left(1);
        block[78] = (block[75] ^ block[70] ^ block[64] ^ block[62]).rotate_left(1);
        block[79] = (block[76] ^ block[71] ^ block[65] ^ block[63]).rotate_left(1);

        let (a, b, c, d, e) = (self.a, self.b, self.c, self.d, self.e);

        // part 1

        #[inline]
        fn f(x: u32, y: u32, z: u32) -> u32 {
            (x & y) | (!x & z)
        }

        #[inline]
        fn ff(a: u32, b: u32, c: u32, d: u32, e: u32, data: u32, constant: u32) -> u32 {
            a.rotate_left(5)
             .wrapping_add(f(b, c, d))
             .wrapping_add(e)
             .wrapping_add(data)
             .wrapping_add(constant)
        }

        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[ 0], 0x5A827999), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[ 1], 0x5A827999), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[ 2], 0x5A827999), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[ 3], 0x5A827999), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[ 4], 0x5A827999), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[ 5], 0x5A827999), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[ 6], 0x5A827999), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[ 7], 0x5A827999), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[ 8], 0x5A827999), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[ 9], 0x5A827999), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[10], 0x5A827999), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[11], 0x5A827999), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[12], 0x5A827999), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[13], 0x5A827999), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[14], 0x5A827999), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[15], 0x5A827999), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[16], 0x5A827999), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[17], 0x5A827999), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[18], 0x5A827999), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ff(a, b, c, d, e, block[19], 0x5A827999), a, b.rotate_left(30), c, d);

        // part 2

        #[inline]
        fn g(x: u32, y: u32, z: u32) -> u32 {
            x ^ y ^ z
        }

        #[inline]
        fn gg(a: u32, b: u32, c: u32, d: u32, e: u32, data: u32, constant: u32) -> u32 {
            a.rotate_left(5)
             .wrapping_add(g(b, c, d))
             .wrapping_add(e)
             .wrapping_add(data)
             .wrapping_add(constant)
        }

        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[20], 0x6ED9EBA1), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[21], 0x6ED9EBA1), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[22], 0x6ED9EBA1), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[23], 0x6ED9EBA1), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[24], 0x6ED9EBA1), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[25], 0x6ED9EBA1), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[26], 0x6ED9EBA1), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[27], 0x6ED9EBA1), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[28], 0x6ED9EBA1), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[29], 0x6ED9EBA1), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[30], 0x6ED9EBA1), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[31], 0x6ED9EBA1), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[32], 0x6ED9EBA1), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[33], 0x6ED9EBA1), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[34], 0x6ED9EBA1), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[35], 0x6ED9EBA1), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[36], 0x6ED9EBA1), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[37], 0x6ED9EBA1), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[38], 0x6ED9EBA1), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (gg(a, b, c, d, e, block[39], 0x6ED9EBA1), a, b.rotate_left(30), c, d);

        // part 3

        #[inline]
        fn h(x: u32, y: u32, z: u32) -> u32 {
            (x & y) | (x & z) | (y & z)
        }

        #[inline]
        fn hh(a: u32, b: u32, c: u32, d: u32, e: u32, data: u32, constant: u32) -> u32 {
            a.rotate_left(5)
             .wrapping_add(h(b, c, d))
             .wrapping_add(e)
             .wrapping_add(data)
             .wrapping_add(constant)
        }

        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[40], 0x8F1BBCDC), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[41], 0x8F1BBCDC), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[42], 0x8F1BBCDC), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[43], 0x8F1BBCDC), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[44], 0x8F1BBCDC), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[45], 0x8F1BBCDC), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[46], 0x8F1BBCDC), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[47], 0x8F1BBCDC), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[48], 0x8F1BBCDC), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[49], 0x8F1BBCDC), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[50], 0x8F1BBCDC), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[51], 0x8F1BBCDC), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[52], 0x8F1BBCDC), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[53], 0x8F1BBCDC), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[54], 0x8F1BBCDC), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[55], 0x8F1BBCDC), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[56], 0x8F1BBCDC), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[57], 0x8F1BBCDC), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[58], 0x8F1BBCDC), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (hh(a, b, c, d, e, block[59], 0x8F1BBCDC), a, b.rotate_left(30), c, d);

        // part 4

        #[inline]
        fn i(x: u32, y: u32, z: u32) -> u32 {
            x ^ y ^ z
        }

        #[inline]
        fn ii(a: u32, b: u32, c: u32, d: u32, e: u32, data: u32, constant: u32) -> u32 {
            a.rotate_left(5)
             .wrapping_add(i(b, c, d))
             .wrapping_add(e)
             .wrapping_add(data)
             .wrapping_add(constant)
        }

        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[60], 0xCA62C1D6), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[61], 0xCA62C1D6), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[62], 0xCA62C1D6), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[63], 0xCA62C1D6), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[64], 0xCA62C1D6), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[65], 0xCA62C1D6), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[66], 0xCA62C1D6), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[67], 0xCA62C1D6), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[68], 0xCA62C1D6), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[69], 0xCA62C1D6), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[70], 0xCA62C1D6), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[71], 0xCA62C1D6), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[72], 0xCA62C1D6), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[73], 0xCA62C1D6), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[74], 0xCA62C1D6), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[75], 0xCA62C1D6), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[76], 0xCA62C1D6), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[77], 0xCA62C1D6), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[78], 0xCA62C1D6), a, b.rotate_left(30), c, d);
        let (a, b, c, d, e) = (ii(a, b, c, d, e, block[79], 0xCA62C1D6), a, b.rotate_left(30), c, d);

        // Update state

        self.a = self.a.wrapping_add(a);
        self.b = self.b.wrapping_add(b);
        self.c = self.c.wrapping_add(c);
        self.d = self.d.wrapping_add(d);
        self.e = self.e.wrapping_add(e);

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
            let length = length.to_be_bytes();

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
    use super::Digest;

    #[test]
    fn digest_new() {
        let digest = Digest::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                  0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                                  0x00, 0x11, 0x22, 0x33]);
        assert_eq!([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                    0x00, 0x11, 0x22, 0x33], digest.digest());
        assert_eq!("00112233445566778899aabbccddeeff00112233", digest.hex());
    }

    use super::super::Context;

    #[test]
    fn sha1_empty() {
        let context = super::new();
        assert_eq!(Digest::new([0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D,
                                0x32, 0x55, 0xBF, 0xEF, 0x95, 0x60, 0x18, 0x90,
                                0xAF, 0xD8, 0x07, 0x09]), context.digest());
    }

    #[test]
    fn sha1_hello_world() {
        let mut context = super::new();
        let text = "Hello World".as_bytes();
        assert_eq!(text.len(), context.update(text));
        assert_eq!(Digest::new([0x0A, 0x4D, 0x55, 0xA8, 0xD7, 0x78, 0xE5, 0x02,
                                0x2F, 0xAB, 0x70, 0x19, 0x77, 0xC5, 0xD8, 0x40,
                                0xBB, 0xC4, 0x86, 0xD0]), context.digest());
    }

    #[test]
    fn sha1_hello_world_by_parts() {
        let mut context = super::new();
        let text = "Hello".as_bytes();
        assert_eq!(text.len(), context.update(text));
        let text = " ".as_bytes();
        assert_eq!(text.len(), context.update(text));
        let text = "World".as_bytes();
        assert_eq!(text.len(), context.update(text));
        assert_eq!(Digest::new([0x0A, 0x4D, 0x55, 0xA8, 0xD7, 0x78, 0xE5, 0x02,
                                0x2F, 0xAB, 0x70, 0x19, 0x77, 0xC5, 0xD8, 0x40,
                                0xBB, 0xC4, 0x86, 0xD0]), context.digest());
    }

    #[test]
    fn sha1_lorem_ipsum() {
        let mut context = super::new();
        let text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus eget imperdiet libero. Quisque pulvinar lacinia turpis ac luctus. Suspendisse ut dui vehicula libero porttitor consectetur a quis felis. Praesent finibus efficitur justo a iaculis. Suspendisse rutrum sem sit amet lacus consequat ultrices. Duis blandit congue iaculis. Quisque eget quam enim. Cras tempor justo neque, dictum cursus mi facilisis nec. Donec tincidunt, felis non eleifend condimentum, mi tellus scelerisque nulla, vitae sagittis arcu libero vitae purus. Pellentesque pretium sem eu varius accumsan. Nullam vestibulum lacinia nisi, ac consequat erat volutpat et. Pellentesque eu imperdiet lorem. Vestibulum placerat condimentum sapien, a eleifend libero rutrum a. Cras eros tellus, consectetur vel ante et, pretium lacinia tortor. Quisque hendrerit orci neque, sed faucibus quam interdum quis.".as_bytes();
        assert_eq!(text.len(), context.update(text));
        assert_eq!(Digest::new([0xC8, 0xDB, 0xD1, 0x4C, 0xC4, 0x9E, 0xDB, 0x80,
                                0xF2, 0xA4, 0x9F, 0x4D, 0x45, 0x29, 0xF6, 0x84,
                                0x65, 0xCB, 0x1A, 0x36]), context.digest());
    }
}
