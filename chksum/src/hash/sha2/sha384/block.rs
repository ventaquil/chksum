use std::ops::{BitOr, Shr};

pub(super) const BLOCK_LENGTH_BITS: usize = 1024;
pub(super) const BLOCK_LENGTH_BYTES: usize = BLOCK_LENGTH_BITS / 8;
pub(super) const BLOCK_LENGTH_WORDS: usize = BLOCK_LENGTH_BYTES / 2;
pub(super) const BLOCK_LENGTH_DWORDS: usize = BLOCK_LENGTH_WORDS / 2;
pub(super) const BLOCK_LENGTH_QWORDS: usize = BLOCK_LENGTH_DWORDS / 2;

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Block([u8; BLOCK_LENGTH_BYTES]);

impl BitOr for Block {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline)]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self([
            self.0[0x00] | rhs.0[0x00],
            self.0[0x01] | rhs.0[0x01],
            self.0[0x02] | rhs.0[0x02],
            self.0[0x03] | rhs.0[0x03],
            self.0[0x04] | rhs.0[0x04],
            self.0[0x05] | rhs.0[0x05],
            self.0[0x06] | rhs.0[0x06],
            self.0[0x07] | rhs.0[0x07],
            self.0[0x08] | rhs.0[0x08],
            self.0[0x09] | rhs.0[0x09],
            self.0[0x0A] | rhs.0[0x0A],
            self.0[0x0B] | rhs.0[0x0B],
            self.0[0x0C] | rhs.0[0x0C],
            self.0[0x0D] | rhs.0[0x0D],
            self.0[0x0E] | rhs.0[0x0E],
            self.0[0x0F] | rhs.0[0x0F],
            self.0[0x10] | rhs.0[0x10],
            self.0[0x11] | rhs.0[0x11],
            self.0[0x12] | rhs.0[0x12],
            self.0[0x13] | rhs.0[0x13],
            self.0[0x14] | rhs.0[0x14],
            self.0[0x15] | rhs.0[0x15],
            self.0[0x16] | rhs.0[0x16],
            self.0[0x17] | rhs.0[0x17],
            self.0[0x18] | rhs.0[0x18],
            self.0[0x19] | rhs.0[0x19],
            self.0[0x1A] | rhs.0[0x1A],
            self.0[0x1B] | rhs.0[0x1B],
            self.0[0x1C] | rhs.0[0x1C],
            self.0[0x1D] | rhs.0[0x1D],
            self.0[0x1E] | rhs.0[0x1E],
            self.0[0x1F] | rhs.0[0x1F],
            self.0[0x20] | rhs.0[0x20],
            self.0[0x21] | rhs.0[0x21],
            self.0[0x22] | rhs.0[0x22],
            self.0[0x23] | rhs.0[0x23],
            self.0[0x24] | rhs.0[0x24],
            self.0[0x25] | rhs.0[0x25],
            self.0[0x26] | rhs.0[0x26],
            self.0[0x27] | rhs.0[0x27],
            self.0[0x28] | rhs.0[0x28],
            self.0[0x29] | rhs.0[0x29],
            self.0[0x2A] | rhs.0[0x2A],
            self.0[0x2B] | rhs.0[0x2B],
            self.0[0x2C] | rhs.0[0x2C],
            self.0[0x2D] | rhs.0[0x2D],
            self.0[0x2E] | rhs.0[0x2E],
            self.0[0x2F] | rhs.0[0x2F],
            self.0[0x30] | rhs.0[0x30],
            self.0[0x31] | rhs.0[0x31],
            self.0[0x32] | rhs.0[0x32],
            self.0[0x33] | rhs.0[0x33],
            self.0[0x34] | rhs.0[0x34],
            self.0[0x35] | rhs.0[0x35],
            self.0[0x36] | rhs.0[0x36],
            self.0[0x37] | rhs.0[0x37],
            self.0[0x38] | rhs.0[0x38],
            self.0[0x39] | rhs.0[0x39],
            self.0[0x3A] | rhs.0[0x3A],
            self.0[0x3B] | rhs.0[0x3B],
            self.0[0x3C] | rhs.0[0x3C],
            self.0[0x3D] | rhs.0[0x3D],
            self.0[0x3E] | rhs.0[0x3E],
            self.0[0x3F] | rhs.0[0x3F],
            self.0[0x40] | rhs.0[0x40],
            self.0[0x41] | rhs.0[0x41],
            self.0[0x42] | rhs.0[0x42],
            self.0[0x43] | rhs.0[0x43],
            self.0[0x44] | rhs.0[0x44],
            self.0[0x45] | rhs.0[0x45],
            self.0[0x46] | rhs.0[0x46],
            self.0[0x47] | rhs.0[0x47],
            self.0[0x48] | rhs.0[0x48],
            self.0[0x49] | rhs.0[0x49],
            self.0[0x4A] | rhs.0[0x4A],
            self.0[0x4B] | rhs.0[0x4B],
            self.0[0x4C] | rhs.0[0x4C],
            self.0[0x4D] | rhs.0[0x4D],
            self.0[0x4E] | rhs.0[0x4E],
            self.0[0x4F] | rhs.0[0x4F],
            self.0[0x50] | rhs.0[0x50],
            self.0[0x51] | rhs.0[0x51],
            self.0[0x52] | rhs.0[0x52],
            self.0[0x53] | rhs.0[0x53],
            self.0[0x54] | rhs.0[0x54],
            self.0[0x55] | rhs.0[0x55],
            self.0[0x56] | rhs.0[0x56],
            self.0[0x57] | rhs.0[0x57],
            self.0[0x58] | rhs.0[0x58],
            self.0[0x59] | rhs.0[0x59],
            self.0[0x5A] | rhs.0[0x5A],
            self.0[0x5B] | rhs.0[0x5B],
            self.0[0x5C] | rhs.0[0x5C],
            self.0[0x5D] | rhs.0[0x5D],
            self.0[0x5E] | rhs.0[0x5E],
            self.0[0x5F] | rhs.0[0x5F],
            self.0[0x60] | rhs.0[0x60],
            self.0[0x61] | rhs.0[0x61],
            self.0[0x62] | rhs.0[0x62],
            self.0[0x63] | rhs.0[0x63],
            self.0[0x64] | rhs.0[0x64],
            self.0[0x65] | rhs.0[0x65],
            self.0[0x66] | rhs.0[0x66],
            self.0[0x67] | rhs.0[0x67],
            self.0[0x68] | rhs.0[0x68],
            self.0[0x69] | rhs.0[0x69],
            self.0[0x6A] | rhs.0[0x6A],
            self.0[0x6B] | rhs.0[0x6B],
            self.0[0x6C] | rhs.0[0x6C],
            self.0[0x6D] | rhs.0[0x6D],
            self.0[0x6E] | rhs.0[0x6E],
            self.0[0x6F] | rhs.0[0x6F],
            self.0[0x70] | rhs.0[0x70],
            self.0[0x71] | rhs.0[0x71],
            self.0[0x72] | rhs.0[0x72],
            self.0[0x73] | rhs.0[0x73],
            self.0[0x74] | rhs.0[0x74],
            self.0[0x75] | rhs.0[0x75],
            self.0[0x76] | rhs.0[0x76],
            self.0[0x77] | rhs.0[0x77],
            self.0[0x78] | rhs.0[0x78],
            self.0[0x79] | rhs.0[0x79],
            self.0[0x7A] | rhs.0[0x7A],
            self.0[0x7B] | rhs.0[0x7B],
            self.0[0x7C] | rhs.0[0x7C],
            self.0[0x7D] | rhs.0[0x7D],
            self.0[0x7E] | rhs.0[0x7E],
            self.0[0x7F] | rhs.0[0x7F],
        ])
    }
}

impl BitOr<[u8; BLOCK_LENGTH_BYTES]> for Block {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline)]
    fn bitor(self, rhs: [u8; BLOCK_LENGTH_BYTES]) -> Self::Output {
        let rhs: Self = rhs.into();
        self.bitor(rhs)
    }
}

impl Shr<usize> for Block {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    #[cfg_attr(nightly, optimize(speed))]
    #[cfg_attr(not(debug_assertions), inline)]
    fn shr(self, rhs: usize) -> Self::Output {
        let block = {
            let mut vec = vec![0x00; rhs];
            vec.extend_from_slice(&self.0[..BLOCK_LENGTH_BYTES - rhs]);
            vec
        };
        let block: [u8; BLOCK_LENGTH_BYTES] = block.try_into().unwrap();
        block.into()
    }
}

impl From<[u8; BLOCK_LENGTH_BYTES]> for Block {
    #[cfg_attr(not(debug_assertions), inline)]
    fn from(block: [u8; BLOCK_LENGTH_BYTES]) -> Self {
        Self(block)
    }
}

impl From<Block> for [u8; BLOCK_LENGTH_BYTES] {
    #[cfg_attr(not(debug_assertions), inline)]
    fn from(block: Block) -> Self {
        block.0
    }
}

impl From<Block> for [u64; BLOCK_LENGTH_QWORDS] {
    #[cfg_attr(not(debug_assertions), inline)]
    fn from(block: Block) -> Self {
        [
            u64::from_be_bytes([
                block.0[0x00],
                block.0[0x01],
                block.0[0x02],
                block.0[0x03],
                block.0[0x04],
                block.0[0x05],
                block.0[0x06],
                block.0[0x07],
            ]),
            u64::from_be_bytes([
                block.0[0x08],
                block.0[0x09],
                block.0[0x0A],
                block.0[0x0B],
                block.0[0x0C],
                block.0[0x0D],
                block.0[0x0E],
                block.0[0x0F],
            ]),
            u64::from_be_bytes([
                block.0[0x10],
                block.0[0x11],
                block.0[0x12],
                block.0[0x13],
                block.0[0x14],
                block.0[0x15],
                block.0[0x16],
                block.0[0x17],
            ]),
            u64::from_be_bytes([
                block.0[0x18],
                block.0[0x19],
                block.0[0x1A],
                block.0[0x1B],
                block.0[0x1C],
                block.0[0x1D],
                block.0[0x1E],
                block.0[0x1F],
            ]),
            u64::from_be_bytes([
                block.0[0x20],
                block.0[0x21],
                block.0[0x22],
                block.0[0x23],
                block.0[0x24],
                block.0[0x25],
                block.0[0x26],
                block.0[0x27],
            ]),
            u64::from_be_bytes([
                block.0[0x28],
                block.0[0x29],
                block.0[0x2A],
                block.0[0x2B],
                block.0[0x2C],
                block.0[0x2D],
                block.0[0x2E],
                block.0[0x2F],
            ]),
            u64::from_be_bytes([
                block.0[0x30],
                block.0[0x31],
                block.0[0x32],
                block.0[0x33],
                block.0[0x34],
                block.0[0x35],
                block.0[0x36],
                block.0[0x37],
            ]),
            u64::from_be_bytes([
                block.0[0x38],
                block.0[0x39],
                block.0[0x3A],
                block.0[0x3B],
                block.0[0x3C],
                block.0[0x3D],
                block.0[0x3E],
                block.0[0x3F],
            ]),
            u64::from_be_bytes([
                block.0[0x40],
                block.0[0x41],
                block.0[0x42],
                block.0[0x43],
                block.0[0x44],
                block.0[0x45],
                block.0[0x46],
                block.0[0x47],
            ]),
            u64::from_be_bytes([
                block.0[0x48],
                block.0[0x49],
                block.0[0x4A],
                block.0[0x4B],
                block.0[0x4C],
                block.0[0x4D],
                block.0[0x4E],
                block.0[0x4F],
            ]),
            u64::from_be_bytes([
                block.0[0x50],
                block.0[0x51],
                block.0[0x52],
                block.0[0x53],
                block.0[0x54],
                block.0[0x55],
                block.0[0x56],
                block.0[0x57],
            ]),
            u64::from_be_bytes([
                block.0[0x58],
                block.0[0x59],
                block.0[0x5A],
                block.0[0x5B],
                block.0[0x5C],
                block.0[0x5D],
                block.0[0x5E],
                block.0[0x5F],
            ]),
            u64::from_be_bytes([
                block.0[0x60],
                block.0[0x61],
                block.0[0x62],
                block.0[0x63],
                block.0[0x64],
                block.0[0x65],
                block.0[0x66],
                block.0[0x67],
            ]),
            u64::from_be_bytes([
                block.0[0x68],
                block.0[0x69],
                block.0[0x6A],
                block.0[0x6B],
                block.0[0x6C],
                block.0[0x6D],
                block.0[0x6E],
                block.0[0x6F],
            ]),
            u64::from_be_bytes([
                block.0[0x70],
                block.0[0x71],
                block.0[0x72],
                block.0[0x73],
                block.0[0x74],
                block.0[0x75],
                block.0[0x76],
                block.0[0x77],
            ]),
            u64::from_be_bytes([
                block.0[0x78],
                block.0[0x79],
                block.0[0x7A],
                block.0[0x7B],
                block.0[0x7C],
                block.0[0x7D],
                block.0[0x7E],
                block.0[0x7F],
            ]),
        ]
    }
}
