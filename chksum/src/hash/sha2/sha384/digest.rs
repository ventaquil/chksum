use std::fmt::{self, Formatter, LowerHex, UpperHex};

use super::State;
use crate::hash::digest;

pub(super) const DIGEST_LENGTH_BITS: usize = 384;
pub(super) const DIGEST_LENGTH_BYTES: usize = DIGEST_LENGTH_BITS / 8;
pub(super) const DIGEST_LENGTH_WORDS: usize = DIGEST_LENGTH_BYTES / 2;
pub(super) const DIGEST_LENGTH_DWORDS: usize = DIGEST_LENGTH_WORDS / 2;
pub(super) const DIGEST_LENGTH_QWORDS: usize = DIGEST_LENGTH_DWORDS / 2;
pub(super) const DIGEST_LENGTH_HEX: usize = DIGEST_LENGTH_BYTES * 2;

/// Represents hash digest.
///
/// # Examples
///
/// ```rust
/// # use chksum::hash::digest::Result;
/// use chksum::hash::sha2::sha384::Digest;
///
/// #[rustfmt::skip]
/// # fn wrapper() -> Result<()> {
/// let digest = Digest::try_from("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b")?;
/// println!("digest {:?}", digest);
/// println!("digest {:x}", digest);
/// println!("digest {:X}", digest);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Digest([u8; DIGEST_LENGTH_BYTES]);

impl From<[u64; DIGEST_LENGTH_QWORDS]> for Digest {
    #[cfg_attr(not(debug_assertions), inline)]
    #[rustfmt::skip]
    fn from(digest: [u64; DIGEST_LENGTH_QWORDS]) -> Self {
        let [a, b, c, d, e, f] = digest;
        let [a, b, c, d, e, f] = [
            a.to_be_bytes(),
            b.to_be_bytes(),
            c.to_be_bytes(),
            d.to_be_bytes(),
            e.to_be_bytes(),
            f.to_be_bytes(),
        ];
        Self([
            a[0], a[1], a[2], a[3],
            a[4], a[5], a[6], a[7],
            b[0], b[1], b[2], b[3],
            b[4], b[5], b[6], b[7],
            c[0], c[1], c[2], c[3],
            c[4], c[5], c[6], c[7],
            d[0], d[1], d[2], d[3],
            d[4], d[5], d[6], d[7],
            e[0], e[1], e[2], e[3],
            e[4], e[5], e[6], e[7],
            f[0], f[1], f[2], f[3],
            f[4], f[5], f[6], f[7],
        ])
    }
}

impl From<State> for Digest {
    #[cfg_attr(not(debug_assertions), inline)]
    #[rustfmt::skip]
    fn from(State { a, b, c, d, e, f, g: _, h: _ }: State) -> Self {
        Self::from([a, b, c, d, e, f])
    }
}

impl From<Digest> for [u8; DIGEST_LENGTH_BYTES] {
    #[cfg_attr(not(debug_assertions), inline)]
    fn from(digest: Digest) -> Self {
        digest.0
    }
}

impl LowerHex for Digest {
    #[cfg_attr(not(debug_assertions), inline)]
    #[rustfmt::skip]
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        let digest = format!(
            "{:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}",
            self.0[0x00], self.0[0x01], self.0[0x02], self.0[0x03],
            self.0[0x04], self.0[0x05], self.0[0x06], self.0[0x07],
            self.0[0x08], self.0[0x09], self.0[0x0A], self.0[0x0B],
            self.0[0x0C], self.0[0x0D], self.0[0x0E], self.0[0x0F],
            self.0[0x10], self.0[0x11], self.0[0x12], self.0[0x13],
            self.0[0x14], self.0[0x15], self.0[0x16], self.0[0x17],
            self.0[0x18], self.0[0x19], self.0[0x1A], self.0[0x1B],
            self.0[0x1C], self.0[0x1D], self.0[0x1E], self.0[0x1F],
            self.0[0x20], self.0[0x21], self.0[0x22], self.0[0x23],
            self.0[0x24], self.0[0x25], self.0[0x26], self.0[0x27],
            self.0[0x28], self.0[0x29], self.0[0x2A], self.0[0x2B],
            self.0[0x2C], self.0[0x2D], self.0[0x2E], self.0[0x2F],
        );
        if formatter.alternate() {
            formatter.pad_integral(true, "0x", &digest)
        } else {
            formatter.pad(&digest)
        }
    }
}

impl UpperHex for Digest {
    #[cfg_attr(not(debug_assertions), inline)]
    #[rustfmt::skip]
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        let digest = format!(
            "{:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}",
            self.0[0x00], self.0[0x01], self.0[0x02], self.0[0x03],
            self.0[0x04], self.0[0x05], self.0[0x06], self.0[0x07],
            self.0[0x08], self.0[0x09], self.0[0x0A], self.0[0x0B],
            self.0[0x0C], self.0[0x0D], self.0[0x0E], self.0[0x0F],
            self.0[0x10], self.0[0x11], self.0[0x12], self.0[0x13],
            self.0[0x14], self.0[0x15], self.0[0x16], self.0[0x17],
            self.0[0x18], self.0[0x19], self.0[0x1A], self.0[0x1B],
            self.0[0x1C], self.0[0x1D], self.0[0x1E], self.0[0x1F],
            self.0[0x20], self.0[0x21], self.0[0x22], self.0[0x23],
            self.0[0x24], self.0[0x25], self.0[0x26], self.0[0x27],
            self.0[0x28], self.0[0x29], self.0[0x2A], self.0[0x2B],
            self.0[0x2C], self.0[0x2D], self.0[0x2E], self.0[0x2F],
        );
        if formatter.alternate() {
            formatter.pad_integral(true, "0X", &digest)
        } else {
            formatter.pad(&digest)
        }
    }
}

impl TryFrom<&str> for Digest {
    type Error = digest::Error;

    #[cfg_attr(not(debug_assertions), inline)]
    fn try_from(digest: &str) -> Result<Self, Self::Error> {
        if digest.len() != DIGEST_LENGTH_HEX {
            let error = Self::Error::InvalidLength {
                value: digest.len(),
                proper: DIGEST_LENGTH_HEX,
            };
            return Err(error);
        }
        let (a, b, c, d, e, f) = (
            u64::from_str_radix(&digest[0x00..0x10], 16)?,
            u64::from_str_radix(&digest[0x10..0x20], 16)?,
            u64::from_str_radix(&digest[0x20..0x30], 16)?,
            u64::from_str_radix(&digest[0x30..0x40], 16)?,
            u64::from_str_radix(&digest[0x40..0x50], 16)?,
            u64::from_str_radix(&digest[0x50..0x60], 16)?,
        );
        let digest = [a, b, c, d, e, f];
        let digest = Self::from(digest);
        Ok(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::digest::Result;

    #[test]
    fn digest_format() -> Result<()> {
        let digest = Digest::try_from(
            "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B",
        )?;
        assert_eq!(
            format!("{digest:x}"),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
        assert_eq!(
            format!("{digest:#x}"),
            "0x38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
        assert_eq!(
            format!("{digest:104x}"),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b        "
        );
        assert_eq!(
            format!("{digest:>104x}"),
            "        38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
        assert_eq!(
            format!("{digest:^104x}"),
            "    38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b    "
        );
        assert_eq!(
            format!("{digest:<104x}"),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b        "
        );
        assert_eq!(
            format!("{digest:.^104x}"),
            "....38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b...."
        );
        assert_eq!(format!("{digest:.8x}"), "38b060a7");
        assert_eq!(
            format!("{digest:X}"),
            "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B"
        );
        assert_eq!(
            format!("{digest:#X}"),
            "0X38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B"
        );
        assert_eq!(
            format!("{digest:104X}"),
            "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B        "
        );
        assert_eq!(
            format!("{digest:>104X}"),
            "        38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B"
        );
        assert_eq!(
            format!("{digest:^104X}"),
            "    38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B    "
        );
        assert_eq!(
            format!("{digest:<104X}"),
            "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B        "
        );
        assert_eq!(
            format!("{digest:.^104X}"),
            "....38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B...."
        );
        assert_eq!(format!("{digest:.8X}"), "38B060A7");
        Ok(())
    }

    #[test]
    fn digest_tryfrom() {
        assert_eq!(
            Digest::try_from(
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
            ),
            Digest::try_from(
                "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B"
            )
        );
        #[rustfmt::skip]
        assert_eq!(
            Digest::try_from("38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B"),
            Ok(Digest([
                0x38, 0xB0, 0x60, 0xA7,
                0x51, 0xAC, 0x96, 0x38,
                0x4C, 0xD9, 0x32, 0x7E,
                0xB1, 0xB1, 0xE3, 0x6A,
                0x21, 0xFD, 0xB7, 0x11,
                0x14, 0xBE, 0x07, 0x43,
                0x4C, 0x0C, 0xC7, 0xBF,
                0x63, 0xF6, 0xE1, 0xDA,
                0x27, 0x4E, 0xDE, 0xBF,
                0xE7, 0x6F, 0x65, 0xFB,
                0xD5, 0x1A, 0xD2, 0xF1,
                0x48, 0x98, 0xB9, 0x5B,
            ]))
        );
        assert!(matches!(
            Digest::try_from("38"),
            Err(digest::Error::InvalidLength { value: _, proper: _ })
        ));
        assert!(matches!(
            Digest::try_from(
                "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95BXX"
            ),
            Err(digest::Error::InvalidLength { value: _, proper: _ })
        ));
        assert!(matches!(
            Digest::try_from(
                "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B9XX"
            ),
            Err(digest::Error::ParseError(_))
        ));
    }
}
