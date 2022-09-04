use std::fmt::{self, Formatter, LowerHex, UpperHex};

use super::State;
use crate::hash::digest;

pub(super) const DIGEST_LENGTH_BITS: usize = 512;
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
/// use chksum::hash::sha2::sha512::Digest;
///
/// #[rustfmt::skip]
/// # fn wrapper() -> Result<()> {
/// let digest = Digest::try_from("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")?;
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
        let [a, b, c, d, e, f, g, h] = digest;
        let [a, b, c, d, e, f, g, h] = [
            a.to_be_bytes(),
            b.to_be_bytes(),
            c.to_be_bytes(),
            d.to_be_bytes(),
            e.to_be_bytes(),
            f.to_be_bytes(),
            g.to_be_bytes(),
            h.to_be_bytes(),
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
            g[0], g[1], g[2], g[3],
            g[4], g[5], g[6], g[7],
            h[0], h[1], h[2], h[3],
            h[4], h[5], h[6], h[7],
        ])
    }
}

impl From<State> for Digest {
    #[cfg_attr(not(debug_assertions), inline)]
    fn from(State { a, b, c, d, e, f, g, h }: State) -> Self {
        Self::from([a, b, c, d, e, f, g, h])
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
            self.0[0x30], self.0[0x31], self.0[0x32], self.0[0x33],
            self.0[0x34], self.0[0x35], self.0[0x36], self.0[0x37],
            self.0[0x38], self.0[0x39], self.0[0x3A], self.0[0x3B],
            self.0[0x3C], self.0[0x3D], self.0[0x3E], self.0[0x3F],
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
             self.0[0x30], self.0[0x31], self.0[0x32], self.0[0x33],
             self.0[0x34], self.0[0x35], self.0[0x36], self.0[0x37],
             self.0[0x38], self.0[0x39], self.0[0x3A], self.0[0x3B],
             self.0[0x3C], self.0[0x3D], self.0[0x3E], self.0[0x3F],
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
        let (a, b, c, d, e, f, g, h) = (
            u64::from_str_radix(&digest[0x00..0x10], 16)?,
            u64::from_str_radix(&digest[0x10..0x20], 16)?,
            u64::from_str_radix(&digest[0x20..0x30], 16)?,
            u64::from_str_radix(&digest[0x30..0x40], 16)?,
            u64::from_str_radix(&digest[0x40..0x50], 16)?,
            u64::from_str_radix(&digest[0x50..0x60], 16)?,
            u64::from_str_radix(&digest[0x60..0x70], 16)?,
            u64::from_str_radix(&digest[0x70..0x80], 16)?,
        );
        let digest = [a, b, c, d, e, f, g, h];
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
        let digest = Digest::try_from("CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E")?;
        assert_eq!(
            format!("{digest:x}"),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        assert_eq!(
            format!("{digest:#x}"),
            "0xcf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        assert_eq!(
            format!("{digest:136x}"),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e        "
        );
        assert_eq!(
            format!("{digest:>136x}"),
            "        cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        assert_eq!(
            format!("{digest:^136x}"),
            "    cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e    "
        );
        assert_eq!(
            format!("{digest:<136x}"),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e        "
        );
        assert_eq!(
            format!("{digest:.^136x}"),
            "....cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e...."
        );
        assert_eq!(format!("{digest:.8x}"), "cf83e135");
        assert_eq!(
            format!("{digest:X}"),
            "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E"
        );
        assert_eq!(
            format!("{digest:#X}"),
            "0XCF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E"
        );
        assert_eq!(
            format!("{digest:136X}"),
            "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E        "
        );
        assert_eq!(
            format!("{digest:>136X}"),
            "        CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E"
        );
        assert_eq!(
            format!("{digest:^136X}"),
            "    CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E    "
        );
        assert_eq!(
            format!("{digest:<136X}"),
            "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E        "
        );
        assert_eq!(
            format!("{digest:.^136X}"),
            "....CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E...."
        );
        assert_eq!(format!("{digest:.8X}"), "CF83E135");
        Ok(())
    }

    #[test]
    fn digest_tryfrom() {
        assert_eq!(
            Digest::try_from("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
            Digest::try_from("CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E")
        );
        #[rustfmt::skip]
        assert_eq!(
            Digest::try_from("CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E"),
            Ok(Digest([
                0xCF, 0x83, 0xE1, 0x35,
                0x7E, 0xEF, 0xB8, 0xBD,
                0xF1, 0x54, 0x28, 0x50,
                0xD6, 0x6D, 0x80, 0x07,
                0xD6, 0x20, 0xE4, 0x05,
                0x0B, 0x57, 0x15, 0xDC,
                0x83, 0xF4, 0xA9, 0x21,
                0xD3, 0x6C, 0xE9, 0xCE,
                0x47, 0xD0, 0xD1, 0x3C,
                0x5D, 0x85, 0xF2, 0xB0,
                0xFF, 0x83, 0x18, 0xD2,
                0x87, 0x7E, 0xEC, 0x2F,
                0x63, 0xB9, 0x31, 0xBD,
                0x47, 0x41, 0x7A, 0x81,
                0xA5, 0x38, 0x32, 0x7A,
                0xF9, 0x27, 0xDA, 0x3E,
            ]))
        );
        assert!(matches!(
            Digest::try_from("CF"),
            Err(digest::Error::InvalidLength { value: _, proper: _ })
        ));
        assert!(matches!(
            Digest::try_from("CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3EXX"),
            Err(digest::Error::InvalidLength { value: _, proper: _ })
        ));
        assert!(matches!(
            Digest::try_from("CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DAXX"),
            Err(digest::Error::ParseError(_))
        ));
    }
}
