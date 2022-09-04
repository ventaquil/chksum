use std::fmt::{self, Formatter, LowerHex, UpperHex};

use super::State;
use crate::hash::digest;

pub(super) const DIGEST_LENGTH_BITS: usize = 160;
pub(super) const DIGEST_LENGTH_BYTES: usize = DIGEST_LENGTH_BITS / 8;
pub(super) const DIGEST_LENGTH_WORDS: usize = DIGEST_LENGTH_BYTES / 2;
pub(super) const DIGEST_LENGTH_DWORDS: usize = DIGEST_LENGTH_WORDS / 2;
pub(super) const DIGEST_LENGTH_HEX: usize = DIGEST_LENGTH_BYTES * 2;

/// Represents hash digest.
///
/// # Examples
///
/// ```rust
/// # use chksum::hash::digest::Result;
/// use chksum::hash::sha1::Digest;
///
/// # fn wrapper() -> Result<()> {
/// let digest = Digest::try_from("da39a3ee5e6b4b0d3255bfef95601890afd80709")?;
/// println!("digest {:?}", digest);
/// println!("digest {:x}", digest);
/// println!("digest {:X}", digest);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Digest([u8; DIGEST_LENGTH_BYTES]);

impl From<[u32; DIGEST_LENGTH_DWORDS]> for Digest {
    #[cfg_attr(not(debug_assertions), inline)]
    #[rustfmt::skip]
    fn from(digest: [u32; DIGEST_LENGTH_DWORDS]) -> Self {
        let [a, b, c, d, e] = digest;
        let [a, b, c, d, e] = [
            a.to_be_bytes(),
            b.to_be_bytes(),
            c.to_be_bytes(),
            d.to_be_bytes(),
            e.to_be_bytes(),
        ];
        Self([
            a[0], a[1], a[2], a[3],
            b[0], b[1], b[2], b[3],
            c[0], c[1], c[2], c[3],
            d[0], d[1], d[2], d[3],
            e[0], e[1], e[2], e[3],
        ])
    }
}

impl From<State> for Digest {
    #[cfg_attr(not(debug_assertions), inline)]
    fn from(State { a, b, c, d, e }: State) -> Self {
        Self::from([a, b, c, d, e])
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
             {:02x}{:02x}{:02x}{:02x}",
            self.0[0x00], self.0[0x01], self.0[0x02], self.0[0x03],
            self.0[0x04], self.0[0x05], self.0[0x06], self.0[0x07],
            self.0[0x08], self.0[0x09], self.0[0x0A], self.0[0x0B],
            self.0[0x0C], self.0[0x0D], self.0[0x0E], self.0[0x0F],
            self.0[0x10], self.0[0x11], self.0[0x12], self.0[0x13],
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
            "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.0[0x00],
            self.0[0x01],
            self.0[0x02],
            self.0[0x03],
            self.0[0x04],
            self.0[0x05],
            self.0[0x06],
            self.0[0x07],
            self.0[0x08],
            self.0[0x09],
            self.0[0x0A],
            self.0[0x0B],
            self.0[0x0C],
            self.0[0x0D],
            self.0[0x0E],
            self.0[0x0F],
            self.0[0x10],
            self.0[0x11],
            self.0[0x12],
            self.0[0x13],
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
        let (a, b, c, d, e) = (
            u32::from_str_radix(&digest[0x00..0x08], 16)?,
            u32::from_str_radix(&digest[0x08..0x10], 16)?,
            u32::from_str_radix(&digest[0x10..0x18], 16)?,
            u32::from_str_radix(&digest[0x18..0x20], 16)?,
            u32::from_str_radix(&digest[0x20..0x28], 16)?,
        );
        let digest = [a, b, c, d, e];
        let digest = Self::from(digest);
        Ok(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_format() {
        let digest = Digest::try_from("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709").unwrap();
        assert_eq!(format!("{digest:x}"), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(format!("{digest:#x}"), "0xda39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            format!("{digest:48x}"),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709        "
        );
        assert_eq!(
            format!("{digest:>48x}"),
            "        da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            format!("{digest:^48x}"),
            "    da39a3ee5e6b4b0d3255bfef95601890afd80709    "
        );
        assert_eq!(
            format!("{digest:<48x}"),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709        "
        );
        assert_eq!(
            format!("{digest:.^48x}"),
            "....da39a3ee5e6b4b0d3255bfef95601890afd80709...."
        );
        assert_eq!(format!("{digest:.8x}"), "da39a3ee");
        assert_eq!(format!("{digest:X}"), "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
        assert_eq!(format!("{digest:#X}"), "0XDA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
        assert_eq!(
            format!("{digest:48X}"),
            "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709        "
        );
        assert_eq!(
            format!("{digest:>48X}"),
            "        DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
        );
        assert_eq!(
            format!("{digest:^48X}"),
            "    DA39A3EE5E6B4B0D3255BFEF95601890AFD80709    "
        );
        assert_eq!(
            format!("{digest:<48X}"),
            "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709        "
        );
        assert_eq!(
            format!("{digest:.^48X}"),
            "....DA39A3EE5E6B4B0D3255BFEF95601890AFD80709...."
        );
        assert_eq!(format!("{digest:.8X}"), "DA39A3EE");
    }

    #[test]
    fn digest_tryfrom() {
        assert_eq!(
            Digest::try_from("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            Digest::try_from("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709")
        );
        assert_eq!(
            Digest::try_from("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"),
            Ok(Digest([
                0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55, 0xBF, 0xEF, 0x95, 0x60, 0x18, 0x90, 0xAF,
                0xD8, 0x07, 0x09
            ]))
        );
        assert!(matches!(
            Digest::try_from("DA"),
            Err(digest::Error::InvalidLength { value: _, proper: _ })
        ));
        assert!(matches!(
            Digest::try_from("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709XX"),
            Err(digest::Error::InvalidLength { value: _, proper: _ })
        ));
        assert!(matches!(
            Digest::try_from("DA39A3EE5E6B4B0D3255BFEF95601890AFD807XX"),
            Err(digest::Error::ParseError(_))
        ));
    }
}
