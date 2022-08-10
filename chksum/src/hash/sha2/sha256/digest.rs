use std::fmt::{self, Formatter, LowerHex, UpperHex};

use super::State;
use crate::hash::digest;

pub(super) const DIGEST_LENGTH_BITS: usize = 256;
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
/// use chksum::hash::sha2::sha256::Digest;
///
/// #[rustfmt::skip]
/// # fn wrapper() -> Result<()> {
/// let digest = Digest::try_from("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")?;
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
            b[0], b[1], b[2], b[3],
            c[0], c[1], c[2], c[3],
            d[0], d[1], d[2], d[3],
            e[0], e[1], e[2], e[3],
            f[0], f[1], f[2], f[3],
            g[0], g[1], g[2], g[3],
            h[0], h[1], h[2], h[3],
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
             {:02x}{:02x}{:02x}{:02x}",
            self.0[0x00], self.0[0x01], self.0[0x02], self.0[0x03],
            self.0[0x04], self.0[0x05], self.0[0x06], self.0[0x07],
            self.0[0x08], self.0[0x09], self.0[0x0A], self.0[0x0B],
            self.0[0x0C], self.0[0x0D], self.0[0x0E], self.0[0x0F],
            self.0[0x10], self.0[0x11], self.0[0x12], self.0[0x13],
            self.0[0x14], self.0[0x15], self.0[0x16], self.0[0x17],
            self.0[0x18], self.0[0x19], self.0[0x1A], self.0[0x1B],
            self.0[0x1C], self.0[0x1D], self.0[0x1E], self.0[0x1F],
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
             {:02X}{:02X}{:02X}{:02X}",
            self.0[0x00], self.0[0x01], self.0[0x02], self.0[0x03],
            self.0[0x04], self.0[0x05], self.0[0x06], self.0[0x07],
            self.0[0x08], self.0[0x09], self.0[0x0A], self.0[0x0B],
            self.0[0x0C], self.0[0x0D], self.0[0x0E], self.0[0x0F],
            self.0[0x10], self.0[0x11], self.0[0x12], self.0[0x13],
            self.0[0x14], self.0[0x15], self.0[0x16], self.0[0x17],
            self.0[0x18], self.0[0x19], self.0[0x1A], self.0[0x1B],
            self.0[0x1C], self.0[0x1D], self.0[0x1E], self.0[0x1F],
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
            u32::from_str_radix(&digest[0x00..0x08], 16)?,
            u32::from_str_radix(&digest[0x08..0x10], 16)?,
            u32::from_str_radix(&digest[0x10..0x18], 16)?,
            u32::from_str_radix(&digest[0x18..0x20], 16)?,
            u32::from_str_radix(&digest[0x20..0x28], 16)?,
            u32::from_str_radix(&digest[0x28..0x30], 16)?,
            u32::from_str_radix(&digest[0x30..0x38], 16)?,
            u32::from_str_radix(&digest[0x38..0x40], 16)?,
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
        let digest = Digest::try_from("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")?;
        assert_eq!(
            format!("{digest:x}"),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            format!("{digest:#x}"),
            "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            format!("{digest:72x}"),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        "
        );
        assert_eq!(
            format!("{digest:>72x}"),
            "        e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            format!("{digest:^72x}"),
            "    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855    "
        );
        assert_eq!(
            format!("{digest:<72x}"),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        "
        );
        assert_eq!(
            format!("{digest:.^72x}"),
            "....e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855...."
        );
        assert_eq!(format!("{digest:.8x}"), "e3b0c442");
        assert_eq!(
            format!("{digest:X}"),
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        );
        assert_eq!(
            format!("{digest:#X}"),
            "0XE3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        );
        assert_eq!(
            format!("{digest:72X}"),
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855        "
        );
        assert_eq!(
            format!("{digest:>72X}"),
            "        E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        );
        assert_eq!(
            format!("{digest:^72X}"),
            "    E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855    "
        );
        assert_eq!(
            format!("{digest:<72X}"),
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855        "
        );
        assert_eq!(
            format!("{digest:.^72X}"),
            "....E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855...."
        );
        assert_eq!(format!("{digest:.8X}"), "E3B0C442");
        Ok(())
    }

    #[test]
    fn digest_tryfrom() {
        assert_eq!(
            Digest::try_from("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            Digest::try_from("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")
        );
        #[rustfmt::skip]
        assert_eq!(
            Digest::try_from("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"),
            Ok(Digest([
                0xE3, 0xB0, 0xC4, 0x42,
                0x98, 0xFC, 0x1C, 0x14,
                0x9A, 0xFB, 0xF4, 0xC8,
                0x99, 0x6F, 0xB9, 0x24,
                0x27, 0xAE, 0x41, 0xE4,
                0x64, 0x9B, 0x93, 0x4C,
                0xA4, 0x95, 0x99, 0x1B,
                0x78, 0x52, 0xB8, 0x55,
            ]))
        );
        assert!(matches!(
            Digest::try_from("D4"),
            Err(digest::Error::InvalidLength { value: _, proper: _ })
        ));
        assert!(matches!(
            Digest::try_from("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855XX"),
            Err(digest::Error::InvalidLength { value: _, proper: _ })
        ));
        assert!(matches!(
            Digest::try_from("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B8XX"),
            Err(digest::Error::ParseError(_))
        ));
    }
}
