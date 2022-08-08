use std::fmt::{self, Formatter, LowerHex, UpperHex};

use super::State;
use crate::hash::DigestError;

pub(super) const DIGEST_LENGTH_BITS: usize = 224;
pub(super) const DIGEST_LENGTH_BYTES: usize = DIGEST_LENGTH_BITS / 8;
pub(super) const DIGEST_LENGTH_WORDS: usize = DIGEST_LENGTH_BYTES / 2;
pub(super) const DIGEST_LENGTH_DWORDS: usize = DIGEST_LENGTH_WORDS / 2;
pub(super) const DIGEST_LENGTH_HEX: usize = DIGEST_LENGTH_BYTES * 2;

/// Represents hash digest.
///
/// # Examples
///
/// ```rust
/// # use chksum::hash::DigestResult;
/// use chksum::hash::sha2::sha224::Digest;
///
/// # fn wrapper() -> DigestResult<()> {
/// let digest = Digest::try_from("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f")?;
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
        let [a, b, c, d, e, f, g] = digest;
        let [a, b, c, d, e, f, g] = [
            a.to_be_bytes(),
            b.to_be_bytes(),
            c.to_be_bytes(),
            d.to_be_bytes(),
            e.to_be_bytes(),
            f.to_be_bytes(),
            g.to_be_bytes(),
        ];
        Self([
            a[0], a[1], a[2], a[3],
            b[0], b[1], b[2], b[3],
            c[0], c[1], c[2], c[3],
            d[0], d[1], d[2], d[3],
            e[0], e[1], e[2], e[3],
            f[0], f[1], f[2], f[3],
            g[0], g[1], g[2], g[3],
        ])
    }
}

impl From<State> for Digest {
    #[cfg_attr(not(debug_assertions), inline)]
    fn from(
        State {
            a,
            b,
            c,
            d,
            e,
            f,
            g,
            h: _,
        }: State,
    ) -> Self {
        Self::from([a, b, c, d, e, f, g])
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
             {:02x}{:02x}{:02x}{:02x}",
            self.0[0x00], self.0[0x01], self.0[0x02], self.0[0x03],
            self.0[0x04], self.0[0x05], self.0[0x06], self.0[0x07],
            self.0[0x08], self.0[0x09], self.0[0x0A], self.0[0x0B],
            self.0[0x0C], self.0[0x0D], self.0[0x0E], self.0[0x0F],
            self.0[0x10], self.0[0x11], self.0[0x12], self.0[0x13],
            self.0[0x14], self.0[0x15], self.0[0x16], self.0[0x17],
            self.0[0x18], self.0[0x19], self.0[0x1A], self.0[0x1B],
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
             {:02X}{:02X}{:02X}{:02X}",
            self.0[0x00], self.0[0x01], self.0[0x02], self.0[0x03],
            self.0[0x04], self.0[0x05], self.0[0x06], self.0[0x07],
            self.0[0x08], self.0[0x09], self.0[0x0A], self.0[0x0B],
            self.0[0x0C], self.0[0x0D], self.0[0x0E], self.0[0x0F],
            self.0[0x10], self.0[0x11], self.0[0x12], self.0[0x13],
            self.0[0x14], self.0[0x15], self.0[0x16], self.0[0x17],
            self.0[0x18], self.0[0x19], self.0[0x1A], self.0[0x1B],
        );
        if formatter.alternate() {
            formatter.pad_integral(true, "0X", &digest)
        } else {
            formatter.pad(&digest)
        }
    }
}

impl TryFrom<&str> for Digest {
    type Error = DigestError;

    #[cfg_attr(not(debug_assertions), inline)]
    fn try_from(digest: &str) -> Result<Self, Self::Error> {
        if digest.len() != DIGEST_LENGTH_HEX {
            let error = Self::Error::InvalidLength {
                value: digest.len(),
                proper: DIGEST_LENGTH_HEX,
            };
            return Err(error);
        }
        let (a, b, c, d, e, f, g) = (
            u32::from_str_radix(&digest[0x00..0x08], 16)?,
            u32::from_str_radix(&digest[0x08..0x10], 16)?,
            u32::from_str_radix(&digest[0x10..0x18], 16)?,
            u32::from_str_radix(&digest[0x18..0x20], 16)?,
            u32::from_str_radix(&digest[0x20..0x28], 16)?,
            u32::from_str_radix(&digest[0x28..0x30], 16)?,
            u32::from_str_radix(&digest[0x30..0x38], 16)?,
        );
        let digest = [a, b, c, d, e, f, g];
        let digest = Self::from(digest);
        Ok(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::DigestResult;

    #[test]
    fn digest_format() -> DigestResult<()> {
        let digest = Digest::try_from("D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F")?;
        assert_eq!(
            format!("{digest:x}"),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
        assert_eq!(
            format!("{digest:#x}"),
            "0xd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
        assert_eq!(
            format!("{digest:64x}"),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f        "
        );
        assert_eq!(
            format!("{digest:>64x}"),
            "        d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
        assert_eq!(
            format!("{digest:^64x}"),
            "    d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f    "
        );
        assert_eq!(
            format!("{digest:<64x}"),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f        "
        );
        assert_eq!(
            format!("{digest:.^64x}"),
            "....d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f...."
        );
        assert_eq!(format!("{digest:.8x}"), "d14a028c");
        assert_eq!(
            format!("{digest:X}"),
            "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F"
        );
        assert_eq!(
            format!("{digest:#X}"),
            "0XD14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F"
        );
        assert_eq!(
            format!("{digest:64X}"),
            "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F        "
        );
        assert_eq!(
            format!("{digest:>64X}"),
            "        D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F"
        );
        assert_eq!(
            format!("{digest:^64X}"),
            "    D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F    "
        );
        assert_eq!(
            format!("{digest:<64X}"),
            "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F        "
        );
        assert_eq!(
            format!("{digest:.^64X}"),
            "....D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F...."
        );
        assert_eq!(format!("{digest:.8X}"), "D14A028C");

        Ok(())
    }

    #[test]
    fn digest_tryfrom() {
        assert_eq!(
            Digest::try_from("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"),
            Digest::try_from("D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F")
        );
        #[rustfmt::skip]
        assert_eq!(
            Digest::try_from("D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F"),
            Ok(Digest([
                0xD1, 0x4A, 0x02, 0x8C,
                0x2A, 0x3A, 0x2B, 0xC9,
                0x47, 0x61, 0x02, 0xBB,
                0x28, 0x82, 0x34, 0xC4,
                0x15, 0xA2, 0xB0, 0x1F,
                0x82, 0x8E, 0xA6, 0x2A,
                0xC5, 0xB3, 0xE4, 0x2F,
            ]))
        );
        assert!(matches!(
            Digest::try_from("D4"),
            Err(DigestError::InvalidLength { value: _, proper: _ })
        ));
        assert!(matches!(
            Digest::try_from("D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42FXX"),
            Err(DigestError::InvalidLength { value: _, proper: _ })
        ));
        assert!(matches!(
            Digest::try_from("D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E4XX"),
            Err(DigestError::ParseError(_))
        ));
    }
}
