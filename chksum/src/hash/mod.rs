use std::fmt::{self, Formatter, LowerHex, UpperHex};

pub mod digest;
pub mod md5;
pub mod sha1;
pub mod sha2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashAlgorithm {
    /// MD5 hash function implemented in [`md5`] module.
    MD5,
    /// SHA-1 hash function implemented in [`sha1`] module.
    SHA1,
    /// SHA-2 224 hash function implemented in [`sha2::sha224`] module.
    SHA2_224,
    /// SHA-2 256 hash function implemented in [`sha2::sha256`] module.
    SHA2_256,
    /// SHA-2 512 hash function implemented in [`sha2::sha512`] module.
    SHA2_512,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashDigest {
    /// Digest of MD5 hash function implemented in [`md5`] module.
    MD5(md5::Digest),
    /// Digest of SHA-1 hash function implemented in [`sha1`] module.
    SHA1(sha1::Digest),
    /// Digest of SHA-2 224 hash function implemented in [`sha2::sha224`] module.
    SHA2_224(sha2::sha224::Digest),
    /// Digest of SHA-2 256 hash function implemented in [`sha2::sha256`] module.
    SHA2_256(sha2::sha256::Digest),
    /// Digest of SHA-2 512 hash function implemented in [`sha2::sha512`] module.
    SHA2_512(sha2::sha512::Digest),
}

impl From<md5::Digest> for HashDigest {
    #[cfg_attr(not(debug_assertions), inline)]
    fn from(digest: md5::Digest) -> Self {
        Self::MD5(digest)
    }
}

impl From<sha1::Digest> for HashDigest {
    #[cfg_attr(not(debug_assertions), inline)]
    fn from(digest: sha1::Digest) -> Self {
        Self::SHA1(digest)
    }
}

impl From<sha2::sha224::Digest> for HashDigest {
    #[cfg_attr(not(debug_assertions), inline)]
    fn from(digest: sha2::sha224::Digest) -> Self {
        Self::SHA2_224(digest)
    }
}

impl From<sha2::sha256::Digest> for HashDigest {
    #[cfg_attr(not(debug_assertions), inline)]
    fn from(digest: sha2::sha256::Digest) -> Self {
        Self::SHA2_256(digest)
    }
}

impl From<sha2::sha512::Digest> for HashDigest {
    #[cfg_attr(not(debug_assertions), inline)]
    fn from(digest: sha2::sha512::Digest) -> Self {
        Self::SHA2_512(digest)
    }
}

impl LowerHex for HashDigest {
    #[cfg_attr(not(debug_assertions), inline)]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MD5(digest) => LowerHex::fmt(digest, f),
            Self::SHA1(digest) => LowerHex::fmt(digest, f),
            Self::SHA2_224(digest) => LowerHex::fmt(digest, f),
            Self::SHA2_256(digest) => LowerHex::fmt(digest, f),
            Self::SHA2_512(digest) => LowerHex::fmt(digest, f),
        }
    }
}

impl UpperHex for HashDigest {
    #[cfg_attr(not(debug_assertions), inline)]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MD5(digest) => UpperHex::fmt(digest, f),
            Self::SHA1(digest) => UpperHex::fmt(digest, f),
            Self::SHA2_224(digest) => UpperHex::fmt(digest, f),
            Self::SHA2_256(digest) => UpperHex::fmt(digest, f),
            Self::SHA2_512(digest) => UpperHex::fmt(digest, f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_digest_from_md5() -> digest::Result<()> {
        let digest = "D41D8CD98F00B204E9800998ECF8427E";
        let digest = md5::Digest::try_from(digest)?;
        assert_eq!(HashDigest::from(digest), HashDigest::MD5(digest));
        Ok(())
    }

    #[test]
    fn hash_digest_from_sha1() -> digest::Result<()> {
        let digest = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709";
        let digest = sha1::Digest::try_from(digest)?;
        assert_eq!(HashDigest::from(digest), HashDigest::SHA1(digest));
        Ok(())
    }

    #[test]
    fn hash_digest_from_sha2_224() -> digest::Result<()> {
        let digest = "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F";
        let digest = sha2::sha224::Digest::try_from(digest)?;
        assert_eq!(HashDigest::from(digest), HashDigest::SHA2_224(digest));
        Ok(())
    }

    #[test]
    fn hash_digest_from_sha2_256() -> digest::Result<()> {
        let digest = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        let digest = sha2::sha256::Digest::try_from(digest)?;
        assert_eq!(HashDigest::from(digest), HashDigest::SHA2_256(digest));
        Ok(())
    }

    #[test]
    fn hash_digest_from_sha2_512() -> digest::Result<()> {
        let digest = "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E";
        let digest = sha2::sha512::Digest::try_from(digest)?;
        assert_eq!(HashDigest::from(digest), HashDigest::SHA2_512(digest));
        Ok(())
    }

    #[test]
    fn hash_digest_md5_lower_hex() -> digest::Result<()> {
        let digest = "D41D8CD98F00B204E9800998ECF8427E";
        let digest = md5::Digest::try_from(digest)?;
        let digest = HashDigest::MD5(digest);
        assert_eq!(format!("{:x}", digest), "d41d8cd98f00b204e9800998ecf8427e");
        Ok(())
    }

    #[test]
    fn hash_digest_sha1_lower_hex() -> digest::Result<()> {
        let digest = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709";
        let digest = sha1::Digest::try_from(digest)?;
        let digest = HashDigest::SHA1(digest);
        assert_eq!(format!("{:x}", digest), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        Ok(())
    }

    #[test]
    fn hash_digest_sha2_224_lower_hex() -> digest::Result<()> {
        let digest = "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F";
        let digest = sha2::sha224::Digest::try_from(digest)?;
        let digest = HashDigest::SHA2_224(digest);
        assert_eq!(
            format!("{:x}", digest),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
        Ok(())
    }

    #[test]
    fn hash_digest_sha2_256_lower_hex() -> digest::Result<()> {
        let digest = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        let digest = sha2::sha256::Digest::try_from(digest)?;
        let digest = HashDigest::SHA2_256(digest);
        assert_eq!(
            format!("{:x}", digest),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        Ok(())
    }

    #[test]
    fn hash_digest_sha2_512_lower_hex() -> digest::Result<()> {
        let digest = "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E";
        let digest = sha2::sha512::Digest::try_from(digest)?;
        let digest = HashDigest::SHA2_512(digest);
        assert_eq!(
            format!("{:x}", digest),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        Ok(())
    }

    #[test]
    fn hash_digest_md5_upper_hex() -> digest::Result<()> {
        let digest = "d41d8cd98f00b204e9800998ecf8427e";
        let digest = md5::Digest::try_from(digest)?;
        let digest = HashDigest::MD5(digest);
        assert_eq!(format!("{:X}", digest), "D41D8CD98F00B204E9800998ECF8427E");
        Ok(())
    }

    #[test]
    fn hash_digest_sha1_upper_hex() -> digest::Result<()> {
        let digest = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        let digest = sha1::Digest::try_from(digest)?;
        let digest = HashDigest::SHA1(digest);
        assert_eq!(format!("{:X}", digest), "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
        Ok(())
    }

    #[test]
    fn hash_digest_sha2_224_upper_hex() -> digest::Result<()> {
        let digest = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f";
        let digest = sha2::sha224::Digest::try_from(digest)?;
        let digest = HashDigest::SHA2_224(digest);
        assert_eq!(
            format!("{:X}", digest),
            "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F"
        );
        Ok(())
    }

    #[test]
    fn hash_digest_sha2_256_upper_hex() -> digest::Result<()> {
        let digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let digest = sha2::sha256::Digest::try_from(digest)?;
        let digest = HashDigest::SHA2_256(digest);
        assert_eq!(
            format!("{:X}", digest),
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        );
        Ok(())
    }

    #[test]
    fn hash_digest_sha2_512_upper_hex() -> digest::Result<()> {
        let digest = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        let digest = sha2::sha512::Digest::try_from(digest)?;
        let digest = HashDigest::SHA2_512(digest);
        assert_eq!(
            format!("{:X}", digest),
            "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E"
        );
        Ok(())
    }
}
