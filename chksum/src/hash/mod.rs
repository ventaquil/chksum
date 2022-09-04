use std::fmt::{self, Formatter, LowerHex, UpperHex};

pub mod digest;
#[cfg(feature = "md5")]
pub mod md5;
#[cfg(feature = "sha1")]
pub mod sha1;
#[cfg(any(feature = "sha2_224", feature = "sha2_256", feature = "sha2_384", feature = "sha2_512"))]
pub mod sha2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashAlgorithm {
    /// MD5 hash function implemented in [`md5`] module.
    #[cfg(feature = "md5")]
    MD5,
    /// SHA-1 hash function implemented in [`sha1`] module.
    #[cfg(feature = "sha1")]
    SHA1,
    /// SHA-2 224 hash function implemented in [`sha2::sha224`] module.
    #[cfg(feature = "sha2_224")]
    SHA2_224,
    /// SHA-2 256 hash function implemented in [`sha2::sha256`] module.
    #[cfg(feature = "sha2_256")]
    SHA2_256,
    /// SHA-2 384 hash function implemented in [`sha2::sha384`] module.
    #[cfg(feature = "sha2_384")]
    SHA2_384,
    /// SHA-2 512 hash function implemented in [`sha2::sha512`] module.
    #[cfg(feature = "sha2_512")]
    SHA2_512,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashDigest {
    /// Digest of MD5 hash function implemented in [`md5`] module.
    #[cfg(feature = "md5")]
    MD5(md5::Digest),
    /// Digest of SHA-1 hash function implemented in [`sha1`] module.
    #[cfg(feature = "sha1")]
    SHA1(sha1::Digest),
    /// Digest of SHA-2 224 hash function implemented in [`sha2::sha224`] module.
    #[cfg(feature = "sha2_224")]
    SHA2_224(sha2::sha224::Digest),
    /// Digest of SHA-2 256 hash function implemented in [`sha2::sha256`] module.
    #[cfg(feature = "sha2_256")]
    SHA2_256(sha2::sha256::Digest),
    /// Digest of SHA-2 384 hash function implemented in [`sha2::sha384`] module.
    #[cfg(feature = "sha2_384")]
    SHA2_384(sha2::sha384::Digest),
    /// Digest of SHA-2 512 hash function implemented in [`sha2::sha512`] module.
    #[cfg(feature = "sha2_512")]
    SHA2_512(sha2::sha512::Digest),
}

#[cfg(feature = "md5")]
impl From<md5::Digest> for HashDigest {
    #[cfg_attr(not(debug_assertions), inline)]
    fn from(digest: md5::Digest) -> Self {
        Self::MD5(digest)
    }
}

#[cfg(feature = "sha1")]
impl From<sha1::Digest> for HashDigest {
    #[cfg_attr(not(debug_assertions), inline)]
    fn from(digest: sha1::Digest) -> Self {
        Self::SHA1(digest)
    }
}

#[cfg(feature = "sha2_224")]
impl From<sha2::sha224::Digest> for HashDigest {
    #[cfg_attr(not(debug_assertions), inline)]
    fn from(digest: sha2::sha224::Digest) -> Self {
        Self::SHA2_224(digest)
    }
}

#[cfg(feature = "sha2_256")]
impl From<sha2::sha256::Digest> for HashDigest {
    #[cfg_attr(not(debug_assertions), inline)]
    fn from(digest: sha2::sha256::Digest) -> Self {
        Self::SHA2_256(digest)
    }
}

#[cfg(feature = "sha2_384")]
impl From<sha2::sha384::Digest> for HashDigest {
    #[cfg_attr(not(debug_assertions), inline)]
    fn from(digest: sha2::sha384::Digest) -> Self {
        Self::SHA2_384(digest)
    }
}

#[cfg(feature = "sha2_512")]
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
            #[cfg(feature = "md5")]
            Self::MD5(digest) => LowerHex::fmt(digest, f),
            #[cfg(feature = "sha1")]
            Self::SHA1(digest) => LowerHex::fmt(digest, f),
            #[cfg(feature = "sha2_224")]
            Self::SHA2_224(digest) => LowerHex::fmt(digest, f),
            #[cfg(feature = "sha2_256")]
            Self::SHA2_256(digest) => LowerHex::fmt(digest, f),
            #[cfg(feature = "sha2_384")]
            Self::SHA2_384(digest) => LowerHex::fmt(digest, f),
            #[cfg(feature = "sha2_512")]
            Self::SHA2_512(digest) => LowerHex::fmt(digest, f),
        }
    }
}

impl UpperHex for HashDigest {
    #[cfg_attr(not(debug_assertions), inline)]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "md5")]
            Self::MD5(digest) => UpperHex::fmt(digest, f),
            #[cfg(feature = "sha1")]
            Self::SHA1(digest) => UpperHex::fmt(digest, f),
            #[cfg(feature = "sha2_224")]
            Self::SHA2_224(digest) => UpperHex::fmt(digest, f),
            #[cfg(feature = "sha2_256")]
            Self::SHA2_256(digest) => UpperHex::fmt(digest, f),
            #[cfg(feature = "sha2_384")]
            Self::SHA2_384(digest) => UpperHex::fmt(digest, f),
            #[cfg(feature = "sha2_512")]
            Self::SHA2_512(digest) => UpperHex::fmt(digest, f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "md5")]
    #[test]
    fn hash_digest_from_md5() -> digest::Result<()> {
        let digest = "D41D8CD98F00B204E9800998ECF8427E";
        let digest = md5::Digest::try_from(digest)?;
        assert_eq!(HashDigest::from(digest), HashDigest::MD5(digest));
        Ok(())
    }

    #[cfg(feature = "sha1")]
    #[test]
    fn hash_digest_from_sha1() -> digest::Result<()> {
        let digest = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709";
        let digest = sha1::Digest::try_from(digest)?;
        assert_eq!(HashDigest::from(digest), HashDigest::SHA1(digest));
        Ok(())
    }

    #[cfg(feature = "sha2_224")]
    #[test]
    fn hash_digest_from_sha2_224() -> digest::Result<()> {
        let digest = "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F";
        let digest = sha2::sha224::Digest::try_from(digest)?;
        assert_eq!(HashDigest::from(digest), HashDigest::SHA2_224(digest));
        Ok(())
    }

    #[cfg(feature = "sha2_256")]
    #[test]
    fn hash_digest_from_sha2_256() -> digest::Result<()> {
        let digest = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        let digest = sha2::sha256::Digest::try_from(digest)?;
        assert_eq!(HashDigest::from(digest), HashDigest::SHA2_256(digest));
        Ok(())
    }

    #[cfg(feature = "sha2_384")]
    #[test]
    fn hash_digest_from_sha2_384() -> digest::Result<()> {
        let digest = "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B";
        let digest = sha2::sha384::Digest::try_from(digest)?;
        assert_eq!(HashDigest::from(digest), HashDigest::SHA2_384(digest));
        Ok(())
    }

    #[cfg(feature = "sha2_512")]
    #[test]
    fn hash_digest_from_sha2_512() -> digest::Result<()> {
        let digest = "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E";
        let digest = sha2::sha512::Digest::try_from(digest)?;
        assert_eq!(HashDigest::from(digest), HashDigest::SHA2_512(digest));
        Ok(())
    }

    #[cfg(feature = "md5")]
    #[test]
    fn hash_digest_md5_lower_hex() -> digest::Result<()> {
        let digest = "D41D8CD98F00B204E9800998ECF8427E";
        let digest = md5::Digest::try_from(digest)?;
        let digest = HashDigest::MD5(digest);
        assert_eq!(format!("{:x}", digest), "d41d8cd98f00b204e9800998ecf8427e");
        Ok(())
    }

    #[cfg(feature = "sha1")]
    #[test]
    fn hash_digest_sha1_lower_hex() -> digest::Result<()> {
        let digest = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709";
        let digest = sha1::Digest::try_from(digest)?;
        let digest = HashDigest::SHA1(digest);
        assert_eq!(format!("{:x}", digest), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        Ok(())
    }

    #[cfg(feature = "sha2_224")]
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

    #[cfg(feature = "sha2_256")]
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

    #[cfg(feature = "sha2_384")]
    #[test]
    fn hash_digest_sha2_384_lower_hex() -> digest::Result<()> {
        let digest = "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B";
        let digest = sha2::sha384::Digest::try_from(digest)?;
        let digest = HashDigest::SHA2_384(digest);
        assert_eq!(
            format!("{:x}", digest),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
        Ok(())
    }

    #[cfg(feature = "sha2_512")]
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

    #[cfg(feature = "md5")]
    #[test]
    fn hash_digest_md5_upper_hex() -> digest::Result<()> {
        let digest = "d41d8cd98f00b204e9800998ecf8427e";
        let digest = md5::Digest::try_from(digest)?;
        let digest = HashDigest::MD5(digest);
        assert_eq!(format!("{:X}", digest), "D41D8CD98F00B204E9800998ECF8427E");
        Ok(())
    }

    #[cfg(feature = "sha1")]
    #[test]
    fn hash_digest_sha1_upper_hex() -> digest::Result<()> {
        let digest = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        let digest = sha1::Digest::try_from(digest)?;
        let digest = HashDigest::SHA1(digest);
        assert_eq!(format!("{:X}", digest), "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
        Ok(())
    }

    #[cfg(feature = "sha2_224")]
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

    #[cfg(feature = "sha2_256")]
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

    #[cfg(feature = "sha2_384")]
    #[test]
    fn hash_digest_sha2_384_upper_hex() -> digest::Result<()> {
        let digest = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";
        let digest = sha2::sha384::Digest::try_from(digest)?;
        let digest = HashDigest::SHA2_384(digest);
        assert_eq!(
            format!("{:X}", digest),
            "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B"
        );
        Ok(())
    }

    #[cfg(feature = "sha2_512")]
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
