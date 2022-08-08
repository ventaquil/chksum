use chksum::prelude::*;

mod common;
use common::{data_with_size, Result, Size};

mod md5 {
    use super::*;

    #[test]
    fn empty_bytes() -> Result {
        let data = data_with_size(Size::Empty as usize);
        let mut bytes: &[u8] = &data;
        let digest = bytes.chksum(HashAlgorithm::MD5)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "D41D8CD98F00B204E9800998ECF8427E");
        Ok(())
    }

    #[test]
    fn tiny_bytes() -> Result {
        let data = data_with_size(Size::Tiny as usize);
        let mut bytes: &[u8] = &data;
        let digest = bytes.chksum(HashAlgorithm::MD5)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "E8DC4081B13434B45189A720B77B6818");
        Ok(())
    }

    #[test]
    fn small_bytes() -> Result {
        let data = data_with_size(Size::Small as usize);
        let mut bytes: &[u8] = &data;
        let digest = bytes.chksum(HashAlgorithm::MD5)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "C844E7E6F76809EDEE8C6BC64404C963");
        Ok(())
    }

    #[test]
    fn medium_bytes() -> Result {
        let data = data_with_size(Size::Medium as usize);
        let mut bytes: &[u8] = &data;
        let digest = bytes.chksum(HashAlgorithm::MD5)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "2108E2728DE71A20ABB35644801BD8EE");
        Ok(())
    }

    #[test]
    fn big_bytes() -> Result {
        let data = data_with_size(Size::Big as usize);
        let mut bytes: &[u8] = &data;
        let digest = bytes.chksum(HashAlgorithm::MD5)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "06040296DEC20641F15D324E454C237D");
        Ok(())
    }

    #[test]
    fn huge_bytes() -> Result {
        let data = data_with_size(Size::Huge as usize);
        let mut bytes: &[u8] = &data;
        let digest = bytes.chksum(HashAlgorithm::MD5)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "9C6C1BFB236EDE4FD3C2E0027A169874");
        Ok(())
    }
}

mod sha1 {
    use super::*;

    #[test]
    fn empty_bytes() -> Result {
        let data = data_with_size(Size::Empty as usize);
        let mut bytes: &[u8] = &data;
        let digest = bytes.chksum(HashAlgorithm::SHA1)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
        Ok(())
    }

    #[test]
    fn tiny_bytes() -> Result {
        let data = data_with_size(Size::Tiny as usize);
        let mut bytes: &[u8] = &data;
        let digest = bytes.chksum(HashAlgorithm::SHA1)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "425AF12A0743502B322E93A015BCF868E324D56A");
        Ok(())
    }

    #[test]
    fn small_bytes() -> Result {
        let data = data_with_size(Size::Small as usize);
        let mut bytes: &[u8] = &data;
        let digest = bytes.chksum(HashAlgorithm::SHA1)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "EA33090EAC3A084A89AEBECBDBBCC5C6E0E56F23");
        Ok(())
    }

    #[test]
    fn medium_bytes() -> Result {
        let data = data_with_size(Size::Medium as usize);
        let mut bytes: &[u8] = &data;
        let digest = bytes.chksum(HashAlgorithm::SHA1)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "972EB0B736B22CB72EE599AB3DB6A47BB7F7D8EB");
        Ok(())
    }

    #[test]
    fn big_bytes() -> Result {
        let data = data_with_size(Size::Big as usize);
        let mut bytes: &[u8] = &data;
        let digest = bytes.chksum(HashAlgorithm::SHA1)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "39941AB1AED3936DACBB3B6E98BF707BCE08F6A1");
        Ok(())
    }

    #[test]
    fn huge_bytes() -> Result {
        let data = data_with_size(Size::Huge as usize);
        let mut bytes: &[u8] = &data;
        let digest = bytes.chksum(HashAlgorithm::SHA1)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "A1DD2F8107116C3A1DA46EA4959258FDA49C44F0");
        Ok(())
    }
}

mod sha2 {
    use super::*;

    mod sha256 {
        use super::*;

        #[test]
        fn empty_bytes() -> Result {
            let data = data_with_size(Size::Empty as usize);
            let mut bytes: &[u8] = &data;
            let digest = bytes.chksum(HashAlgorithm::SHA2_256)?;
            let digest = format!("{:X}", digest);
            assert_eq!(
                digest,
                "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
            );
            Ok(())
        }

        #[test]
        fn tiny_bytes() -> Result {
            let data = data_with_size(Size::Tiny as usize);
            let mut bytes: &[u8] = &data;
            let digest = bytes.chksum(HashAlgorithm::SHA2_256)?;
            let digest = format!("{:X}", digest);
            assert_eq!(
                digest,
                "9C56CC51B374C3BA189210D5B6D4BF57790D351C96C47C02190ECF1E430635AB"
            );
            Ok(())
        }

        #[test]
        fn small_bytes() -> Result {
            let data = data_with_size(Size::Small as usize);
            let mut bytes: &[u8] = &data;
            let digest = bytes.chksum(HashAlgorithm::SHA2_256)?;
            let digest = format!("{:X}", digest);
            assert_eq!(
                digest,
                "FA443F246563D77F1F47C322251159E32A357005BF6BFCC618C3C905E849CBCD"
            );
            Ok(())
        }

        #[test]
        fn medium_bytes() -> Result {
            let data = data_with_size(Size::Medium as usize);
            let mut bytes: &[u8] = &data;
            let digest = bytes.chksum(HashAlgorithm::SHA2_256)?;
            let digest = format!("{:X}", digest);
            assert_eq!(
                digest,
                "4E54C175A12A9172FA0C81DF71542AC61F7B7A9AC032E8CA607FE2C00C172ECE"
            );
            Ok(())
        }

        #[test]
        fn big_bytes() -> Result {
            let data = data_with_size(Size::Big as usize);
            let mut bytes: &[u8] = &data;
            let digest = bytes.chksum(HashAlgorithm::SHA2_256)?;
            let digest = format!("{:X}", digest);
            assert_eq!(
                digest,
                "85ECFC8853A01F2F02D60E3E5C424F228F17D838103C55A64DFAEFC9A5D8D821"
            );
            Ok(())
        }

        #[test]
        fn huge_bytes() -> Result {
            let data = data_with_size(Size::Huge as usize);
            let mut bytes: &[u8] = &data;
            let digest = bytes.chksum(HashAlgorithm::SHA2_256)?;
            let digest = format!("{:X}", digest);
            assert_eq!(
                digest,
                "B98AD09EDAEBC3F92CC63176DB23E37ADDE356AD2745CFA8885280A2D4EDFC1C"
            );
            Ok(())
        }
    }
}
