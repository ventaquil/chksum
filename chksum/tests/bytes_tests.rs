use chksum::prelude::*;

mod common;
use common::{data_with_size, Result, Size};

#[cfg(feature = "md5")]
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

#[cfg(feature = "sha1")]
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

#[cfg(any(feature = "sha2_224", feature = "sha2_256", feature = "sha2_384", feature = "sha2_512"))]
mod sha2 {
    use super::*;

    #[cfg(feature = "sha2_224")]
    mod sha224 {
        use super::*;

        #[test]
        fn empty_bytes() -> Result {
            let data = data_with_size(Size::Empty as usize);
            let mut bytes: &[u8] = &data;
            let digest = bytes.chksum(HashAlgorithm::SHA2_224)?;
            let digest = format!("{:X}", digest);
            assert_eq!(digest, "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F");
            Ok(())
        }

        #[test]
        fn tiny_bytes() -> Result {
            let data = data_with_size(Size::Tiny as usize);
            let mut bytes: &[u8] = &data;
            let digest = bytes.chksum(HashAlgorithm::SHA2_224)?;
            let digest = format!("{:X}", digest);
            assert_eq!(digest, "17EB7D40F0356F8598E89EAFAD5F6C759B1F822975D9C9B737C8A517");
            Ok(())
        }

        #[test]
        fn small_bytes() -> Result {
            let data = data_with_size(Size::Small as usize);
            let mut bytes: &[u8] = &data;
            let digest = bytes.chksum(HashAlgorithm::SHA2_224)?;
            let digest = format!("{:X}", digest);
            assert_eq!(digest, "9479815F0224752111E912E8CB8A9CBC3798F6EC5B027780C508E7AC");
            Ok(())
        }

        #[test]
        fn medium_bytes() -> Result {
            let data = data_with_size(Size::Medium as usize);
            let mut bytes: &[u8] = &data;
            let digest = bytes.chksum(HashAlgorithm::SHA2_224)?;
            let digest = format!("{:X}", digest);
            assert_eq!(digest, "AF01EFC931B463221861EF64EF4BA40D4E9428E20CE0DD2CBAA0E971");
            Ok(())
        }

        #[test]
        fn big_bytes() -> Result {
            let data = data_with_size(Size::Big as usize);
            let mut bytes: &[u8] = &data;
            let digest = bytes.chksum(HashAlgorithm::SHA2_224)?;
            let digest = format!("{:X}", digest);
            assert_eq!(digest, "88DA45B43E89E5481CCB23C87A1DE2370E39DB6F605386FA9E1D5FFC");
            Ok(())
        }

        #[test]
        fn huge_bytes() -> Result {
            let data = data_with_size(Size::Huge as usize);
            let mut bytes: &[u8] = &data;
            let digest = bytes.chksum(HashAlgorithm::SHA2_224)?;
            let digest = format!("{:X}", digest);
            assert_eq!(digest, "95A65DBFCD6F3B39833E239E8AE1BBBD3B673D6D1DAC0187C806BB5B");
            Ok(())
        }
    }

    #[cfg(feature = "sha2_256")]
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

    #[cfg(feature = "sha2_384")]
    mod sha384 {
        use super::*;

        #[test]
        fn empty_bytes() -> Result {
            let data = data_with_size(Size::Empty as usize);
            let mut bytes: &[u8] = &data;
            let digest = bytes.chksum(HashAlgorithm::SHA2_384)?;
            let digest = format!("{:X}", digest);
            assert_eq!(
                digest,
                "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B"
            );
            Ok(())
        }

        #[test]
        fn tiny_bytes() -> Result {
            let data = data_with_size(Size::Tiny as usize);
            let mut bytes: &[u8] = &data;
            let digest = bytes.chksum(HashAlgorithm::SHA2_384)?;
            let digest = format!("{:X}", digest);
            assert_eq!(
                digest,
                "9000CD7CADA59D1D2EB82912F7F24E5E69CC5517F68283B005FA27C285B61E05EDF1AD1A8A9BDED6FD29EB87D75AD806"
            );
            Ok(())
        }

        #[test]
        fn small_bytes() -> Result {
            let data = data_with_size(Size::Small as usize);
            let mut bytes: &[u8] = &data;
            let digest = bytes.chksum(HashAlgorithm::SHA2_384)?;
            let digest = format!("{:X}", digest);
            assert_eq!(
                digest,
                "393ADBE4D176063A1256861BCEF37605117F9E43C0CB25D4A6D5F9A3A0D0529657DB7F7C19235A299711B1B81218FC61"
            );
            Ok(())
        }

        #[test]
        fn medium_bytes() -> Result {
            let data = data_with_size(Size::Medium as usize);
            let mut bytes: &[u8] = &data;
            let digest = bytes.chksum(HashAlgorithm::SHA2_384)?;
            let digest = format!("{:X}", digest);
            assert_eq!(
                digest,
                "E0A8A701842A4F836EE11EE2715973FE08CA1AD0B4C6660F07537149BC6F930B5B2B24F7EF87C93DA7D9054F1576D0E7"
            );
            Ok(())
        }

        #[test]
        fn big_bytes() -> Result {
            let data = data_with_size(Size::Big as usize);
            let mut bytes: &[u8] = &data;
            let digest = bytes.chksum(HashAlgorithm::SHA2_384)?;
            let digest = format!("{:X}", digest);
            assert_eq!(
                digest,
                "DAB49CABF7FAD7EE6784B67541AD7CD8E1541D0E58A0E4969BF32F8308B484575FCFAD4B6D2F05288AEFF39B0B6A0BD0"
            );
            Ok(())
        }

        #[test]
        fn huge_bytes() -> Result {
            let data = data_with_size(Size::Huge as usize);
            let mut bytes: &[u8] = &data;
            let digest = bytes.chksum(HashAlgorithm::SHA2_384)?;
            let digest = format!("{:X}", digest);
            assert_eq!(
                digest,
                "507E8F0357DBB00B736720330D8C258E58415ACCD838894D5FCB13761990F5F9F4C1A87EF6E0760990F64C945A21E337"
            );
            Ok(())
        }
    }

    #[cfg(feature = "sha2_512")]
    mod sha512 {
        use super::*;

        #[test]
        fn empty_bytes() -> Result {
            let data = data_with_size(Size::Empty as usize);
            let mut bytes: &[u8] = &data;
            let digest = bytes.chksum(HashAlgorithm::SHA2_512)?;
            let digest = format!("{:X}", digest);
            assert_eq!(
                digest,
                "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E"
            );
            Ok(())
        }

        #[test]
        fn tiny_bytes() -> Result {
            let data = data_with_size(Size::Tiny as usize);
            let mut bytes: &[u8] = &data;
            let digest = bytes.chksum(HashAlgorithm::SHA2_512)?;
            let digest = format!("{:X}", digest);
            assert_eq!(
                digest,
                "A3A8C81BC97C2560010D7389BC88AAC974A104E0E2381220C6E084C4DCCD1D2D17D4F86DB31C2A851DC80E6681D74733C55DCD03DD96F6062CDDA12A291AE6CE"
            );
            Ok(())
        }

        #[test]
        fn small_bytes() -> Result {
            let data = data_with_size(Size::Small as usize);
            let mut bytes: &[u8] = &data;
            let digest = bytes.chksum(HashAlgorithm::SHA2_512)?;
            let digest = format!("{:X}", digest);
            assert_eq!(
                digest,
                "B4D18A20A6333CE63A9D50065F440267A66BE94BADD7EF87828A22B6133F943B2E525577CC64B9B6852CAAF36FF52B0FE4F5C691F835EC0AD3A2B5C50806655F"
            );
            Ok(())
        }

        #[test]
        fn medium_bytes() -> Result {
            let data = data_with_size(Size::Medium as usize);
            let mut bytes: &[u8] = &data;
            let digest = bytes.chksum(HashAlgorithm::SHA2_512)?;
            let digest = format!("{:X}", digest);
            assert_eq!(
                digest,
                "DBCD7D1B4B363FB217B6A0CE274528BF0E9C0763B250EDCDC1936047ED92B9D91EF17E48E171835451CDCF7C89E31A699B17A2FFF210E57C0A294CC36DC7AF10"
            );
            Ok(())
        }

        #[test]
        fn big_bytes() -> Result {
            let data = data_with_size(Size::Big as usize);
            let mut bytes: &[u8] = &data;
            let digest = bytes.chksum(HashAlgorithm::SHA2_512)?;
            let digest = format!("{:X}", digest);
            assert_eq!(
                digest,
                "42AB76F145553CCB7BBC018F661471DD9B5AE15193C81AE4BF186F9CA15CCB05DCB069B27F533FC63EC530C3E5835969F91BE8C6EA45ADE9BB90BB023CF78849"
            );
            Ok(())
        }

        #[test]
        fn huge_bytes() -> Result {
            let data = data_with_size(Size::Huge as usize);
            let mut bytes: &[u8] = &data;
            let digest = bytes.chksum(HashAlgorithm::SHA2_512)?;
            let digest = format!("{:X}", digest);
            assert_eq!(
                digest,
                "86076E16966A41B4AB25E7D328001168B14A6CEA0EBB96A81404106A73A268CE1D78EA0F6C3B22BC790644830BC2D4CBC061479462DAEACC132E06A23D48F4F3"
            );
            Ok(())
        }
    }
}
