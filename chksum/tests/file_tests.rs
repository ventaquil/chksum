use std::io::{Seek, SeekFrom, Write};

use chksum::prelude::*;
use tempfile::tempfile;

mod common;
use common::{data_with_size, Result, Size};

mod md5 {
    use super::*;

    #[test]
    fn empty_file() -> Result {
        let data = data_with_size(Size::Empty as usize);
        let mut file = {
            let mut file = tempfile()?;
            file.write(&data)?;
            file.seek(SeekFrom::Start(0))?;
            file
        };
        let digest = file.chksum(HashAlgorithm::MD5)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "D41D8CD98F00B204E9800998ECF8427E");
        Ok(())
    }

    #[test]
    fn tiny_file() -> Result {
        let data = data_with_size(Size::Tiny as usize);
        let mut file = {
            let mut file = tempfile()?;
            file.write(&data)?;
            file.seek(SeekFrom::Start(0))?;
            file
        };
        let digest = file.chksum(HashAlgorithm::MD5)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "E8DC4081B13434B45189A720B77B6818");
        Ok(())
    }

    #[test]
    fn small_file() -> Result {
        let data = data_with_size(Size::Small as usize);
        let mut file = {
            let mut file = tempfile()?;
            file.write(&data)?;
            file.seek(SeekFrom::Start(0))?;
            file
        };
        let digest = file.chksum(HashAlgorithm::MD5)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "C844E7E6F76809EDEE8C6BC64404C963");
        Ok(())
    }

    #[test]
    fn medium_file() -> Result {
        let data = data_with_size(Size::Medium as usize);
        let mut file = {
            let mut file = tempfile()?;
            file.write(&data)?;
            file.seek(SeekFrom::Start(0))?;
            file
        };
        let digest = file.chksum(HashAlgorithm::MD5)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "2108E2728DE71A20ABB35644801BD8EE");
        Ok(())
    }

    #[test]
    fn big_file() -> Result {
        let data = data_with_size(Size::Big as usize);
        let mut file = {
            let mut file = tempfile()?;
            file.write(&data)?;
            file.seek(SeekFrom::Start(0))?;
            file
        };
        let digest = file.chksum(HashAlgorithm::MD5)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "06040296DEC20641F15D324E454C237D");
        Ok(())
    }

    #[test]
    fn huge_file() -> Result {
        let data = data_with_size(Size::Huge as usize);
        let mut file = {
            let mut file = tempfile()?;
            file.write(&data)?;
            file.seek(SeekFrom::Start(0))?;
            file
        };
        let digest = file.chksum(HashAlgorithm::MD5)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "9C6C1BFB236EDE4FD3C2E0027A169874");
        Ok(())
    }
}

mod sha1 {
    use super::*;

    #[test]
    fn empty_file() -> Result {
        let data = data_with_size(Size::Empty as usize);
        let mut file = {
            let mut file = tempfile()?;
            file.write(&data)?;
            file.seek(SeekFrom::Start(0))?;
            file
        };
        let digest = file.chksum(HashAlgorithm::SHA1)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
        Ok(())
    }

    #[test]
    fn tiny_file() -> Result {
        let data = data_with_size(Size::Tiny as usize);
        let mut file = {
            let mut file = tempfile()?;
            file.write(&data)?;
            file.seek(SeekFrom::Start(0))?;
            file
        };
        let digest = file.chksum(HashAlgorithm::SHA1)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "425AF12A0743502B322E93A015BCF868E324D56A");
        Ok(())
    }

    #[test]
    fn small_file() -> Result {
        let data = data_with_size(Size::Small as usize);
        let mut file = {
            let mut file = tempfile()?;
            file.write(&data)?;
            file.seek(SeekFrom::Start(0))?;
            file
        };
        let digest = file.chksum(HashAlgorithm::SHA1)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "EA33090EAC3A084A89AEBECBDBBCC5C6E0E56F23");
        Ok(())
    }

    #[test]
    fn medium_file() -> Result {
        let data = data_with_size(Size::Medium as usize);
        let mut file = {
            let mut file = tempfile()?;
            file.write(&data)?;
            file.seek(SeekFrom::Start(0))?;
            file
        };
        let digest = file.chksum(HashAlgorithm::SHA1)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "972EB0B736B22CB72EE599AB3DB6A47BB7F7D8EB");
        Ok(())
    }

    #[test]
    fn big_file() -> Result {
        let data = data_with_size(Size::Big as usize);
        let mut file = {
            let mut file = tempfile()?;
            file.write(&data)?;
            file.seek(SeekFrom::Start(0))?;
            file
        };
        let digest = file.chksum(HashAlgorithm::SHA1)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "39941AB1AED3936DACBB3B6E98BF707BCE08F6A1");
        Ok(())
    }

    #[test]
    fn huge_file() -> Result {
        let data = data_with_size(Size::Huge as usize);
        let mut file = {
            let mut file = tempfile()?;
            file.write(&data)?;
            file.seek(SeekFrom::Start(0))?;
            file
        };
        let digest = file.chksum(HashAlgorithm::SHA1)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "A1DD2F8107116C3A1DA46EA4959258FDA49C44F0");
        Ok(())
    }
}

mod sha2 {
    use super::*;

    mod sha224 {
        use super::*;

        #[test]
        fn empty_file() -> Result {
            let data = data_with_size(Size::Empty as usize);
            let mut file = {
                let mut file = tempfile()?;
                file.write(&data)?;
                file.seek(SeekFrom::Start(0))?;
                file
            };
            let digest = file.chksum(HashAlgorithm::SHA2_224)?;
            let digest = format!("{:X}", digest);
            assert_eq!(digest, "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F");
            Ok(())
        }

        #[test]
        fn tiny_file() -> Result {
            let data = data_with_size(Size::Tiny as usize);
            let mut file = {
                let mut file = tempfile()?;
                file.write(&data)?;
                file.seek(SeekFrom::Start(0))?;
                file
            };
            let digest = file.chksum(HashAlgorithm::SHA2_224)?;
            let digest = format!("{:X}", digest);
            assert_eq!(digest, "17EB7D40F0356F8598E89EAFAD5F6C759B1F822975D9C9B737C8A517");
            Ok(())
        }

        #[test]
        fn small_file() -> Result {
            let data = data_with_size(Size::Small as usize);
            let mut file = {
                let mut file = tempfile()?;
                file.write(&data)?;
                file.seek(SeekFrom::Start(0))?;
                file
            };
            let digest = file.chksum(HashAlgorithm::SHA2_224)?;
            let digest = format!("{:X}", digest);
            assert_eq!(digest, "9479815F0224752111E912E8CB8A9CBC3798F6EC5B027780C508E7AC");
            Ok(())
        }

        #[test]
        fn medium_file() -> Result {
            let data = data_with_size(Size::Medium as usize);
            let mut file = {
                let mut file = tempfile()?;
                file.write(&data)?;
                file.seek(SeekFrom::Start(0))?;
                file
            };
            let digest = file.chksum(HashAlgorithm::SHA2_224)?;
            let digest = format!("{:X}", digest);
            assert_eq!(digest, "AF01EFC931B463221861EF64EF4BA40D4E9428E20CE0DD2CBAA0E971");
            Ok(())
        }

        #[test]
        fn big_file() -> Result {
            let data = data_with_size(Size::Big as usize);
            let mut file = {
                let mut file = tempfile()?;
                file.write(&data)?;
                file.seek(SeekFrom::Start(0))?;
                file
            };
            let digest = file.chksum(HashAlgorithm::SHA2_224)?;
            let digest = format!("{:X}", digest);
            assert_eq!(digest, "88DA45B43E89E5481CCB23C87A1DE2370E39DB6F605386FA9E1D5FFC");
            Ok(())
        }

        #[test]
        fn huge_file() -> Result {
            let data = data_with_size(Size::Huge as usize);
            let mut file = {
                let mut file = tempfile()?;
                file.write(&data)?;
                file.seek(SeekFrom::Start(0))?;
                file
            };
            let digest = file.chksum(HashAlgorithm::SHA2_224)?;
            let digest = format!("{:X}", digest);
            assert_eq!(digest, "95A65DBFCD6F3B39833E239E8AE1BBBD3B673D6D1DAC0187C806BB5B");
            Ok(())
        }
    }

    mod sha256 {
        use super::*;

        #[test]
        fn empty_file() -> Result {
            let data = data_with_size(Size::Empty as usize);
            let mut file = {
                let mut file = tempfile()?;
                file.write(&data)?;
                file.seek(SeekFrom::Start(0))?;
                file
            };
            let digest = file.chksum(HashAlgorithm::SHA2_256)?;
            let digest = format!("{:X}", digest);
            assert_eq!(
                digest,
                "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
            );
            Ok(())
        }

        #[test]
        fn tiny_file() -> Result {
            let data = data_with_size(Size::Tiny as usize);
            let mut file = {
                let mut file = tempfile()?;
                file.write(&data)?;
                file.seek(SeekFrom::Start(0))?;
                file
            };
            let digest = file.chksum(HashAlgorithm::SHA2_256)?;
            let digest = format!("{:X}", digest);
            assert_eq!(
                digest,
                "9C56CC51B374C3BA189210D5B6D4BF57790D351C96C47C02190ECF1E430635AB"
            );
            Ok(())
        }

        #[test]
        fn small_file() -> Result {
            let data = data_with_size(Size::Small as usize);
            let mut file = {
                let mut file = tempfile()?;
                file.write(&data)?;
                file.seek(SeekFrom::Start(0))?;
                file
            };
            let digest = file.chksum(HashAlgorithm::SHA2_256)?;
            let digest = format!("{:X}", digest);
            assert_eq!(
                digest,
                "FA443F246563D77F1F47C322251159E32A357005BF6BFCC618C3C905E849CBCD"
            );
            Ok(())
        }

        #[test]
        fn medium_file() -> Result {
            let data = data_with_size(Size::Medium as usize);
            let mut file = {
                let mut file = tempfile()?;
                file.write(&data)?;
                file.seek(SeekFrom::Start(0))?;
                file
            };
            let digest = file.chksum(HashAlgorithm::SHA2_256)?;
            let digest = format!("{:X}", digest);
            assert_eq!(
                digest,
                "4E54C175A12A9172FA0C81DF71542AC61F7B7A9AC032E8CA607FE2C00C172ECE"
            );
            Ok(())
        }

        #[test]
        fn big_file() -> Result {
            let data = data_with_size(Size::Big as usize);
            let mut file = {
                let mut file = tempfile()?;
                file.write(&data)?;
                file.seek(SeekFrom::Start(0))?;
                file
            };
            let digest = file.chksum(HashAlgorithm::SHA2_256)?;
            let digest = format!("{:X}", digest);
            assert_eq!(
                digest,
                "85ECFC8853A01F2F02D60E3E5C424F228F17D838103C55A64DFAEFC9A5D8D821"
            );
            Ok(())
        }

        #[test]
        fn huge_file() -> Result {
            let data = data_with_size(Size::Huge as usize);
            let mut file = {
                let mut file = tempfile()?;
                file.write(&data)?;
                file.seek(SeekFrom::Start(0))?;
                file
            };
            let digest = file.chksum(HashAlgorithm::SHA2_256)?;
            let digest = format!("{:X}", digest);
            assert_eq!(
                digest,
                "B98AD09EDAEBC3F92CC63176DB23E37ADDE356AD2745CFA8885280A2D4EDFC1C"
            );
            Ok(())
        }
    }
}
