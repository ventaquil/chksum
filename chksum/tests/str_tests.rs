use std::str;

use chksum::prelude::*;

mod common;
use common::{data_with_size, Result, Size};

mod md5 {
    use super::*;

    #[test]
    fn empty_str() -> Result {
        let data = data_with_size(Size::Empty as usize);
        let mut str = str::from_utf8(&data)?;
        let digest = str.chksum(HashAlgorithm::MD5)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "D41D8CD98F00B204E9800998ECF8427E");
        Ok(())
    }

    #[test]
    fn tiny_str() -> Result {
        let data = data_with_size(Size::Tiny as usize);
        let mut str = str::from_utf8(&data)?;
        let digest = str.chksum(HashAlgorithm::MD5)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "E8DC4081B13434B45189A720B77B6818");
        Ok(())
    }

    #[test]
    fn small_str() -> Result {
        let data = data_with_size(Size::Small as usize);
        let mut str = str::from_utf8(&data)?;
        let digest = str.chksum(HashAlgorithm::MD5)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "C844E7E6F76809EDEE8C6BC64404C963");
        Ok(())
    }

    #[test]
    fn medium_str() -> Result {
        let data = data_with_size(Size::Medium as usize);
        let mut str = str::from_utf8(&data)?;
        let digest = str.chksum(HashAlgorithm::MD5)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "2108E2728DE71A20ABB35644801BD8EE");
        Ok(())
    }

    #[test]
    fn big_str() -> Result {
        let data = data_with_size(Size::Big as usize);
        let mut str = str::from_utf8(&data)?;
        let digest = str.chksum(HashAlgorithm::MD5)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "06040296DEC20641F15D324E454C237D");
        Ok(())
    }

    #[test]
    fn huge_str() -> Result {
        let data = data_with_size(Size::Huge as usize);
        let mut str = str::from_utf8(&data)?;
        let digest = str.chksum(HashAlgorithm::MD5)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "9C6C1BFB236EDE4FD3C2E0027A169874");
        Ok(())
    }
}

mod sha1 {
    use super::*;

    #[test]
    fn empty_str() -> Result {
        let data = data_with_size(Size::Empty as usize);
        let mut str = str::from_utf8(&data)?;
        let digest = str.chksum(HashAlgorithm::SHA1)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
        Ok(())
    }

    #[test]
    fn tiny_str() -> Result {
        let data = data_with_size(Size::Tiny as usize);
        let mut str = str::from_utf8(&data)?;
        let digest = str.chksum(HashAlgorithm::SHA1)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "425AF12A0743502B322E93A015BCF868E324D56A");
        Ok(())
    }

    #[test]
    fn small_str() -> Result {
        let data = data_with_size(Size::Small as usize);
        let mut str = str::from_utf8(&data)?;
        let digest = str.chksum(HashAlgorithm::SHA1)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "EA33090EAC3A084A89AEBECBDBBCC5C6E0E56F23");
        Ok(())
    }

    #[test]
    fn medium_str() -> Result {
        let data = data_with_size(Size::Medium as usize);
        let mut str = str::from_utf8(&data)?;
        let digest = str.chksum(HashAlgorithm::SHA1)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "972EB0B736B22CB72EE599AB3DB6A47BB7F7D8EB");
        Ok(())
    }

    #[test]
    fn big_str() -> Result {
        let data = data_with_size(Size::Big as usize);
        let mut str = str::from_utf8(&data)?;
        let digest = str.chksum(HashAlgorithm::SHA1)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "39941AB1AED3936DACBB3B6E98BF707BCE08F6A1");
        Ok(())
    }

    #[test]
    fn huge_str() -> Result {
        let data = data_with_size(Size::Huge as usize);
        let mut str = str::from_utf8(&data)?;
        let digest = str.chksum(HashAlgorithm::SHA1)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "A1DD2F8107116C3A1DA46EA4959258FDA49C44F0");
        Ok(())
    }
}
