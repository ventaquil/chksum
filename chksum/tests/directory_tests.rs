use std::fs::{read_dir, File};
use std::io::Write;

use chksum::prelude::*;
use tempfile::tempdir;

mod common;
use common::{data_with_size, Result, Size};

// todo make some function that will create random trees of files (with parameters like maximum depth or maximum size of whole structure)

mod md5 {
    use super::*;

    #[test]
    fn empty_directory() -> Result {
        let data = data_with_size(Size::Empty as usize);
        let directory = {
            let directory = tempdir()?;
            let file = directory.path().join("file.txt");
            let mut file = File::create(file)?;
            file.write(&data)?;
            file.flush()?;
            directory
        };
        let digest = read_dir(&directory)?.chksum(HashAlgorithm::MD5)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "D41D8CD98F00B204E9800998ECF8427E");
        directory.close()?;
        Ok(())
    }

    #[test]
    fn tiny_directory() -> Result {
        let data = data_with_size(Size::Tiny as usize);
        let directory = {
            let directory = tempdir()?;
            let file = directory.path().join("file.txt");
            let mut file = File::create(file)?;
            file.write(&data)?;
            file.flush()?;
            directory
        };
        let digest = read_dir(&directory)?.chksum(HashAlgorithm::MD5)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "E8DC4081B13434B45189A720B77B6818");
        directory.close()?;
        Ok(())
    }

    #[test]
    fn small_directory() -> Result {
        let data = data_with_size(Size::Small as usize);
        let directory = {
            let directory = tempdir()?;
            let file = directory.path().join("file.txt");
            let mut file = File::create(file)?;
            file.write(&data)?;
            file.flush()?;
            directory
        };
        let digest = read_dir(&directory)?.chksum(HashAlgorithm::MD5)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "C844E7E6F76809EDEE8C6BC64404C963");
        directory.close()?;
        Ok(())
    }

    #[test]
    fn medium_directory() -> Result {
        let data = data_with_size(Size::Medium as usize);
        let directory = {
            let directory = tempdir()?;
            let file = directory.path().join("file.txt");
            let mut file = File::create(file)?;
            file.write(&data)?;
            file.flush()?;
            directory
        };
        let digest = read_dir(&directory)?.chksum(HashAlgorithm::MD5)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "2108E2728DE71A20ABB35644801BD8EE");
        directory.close()?;
        Ok(())
    }

    #[test]
    fn big_directory() -> Result {
        let data = data_with_size(Size::Big as usize);
        let directory = {
            let directory = tempdir()?;
            let file = directory.path().join("file.txt");
            let mut file = File::create(file)?;
            file.write(&data)?;
            file.flush()?;
            directory
        };
        let digest = read_dir(&directory)?.chksum(HashAlgorithm::MD5)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "06040296DEC20641F15D324E454C237D");
        directory.close()?;
        Ok(())
    }

    #[test]
    fn huge_directory() -> Result {
        let data = data_with_size(Size::Huge as usize);
        let directory = {
            let directory = tempdir()?;
            let file = directory.path().join("file.txt");
            let mut file = File::create(file)?;
            file.write(&data)?;
            file.flush()?;
            directory
        };
        let digest = read_dir(&directory)?.chksum(HashAlgorithm::MD5)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "9C6C1BFB236EDE4FD3C2E0027A169874");
        directory.close()?;
        Ok(())
    }
}

mod sha1 {
    use super::*;

    #[test]
    fn empty_directory() -> Result {
        let data = data_with_size(Size::Empty as usize);
        let directory = {
            let directory = tempdir()?;
            let file = directory.path().join("file.txt");
            let mut file = File::create(file)?;
            file.write(&data)?;
            file.flush()?;
            directory
        };
        let digest = read_dir(&directory)?.chksum(HashAlgorithm::SHA1)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
        directory.close()?;
        Ok(())
    }

    #[test]
    fn tiny_directory() -> Result {
        let data = data_with_size(Size::Tiny as usize);
        let directory = {
            let directory = tempdir()?;
            let file = directory.path().join("file.txt");
            let mut file = File::create(file)?;
            file.write(&data)?;
            file.flush()?;
            directory
        };
        let digest = read_dir(&directory)?.chksum(HashAlgorithm::SHA1)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "425AF12A0743502B322E93A015BCF868E324D56A");
        directory.close()?;
        Ok(())
    }

    #[test]
    fn small_directory() -> Result {
        let data = data_with_size(Size::Small as usize);
        let directory = {
            let directory = tempdir()?;
            let file = directory.path().join("file.txt");
            let mut file = File::create(file)?;
            file.write(&data)?;
            file.flush()?;
            directory
        };
        let digest = read_dir(&directory)?.chksum(HashAlgorithm::SHA1)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "EA33090EAC3A084A89AEBECBDBBCC5C6E0E56F23");
        directory.close()?;
        Ok(())
    }

    #[test]
    fn medium_directory() -> Result {
        let data = data_with_size(Size::Medium as usize);
        let directory = {
            let directory = tempdir()?;
            let file = directory.path().join("file.txt");
            let mut file = File::create(file)?;
            file.write(&data)?;
            file.flush()?;
            directory
        };
        let digest = read_dir(&directory)?.chksum(HashAlgorithm::SHA1)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "972EB0B736B22CB72EE599AB3DB6A47BB7F7D8EB");
        directory.close()?;
        Ok(())
    }

    #[test]
    fn big_directory() -> Result {
        let data = data_with_size(Size::Big as usize);
        let directory = {
            let directory = tempdir()?;
            let file = directory.path().join("file.txt");
            let mut file = File::create(file)?;
            file.write(&data)?;
            file.flush()?;
            directory
        };
        let digest = read_dir(&directory)?.chksum(HashAlgorithm::SHA1)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "39941AB1AED3936DACBB3B6E98BF707BCE08F6A1");
        directory.close()?;
        Ok(())
    }

    #[test]
    fn huge_directory() -> Result {
        let data = data_with_size(Size::Huge as usize);
        let directory = {
            let directory = tempdir()?;
            let file = directory.path().join("file.txt");
            let mut file = File::create(file)?;
            file.write(&data)?;
            file.flush()?;
            directory
        };
        let digest = read_dir(&directory)?.chksum(HashAlgorithm::SHA1)?;
        let digest = format!("{:X}", digest);
        assert_eq!(digest, "A1DD2F8107116C3A1DA46EA4959258FDA49C44F0");
        directory.close()?;
        Ok(())
    }
}
