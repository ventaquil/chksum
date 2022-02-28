mod command;
mod parse;

use anyhow::Result;
use chksum::arch::x1::Arch;
use chksum::hash::{md5, sha1, Alghorithm as HashAlghorithm};
use chksum::prelude::*;

macro_rules! chksum_with_config {
    ($path: expr, $hash: expr, $config: expr) => {
        match Chksum::chksum_with_config(&mut $path, $hash, $config) {
            Ok(digest) => println!("{:x} {}", digest, $path),
            Err(error) => eprintln!("{:#}", error),
        }
        $hash.reset();
    };
}

macro_rules! chksums_with_config {
    ($paths: expr, $hash: expr, $config: expr) => {
        match $hash {
            HashAlghorithm::MD5 => {
                let mut hash = md5::Hash::<Arch>::new();
                for mut path in $paths {
                    chksum_with_config!(path, &mut hash, $config);
                }
            },
            HashAlghorithm::SHA1 => {
                let mut hash = sha1::Hash::<Arch>::new();
                for mut path in $paths {
                    chksum_with_config!(path, &mut hash, $config);
                }
            },
        }
    };
}

fn main() -> Result<()> {
    let command = command::create();

    let matches = command.get_matches();

    let chunk_size = match matches.value_of("chunk-size") {
        Some(chunk_size) => parse::chunk_size(chunk_size)?,
        None => Config::DEFAULT_CHUNK_SIZE,
    };

    let hash = match matches.value_of("hash") {
        Some(hash) => parse::hash(hash)?,
        None => HashAlghorithm::MD5,
    };

    let paths = matches
        .values_of("paths")
        .unwrap()
        .map(String::from)
        .collect::<Vec<String>>();

    let with_paths = matches.is_present("with-paths");

    let config = Config::new(chunk_size, with_paths);

    chksums_with_config!(paths, hash, config);

    Ok(())
}
