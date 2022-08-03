#![cfg_attr(nightly, feature(no_coverage))]

mod command;
mod parse;

use std::fs::{read_dir, File};
use std::io::stdin;
use std::path::Path;

use anyhow::Result;
use chksum::prelude::*;
use itertools::Itertools;
use rayon::prelude::*;

fn path_process<T>(path: T, hash: HashAlgorithm, config: Config) -> Result<HashDigest, Error>
where
    T: AsRef<Path>,
{
    let path = path.as_ref();
    if path.is_file() {
        let digest = File::open(path)?.chksum_with_config(hash, config)?;
        Ok(digest)
    } else if path.is_dir() {
        let digest = read_dir(path)?.chksum_with_config(hash, config)?;
        Ok(digest)
    } else if matches!(path.to_str(), Some("-")) {
        let digest = stdin().chksum_with_config(hash, config)?;
        Ok(digest)
    } else {
        Err(Error::NetherFileNorDirectory { path: path.into() })
    }
}

/// Main function.
#[cfg_attr(nightly, no_coverage)]
fn main() -> Result<()> {
    let command = command::create();

    let matches = command.get_matches();

    let mut config_builder = ConfigBuilder::new();

    if let Some(chunk_size) = matches.value_of("chunk-size") {
        let chunk_size = parse::human_number(chunk_size)?;
        config_builder.chunk_size(chunk_size);
    };

    let hash = match matches.value_of("hash") {
        Some(hash) => parse::hash(hash)?,
        None => HashAlgorithm::MD5,
    };

    let paths = matches
        .values_of("paths")
        .unwrap()
        .map(String::from)
        .unique()
        .collect::<Vec<String>>();

    let config = config_builder.build();

    paths.par_iter().for_each(|path| {
        match path_process(path, hash, config) {
            Ok(digest) => println!("{:x} {}", digest, path),
            Err(error) => eprintln!("{:#}", error),
        }
    });

    Ok(())
}
