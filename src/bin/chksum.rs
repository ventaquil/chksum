use chksum::Config;
use chksum::arch::x1::Arch;
use chksum::hash::{md5::Hash as MD5, Reset, sha1::Hash as SHA1, ToHex};

extern crate clap;
use clap::{App, Arg};

macro_rules! chksums {
    ($config: expr, $hash: expr, $paths: expr) => {
        let mut hash = $hash;
        for path in $paths {
            match chksum::chksum_with_config(&$config, &mut hash, &path) {
                Ok(digest) => {
                    println!("{} {}", digest.to_hex(), path);
                },
                Err(error) => eprintln!("{}", error),
            }
            hash.reset();
        }
    };
}

fn main() {
    const NAME: &str = env!("CARGO_PKG_NAME");
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

    let matches = App::new(NAME)
        .version(VERSION)
        .about(DESCRIPTION)
        .arg(
            Arg::with_name("paths")
                .value_name("path")
                .help("Path to file or directory")
                .index(1)
                .multiple(true)
                .required(true),
        )
        .arg(
            Arg::with_name("chunk size")
                .value_name("size")
                .long("chunk-size")
                .short("s")
                .help("Chunk size")
                .default_value("512")
                .validator(|value| match value.parse::<usize>() { // todo parse values 512M, 1G etc.
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("The value is not a number")),
                }),
        )
        .arg(
            Arg::with_name("hash")
                .long("hash")
                .short("H")
                .help("Chosen hash algorithm")
                .default_value("MD5")
                .validator(|hash| {
                    match &hash[..] {
                        "MD5" | "SHA1" | "SHA-1" => Ok(()),
                        _ => Err(String::from("Unknown hash algorithm")),
                    }
                }),
        )
        .arg(
            Arg::with_name("with paths")
                .long("with-paths")
                .short("P")
                .help("Use paths to calculate digests"),
        )
        .after_help("Implemented hash algorithms:\n - MD5,\n - SHA-1.") // todo implement generator
        .get_matches();

    let paths: Vec<String> = matches
        .values_of("paths")
        .unwrap()
        .map(String::from)
        .collect();

    let chunk_size = matches
        .value_of("chunk size")
        .unwrap()
        .parse::<usize>()
        .unwrap();

    let with_paths = matches.is_present("with paths");

    let config = Config::new(chunk_size, with_paths);

    let hash = matches
        .value_of("hash")
        .unwrap();
    match hash {
        "MD5" => {
            let hash = MD5::<Arch>::new();
            chksums!(config, hash, paths);
        },
        "SHA1" | "SHA-1" => {
            let hash = SHA1::<Arch>::new();
            chksums!(config, hash, paths);
        },
        _ => (), // fixme shouldn't happen?
    };
}
