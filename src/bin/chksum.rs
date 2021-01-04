use std::error::Error;
use std::sync::mpsc;

use chksum::{self, hash, io};

extern crate clap;
use clap::{App, Arg};

extern crate num_cpus;

extern crate threadpool;
use threadpool::ThreadPool;

fn main() -> Result<(), Box<dyn Error>> {
    const NAME: &str = env!("CARGO_PKG_NAME");
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

    let matches = App::new(NAME)
        .version(VERSION)
        .about(DESCRIPTION)
        .arg(
            Arg::with_name("pathnames")
                .value_name("pathname")
                .help("Pathname of file or directory")
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
                .validator(|value| match value.parse::<usize>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("The value is not a number")),
                }),
        )
        .arg(
            Arg::with_name("with pathnames")
                .long("with-pathnames")
                .short("W")
                .help("Use pathnames to calculate digests"),
        )
        .arg(
            Arg::with_name("hash")
                .long("hash")
                .short("H")
                .help("Chosen hash algorithm")
                .default_value("MD5")
                .validator(|hash| hash::new(&hash).map(|_| ()).map_err(|error| error.to_string())),
        )
        .arg(
            Arg::with_name("workers")
                .long("workers")
                .short("w")
                .help("Maximum number of working threads")
                .default_value("auto")
                .validator(|value| {
                    match &value as &str {
                        "auto" => Ok(()),
                        _ => match value.parse::<usize>() {
                            Ok(value) => {
                                if value == 0 {
                                    Err(String::from("Value cannot be zero"))
                                } else {
                                    Ok(())
                                }
                            },
                            Err(_) => Err(String::from("Value must be a positive number")),
                        },
                    }
                }),
        )
        .after_help("Implemented hash algorithms:\n - MD5,\n - SHA-1.") // todo implement generator
        .get_matches();

    let chunk_size = matches
        .value_of("chunk size")
        .unwrap()
        .parse::<usize>()?;

    let hash = matches
        .value_of("hash")
        .unwrap();
    let hash = hash::new(hash)?;

    let workers = matches.value_of("workers");
    let workers = match workers {
        Some("auto") | None => num_cpus::get(),
        _ => workers.unwrap().parse::<usize>()?,
    };

    let pathnames: Vec<String> = matches
        .values_of("pathnames")
        .unwrap()
        .map(String::from)
        .collect();

    let with_pathnames = matches.is_present("with pathnames");

    let io = io::new(
        chunk_size,
        with_pathnames,
    );

    let context = chksum::new(hash, io);

    let jobs = pathnames.len();

    let (tx, rx) = mpsc::channel();
    let pool = ThreadPool::new(workers);
    for pathname in pathnames {
        let context = context.clone();
        let tx = tx.clone();
        pool.execute(move || {
            let checksum = context.chksum(&pathname);
            tx.send((pathname, checksum)).unwrap();
        });
    }

    for _ in 0..jobs {
        let (pathname, result) = rx.recv()?;
        match result {
            Ok(digest) => println!("{}\t{}", pathname, digest),
            Err(error) => eprintln!("{}\t{}", pathname, error),
        }
    }

    Ok(())
}
