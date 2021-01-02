use chksum::{self, hash, io, Context};

extern crate clap;
use clap::{App, Arg};

extern crate num_cpus;

fn parse_arguments() -> Context {
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
            Arg::with_name("process pathnames")
                .long("process-pathnames")
                .short("p")
                .help("Use pathnames to calculate digests"),
        )
        .arg(
            Arg::with_name("hash")
                .long("hash")
                .short("H")
                .help("Chosen hash algorithm")
                .default_value("MD5")
                .validator(|value| match &value[..] {
                    // todo implement generator
                    "MD5" => Ok(()),
                    "SHA1" | "SHA-1" => Ok(()),
                    _ => Err(String::from("Unknown hash algorithm")),
                }),
        )
        .arg(
            Arg::with_name("jobs")
                .long("jobs")
                .short("j")
                .help("Maximum number of working threads")
                .default_value("auto")
                .validator(|value| {
                    let auto = "auto";
                    match value {
                        auto => Ok(()),
                        _ => match value.parse::<usize>() {
                            Ok(_) => Ok(()),
                            Err(_) => Err(String::from("The value is not a number")),
                        },
                    }
                }),
        )
        .after_help("Implemented hash algorithms:\n - MD5,\n - SHA-1.") // todo implement generator
        .get_matches();

    let chunk_size = matches
        .value_of("chunk size")
        .unwrap() // todo do not use unwrap
        .parse::<usize>()
        .unwrap(); // todo do not use unwrap

    let hash = matches.value_of("hash").unwrap();
    let hash = match hash {
        // todo implement generator
        "MD5" => hash::Hash::MD5,
        "SHA1" | "SHA-1" => hash::Hash::SHA1,
        _ => hash::Hash::MD5, // should never happen?
    };

    let jobs = matches.value_of("jobs");
    let jobs = match jobs {
        Some("auto") | None => num_cpus::get(),
        _ => jobs.unwrap().parse::<usize>().unwrap(),
    }; // todo do not use unwrap

    let pathnames: Vec<String> = matches
        .values_of("pathnames")
        .unwrap() // todo do not use unwrap
        .map(String::from)
        .collect();

    let process_pathnames = matches.is_present("process pathnames");

    let io = io::Context {
        chunk_size,
        process_pathnames,
    };

    chksum::new(hash, io, jobs, pathnames)
}

fn main() {
    let context = parse_arguments();
    match context.process() {
        Ok(results) => {
            for pathname in context.pathnames() {
                if let Some(result) = results.get(pathname) {
                    match result {
                        Ok(digest) => println!("{}\t{}", digest, pathname),
                        Err(error) => eprintln!("{}: {}", pathname, error),
                    };
                } else {
                    // should never happen?
                }
            }
        },
        Err(error) => eprintln!("{:?}", error), // todo what do with this error?
    };
}
