use std::cmp::min;
use std::path::Path;
use std::thread;

use chksum::{self, Context, hash, io::Processor};

extern crate clap;
use clap::{Arg, App};

fn parse_arguments() -> Context {
    const NAME: &'static str = env!("CARGO_PKG_NAME");
    const VERSION: &'static str = env!("CARGO_PKG_VERSION");
    const DESCRIPTION: &'static str = env!("CARGO_PKG_DESCRIPTION");

    let hashes = hash::hashes();

    let matches = App::new(NAME)
                      .version(VERSION)
                      .about(DESCRIPTION)
                      .arg(Arg::with_name("pathnames")
                               .value_name("pathname")
                               .help("Pathname of file or directory")
                               .index(1)
                               .multiple(true)
                               .required(true))
                      .arg(Arg::with_name("chunk size")
                               .value_name("size")
                               .long("chunk-size")
                               .short("s")
                               .help("Chunk size")
                               .default_value("512")
                               .validator(|value| {
                                   match value.parse::<usize>() {
                                       Ok(_) => Ok(()),
                                       Err(_) => Err(String::from("The value is not a number")),
                                   }
                               }))
                      .arg(Arg::with_name("process pathnames")
                               .long("process-pathnames")
                               .short("p")
                               .help("Use pathnames to calculate digests"))
                      .arg(Arg::with_name("hash")
                               .long("hash")
                               .short("H")
                               .help("Chosen hash algorithm")
                               .possible_values(&hashes[..])
                               .hide_possible_values(true)
                               .default_value(hashes[0]))
                      .arg(Arg::with_name("jobs")
                               .long("jobs")
                               .short("j")
                               .help("Maximum number of working threads")
                               .default_value("1")
                               .validator(|value| {
                                   match value.parse::<usize>() {
                                       Ok(_) => Ok(()),
                                       Err(_) => Err(String::from("The value is not a number")),
                                   }
                               }))
                      .get_matches();

    let chunk_size = matches.value_of("chunk size")
                            .unwrap()
                            .parse::<usize>()
                            .unwrap();

    // let hash = hash::Hash::from_str(matches.value_of("hash")
    //                                        .unwrap());
    let hash = hash::Hash::MD5; // fixme

    let jobs = matches.value_of("jobs")
                      .unwrap()
                      .parse::<usize>()
                      .unwrap();

    let pathnames: Vec<String> = matches.values_of("pathnames")
                                        .unwrap()
                                        .map(|pathname| String::from(pathname))
                                        .collect();

    let process_pathnames = matches.is_present("process pathnames");

    chksum::new(chunk_size, hash, jobs, pathnames, process_pathnames)
}

fn main() {
    let context = parse_arguments();

    // let threads: Vec<thread::JoinHandle<_>> = context.pathnames
    //                                                  .iter()
    //                                                  .map(|pathname| thread::spawn(move || {
    //                                                      println!("{}", pathname);
    //                                                  }))
    //                                                  .collect();
    for i in (0..context.pathnames.len()).step_by(context.jobs) {
    let j = min(i + context.jobs, context.pathnames.len());
        let mut threads: Vec<thread::JoinHandle<_>> = Vec::new();
        for pathname in &context.pathnames[i..j] {
            let chunk_size = context.chunk_size;
            let hash = context.hash.clone();
            let process_pathnames = context.process_pathnames;
            let pathname = pathname.clone();
            let thread = thread::spawn(move || {
                let path = Path::new(&pathname);
                let processor = Processor::new(chunk_size, hash, process_pathnames);
                let digest = processor.process(&path);
                (digest, pathname)
            });
            threads.push(thread);
        }

        for thread in threads {
            let (digest, pathname) = thread.join().unwrap(); // fixme catch unwrap
            let digest: String = digest.unwrap() // fixme catch unwrap
                                       .iter()
                                       .map(|digit| format!("{:02x}", digit))
                                       .collect();
            println!("{}\t{}", digest, pathname);
        }
    }
}
