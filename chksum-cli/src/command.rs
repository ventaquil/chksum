use clap::{arg, command, Command};

use super::parse;

pub fn create() -> Command<'static> {
    command!("chksum").args([
        arg!(paths: <PATH> "Path to file or directory").multiple_values(true),
        arg!(-H --hash <HASH> "Choose hashing algorithm")
            .required(false)
            .validator(|value| parse::hash(value).map(|_| ())),
        arg!(-P --"with-paths" "Use paths to calculate digest"),
        arg!(-s --"chunk-size" <SIZE> "Set chunk size of processing data")
            .required(false)
            .validator(|value| parse::chunk_size(value).map(|_| ())),
    ])
}
