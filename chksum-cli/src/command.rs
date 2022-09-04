use clap::{arg, command, Command};

use super::parse;

/// Create new [`Command`] with all arguments.
pub(crate) fn create() -> Command<'static> {
    command!("chksum-cli")
        .author("")
        .args([
            arg!(paths: <PATH> "Path to file or directory").multiple_values(true),
            arg!(-H --hash <HASH> "Choose hashing algorithm")
                .required(false)
                .validator(|value| parse::hash(value).map(|_| ())),
            arg!(-s --"chunk-size" <SIZE> "Set chunk size of processing data")
                .required(false)
                .validator(|value| parse::human_number(value).map(|_| ())),
        ])
        .after_help("Implemented hash algorithms:\n - MD5,\n - SHA-1,\n - SHA-2 224,\n - SHA-2 256,\n - SHA-2 512.")
}
