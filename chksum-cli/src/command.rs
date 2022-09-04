use clap::{arg, command, Command};

use super::parse;

static AFTER_HELP: &str = "Implemented hash algorithms:
 - MD5,
 - SHA-1,
 - SHA-2 224,
 - SHA-2 256,
 - SHA-2 384,
 - SHA-2 512.";

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
        .after_help(AFTER_HELP)
}
