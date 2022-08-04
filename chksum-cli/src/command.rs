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
        .after_help("Implemented hash algorithms:\n - MD5,\n - SHA-1.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_about() {
        assert_eq!(create().get_about(), Some("Simple checksum calculator."));
    }

    #[test]
    fn test_command_author() {
        assert_eq!(create().get_author(), Some(""));
    }

    #[test]
    fn test_command_chunk_size() {
        assert!(matches!(create().try_get_matches_from(["chksum-cli", "-s", "64", "path"]), Ok(_)));
        assert!(matches!(create().try_get_matches_from(["chksum-cli", "-s", "128K", "path"]), Ok(_)));
        assert!(matches!(create().try_get_matches_from(["chksum-cli", "-s", "-8", "path"]), Err(_)));
        assert!(matches!(create().try_get_matches_from(["chksum-cli", "-s", "x", "path"]), Err(_)));
        // todo add more precise tests
    }

    #[test]
    fn test_command_hash() {
        assert!(matches!(create().try_get_matches_from(["chksum-cli", "-H", "MD5", "path"]), Ok(_)));
        assert!(matches!(create().try_get_matches_from(["chksum-cli", "-H", "md5", "path"]), Err(_)));
        assert!(matches!(create().try_get_matches_from(["chksum-cli", "-H", "invalid", "path"]), Err(_)));
        // todo add more precise tests
    }

    #[test]
    fn test_command_name() {
        assert_eq!(create().get_name(), "chksum-cli");
    }
}
