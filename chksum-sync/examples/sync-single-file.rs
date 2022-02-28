use std::path::PathBuf;

use chksum_arch::x1::Arch;
use chksum_hash::{md5, sha1};
use chksum_sync::Chksum;

fn main() {
    let mut path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "examples", "sync-single-file.rs"]
        .iter()
        .collect();

    println!("Path: {}", path.to_string_lossy());

    let mut hash = md5::Hash::<Arch>::new();
    match path.chksum(&mut hash) {
        Ok(digest) => println!("MD5 digest: {:x}", digest),
        Err(error) => eprintln!("MD5 error: {}", error),
    }

    let mut hash = sha1::Hash::<Arch>::new();
    match path.chksum(&mut hash) {
        Ok(digest) => println!("SHA-1 digest: {:x}", digest),
        Err(error) => eprintln!("SHA-1 error: {}", error),
    }
}
