use std::path::PathBuf;

use chksum_arch::x1;
use chksum_hash::{md5, sha1, Reset};
use chksum_sync::Chksum;

fn main() {
    let mut paths: [PathBuf; 2] = [
        [env!("CARGO_MANIFEST_DIR"), "examples", "sync-single-file.rs"]
            .iter()
            .collect(),
        [env!("CARGO_MANIFEST_DIR"), "examples", "sync-multiple-files.rs"]
            .iter()
            .collect(),
    ];

    let mut hash = md5::Hash::<x1::Arch>::new();
    for path in &mut paths {
        println!("Path: {}", path.to_string_lossy());
        match path.chksum(&mut hash) {
            Ok(digest) => println!("MD5 digest: {:x}", digest),
            Err(error) => eprintln!("MD5 error: {}", error),
        }
        hash.reset(); // you can reset hash without creating new one
    }

    let mut hash = sha1::Hash::<x1::Arch>::new();
    for path in &mut paths {
        println!("Path: {}", path.to_string_lossy());
        match path.chksum(&mut hash) {
            Ok(digest) => println!("SHA-1 digest: {:x}", digest),
            Err(error) => eprintln!("SHA-1 error: {}", error),
        }
        hash.reset(); // you can reset hash without creating new one
    }
}
