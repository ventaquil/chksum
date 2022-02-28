use std::path::PathBuf;

use chksum_arch::x1;
use chksum_async::AsyncChksum;
use chksum_hash::{md5, sha1};
use futures::future;
use tokio;

#[tokio::main]
async fn main() {
    let paths: [PathBuf; 2] = [
        [env!("CARGO_MANIFEST_DIR"), "examples", "async-single-file.rs"]
            .iter()
            .collect(),
        [env!("CARGO_MANIFEST_DIR"), "examples", "async-multiple-files.rs"]
            .iter()
            .collect(),
    ];

    let futures = paths.into_iter().map(|mut path| {
        tokio::spawn(async move {
            let mut hash = md5::Hash::<x1::Arch>::new();
            match path.chksum(&mut hash).await {
                Ok(digest) => {
                    let path = path.to_string_lossy();
                    println!("Path: {}", path);
                    println!("MD5 digest: {:x}", digest);
                },
                Err(error) => {
                    let path = path.to_string_lossy();
                    println!("Path: {}", path);
                    eprintln!("MD5 error: {}", error);
                },
            }

            let mut hash = sha1::Hash::<x1::Arch>::new();
            match path.chksum(&mut hash).await {
                Ok(digest) => {
                    let path = path.to_string_lossy();
                    println!("Path: {}", path);
                    println!("SHA-1 digest: {:x}", digest);
                },
                Err(error) => {
                    let path = path.to_string_lossy();
                    println!("Path: {}", path);
                    eprintln!("SHA-1 error: {}", error);
                },
            }
        })
    });
    future::join_all(futures).await;
}
