use std::io;
use std::result;

use assert_cmd::Command;
use assert_cmd::cargo::CargoError;
use assert_fs::fixture::{TempDir, FixtureError};
use assert_fs::prelude::*;
use thiserror::Error;

#[derive(Debug, Error)]
enum Error {
    #[error(transparent)]
    Cargo(#[from] CargoError),
    #[error(transparent)]
    Fixture(#[from] FixtureError),
    #[error(transparent)]
    IO(#[from] io::Error),
}

type Result = result::Result<(), Error>;

#[test]
fn test_no_arguments() -> Result {
    // todo add more precise checks

    Command::cargo_bin("chksum-cli")?.assert().failure();

    Ok(())
}

#[test]
fn test_non_existing_path() -> Result {
    // todo add more precise checks

    let directory = TempDir::new()?;
    let child = directory.child("non-existing-path");

    Command::cargo_bin("chksum-cli")?.arg(child.as_ref()).assert().success();

    directory.close()?;

    Ok(())
}

#[test]
fn test_existing_file() -> Result {
    // todo add more precise checks

    let directory = TempDir::new()?;
    let child = {
        let child = directory.child("existing-file");
        child.touch()?;
        child
    };

    Command::cargo_bin("chksum-cli")?.arg(child.as_ref()).assert().success();

    directory.close()?;

    Ok(())
}

#[test]
fn test_stdin() -> Result {
    // todo add more precise checks

    Command::cargo_bin("chksum-cli")?.arg("-").assert().success();

    Ok(())
}

#[test]
fn test_chunk_size() -> Result {
    // todo add more precise checks

    let directory = TempDir::new()?;
    let child = {
        let child = directory.child("existing-file");
        child.touch()?;
        child
    };

    Command::cargo_bin("chksum-cli")?.args(["-s", "512"]).arg(child.as_ref()).assert().success();
    Command::cargo_bin("chksum-cli")?.args(["--chunk-size", "512"]).arg(child.as_ref()).assert().success();
    Command::cargo_bin("chksum-cli")?.args(["--chunk-size", "1k"]).arg(child.as_ref()).assert().success();
    Command::cargo_bin("chksum-cli")?.args(["--chunk-size", "1K"]).arg(child.as_ref()).assert().success();
    Command::cargo_bin("chksum-cli")?.args(["--chunk-size", "1m"]).arg(child.as_ref()).assert().success();
    Command::cargo_bin("chksum-cli")?.args(["--chunk-size", "1M"]).arg(child.as_ref()).assert().success();
    Command::cargo_bin("chksum-cli")?.args(["--chunk-size", "1g"]).arg(child.as_ref()).assert().success();
    Command::cargo_bin("chksum-cli")?.args(["--chunk-size", "1G"]).arg(child.as_ref()).assert().success();
    Command::cargo_bin("chksum-cli")?.args(["--chunk-size", "-1"]).arg(child.as_ref()).assert().failure();
    Command::cargo_bin("chksum-cli")?.args(["--chunk-size", "size"]).arg(child.as_ref()).assert().failure();

    directory.close()?;

    Ok(())
}

#[test]
fn test_hash_md5() -> Result {
    // todo add more precise checks

    let directory = TempDir::new()?;
    let child = {
        let child = directory.child("existing-file");
        child.touch()?;
        child
    };

    Command::cargo_bin("chksum-cli")?.args(["-H", "MD5"]).arg(child.as_ref()).assert().success();
    Command::cargo_bin("chksum-cli")?.args(["--hash", "MD5"]).arg(child.as_ref()).assert().success();
    Command::cargo_bin("chksum-cli")?.args(["--hash", "md5"]).arg(child.as_ref()).assert().failure();

    directory.close()?;

    Ok(())
}

#[test]
fn test_hash_sha1() -> Result {
    // todo add more precise checks

    let directory = TempDir::new()?;
    let child = {
        let child = directory.child("existing-file");
        child.touch()?;
        child
    };

    Command::cargo_bin("chksum-cli")?.args(["-H", "SHA1"]).arg(child.as_ref()).assert().success();
    Command::cargo_bin("chksum-cli")?.args(["--hash", "SHA1"]).arg(child.as_ref()).assert().success();
    Command::cargo_bin("chksum-cli")?.args(["--hash", "SHA-1"]).arg(child.as_ref()).assert().success();
    Command::cargo_bin("chksum-cli")?.args(["--hash", "sha1"]).arg(child.as_ref()).assert().failure();

    directory.close()?;

    Ok(())
}
