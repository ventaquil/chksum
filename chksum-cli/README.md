# chksum-cli

[![crates.io](https://img.shields.io/crates/v/chksum-cli?style=flat-square "crates.io")](https://crates.io/crates/chksum-cli)
[![LICENSE](https://img.shields.io/github/license/ventaquil/chksum?style=flat-square "LICENSE")](https://github.com/ventaquil/chksum/blob/master/LICENSE)

## Installation

```shell
cargo install chksum-cli
```

## Options

```text
chksum-cli 0.1.0-rc4

Simple checksum calculator.

USAGE:
    chksum-cli [OPTIONS] <PATH>...

ARGS:
    <PATH>...    Path to file or directory

OPTIONS:
    -h, --help                 Print help information
    -H, --hash <HASH>          Choose hashing algorithm
    -s, --chunk-size <SIZE>    Set chunk size of processing data
    -V, --version              Print version information

Implemented hash algorithms:
 - MD5,
 - SHA-1.
```
