# chksum

[![Coverage](https://img.shields.io/codecov/c/gh/ventaquil/chksum?style=flat-square&flag=chksum "Coverage")](https://app.codecov.io/gh/ventaquil/chksum/tree/master/chksum)
[![crates.io](https://img.shields.io/crates/v/chksum?style=flat-square "crates.io")](https://crates.io/crates/chksum)
[![docs.rs](https://img.shields.io/docsrs/chksum?style=flat-square "docs.rs")](https://docs.rs/chksum)
[![LICENSE](https://img.shields.io/github/license/ventaquil/chksum?style=flat-square "LICENSE")](https://github.com/ventaquil/chksum/blob/master/LICENSE)

## Installation

```shell
cargo add chksum
```

## Trait `Chksum`

The core of this libary is `Chksum` trait which is implemented for various types like `&[u8]`, `&str` or `File`.

In case when you need to implement `Chksum` for your trait you will need to use cryptographic primitives which are in `chksum::hash` module.

## Example

```rust
use chksum::prelude::*;

let digest = File::open("path/to/file")?.chksum(HashAlgorithm::MD5)?;
println!("digest {:x}", digest);
```
