# chksum

[![crates.io](https://img.shields.io/crates/v/chksum?style=flat-square "crates.io")](https://crates.io/crates/chksum)
[![LICENSE](https://img.shields.io/github/license/ventaquil/chksum?style=flat-square "LICENSE")](https://github.com/ventaquil/chksum/blob/master/LICENSE)

## Installation

```
$ cargo install chksum[sync]
```

## Example

```rust
use chksum::arch::x1::Arch;
use chksum::hash::md5;
use chksum::prelude::*;

let mut hash = md5::Hash::<Arch>::new();
let digest = "path/to/file".chksum(&mut hash)?;
println!("digest {:x}", digest);
```
