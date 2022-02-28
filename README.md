# chksum

[![Build](https://img.shields.io/github/workflow/status/ventaquil/chksum/Rust?style=flat-square "Build")](https://github.com/ventaquil/chksum/actions?query=workflow%3ARust)
[![Release](https://img.shields.io/github/v/release/ventaquil/chksum?include_prereleases&sort=semver&style=flat-square "Release")](https://github.com/ventaquil/chksum/releases)
[![crates.io](https://img.shields.io/crates/v/chksum?style=flat-square "crates.io")](https://crates.io/crates/chksum)
[![LICENSE](https://img.shields.io/github/license/ventaquil/chksum?style=flat-square "LICENSE")](https://github.com/ventaquil/chksum/blob/master/LICENSE)

For people who wants to make checksum of whole directory but doesn't like piping.

```
$ find /path -type f -exec md5sum \{\} + | sort -k1 | md5sum
```

## Running by a CLI

### Installation

```
$ cargo install chksum-cli
```

### Usage

```
$ chksum-cli [options] [--] <path>...
```

Like

```
$ chksum-cli LICENSE
3b7c11a62208f03df96f7cfe215b1e28 LICENSE
$ md5sum LICENSE
3b7c11a62208f03df96f7cfe215b1e28  LICENSE
$ chksum-cli --hash SHA1 docs/ extra/
bc6f0730053530230d6a205309acb606d51130b7 docs/
eb6d3cb291b58ebed93893848b3549264f01290b extra/
$ find docs/ -type f | sort | xargs cat | sha1sum
bc6f0730053530230d6a205309acb606d51130b7  -
```

See [`chksum-cli/README.md`](chksum-cli/README.md) for more.

## Using as a library

See [`chksum/README.md`](chksum/README.md) for more.

### Synchronous

Enable `sync` feature during installation.

```
$ cargo install chksum[sync]
```

```rust
use chksum::arch::x1::Arch;
use chksum::hash::md5;
use chksum::prelude::*;

let mut hash = md5::Hash::<Arch>::new();
let digest = "path/to/file".chksum(&mut hash)?;
println!("digest {:x}", digest);
```

### Asynchronous

Enable `async` feature during installation.

```
$ cargo install chksum[async]
```

```rust
use chksum::arch::x1::Arch;
use chksum::hash::md5;
use chksum::prelude::*;

let mut hash = md5::Hash::<Arch>::new();
let digest = "path/to/file".chksum(&mut hash).await?;
println!("digest {:x}", digest);
```

## Hash algorithms

Currently there are implemented two hash algorithms:
 * MD5 - [RFC 1321: The MD5 Message-Digest Algorithm](https://tools.ietf.org/html/rfc1321)
 * SHA-1 - [RFC 3174: US Secure Hash Algorithm 1 (SHA1)](https://tools.ietf.org/html/rfc3174)
