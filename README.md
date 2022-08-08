# chksum

[![Build](https://img.shields.io/github/workflow/status/ventaquil/chksum/Continuous%20Integration?style=flat-square "Build")](https://github.com/ventaquil/chksum/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/codecov/c/gh/ventaquil/chksum?style=flat-square "Coverage")](https://app.codecov.io/gh/ventaquil/chksum)
[![Release](https://img.shields.io/github/v/release/ventaquil/chksum?include_prereleases&sort=semver&style=flat-square "Release")](https://github.com/ventaquil/chksum/releases)
[![LICENSE](https://img.shields.io/github/license/ventaquil/chksum?style=flat-square "LICENSE")](https://github.com/ventaquil/chksum/blob/master/LICENSE)

Simple checksum calculator - for people who wants to make checksum of whole directory but doesn't like piping.

```shell
find /path -type f -exec md5sum \{\} + | sort -k1 | md5sum
```

## Running by a CLI

### Installation

```shell
cargo install chksum-cli
```

### Usage

```shell
chksum-cli [options] [--] <path>...
```

Like

```shell
$ chksum-cli LICENSE
3b7c11a62208f03df96f7cfe215b1e28 LICENSE
$ md5sum LICENSE
3b7c11a62208f03df96f7cfe215b1e28  LICENSE
$ chksum-cli --hash SHA1 chksum/ chksum-cli/docs/
c244b8c851d881b8fd2856004e90732bd129cf21 chksum/
5d2c74c21711676e39963098746a3498d29aa3e5 chksum-cli/docs/
$ find chksum-cli/docs/ -type f | sort | xargs cat | sha1sum
5d2c74c21711676e39963098746a3498d29aa3e5  -
```

Check [`chksum-cli/README.md`](chksum-cli/README.md) for more.

## Using as a library

### Add to your project

```shell
cargo add chksum
```

### Use

Code example.

```rust
use chksum::prelude::*;

let digest = File::open("path/to/file")?.chksum(HashAlgorithm::MD5)?;
println!("digest {:x}", digest);
```

Check [`chksum/README.md`](chksum/README.md) for more.

## Hash algorithms

Implemented hash algorithms:

* MD5 - [RFC 1321: The MD5 Message-Digest Algorithm](https://tools.ietf.org/html/rfc1321)
* SHA-1 - [RFC 3174: US Secure Hash Algorithm 1 (SHA1)](https://tools.ietf.org/html/rfc3174)
* SHA-2 SHA-224, SHA-256 - [FIPS PUB 180-4: Secure Hash Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)

## Disclaimer

Code is under development. The interface, both for library and application, **may** change in the future.
