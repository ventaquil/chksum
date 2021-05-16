# chksum

[![Build](https://img.shields.io/github/workflow/status/ventaquil/chksum/Rust?style=flat-square "Build")](https://github.com/ventaquil/chksum/actions?query=workflow%3ARust)
[![Release](https://img.shields.io/github/v/release/ventaquil/chksum?include_prereleases&sort=semver&style=flat-square "Release")](https://github.com/ventaquil/chksum/releases)
[![crates.io](https://img.shields.io/crates/v/chksum?style=flat-square "crates.io")](https://crates.io/crates/chksum)
[![LICENSE](https://img.shields.io/github/license/ventaquil/chksum?style=flat-square "LICENSE")](https://github.com/ventaquil/chksum/blob/master/LICENSE)

For people who wants to make checksum of whole directory but doesn't like:

    find /path -type f -exec md5sum \{\} + | sort -k1 | md5sum

## Building

Simply run `cargo build`.

    cargo build [--release]

You can use `make` command too.

    make [DEBUG=1]

## Installation

Simply install using `make install` target.

    make install PREFIX='/usr'

**Note:** This may require root privileges.

## Running

Usage:

    chksum [options] [--] <path>...

Like:

    $ chksum LICENSE
    256cc158ea3c7dd3efcee650b022b5a5 LICENSE
    $ md5sum LICENSE
    256cc158ea3c7dd3efcee650b022b5a5  LICENSE
    $ chksum --hash SHA1 docs/ extra/
    d6143fde775af08fc43329295a620408fbcdd72b docs/
    3e1c845b152bf99431b4c709c95c1aa20d4735b6 extra/
    $ find docs/ -type f -exec cat \{\} + | sha1sum
    d6143fde775af08fc43329295a620408fbcdd72b  -

## Hash algorithms

Currently there are implemented two hash algorithms:
 * MD5 - [RFC 1321: The MD5 Message-Digest Algorithm](https://tools.ietf.org/html/rfc1321)
 * SHA-1 - [RFC 3174: US Secure Hash Algorithm 1 (SHA1)](https://tools.ietf.org/html/rfc3174)
