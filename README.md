# chksum

[![Build](https://img.shields.io/github/workflow/status/ventaquil/chksum/Rust?style=flat-square "Build")](https://github.com/ventaquil/chksum/actions?query=workflow%3ARust)
[![Release](https://img.shields.io/github/v/release/ventaquil/chksum?include_prereleases&sort=semver&style=flat-square "Release")](https://github.com/ventaquil/chksum/releases)
[![crates.io](https://img.shields.io/crates/v/chksum?style=flat-square "crates.io")](https://crates.io/crates/chksum)
[![LICENSE](https://img.shields.io/github/license/ventaquil/chksum?style=flat-square "LICENSE")](https://github.com/ventaquil/chksum/blob/master/LICENSE)

For people who wants to make checksum of whole directory but don't like:

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

    chksum [options] [--] <pathname>...

Like:

    $ chksum LICENSE
    LICENSE 256cc158ea3c7dd3efcee650b022b5a5
    $ md5sum LICENSE
    256cc158ea3c7dd3efcee650b022b5a5  LICENSE
    $ chksum --with-pathnames src src/
    src     dc257745d9bb3c573d7756488dc90f80
    src/    dc257745d9bb3c573d7756488dc90f80
    $ chksum --hash SHA1 doc/ extra/
    doc/    62ab37c8151bdecf618765b77910003ada71bda3
    extra/  d92271a891f58f6f649de3631427e3253090a61f
    $ find doc/ -type f -exec cat \{\} + | sha1sum
    62ab37c8151bdecf618765b77910003ada71bda3  -

## Hash algorithms

Currently there are implemented two hash algorithms:
 * MD5 - [RFC 1321: The MD5 Message-Digest Algorithm](https://tools.ietf.org/html/rfc1321)
 * SHA-1 - [RFC 3174: US Secure Hash Algorithm 1 (SHA1)](https://tools.ietf.org/html/rfc3174)
