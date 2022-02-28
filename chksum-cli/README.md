# chksum-cli

[![crates.io](https://img.shields.io/crates/v/chksum-cli?style=flat-square "crates.io")](https://crates.io/crates/chksum-cli)
[![LICENSE](https://img.shields.io/github/license/ventaquil/chksum?style=flat-square "LICENSE")](https://github.com/ventaquil/chksum/blob/master/LICENSE)

## Installation

```
$ cargo install chksum-cli
```

## Options

|        Flags        |            Description            |      Allowed values     |
|:-------------------:|-----------------------------------|:-----------------------:|
|    `-H`/`--hash`    | Choose hashing algorithm          | `MD5`<br>`SHA1`/`SHA-1` |
| `-P`/`--with-paths` | Use paths to calculate digest     |    *Flag only option*   |
| `-s`/`--chunk-size` | Set chunk size of processing data |     positive integer    |
