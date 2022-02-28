# chksum-ffi

[![crates.io](https://img.shields.io/crates/v/chksum-ffi?style=flat-square "crates.io")](https://crates.io/crates/chksum-ffi)
[![LICENSE](https://img.shields.io/github/license/ventaquil/chksum?style=flat-square "LICENSE")](https://github.com/ventaquil/chksum/blob/master/LICENSE)

Basic FFI bindings which allows to use `chksum` library in other languages.

## Available bindings

Bindings are available for both `md5` and `sha1` hash functions.

|                   Binding                  |                                               Description                                              |
|--------------------------------------------|--------------------------------------------------------------------------------------------------------|
| `chksum_hash_*_new()`                      | Create new instance of hash.                                                                           |
| `chksum_hash_*_update(hash, data, length)` | Update hash with incoming data. Function processes only full blocks of data and doesn't apply padding. |
| `chksum_hash_*_digest(hash)`               | Return hash raw digest. You need to free memory on your own.                                           |
| `chksum_hash_*_hexdigest(hash)`            | Return hash digest as hex string. You need to free memory on your own.                                 |
| `chksum_hash_*_drop(hash)`                 | Drop memory of hash structure.                                                                         |
