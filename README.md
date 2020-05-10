# chksum

For people who wants to make checksum of whole directory but don't like:

    find /path -type f -exec md5sum \{\} + | sort -k1 | md5sum

## Building

Simply run

    cargo build [--release]

## Running

Usage:

    chksum [options] [--] (<file> | <directory>)...

Like:

    $ chksum . src/ src/main.rs
    .       3751316348d8c5fb49e8dbd1c661f180
    src/    d83428a907afeaa083e2a08f0eb5bcc4
    src/main.rs     d83428a907afeaa083e2a08f0eb5bcc4

