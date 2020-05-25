# chksum

For people who wants to make checksum of whole directory but don't like:

    find /path -type f -exec md5sum \{\} + | sort -k1 | md5sum

## Building

Simply run

    cargo build [--release]

## Running

Usage:

    chksum [options] [--] <pathname>...

Like:

    $ chksum src/ src/bin/chksum.rs
    8139f084f6680a03c74123c666b03bf9        src/
    c52bb04e42a80c00c6e764bf212c6919        src/bin/chksum.rs
    $ cat $(find src/ -type f) | md5sum
    8139f084f6680a03c74123c666b03bf9  -
    $ md5sum src/bin/chksum.rs
    c52bb04e42a80c00c6e764bf212c6919  src/bin/chksum.rs
    $ chksum --hash SHA-1 *
    1b6f4615cb3b63c61c3b626aef3803557f2360bd        Cargo.toml
    7d096ad0b4d899a63d3d2e3594d5ed7315045b3b        LICENSE
    62d1b6b28f7efee461258648b4e60d6a1acae756        README.md
    fcca38c687bad1547788379e8f9239a483bcea0f        src
    $ sha1sum Cargo.toml LICENSE README.md
    1b6f4615cb3b63c61c3b626aef3803557f2360bd  Cargo.toml
    7d096ad0b4d899a63d3d2e3594d5ed7315045b3b  LICENSE
    62d1b6b28f7efee461258648b4e60d6a1acae756  README.md
    $ cat $(find src/ -type f) | sha1sum
    fcca38c687bad1547788379e8f9239a483bcea0f  -
    $ chksum --process-pathnames --hash SHA-1 *
    8e20b8bd28e8883582a13fd7f01ecf67404fed55        Cargo.toml
    15dbe1f6b0e98951b1d2d58b0232ea4b51b8f91f        LICENSE
    4e5524c24b52b9ad11891912a3661a7f1019a666        README.md
    b72ccc67e545bb18f8fb5faba10525379c96be49        src

## Hash algorithms

Currently there are implemented two hash algorithms:
 * MD5 - [RFC 1321: The MD5 Message-Digest Algorithm](https://tools.ietf.org/html/rfc1321)
 * SHA-1 - [RFC 3174: US Secure Hash Algorithm 1 (SHA1)](https://tools.ietf.org/html/rfc3174)
