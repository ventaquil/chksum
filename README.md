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
    8139f084f6680a03c74123c666b03bf9        src/              # cat $(find src/ -type f) | md5sum -> 8139f084f6680a03c74123c666b03bf9
    c52bb04e42a80c00c6e764bf212c6919        src/bin/chksum.rs # md5sum src/bin/chksum.rs          -> c52bb04e42a80c00c6e764bf212c6919
    $ chksum --hash SHA-1 *
    87cadd0584059b8d2448acdfe3576fb1acaaa935        Cargo.toml # sha1sum Cargo.toml                 -> 87cadd0584059b8d2448acdfe3576fb1acaaa935
    7d096ad0b4d899a63d3d2e3594d5ed7315045b3b        LICENSE    # sha1sum LICENSE                    -> 7d096ad0b4d899a63d3d2e3594d5ed7315045b3b
    f2dfc62dd4f1b2a2fe23f19e1dfb45a4f87da38e        README.md  # sha1sum README.md                  -> f2dfc62dd4f1b2a2fe23f19e1dfb45a4f87da38e
    fcca38c687bad1547788379e8f9239a483bcea0f        src        # cat $(find src/ -type f) | sha1sum -> fcca38c687bad1547788379e8f9239a483bcea0f
    $ chksum --process-pathnames --hash SHA-1 *
    4cc4587be1179b6aa350cb1d2c5c1c46e531409b        Cargo.toml
    15dbe1f6b0e98951b1d2d58b0232ea4b51b8f91f        LICENSE
    b58b6601dc56ef3415946034670f13b83abaef27        README.md
    b72ccc67e545bb18f8fb5faba10525379c96be49        src

## Hash algorithms

Currently there are implemented two hash algorithms:
 * MD5 - [RFC 1321: The MD5 Message-Digest Algorithm](https://tools.ietf.org/html/rfc1321)
 * SHA-1 - [RFC 3174: US Secure Hash Algorithm 1 (SHA1)](https://tools.ietf.org/html/rfc3174)
