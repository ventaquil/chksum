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

    $ chksum . src/ src/bin/chksum.rs
    3edc7b1a1b7f69782846eea9d7e39796        .
    ad874c46825b791ac1993f6585f92184        src/
    79ed3c7ade779ad02baa81f2991be022        src/bin/chksum.rs
    $ chksum *
    06a72d5387e1466a116792166b43fe34        Cargo.lock
    f8bc3b94741061dcc01fc3a2ce7209a8        Cargo.toml
    0368688c7cb5dac7b74720699cf95013        LICENSE
    03ac52a9e3d7094a573602a562354928        README.md
    ad874c46825b791ac1993f6585f92184        src
    $ chksum --process-pathnames *
    a1ab0c59760703b5103df7604cfa7b69        Cargo.lock
    238ff911e1d59263936a65c9d0b35100        Cargo.toml
    95d2a23e144b6c76c6ab4e22c5372477        LICENSE
    851c43604e664f98f2278cd2d188dd0c        README.md
    631330abd8bd8609d9981849c275ac39        src

