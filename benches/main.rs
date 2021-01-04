mod hash;

use criterion::criterion_main;

criterion_main! {
    hash::md5,
    hash::sha1,
}
