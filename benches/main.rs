mod hash;

use criterion::criterion_main;

criterion_main! {
    hash::md5,
}
