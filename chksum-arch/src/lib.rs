#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(all(
    feature = "simd",
    target_arch = "x86",
    target_feature = "sse",
    target_feature = "sse2",
    target_feature = "sse4.1",
))]
#[cfg_attr(
    docsrs,
    doc(cfg(all(
        feature = "simd",
        target_arch = "x86",
        target_feature = "sse",
        target_feature = "sse2",
        target_feature = "sse4.1",
    )))
)]
pub mod x86;
#[cfg(all(
    feature = "simd",
    target_arch = "x86_64",
    target_feature = "sse",
    target_feature = "sse2",
    target_feature = "sse4.1",
))]
#[cfg_attr(
    docsrs,
    doc(cfg(all(
        feature = "simd",
        target_arch = "x86_64",
        target_feature = "sse",
        target_feature = "sse2",
        target_feature = "sse4.1",
    )))
)]
pub mod x86_64;

#[allow(non_camel_case_types)]
pub trait Arch {
    const N: usize;

    type u8;
    type u32;
}

pub mod x1 {
    #[derive(Clone, Copy, Debug)]
    pub struct Arch;

    impl super::Arch for Arch {
        type u32 = u32;
        type u8 = u8;

        const N: usize = 1;
    }
}

#[cfg(all(
    feature = "simd",
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse",
    target_feature = "sse2",
    target_feature = "sse4.1",
))]
#[cfg_attr(
    docsrs,
    doc(cfg(all(
        feature = "simd",
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse",
        target_feature = "sse2",
        target_feature = "sse4.1",
    )))
)]
pub mod x4 {
    #[derive(Clone, Copy, Debug)]
    pub struct Arch;

    #[cfg(target_arch = "x86")]
    use super::x86::{u32x4, u8x4};
    #[cfg(target_arch = "x86_64")]
    use super::x86_64::{u32x4, u8x4};

    impl super::Arch for Arch {
        type u32 = u32x4;
        type u8 = u8x4;

        const N: usize = 4;
    }
}
