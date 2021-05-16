#[cfg(
    all(
        feature = "simd",
        target_arch = "x86",
        target_feature = "sse",
        target_feature = "sse2",
        target_feature = "sse4.1",
    )
)]
pub mod x86;
#[cfg(
    all(
        feature = "simd",
        target_arch = "x86_64",
        target_feature = "sse",
        target_feature = "sse2",
        target_feature = "sse4.1",
    )
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
        const N: usize = 1;
        type u8 = u8;
        type u32 = u32;
    }
}

#[cfg(
    all(
        feature = "simd",
        any(
            target_arch = "x86",
            target_arch = "x86_64",
        ),
        target_feature = "sse",
        target_feature = "sse2",
        target_feature = "sse4.1",
    )
)]
pub mod x4 {
    #[derive(Clone, Copy, Debug)]
    pub struct Arch;

    #[cfg(target_arch = "x86")]
    impl super::Arch for Arch {
        const N: usize = 4;
        type u8 = super::x86::u8x4;
        type u32 = super::x86::u32x4;
    }

    #[cfg(target_arch = "x86_64")]
    impl super::Arch for Arch {
        const N: usize = 4;
        type u8 = super::x86_64::u8x4;
        type u32 = super::x86_64::u32x4;
    }
}
