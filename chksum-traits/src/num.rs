#[cfg(not(feature = "std"))]
use core::ops::Add;
#[cfg(feature = "std")]
use std::ops::Add;

pub trait WrappingAdd<Rhs = Self>: Add<Self, Output = Self> + Sized {
    #[must_use]
    fn wrapping_add(self, rhs: Rhs) -> Self;
}

impl WrappingAdd for u32 {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn wrapping_add(self, rhs: Self) -> Self {
        self.wrapping_add(rhs)
    }
}
