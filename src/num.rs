use std::ops::Add;

pub trait WrappingAdd<Rhs = Self>: Sized + Add<Self, Output=Self> {
    fn wrapping_add(self, rhs: Rhs) -> Self;
}

impl WrappingAdd for u32 {
    #[cfg_attr(feature = "inline", inline)]
    fn wrapping_add(self, rhs: Self) -> Self {
        self.wrapping_add(rhs)
    }
}
