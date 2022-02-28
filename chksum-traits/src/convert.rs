pub trait From1<T> {
    fn from1(_: T) -> Self;
}

impl From1<u8> for u32 {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from1(number: u8) -> u32 {
        u32::from(number)
    }
}

impl From1<u32> for u32 {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from1(number: u32) -> u32 {
        number
    }
}

pub trait FromBeBytes<T, const N: usize> {
    fn from_be_bytes(bytes: [T; N]) -> Self;
}

impl FromBeBytes<u8, 4> for u32 {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from_be_bytes(bytes: [u8; 4]) -> Self {
        u32::from_be_bytes(bytes)
    }
}

pub trait FromLeBytes<T, const N: usize> {
    fn from_le_bytes(bytes: [T; N]) -> Self;
}

impl FromLeBytes<u8, 4> for u32 {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from_le_bytes(bytes: [u8; 4]) -> Self {
        u32::from_le_bytes(bytes)
    }
}

pub trait ToLeBytes<T, const N: usize> {
    fn to_le_bytes(self) -> [T; N];
}

impl ToLeBytes<u8, 4> for u32 {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn to_le_bytes(self) -> [u8; 4] {
        self.to_le_bytes()
    }
}

pub trait ToBeBytes<T, const N: usize> {
    fn to_be_bytes(self) -> [T; N];
}

impl ToBeBytes<u8, 4> for u32 {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn to_be_bytes(self) -> [u8; 4] {
        self.to_be_bytes()
    }
}
