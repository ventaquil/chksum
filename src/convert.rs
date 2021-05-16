pub mod arch {
    pub trait From1<T> {
        fn from1(_: T) -> Self;
    }

    impl From1<u8> for u32 {
        #[inline]
        fn from1(number: u8) -> u32 {
            number as u32
        }
    }

    impl From1<u32> for u32 {
        #[inline]
        fn from1(number: u32) -> u32 {
            number
        }
    }
}

pub trait FromBeBytes<T> {
    fn from_be_bytes(bytes: T) -> Self; // todo waiting for const generics to allow [T; L]
}

impl FromBeBytes<[u8; 4]> for u32 {
    #[inline]
    fn from_be_bytes(bytes: [u8; 4]) -> Self {
        u32::from_be_bytes(bytes)
    }
}

pub trait FromLeBytes<T> {
    fn from_le_bytes(bytes: T) -> Self; // todo waiting for const generics to allow [T; L]
}

impl FromLeBytes<[u8; 4]> for u32 {
    #[inline]
    fn from_le_bytes(bytes: [u8; 4]) -> Self {
        u32::from_le_bytes(bytes)
    }
}

pub trait ToLeBytes<T> {
    fn to_le_bytes(self) -> T; // todo waiting for const generics to allow [T; L]
}

impl ToLeBytes<[u8; 4]> for u32 {
    #[inline]
    fn to_le_bytes(self) -> [u8; 4] {
        self.to_le_bytes()
    }
}
