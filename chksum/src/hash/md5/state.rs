use super::block::BLOCK_LENGTH_DWORDS;

#[allow(clippy::unreadable_literal)]
const A: u32 = 0x67452301;
#[allow(clippy::unreadable_literal)]
const B: u32 = 0xEFCDAB89;
#[allow(clippy::unreadable_literal)]
const C: u32 = 0x98BADCFE;
#[allow(clippy::unreadable_literal)]
const D: u32 = 0x10325476;

#[allow(clippy::unreadable_literal)]
#[rustfmt::skip]
const CONSTS: [u32; 64] = [
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE, 0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C, 0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1, 0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
];

#[allow(clippy::unreadable_literal)]
const SHIFTS: [u32; 16] = [
    0x07, 0x0C, 0x11, 0x16, 0x05, 0x09, 0x0E, 0x14, 0x04, 0x0B, 0x10, 0x17, 0x06, 0x0A, 0x0F, 0x15,
];

/// Low-level struct for manual manipulation of hash state.
///
/// **Warning**: You need to add padding manually.
///
/// # Examples
///
/// Process empty block.
///
/// ```rust
/// use chksum::hash::md5::State;
///
/// let mut state = State::new();
/// assert_eq!(
///     state.digest(),
///     [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
/// );
/// let data = [
///     u32::from_le_bytes([0x80, 0x00, 0x00, 0x00]),
///     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
///     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
///     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
///     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
///     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
///     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
///     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
///     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
///     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
///     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
///     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
///     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
///     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
///     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
///     // ...
///     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
/// ];
/// state.update(data);
/// assert_eq!(
///     state.digest(),
///     [0xD98C1DD4, 0x04B2008F, 0x980980E9, 0x7E42F8EC]
/// );
/// ```
///
/// Process two blocks of data.
///
/// ```rust
/// use chksum::hash::md5::State;
///
/// let mut state = State::new();
/// assert_eq!(
///     state.digest(),
///     [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
/// );
/// let data = [
///     u32::from_le_bytes([0x31, 0x32, 0x33, 0x34]),
///     u32::from_le_bytes([0x35, 0x36, 0x37, 0x38]),
///     u32::from_le_bytes([0x39, 0x30, 0x31, 0x32]),
///     # u32::from_le_bytes([0x33, 0x34, 0x35, 0x36]),
///     # u32::from_le_bytes([0x37, 0x38, 0x39, 0x30]),
///     # u32::from_le_bytes([0x31, 0x32, 0x33, 0x34]),
///     # u32::from_le_bytes([0x35, 0x36, 0x37, 0x38]),
///     # u32::from_le_bytes([0x39, 0x30, 0x31, 0x32]),
///     # u32::from_le_bytes([0x33, 0x34, 0x35, 0x36]),
///     # u32::from_le_bytes([0x37, 0x38, 0x39, 0x30]),
///     # u32::from_le_bytes([0x31, 0x32, 0x33, 0x34]),
///     # u32::from_le_bytes([0x35, 0x36, 0x37, 0x38]),
///     # u32::from_le_bytes([0x39, 0x30, 0x31, 0x32]),
///     # u32::from_le_bytes([0x33, 0x34, 0x35, 0x36]),
///     # u32::from_le_bytes([0x37, 0x38, 0x39, 0x30]),
///     // ...
///     u32::from_le_bytes([0x31, 0x32, 0x33, 0x34]),
/// ];
/// state.update(data);
/// let data = [
///     u32::from_le_bytes([0x35, 0x36, 0x37, 0x38]),
///     # u32::from_le_bytes([0x39, 0x30, 0x31, 0x32]),
///     # u32::from_le_bytes([0x33, 0x34, 0x35, 0x36]),
///     // ...
///     u32::from_le_bytes([0x37, 0x38, 0x39, 0x30]),
///     u32::from_le_bytes([0x80, 0x00, 0x00, 0x00]),
///     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
///     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
///     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
///     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
///     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
///     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
///     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
///     # u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
///     // ...
///     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
///     u32::from_le_bytes([0x80, 0x02, 0x00, 0x00]),
///     u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
/// ];
/// state.update(data);
/// assert_eq!(
///     state.digest(),
///     [0xA2F4ED57, 0x55C9E32B, 0x2EDA49AC, 0x7AB60721]
/// );
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct State {
    pub(super) a: u32,
    pub(super) b: u32,
    pub(super) c: u32,
    pub(super) d: u32,
}

impl State {
    /// Return state digest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum::hash::md5::State;
    ///
    /// let mut state = State::new();
    /// assert_eq!(
    ///     state.digest(),
    ///     [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    /// );
    /// ```
    #[cfg_attr(not(debug_assertions), inline)]
    #[must_use]
    pub const fn digest(&self) -> [u32; 4] {
        [self.a, self.b, self.c, self.d]
    }

    #[cfg_attr(not(debug_assertions), inline)]
    #[must_use]
    const fn from_raw(a: u32, b: u32, c: u32, d: u32) -> Self {
        Self { a, b, c, d }
    }

    /// Create new state instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum::hash::md5::State;
    ///
    /// let state = State::new();
    /// ```
    #[cfg_attr(not(debug_assertions), inline)]
    #[must_use]
    pub const fn new() -> Self {
        Self::from_raw(A, B, C, D)
    }

    /// Reset state to default values.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum::hash::md5::State;
    ///
    /// let mut state = State::new();
    /// let data = [0x00; 16];
    /// assert_ne!(
    ///     state.update(data).digest(),
    ///     [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    /// );
    /// assert_eq!(
    ///     state.reset().digest(),
    ///     [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    /// );
    /// ```
    #[cfg_attr(not(debug_assertions), inline)]
    pub fn reset(&mut self) -> &mut Self {
        self.a = A;
        self.b = B;
        self.c = C;
        self.d = D;
        self
    }

    /// Update state with block of data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum::hash::md5::State;
    ///
    /// let mut state = State::new();
    /// let data = [0x00; 16];
    /// state.update(data);
    /// ```
    #[cfg_attr(nightly, optimize(speed))]
    pub fn update(&mut self, block: [u32; BLOCK_LENGTH_DWORDS]) -> &mut Self {
        let (a, b, c, d) = (self.a, self.b, self.c, self.d);

        // Round 1

        #[cfg_attr(not(debug_assertions), inline)]
        const fn f(x: u32, y: u32, z: u32) -> u32 {
            (x & y) | (!x & z)
        }

        #[cfg_attr(not(debug_assertions), inline)]
        const fn ff(a: u32, b: u32, c: u32, d: u32, data: u32, shl: u32, constant: u32) -> u32 {
            a.wrapping_add(f(b, c, d))
                .wrapping_add(data)
                .wrapping_add(constant)
                .rotate_left(shl)
                .wrapping_add(b)
        }

        let a = ff(a, b, c, d, block[0x0], SHIFTS[0x0], CONSTS[0x00]);
        let d = ff(d, a, b, c, block[0x1], SHIFTS[0x1], CONSTS[0x01]);
        let c = ff(c, d, a, b, block[0x2], SHIFTS[0x2], CONSTS[0x02]);
        let b = ff(b, c, d, a, block[0x3], SHIFTS[0x3], CONSTS[0x03]);
        let a = ff(a, b, c, d, block[0x4], SHIFTS[0x0], CONSTS[0x04]);
        let d = ff(d, a, b, c, block[0x5], SHIFTS[0x1], CONSTS[0x05]);
        let c = ff(c, d, a, b, block[0x6], SHIFTS[0x2], CONSTS[0x06]);
        let b = ff(b, c, d, a, block[0x7], SHIFTS[0x3], CONSTS[0x07]);
        let a = ff(a, b, c, d, block[0x8], SHIFTS[0x0], CONSTS[0x08]);
        let d = ff(d, a, b, c, block[0x9], SHIFTS[0x1], CONSTS[0x09]);
        let c = ff(c, d, a, b, block[0xA], SHIFTS[0x2], CONSTS[0x0A]);
        let b = ff(b, c, d, a, block[0xB], SHIFTS[0x3], CONSTS[0x0B]);
        let a = ff(a, b, c, d, block[0xC], SHIFTS[0x0], CONSTS[0x0C]);
        let d = ff(d, a, b, c, block[0xD], SHIFTS[0x1], CONSTS[0x0D]);
        let c = ff(c, d, a, b, block[0xE], SHIFTS[0x2], CONSTS[0x0E]);
        let b = ff(b, c, d, a, block[0xF], SHIFTS[0x3], CONSTS[0x0F]);

        // Round 2

        #[cfg_attr(not(debug_assertions), inline)]
        const fn g(x: u32, y: u32, z: u32) -> u32 {
            (x & z) | (y & !z)
        }

        #[cfg_attr(not(debug_assertions), inline)]
        const fn gg(a: u32, b: u32, c: u32, d: u32, data: u32, shl: u32, constant: u32) -> u32 {
            a.wrapping_add(g(b, c, d))
                .wrapping_add(data)
                .wrapping_add(constant)
                .rotate_left(shl)
                .wrapping_add(b)
        }

        let a = gg(a, b, c, d, block[0x1], SHIFTS[0x4], CONSTS[0x10]);
        let d = gg(d, a, b, c, block[0x6], SHIFTS[0x5], CONSTS[0x11]);
        let c = gg(c, d, a, b, block[0xB], SHIFTS[0x6], CONSTS[0x12]);
        let b = gg(b, c, d, a, block[0x0], SHIFTS[0x7], CONSTS[0x13]);
        let a = gg(a, b, c, d, block[0x5], SHIFTS[0x4], CONSTS[0x14]);
        let d = gg(d, a, b, c, block[0xA], SHIFTS[0x5], CONSTS[0x15]);
        let c = gg(c, d, a, b, block[0xF], SHIFTS[0x6], CONSTS[0x16]);
        let b = gg(b, c, d, a, block[0x4], SHIFTS[0x7], CONSTS[0x17]);
        let a = gg(a, b, c, d, block[0x9], SHIFTS[0x4], CONSTS[0x18]);
        let d = gg(d, a, b, c, block[0xE], SHIFTS[0x5], CONSTS[0x19]);
        let c = gg(c, d, a, b, block[0x3], SHIFTS[0x6], CONSTS[0x1A]);
        let b = gg(b, c, d, a, block[0x8], SHIFTS[0x7], CONSTS[0x1B]);
        let a = gg(a, b, c, d, block[0xD], SHIFTS[0x4], CONSTS[0x1C]);
        let d = gg(d, a, b, c, block[0x2], SHIFTS[0x5], CONSTS[0x1D]);
        let c = gg(c, d, a, b, block[0x7], SHIFTS[0x6], CONSTS[0x1E]);
        let b = gg(b, c, d, a, block[0xC], SHIFTS[0x7], CONSTS[0x1F]);

        // Round 3

        #[cfg_attr(not(debug_assertions), inline)]
        const fn h(x: u32, y: u32, z: u32) -> u32 {
            x ^ y ^ z
        }

        #[cfg_attr(not(debug_assertions), inline)]
        const fn hh(a: u32, b: u32, c: u32, d: u32, data: u32, shl: u32, constant: u32) -> u32 {
            a.wrapping_add(h(b, c, d))
                .wrapping_add(data)
                .wrapping_add(constant)
                .rotate_left(shl)
                .wrapping_add(b)
        }

        let a = hh(a, b, c, d, block[0x5], SHIFTS[0x8], CONSTS[0x20]);
        let d = hh(d, a, b, c, block[0x8], SHIFTS[0x9], CONSTS[0x21]);
        let c = hh(c, d, a, b, block[0xB], SHIFTS[0xA], CONSTS[0x22]);
        let b = hh(b, c, d, a, block[0xE], SHIFTS[0xB], CONSTS[0x23]);
        let a = hh(a, b, c, d, block[0x1], SHIFTS[0x8], CONSTS[0x24]);
        let d = hh(d, a, b, c, block[0x4], SHIFTS[0x9], CONSTS[0x25]);
        let c = hh(c, d, a, b, block[0x7], SHIFTS[0xA], CONSTS[0x26]);
        let b = hh(b, c, d, a, block[0xA], SHIFTS[0xB], CONSTS[0x27]);
        let a = hh(a, b, c, d, block[0xD], SHIFTS[0x8], CONSTS[0x28]);
        let d = hh(d, a, b, c, block[0x0], SHIFTS[0x9], CONSTS[0x29]);
        let c = hh(c, d, a, b, block[0x3], SHIFTS[0xA], CONSTS[0x2A]);
        let b = hh(b, c, d, a, block[0x6], SHIFTS[0xB], CONSTS[0x2B]);
        let a = hh(a, b, c, d, block[0x9], SHIFTS[0x8], CONSTS[0x2C]);
        let d = hh(d, a, b, c, block[0xC], SHIFTS[0x9], CONSTS[0x2D]);
        let c = hh(c, d, a, b, block[0xF], SHIFTS[0xA], CONSTS[0x2E]);
        let b = hh(b, c, d, a, block[0x2], SHIFTS[0xB], CONSTS[0x2F]);

        // Round 4

        #[cfg_attr(not(debug_assertions), inline)]
        const fn i(x: u32, y: u32, z: u32) -> u32 {
            y ^ (x | !z)
        }

        #[cfg_attr(not(debug_assertions), inline)]
        const fn ii(a: u32, b: u32, c: u32, d: u32, data: u32, shl: u32, constant: u32) -> u32 {
            a.wrapping_add(i(b, c, d))
                .wrapping_add(data)
                .wrapping_add(constant)
                .rotate_left(shl)
                .wrapping_add(b)
        }

        let a = ii(a, b, c, d, block[0x0], SHIFTS[0xC], CONSTS[0x30]);
        let d = ii(d, a, b, c, block[0x7], SHIFTS[0xD], CONSTS[0x31]);
        let c = ii(c, d, a, b, block[0xE], SHIFTS[0xE], CONSTS[0x32]);
        let b = ii(b, c, d, a, block[0x5], SHIFTS[0xF], CONSTS[0x33]);
        let a = ii(a, b, c, d, block[0xC], SHIFTS[0xC], CONSTS[0x34]);
        let d = ii(d, a, b, c, block[0x3], SHIFTS[0xD], CONSTS[0x35]);
        let c = ii(c, d, a, b, block[0xA], SHIFTS[0xE], CONSTS[0x36]);
        let b = ii(b, c, d, a, block[0x1], SHIFTS[0xF], CONSTS[0x37]);
        let a = ii(a, b, c, d, block[0x8], SHIFTS[0xC], CONSTS[0x38]);
        let d = ii(d, a, b, c, block[0xF], SHIFTS[0xD], CONSTS[0x39]);
        let c = ii(c, d, a, b, block[0x6], SHIFTS[0xE], CONSTS[0x3A]);
        let b = ii(b, c, d, a, block[0xD], SHIFTS[0xF], CONSTS[0x3B]);
        let a = ii(a, b, c, d, block[0x4], SHIFTS[0xC], CONSTS[0x3C]);
        let d = ii(d, a, b, c, block[0xB], SHIFTS[0xD], CONSTS[0x3D]);
        let c = ii(c, d, a, b, block[0x2], SHIFTS[0xE], CONSTS[0x3E]);
        let b = ii(b, c, d, a, block[0x9], SHIFTS[0xF], CONSTS[0x3F]);

        // Update state

        self.a = self.a.wrapping_add(a);
        self.b = self.b.wrapping_add(b);
        self.c = self.c.wrapping_add(c);
        self.d = self.d.wrapping_add(d);

        self
    }
}

impl Default for State {
    #[cfg_attr(not(debug_assertions), inline)]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::State;

    #[test]
    fn state_new() {
        assert_eq!(State::new().digest(), [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]);
    }

    #[test]
    fn state_empty() {
        let block = [
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            State::new().update(block).digest(),
            [0xD98C1DD4, 0x04B2008F, 0x980980E9, 0x7E42F8EC]
        );
    }
}
