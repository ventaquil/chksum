use std::io::{self, Write};

use super::block::{Block, BLOCK_LENGTH_BYTES};
use super::digest::Digest;
use super::padding::{pad, Padding};
use super::State;

/// Hash struct with internal buffer.
///
/// # Examples
///
/// ```rust
/// # use chksum::hash::digest::Result;
/// use chksum::hash::sha2::sha384::{Digest, Hash};
///
/// # fn wrapper() -> Result<()> {
/// assert_eq!(
///     Hash::new().update(b"data").pad().digest(),
///     Digest::try_from("2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41")?
/// );
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Hash {
    state: State,
    buffer: Vec<u8>,
    counter: usize,
}

impl Hash {
    /// Return digest.
    ///
    /// **Warning**: To get proper result must call [`Hash::pad()`] before [`Hash::digest()`].
    #[cfg_attr(not(debug_assertions), inline)]
    #[must_use]
    pub fn digest(&self) -> Digest {
        self.state.into()
    }

    /// Create new hash instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum::hash::sha2::sha384::Hash;
    ///
    /// let hash = Hash::new();
    /// println!("{:?}", hash);
    /// ```
    #[cfg_attr(not(debug_assertions), inline)]
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: State::new(),
            buffer: Vec::with_capacity(BLOCK_LENGTH_BYTES),
            counter: 0,
        }
    }

    /// Add padding to internal state and prepare digest.
    #[cfg_attr(not(debug_assertions), inline)]
    pub fn pad(&mut self) -> &mut Self {
        let block_length = self.buffer.len();
        let block: Block = {
            self.buffer.resize(BLOCK_LENGTH_BYTES, 0x00);
            let block = self.buffer.drain(..BLOCK_LENGTH_BYTES);
            let block: [u8; BLOCK_LENGTH_BYTES] = block.as_slice().try_into().unwrap();
            block.into()
        };
        match pad(block, block_length, self.counter) {
            Padding::Single(block) => {
                self.state.update(block.into());
            },
            Padding::Double(block0, block1) => {
                self.state.update(block0.into()).update(block1.into());
            },
        }
        self
    }

    /// Reset internal state and buffer.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use chksum::hash::digest::Result;
    /// use chksum::hash::sha2::sha384::{Digest, Hash};
    ///
    /// # fn wrapper() -> Result<()> {
    /// let data = [0x00u8; 16];
    /// #[rustfmt::skip]
    /// let digest = Digest::try_from("38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B")?;
    ///
    /// let mut hash = Hash::new();
    /// assert_ne!(hash.update(&data[..]).pad().digest(), digest);
    /// assert_eq!(hash.reset().pad().digest(), digest);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg_attr(not(debug_assertions), inline)]
    pub fn reset(&mut self) -> &mut Self {
        self.state.reset();
        self.buffer.clear();
        self.counter = 0;
        self
    }

    /// Update hash with incoming data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use chksum::hash::sha2::sha384::Hash;
    ///
    /// let mut hash = Hash::new();
    /// let data = [0, 1, 2, 3];
    /// hash.update(data);
    /// let data = "string";
    /// hash.update(data);
    /// let data = b"bytes";
    /// hash.update(data);
    /// ```
    #[cfg_attr(nightly, optimize(speed))]
    pub fn update<T>(&mut self, data: T) -> &mut Self
    where
        T: AsRef<[u8]>,
    {
        let data = data.as_ref();
        self.counter = self.counter.wrapping_add(data.len());
        let mut data = data;
        if self.buffer.is_empty() {
            // if buffer is empty parse as many blocks as it is possible
            while data.len() >= BLOCK_LENGTH_BYTES {
                let block: [u8; BLOCK_LENGTH_BYTES] = data[..BLOCK_LENGTH_BYTES].try_into().unwrap();
                data = &data[BLOCK_LENGTH_BYTES..];
                let block: Block = block.into();
                self.state.update(block.into());
            }
        } else if ((self.buffer.len() % BLOCK_LENGTH_BYTES) + data.len()) > BLOCK_LENGTH_BYTES {
            // if buffer is not empty fill buffer with missing data that the buffer's length will be multiple of block's length
            let buffer_length = self.buffer.len() % BLOCK_LENGTH_BYTES;
            if buffer_length > 0 {
                let buffer_missing = BLOCK_LENGTH_BYTES - buffer_length;
                let buffer = &data[..buffer_missing];
                data = &data[buffer_missing..];
                self.buffer.extend_from_slice(buffer);
            }
            // create as many blocks from buffer as it is possible
            while self.buffer.len() >= BLOCK_LENGTH_BYTES {
                let block: [u8; BLOCK_LENGTH_BYTES] =
                    self.buffer.drain(..BLOCK_LENGTH_BYTES).as_slice().try_into().unwrap();
                let block: Block = block.into();
                self.state.update(block.into());
            }
            // create as many blocks from data as it is possible
            while data.len() >= BLOCK_LENGTH_BYTES {
                let block: [u8; BLOCK_LENGTH_BYTES] = data[..BLOCK_LENGTH_BYTES].try_into().unwrap();
                data = &data[BLOCK_LENGTH_BYTES..];
                let block: Block = block.into();
                self.state.update(block.into());
            }
        }
        if !data.is_empty() {
            // update buffer with rest of data
            self.buffer.extend_from_slice(data);
        }
        self
    }
}

impl Default for Hash {
    #[cfg_attr(not(debug_assertions), inline)]
    fn default() -> Self {
        Self::new()
    }
}

impl Write for Hash {
    #[cfg_attr(not(debug_assertions), inline)]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    #[cfg_attr(not(debug_assertions), inline)]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::digest::Result;

    #[test]
    fn hash_new() -> Result<()> {
        assert_eq!(
            Hash::new().pad().digest(),
            Digest::try_from(
                "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B"
            )?
        );
        Ok(())
    }

    #[test]
    fn hash_hello_world() -> Result<()> {
        assert_eq!(
            Hash::new().update("Hello World").pad().digest(),
            Digest::try_from(
                "99514329186B2F6AE4A1329E7EE6C610A729636335174AC6B740F9028396FCC803D0E93863A7C3D90F86BEEE782F4F3F"
            )?
        );
        Ok(())
    }

    #[test]
    fn hash_hello_world_by_chunks() -> Result<()> {
        assert_eq!(
            Hash::new().update("Hello").update(" ").update("World").pad().digest(),
            Digest::try_from(
                "99514329186B2F6AE4A1329E7EE6C610A729636335174AC6B740F9028396FCC803D0E93863A7C3D90F86BEEE782F4F3F"
            )?
        );
        Ok(())
    }
}