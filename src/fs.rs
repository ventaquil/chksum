pub use std::fs::File;
use std::io::{self, Cursor, Read};

use crate::hash::Padding;

#[derive(Debug)]
pub struct PaddedFile<T: Padding<u8>> {
    file: File,
    cursor: Cursor<Vec<u8>>,
    padding: T,
    updated: bool,
}

impl<T: Padding<u8>> PaddedFile<T> {
    #[inline]
    pub fn new(file: File, padding: T) -> Self {
        let cursor = Cursor::new(Vec::new());
        Self {
            file,
            cursor,
            padding,
            updated: false,
        }
    }
}

impl<T: Padding<u8>> Read for PaddedFile<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.updated {
            self.cursor.read(buf)
        } else {
            let length = self.file.read(buf)?;
            self.padding.update(&mut buf[..length]);
            if length < buf.len() {
                let data = self.padding.data();
                self.cursor = Cursor::new(data);
                self.updated = true;
                let length = length + self.cursor.read(&mut buf[length..])?;
                Ok(length)
            } else {
                Ok(length)
            }
        }
    }
}
