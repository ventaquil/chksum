use std::io::{self, Read};

// use crate::fs::{File, PaddedFile};
use crate::fs::PaddedFile as File;
use crate::hash::Padding;

#[derive(Debug)]
pub enum Stream<T: Padding<u8>> {
    Empty,
    // File(File),
    // PaddedFile(Chain<File, T>),
    // PaddedFile(PaddedFile<T>),
    File(File<T>),
}

impl<T: Padding<u8>> Read for Stream<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Empty => {
                buf.fill(0u8);
                Ok(buf.len())
            },
            Self::File(file) => file.read(buf),
            // Self::PaddedFile(file) => file.read(buf),
            // Self::PaddedFile(chain) => {
            //     let length = chain.read(buf)?;
            //     Ok(length)
            // },
        }
    }
}

/*
use std::convert::From;
use std::fs::File;
use std::io::{self, Read, Seek};

pub trait Stream: Read {
    // fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    //     Read::read(mut self, buf)
    // }

    fn size(&self) -> usize;
}

// impl Stream for File {}

pub struct WrapStream<T: Read> {
    inner: T,
}

#[derive(Debug)]
pub struct FileStream {
    file: File,
}

// impl From<String> for FileStream {
//     #[inline]
//     fn from(pathname: String) -> Self {
//         Self::from(File::open(pathname).unwrap())
//     }
// }

impl From<File> for FileStream {
    #[inline]
    fn from(file: File) -> Self {
        Self {
            file,
        }
    }
}

impl Read for FileStream {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

// impl Read for FileStream {
//     #[inline]
//     fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
//         println!("{:?}", self.file.read(buf));
//         if self.file.stream_position().unwrap() < self.size() as u64 {
//             self.file.read(buf)
//         } else {
//             Ok(0)
//         }
//     }
// }

impl Stream for FileStream {
    #[inline]
    fn size(&self) -> usize {
        self.file.metadata().unwrap().len() as usize
    }
}

#[derive(Debug)]
pub struct ZeroStream {}

impl ZeroStream {
    #[inline]
    pub fn new() -> Self {
        Self {}
    } 
}

impl Read for ZeroStream {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        buf.fill(0);
        Ok(buf.len())
    }
}

impl Stream for ZeroStream {
    #[inline]
    fn size(&self) -> usize {
        usize::MAX
    }
}
*/
