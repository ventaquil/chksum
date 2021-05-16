use std::cmp::{Ord, Ordering, PartialOrd};
use std::io::{self, Read as _};
use std::sync::mpsc::Sender;

use crate::arch::Arch;
use crate::fs::{File, PaddedFile};
use crate::hash::{Digest, Hash, Padding};
use crate::stream::Stream;

extern crate spmc;
use spmc::Receiver;

// struct Worker<T: Arch> {
//     arch: T,
// }

#[derive(Debug)]
struct Entry<'a, T: Padding<u8>> {
    pathname: Option<&'a str>,
    stream: Stream<T>,
}

impl<'a, T: Padding<u8>> Entry<'a, T> {
    #[inline]
    fn new(pathname: Option<&'a str>, stream: Stream<T>) -> Self {
        Self {
            pathname,
            stream,
        }
    }
}

#[derive(Debug)]
pub enum Output {
    Digest(Vec<u8>),
    Empty,
    Error(io::Error),
}

#[inline]
fn create_stream<T: Padding<u8>>(pathname: &str, padding: T) -> io::Result<Stream<T>> {
    // fixme check whether pathname is dir or file
    let file = File::open(pathname)?;
    let file = PaddedFile::new(file, padding);
    let stream = Stream::File(file);
    Ok(stream)
}

pub fn process_x4<'a, T: Copy + From<[u8; 4]> + Into<[u8; 4]>, U: Into<[T; 16]>, V: Copy + Padding<u8>, W: Hash<T, Digest = U, Padding = V>>(rx: Receiver<&'a str>, tx: Sender<(&'a str, Output)>, hash: W, padding: V) {
    #[inline]
    fn receive_stream<'a, T: Padding<u8>>(rx: Receiver<&'a str>, tx: Sender<(&'a str, Output)>, padding: T) -> Entry<'a, T> {
        match rx.try_recv() {
            Ok(pathname) => {
                match create_stream::<T>(pathname, padding) {
                    Ok(stream) => Entry::new(Some(pathname), stream),
                    Err(error) => {
                        // fixme send error as a result
                        let output = (pathname, Output::Error(error));
                        tx.send(output);
                        Entry::new(None, Stream::Empty)
                    },
                }
            },
            _ => Entry::new(None, Stream::Empty),
        }
    }

    #[inline]
    fn read_stream<'a, T: Padding<u8>>(tx: Sender<(&'a str, Output)>, entry: &mut Entry<'a, T>, buffer: &mut [u8]) -> usize {
        let mut stream = &mut entry.stream;
        match stream.read(buffer) {
            Ok(length) => length,
            Err(error) => {
                if let Some(pathname) = entry.pathname {
                    let output = (pathname, Output::Error(error));
                    tx.send(output);
                }
                *entry = Entry::new(None, Stream::Empty);
                buffer.len()
            },
        }
    }

    let mut hash = hash;
    let mut entries = [
        receive_stream::<V>(rx.clone(), tx.clone(), padding),
        receive_stream::<V>(rx.clone(), tx.clone(), padding),
        receive_stream::<V>(rx.clone(), tx.clone(), padding),
        receive_stream::<V>(rx.clone(), tx.clone(), padding),
    ];

    loop {
        match entries {
            [Entry { stream: Stream::Empty, .. }, Entry { stream: Stream::Empty, .. }, Entry { stream: Stream::Empty, .. }, Entry { stream: Stream::Empty, .. }] => {
                break;
            },
            _ => {},
        }

        let buffer_size = 4096;
        let mut buffers = [
            vec![0; buffer_size],
            vec![0; buffer_size],
            vec![0; buffer_size],
            vec![0; buffer_size],
        ];
        let lengths = [
            read_stream(tx.clone(), &mut entries[0], &mut buffers[0]),
            read_stream(tx.clone(), &mut entries[1], &mut buffers[1]),
            read_stream(tx.clone(), &mut entries[2], &mut buffers[2]),
            read_stream(tx.clone(), &mut entries[3], &mut buffers[3]),
        ];
        let mut positions = [
            Position::new(0, lengths[0]),
            Position::new(1, lengths[1]),
            Position::new(2, lengths[2]),
            Position::new(3, lengths[3]),
        ];
        positions.sort();
        let positions = positions;
        let minimum = positions[0].length;
        let maximum = positions[3].length;
        let mut buffer = Vec::with_capacity(maximum);
        for i in 0..maximum {
            buffer.push(T::from([
                buffers[0][i],
                buffers[1][i],
                buffers[2][i],
                buffers[3][i],
            ]))
        }
        let buffer = buffer;
        if minimum == maximum {
            hash.update(&buffer[..]);
            if maximum < buffer_size {
                let digest = hash.digest();
                let digest: [T; 16] = digest.into();
                let digest: [[u8; 4]; 16] = [
                    digest[0x0].into(), digest[0x1].into(), digest[0x2].into(), digest[0x3].into(), 
                    digest[0x4].into(), digest[0x5].into(), digest[0x6].into(), digest[0x7].into(), 
                    digest[0x8].into(), digest[0x9].into(), digest[0xA].into(), digest[0xB].into(),
                    digest[0xC].into(), digest[0xD].into(), digest[0xE].into(), digest[0xF].into(),
                ];
                for i in 0..4 {
                    let mut entry = &mut entries[i];
                    if let Some(pathname) = entry.pathname { // todo
                        let digest = vec![
                            digest[0x0][i], digest[0x1][i], digest[0x2][i], digest[0x3][i], 
                            digest[0x4][i], digest[0x5][i], digest[0x6][i], digest[0x7][i], 
                            digest[0x8][i], digest[0x9][i], digest[0xA][i], digest[0xB][i],
                            digest[0xC][i], digest[0xD][i], digest[0xE][i], digest[0xF][i],
                        ];
                        let output = Output::Digest(digest);
                    let output = (pathname, output);
                        tx.send(output);
                        *entry = Entry::new(None, Stream::Empty);
                    }
                }
            }
        } else {
            let mut processed = 0;
            for position in &positions {
                let length = position.length;
                let buffer = &buffer[processed..length];
                hash.update(buffer);
                let index = position.index;
                let mut entry = &mut entries[index];
                if let Some(pathname) = entry.pathname { // todo
                    // println!("pathname={:?}, length={:?}. buffer_size={:?}", pathname, length, buffer_size);
                    if length < buffer_size {
                        let digest = hash.digest();
                        let digest: [T; 16] = digest.into();
                        let digest: [[u8; 4]; 16] = [
                            digest[0x0].into(), digest[0x1].into(), digest[0x2].into(), digest[0x3].into(), 
                            digest[0x4].into(), digest[0x5].into(), digest[0x6].into(), digest[0x7].into(), 
                            digest[0x8].into(), digest[0x9].into(), digest[0xA].into(), digest[0xB].into(),
                            digest[0xC].into(), digest[0xD].into(), digest[0xE].into(), digest[0xF].into(),
                        ];
                        let digest = vec![
                            digest[0x0][index], digest[0x1][index], digest[0x2][index], digest[0x3][index], 
                            digest[0x4][index], digest[0x5][index], digest[0x6][index], digest[0x7][index], 
                            digest[0x8][index], digest[0x9][index], digest[0xA][index], digest[0xB][index],
                            digest[0xC][index], digest[0xD][index], digest[0xE][index], digest[0xF][index],
                        ];
                        let output = Output::Digest(digest);
                        // println!("{:?} {:?}", pathname, output);
                        let output = (pathname, output);
                        tx.send(output);
                        *entry = Entry::new(None, Stream::Empty);
                    }
                }
                // if let Some(pathname) = entry.pathname { // todo
                //     if length < buffer_size {
                //         let digest = hash.digest();
                //         let digest: [T; 16] = digest.into();
                //         let digest: [[u8; 4]; 16] = [
                //             digest[0x0].into(), digest[0x1].into(), digest[0x2].into(), digest[0x3].into(), 
                //             digest[0x4].into(), digest[0x5].into(), digest[0x6].into(), digest[0x7].into(), 
                //             digest[0x8].into(), digest[0x9].into(), digest[0xA].into(), digest[0xB].into(),
                //             digest[0xC].into(), digest[0xD].into(), digest[0xE].into(), digest[0xF].into(),
                //         ];
                //         let digest = vec![
                //             digest[0x0][index], digest[0x1][index], digest[0x2][index], digest[0x3][index], 
                //             digest[0x4][index], digest[0x5][index], digest[0x6][index], digest[0x7][index], 
                //             digest[0x8][index], digest[0x9][index], digest[0xA][index], digest[0xB][index],
                //             digest[0xC][index], digest[0xD][index], digest[0xE][index], digest[0xF][index],
                //         ];
                //         let output = Output::Digest(digest);
                //     }
                // }
                processed = length;
            }
        }
    }
    // hash.finalize();
    // let digest = hash.digest();
    // let digest: [T; 16] = digest.into();
    // let digest: [[u8; 4]; 16] = [
    //     digest[0x0].into(), digest[0x1].into(), digest[0x2].into(), digest[0x3].into(), 
    //     digest[0x4].into(), digest[0x5].into(), digest[0x6].into(), digest[0x7].into(), 
    //     digest[0x8].into(), digest[0x9].into(), digest[0xA].into(), digest[0xB].into(),
    //     digest[0xC].into(), digest[0xD].into(), digest[0xE].into(), digest[0xF].into(),
    // ];
    // for index in 0..4 {
    //     if let Some(pathname) = entries[index].pathname  {
    //         let output = Output::Digest(vec![
    //             digest[0x0][index], digest[0x1][index], digest[0x2][index], digest[0x3][index], 
    //             digest[0x4][index], digest[0x5][index], digest[0x6][index], digest[0x7][index], 
    //             digest[0x8][index], digest[0x9][index], digest[0xA][index], digest[0xB][index],
    //             digest[0xC][index], digest[0xD][index], digest[0xE][index], digest[0xF][index],
    //         ]);
    //         let output = (pathname, output);
    //         tx.send(output);
    //     }
    // }
}

// fn read_stream<T: Padding<u8>>(stream: Stream<T>, buffer: &mut [u8]) -> io::Result<usize> {
//     match stream.read(&mut buffer) {
//         Ok(length) => {
//             if length < buffer_size {
//                 streams[i] = Stream::Empty;
//             }
//             length
//         },
//         Err(error) => {
//             streams[i] = Stream::Empty;
//             outputs[i] = Output::Error(error);
//             let length = streams[i].read(&mut buffers[i]).unwrap();
//             length
//         },
//     }
// }

// impl<T: Arch> Worker<T> {
//     fn spawn(arch: T) -> Self {
//         Self {
//             arch,
//         }
//     }
// 
//     fn process(&self, rx: Receiver<&str>) {
//         match T::N {
//             4 => {
//                 x4::process(rx)
//             },
//             1 | _ => {},
//         }
//     }
// }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Position {
    index: usize,
    length: usize,
}

impl Position {
    #[inline]
    fn new(index: usize, length: usize) -> Self{
        Self {
            index,
            length,
        }
    }

    // #[inline]
    // fn index(&self) -> usize {
    //     self.index
    // }

    // #[inline]
    // fn length(&self) -> usize {
    //     self.length
    // }
}

impl Ord for Position {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.length.cmp(&other.length)
    }
}

impl PartialOrd for Position {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn process<T: Arch>(rx: Receiver<&str>) -> Vec<Output> {
    match T::N {
        4 => {
            // x4::process(rx).to_vec()
            Vec::new()
        },
        1 | _ => Vec::new(),
    }
}

pub mod x4 {
    use std::io::Read;

    use crate::stream::Stream;

    use super::{Output, Position};

    extern crate spmc;
    use spmc::Receiver;

    // fn create_stream<T>(rx: Receiver<&str>) -> Stream<T> {
    //     match rx.try_recv() {
    //         Ok(pathname) => {
    //             use crate::fs::{File, PaddedFile};
    //             match File::open(pathname) {
    //                 Ok(file) => {
    //                     let file
    //                 }
    //                 // Ok(file) => {
    //                 //     let stream = Stream::PaddedFile(PaddedFile::new(file, Padding::new()));
    //                 //     streams[i] = stream;
    //                 // },
    //                 // Err(error) => {
    //                 //     outputs[i] = Output::Error(error);
    //                 // },
    //             }
    //         },
    //         _ => Stream::Empty,
    //     }
    // }

    pub fn process(rx: Receiver<&str>) -> [Output; 4] {
        use crate::arch::{x4::Arch, x86_64::u8x4}; // fixme
        use crate::hash::{Digest, Update, md5::{Hash, Padding}}; // fixme

        let mut hash = Hash::<Arch>::new();
        let mut outputs = [
            Output::Empty,
            Output::Empty,
            Output::Empty,
            Output::Empty,
        ];
        // let mut streams: [Stream<Padding>; 4] = [
        //     Stream::Empty,
        //     Stream::Empty,
        //     Stream::Empty,
        //     Stream::Empty,
        // ];
        // // todo unroll
        // for i in 0..4 {
        //     match rx.try_recv() {
        //         Ok(pathname) => {
        //             use crate::fs::{File, PaddedFile};
        //             match File::open(pathname) {
        //                 Ok(file) => {
        //                     let stream = Stream::PaddedFile(PaddedFile::new(file, Padding::new()));
        //                     streams[i] = stream;
        //                 },
        //                 Err(error) => {
        //                     outputs[i] = Output::Error(error);
        //                 },
        //             }
        //         },
        //         _ => {}, // ignore if there are no more data to receive
        //     }
        // }
        use crate::fs::{File, PaddedFile};
        let mut streams: [Stream<Padding>; 4] = [
            // Stream::PaddedFile(PaddedFile::new(File::open("Makefile").unwrap(), Padding::new())),
            // Stream::PaddedFile(PaddedFile::new(File::open("random").unwrap(), Padding::new())),
            // Stream::PaddedFile(PaddedFile::new(File::open("random").unwrap(), Padding::new())),
            // Stream::PaddedFile(PaddedFile::new(File::open("random").unwrap(), Padding::new())),
            // Stream::PaddedFile(PaddedFile::new(File::open("random").unwrap(), Padding::new())),
            Stream::File(PaddedFile::new(File::open("random").unwrap(), Padding::new())),
            Stream::File(PaddedFile::new(File::open("random").unwrap(), Padding::new())),
            Stream::File(PaddedFile::new(File::open("random").unwrap(), Padding::new())),
            Stream::File(PaddedFile::new(File::open("random").unwrap(), Padding::new())),
        ];
        loop {
            match streams {
                [Stream::Empty, Stream::Empty, Stream::Empty, Stream::Empty] => {
                    break;
                },
                _ => {
                    let buffer_size = 4096;
                    let mut buffers = [
                        vec![0; buffer_size],
                        vec![0; buffer_size],
                        vec![0; buffer_size],
                        vec![0; buffer_size],
                    ];
                    let mut lengths: [usize; 4] = [0; 4];
                    // todo unroll
                    for i in 0..4 {
                        lengths[i] = match streams[i].read(&mut buffers[i]) {
                            Ok(length) => {
                                if length < buffer_size {
                                    streams[i] = Stream::Empty;
                                }
                                length
                            },
                            Err(error) => {
                                streams[i] = Stream::Empty;
                                outputs[i] = Output::Error(error);
                                let length = streams[i].read(&mut buffers[i]).unwrap();
                                length
                            },
                        }
                    }
                    let mut positions = [
                        Position::new(0, lengths[0]),
                        Position::new(1, lengths[1]),
                        Position::new(2, lengths[2]),
                        Position::new(3, lengths[3]),
                    ];
                    positions.sort();
                    let positions = positions;
                    let minimum = positions[0].length;
                    let maximum = positions[3].length;
                    let mut buffer = Vec::with_capacity(maximum);
                    for i in 0..maximum {
                        buffer.push(u8x4::from([
                            buffers[0][i],
                            buffers[1][i],
                            buffers[2][i],
                            buffers[3][i],
                        ]))
                    }
                    let buffer = buffer;
                    if minimum == maximum {
                        hash.update(&buffer);
                    } else {
                        let mut processed = 0;
                        for position in &positions {
                            let length = position.length;
                            let buffer = &buffer[processed..length];
                            hash.update(buffer);
                            let index = position.index;
                            match outputs[index] {
                                Output::Empty => {
                                    if length < buffer_size {
                                        let digest = hash.digest();
                                        let digest: [u8x4; 16] = digest.into();
                                        let digest: [[u8; 4]; 16] = [
                                            digest[0x0].into(), digest[0x1].into(), digest[0x2].into(), digest[0x3].into(), 
                                            digest[0x4].into(), digest[0x5].into(), digest[0x6].into(), digest[0x7].into(), 
                                            digest[0x8].into(), digest[0x9].into(), digest[0xA].into(), digest[0xB].into(),
                                            digest[0xC].into(), digest[0xD].into(), digest[0xE].into(), digest[0xF].into(),
                                        ];
                                        outputs[index] = Output::Digest(vec![
                                            digest[0x0][index], digest[0x1][index], digest[0x2][index], digest[0x3][index], 
                                            digest[0x4][index], digest[0x5][index], digest[0x6][index], digest[0x7][index], 
                                            digest[0x8][index], digest[0x9][index], digest[0xA][index], digest[0xB][index],
                                            digest[0xC][index], digest[0xD][index], digest[0xE][index], digest[0xF][index],
                                        ]);
                                        {
                                            let digest = [
                                                digest[0x0][index], digest[0x1][index], digest[0x2][index], digest[0x3][index], 
                                                digest[0x4][index], digest[0x5][index], digest[0x6][index], digest[0x7][index], 
                                                digest[0x8][index], digest[0x9][index], digest[0xA][index], digest[0xB][index],
                                                digest[0xC][index], digest[0xD][index], digest[0xE][index], digest[0xF][index],
                                            ];
                                            println!("digest\t{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}", digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7], digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14], digest[15]);
                                        }
                                    }
                                },
                                _ => {},
                            }
                            processed = length;
                        }
                    }
                }
            }
        }

        outputs
    }
}

// use std::fs::File;
// use std::io::{self, Read};

// use crate::arch::{self, Arch, x86_64::u8x4};
// use crate::hash::{Digest, Finalize, Hash, Update};
// // use crate::stream::{FileStream, Stream, ZeroStream};

// extern crate spmc;
// use spmc::Receiver;

// // enum Source {
// //     Empty,
// //     File(File),
// // }

// // impl Read for Source {
// //     fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
// //         match self {
// //             Self::Empty => {
// //                 buf.fill(0u8);
// //                 Ok(buf.len())
// //             },
// //             Self::File(file) => file.read(buf),
// //         }
// //     }
// // }

// // impl From<&str> for Source {
// //     #[inline]
// //     fn from(pathname: &str) -> Self {
// //         if let Ok(file) = File::open(pathname) {
// //             Source::File(file)
// //         } else {
// //             Source::Empty
// //         }
// //     }
// // }

// /*
// pub fn worker<T: Arch, U: Hash<T::u8>>(rx: Receiver<&str>, hash: &mut U) {
//     // hash.reset();

//     for _ in 0..T::N {
//         let mut stream: Stream = match rx.try_recv() {
//             Ok(pathname) => FileStream::from(pathname),
//             Err(error) => ZeroStream::new(),
//         };
//         let mut data = [1u8; 32];
//         // println!("{:?}", stream);
//         println!("{:?}: {:?}", stream.read(&mut data), data);
//         // fixme create array of streams
//     }

//     // let n = 512; // chunk size
//     // // fixme some while
//     // for _ in 0..T::N {
//     //     let data = stream.read(n);
//     //     // fixme create array of datas
//     // }
//     // let data = T::u8::from(...);  // from data
//     // hash.update(data);
// }
// */

// pub enum Output {
//     Result,
//     Empty,
//     Error(io::Error),
// }

// pub fn worker_x1(rx: Receiver<&str>) -> Output {
//     match rx.try_recv() {
//         Ok(pathname) => {
//             use crate::hash::md5::{Hash, Digest};
//             let mut hash = Hash::<arch::x1::Arch>::new();
//             let digest = process_x1_pathname(pathname, hash);
//             if let Ok(digest) = digest {
//                 let digest: [u8; 16] = digest.into();
//                 println!("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}", digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7], digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14], digest[15]);
//             }
//         },
//         Err(_) => {},
//     }
//     Output::Result
// }

// fn process_x1_pathname<T: Hash<u8>>(pathname: &str, mut hash: T) -> io::Result<T::Digest> {
//     // let file = File::open(pathname)?;
//     // let mut stream = FileStream::from(file);
//     let mut file = File::open(pathname)?;
//     let mut buffer = [0u8; 512];
//     // while let Ok(length) = stream.read(&mut buffer) { // TODO `&& length > 0` waiting for https://github.com/rust-lang/rust/issues/53667
//     while let Ok(length) = file.read(&mut buffer) { // TODO `&& length > 0` waiting for https://github.com/rust-lang/rust/issues/53667
//         if length == 0 {
//             break;
//         }
//         let buffer = &buffer[..length];
//         hash.update(buffer);
//     }
//     hash.finalize();
//     let digest = hash.digest();
//     Ok(digest)
// }

// pub fn worker_x4(rx: Receiver<&str>) -> [Output; 4] {
//     let pathnames = [rx.try_recv(), rx.try_recv(), rx.try_recv(), rx.try_recv()];
//     let results = match pathnames {
//         [Ok(_), Ok(_), Ok(_), Ok(_)] => {
//             [Output::Result, Output::Result, Output::Result, Output::Result]
//         },
//         [Ok(_), Ok(_), Ok(_), Err(_)] => {
//             let pathnames = [pathnames[0].unwrap(), pathnames[1].unwrap(), pathnames[2].unwrap()];
//             let mut sources = [Source::from(pathnames[0]), Source::from(pathnames[1]), Source::from(pathnames[2]), Source::Empty];
//             match sources {
//                 [Source::Empty, Source::Empty, Source::Empty, Source::Empty] => {},
//                 _ => {
//                     let mut buffers = [[0u8; 512], [0u8; 512], [0u8; 512], [0u8; 512]];
//                     use crate::hash::md5::{Hash, Digest};
//                     let mut hash = Hash::<arch::x4::Arch>::new();
//                     loop {
//                         let lengths = [
//                             sources[0].read(&mut buffers[0]),
//                             sources[1].read(&mut buffers[1]),
//                             sources[2].read(&mut buffers[2]),
//                             sources[3].read(&mut buffers[3]),
//                         ];

//                         // FIXME check that all lengths are Ok(...)

//                         // let lengths = [
//                         //     lengths[0]?, //.unwrap(),
//                         //     lengths[1]?, //.unwrap(),
//                         //     lengths[2]?, //.unwrap(),
//                         //     lengths[3]?, //.unwrap(),
//                         // ];

//                         // match lengths {
//                         //     [Ok(a), Ok(b), Ok(c), Ok(d)] => {
//                         //         let minimums = if a <= b {
//                         //             [a, b]
//                         //         } else {
//                         //             [b, a]
//                         //         };
//                         //         let minimums = if c <= d {
//                         //             [minimums [0], minimums[1], c, d];
//                         //         } else {
//                         //             [minimums[0], minimums[1], d, c];
//                         //         };
//                         //         let [a, b, c, d] 
//                         //     },
//                         //     _ => {},
//                         // }

//                         // let minimums = if lengths[0] <= lengths[1] {
//                         //     [0, 1]
//                         // } else {
//                         //     [1, 0]
//                         // };
//                         // let minimums = if lengths[2] <= lengths[3] {
//                         //     [minimums[0], minimums[1], 2, 3]
//                         // } else {
//                         //     [minimums[0], minimums[1], 3, 2]
//                         // };

//                         // hash.update(&buffer);
//                         break;
//                     }
//                 },
//             }
//             [Output::Result, Output::Result, Output::Result, Output::Empty]
//         },
//         [Ok(_), Ok(_), Err(_), Err(_)] => {
//             [Output::Result, Output::Result, Output::Empty, Output::Empty]
//         },
//         [Ok(_), Err(_), Err(_), Err(_)] => {
//             [Output::Result, Output::Empty, Output::Empty, Output::Empty]
//         },
//         _ => {
//             [Output::Empty, Output::Empty, Output::Empty, Output::Empty]
//         },
//     };
//     /*
//     match pathnames {
//         [Ok(_), Ok(_), Ok(_), Ok(_)] => println!("woo! all 4!"),
//         // [Ok(_), Ok(_), Ok(_), Err(_)] => println!("woo. almost all 4, it's 3!"),
//         [Ok(_), Ok(_), Ok(_), Err(_)] => {
//             println!("woo. almost all 4, it's 3!");
//             let pathnames = [pathnames[0].unwrap(), pathnames[1].unwrap(), pathnames[2].unwrap()];
//             // let files = [File::open(pathnames[0]), File::open(pathnames[1]), File::open(pathnames[2])];
//             // let source = Source::File(files[0].unwrap());
//             // let source = if let Ok(file) = File::open(pathnames[0]) {
//             //     Source::File(file)
//             // } else {
//             //     Source::Empty
//             // };
//             let sources = [Source::from(pathnames[0]), Source::from(pathnames[1]), Source::from(pathnames[2]), Source::Empty];
//             match sources {
//                 [Source::Empty, Source::Empty, Source::Empty, Source::Empty] => {},
//                 _ => {
//                     let mut buffers = [[0u8; 512], [0u8; 512], [0u8; 512], [0u8; 512]];
//                 },
//             }
//         },
//         [Ok(_), Ok(_), Err(_), Err(_)] => println!("woo, it's just 2"),
//         [Ok(_), Err(_), Err(_), Err(_)] => println!("woo only 1"),
//         _ => println!("damn, no pathnames"),
//     }
//     */
//     // if let [Ok(pathname0), Ok(pathname1), Ok(pathname2), Ok(pathname3)] = pathnames {
//     //     println!("woo! all 4!");
//     //     // let files = [File::open(pathname0).unwrap(), File::open(pathname1).unwrap(), File::open(pathname2).unwrap(), File::open(pathname3).unwrap()]; // FIXME don't use unwraps
//     //     // let streams = [FileStream::from(files[0]), FileStream::from(files[1]), FileStream::from(files[2]), FileStream::from(files[3])];
//     //     // FileStream::from(&files[0]);
//     //     let stream0 = {
//     //         let file = File::open(pathname0).unwrap(); // FIXME don't use unwraps
//     //         FileStream::from(file)
//     //     };
//     // 
//     // } else if let [Ok(pathname0), Ok(pathname1), Ok(pathname2), Err(_)] = pathnames {
//     //     println!("woo. almost all 4, it's 3!");
//     // } else if let [Ok(pathname0), Ok(pathname1), Err(_), Err(_)] = pathnames {
//     //     println!("woo, it's just 2");
//     // } else if let [Ok(pathname0), Err(_), Err(_), Err(_)] = pathnames {
//     //     println!("woo only 1");
//     // } else {
//     //     println!("damn, no pathnames");
//     // }
//     [Output::Result, Output::Result, Output::Result, Output::Result]
// }
