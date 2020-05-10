use std::env;

mod hash {
    pub trait Context {
        fn block_size(&self) -> usize;

        fn update(&mut self, data: Vec<u8>);

        fn finalize(&mut self);

        fn digest(&self) -> Vec<u8>;
    }

    pub mod md5 {
        use std::num::Wrapping;

        pub fn new() -> Context {
            Context { a: 0x67452301, b: 0xefcdab89, c: 0x98badcfe, d: 0x10325476, length: 0, block: Vec::<u8>::new(), }
        }

        #[derive(Clone, Debug)]
        pub struct Context {
            a: u32,
            b: u32,
            c: u32,
            d: u32,
            length: usize,
            block: Vec<u8>,
        }

        // impl Clone for self::Context {
        //     fn clone(&self) -> Context {
        //         Context { a: self.a, b: self.b, c: self.c, d: self.d, length: self.length, block: self.block.clone() }
        //     }
        // }

        impl self::Context {
            fn process_block(&mut self, block: [u32; 16]) {
                fn step(a: u32, b: u32, c: u32, d: u32, function: &dyn Fn(u32, u32, u32) -> u32, data: u32, rotation: u32, constant: u32) -> u32 {
                    let a = Wrapping(a) + Wrapping(function(b, c, d)) + Wrapping(data) + Wrapping(constant);
                    let a = a.0.rotate_left(rotation);
                    let a = Wrapping(a) + Wrapping(b);
                    a.0
                }

                let (mut a, mut b, mut c, mut d) = (self.a, self.b, self.c, self.d);

                // round 1

                fn f(x: u32, y: u32, z: u32) -> u32 {
                    (x & y) | (!x & z)
                }

                a = step(a, b, c, d, &f, block[ 0],  7, 0xd76aa478);
                d = step(d, a, b, c, &f, block[ 1], 12, 0xe8c7b756);
                c = step(c, d, a, b, &f, block[ 2], 17, 0x242070db);
                b = step(b, c, d, a, &f, block[ 3], 22, 0xc1bdceee);
                a = step(a, b, c, d, &f, block[ 4],  7, 0xf57c0faf);
                d = step(d, a, b, c, &f, block[ 5], 12, 0x4787c62a);
                c = step(c, d, a, b, &f, block[ 6], 17, 0xa8304613);
                b = step(b, c, d, a, &f, block[ 7], 22, 0xfd469501);
                a = step(a, b, c, d, &f, block[ 8],  7, 0x698098d8);
                d = step(d, a, b, c, &f, block[ 9], 12, 0x8b44f7af);
                c = step(c, d, a, b, &f, block[10], 17, 0xffff5bb1);
                b = step(b, c, d, a, &f, block[11], 22, 0x895cd7be);
                a = step(a, b, c, d, &f, block[12],  7, 0x6b901122);
                d = step(d, a, b, c, &f, block[13], 12, 0xfd987193);
                c = step(c, d, a, b, &f, block[14], 17, 0xa679438e);
                b = step(b, c, d, a, &f, block[15], 22, 0x49b40821);

                // round 2

                fn g(x: u32, y: u32, z: u32) -> u32 {
                    (x & z) | (y & !z)
                }

                a = step(a, b, c, d, &g, block[ 1],  5, 0xf61e2562);
                d = step(d, a, b, c, &g, block[ 6],  9, 0xc040b340);
                c = step(c, d, a, b, &g, block[11], 14, 0x265e5a51);
                b = step(b, c, d, a, &g, block[ 0], 20, 0xe9b6c7aa);
                a = step(a, b, c, d, &g, block[ 5],  5, 0xd62f105d);
                d = step(d, a, b, c, &g, block[10],  9, 0x02441453);
                c = step(c, d, a, b, &g, block[15], 14, 0xd8a1e681);
                b = step(b, c, d, a, &g, block[ 4], 20, 0xe7d3fbc8);
                a = step(a, b, c, d, &g, block[ 9],  5, 0x21e1cde6);
                d = step(d, a, b, c, &g, block[14],  9, 0xc33707d6);
                c = step(c, d, a, b, &g, block[ 3], 14, 0xf4d50d87);
                b = step(b, c, d, a, &g, block[ 8], 20, 0x455a14ed);
                a = step(a, b, c, d, &g, block[13],  5, 0xa9e3e905);
                d = step(d, a, b, c, &g, block[ 2],  9, 0xfcefa3f8);
                c = step(c, d, a, b, &g, block[ 7], 14, 0x676f02d9);
                b = step(b, c, d, a, &g, block[12], 20, 0x8d2a4c8a);

                // round 3

                fn h(x: u32, y: u32, z: u32) -> u32 {
                    x ^ y ^ z
                }

                a = step(a, b, c, d, &h, block[ 5],  4, 0xfffa3942);
                d = step(d, a, b, c, &h, block[ 8], 11, 0x8771f681);
                c = step(c, d, a, b, &h, block[11], 16, 0x6d9d6122);
                b = step(b, c, d, a, &h, block[14], 23, 0xfde5380c);
                a = step(a, b, c, d, &h, block[ 1],  4, 0xa4beea44);
                d = step(d, a, b, c, &h, block[ 4], 11, 0x4bdecfa9);
                c = step(c, d, a, b, &h, block[ 7], 16, 0xf6bb4b60);
                b = step(b, c, d, a, &h, block[10], 23, 0xbebfbc70);
                a = step(a, b, c, d, &h, block[13],  4, 0x289b7ec6);
                d = step(d, a, b, c, &h, block[ 0], 11, 0xeaa127fa);
                c = step(c, d, a, b, &h, block[ 3], 16, 0xd4ef3085);
                b = step(b, c, d, a, &h, block[ 6], 23, 0x04881d05);
                a = step(a, b, c, d, &h, block[ 9],  4, 0xd9d4d039);
                d = step(d, a, b, c, &h, block[12], 11, 0xe6db99e5);
                c = step(c, d, a, b, &h, block[15], 16, 0x1fa27cf8);
                b = step(b, c, d, a, &h, block[ 2], 23, 0xc4ac5665);

                // round 4

                fn i(x: u32, y: u32, z: u32) -> u32 {
                    y ^ (x | !z)
                }

                a = step(a, b, c, d, &i, block[ 0],  6, 0xf4292244);
                d = step(d, a, b, c, &i, block[ 7], 10, 0x432aff97);
                c = step(c, d, a, b, &i, block[14], 15, 0xab9423a7);
                b = step(b, c, d, a, &i, block[ 5], 21, 0xfc93a039);
                a = step(a, b, c, d, &i, block[12],  6, 0x655b59c3);
                d = step(d, a, b, c, &i, block[ 3], 10, 0x8f0ccc92);
                c = step(c, d, a, b, &i, block[10], 15, 0xffeff47d);
                b = step(b, c, d, a, &i, block[ 1], 21, 0x85845dd1);
                a = step(a, b, c, d, &i, block[ 8],  6, 0x6fa87e4f);
                d = step(d, a, b, c, &i, block[15], 10, 0xfe2ce6e0);
                c = step(c, d, a, b, &i, block[ 6], 15, 0xa3014314);
                b = step(b, c, d, a, &i, block[13], 21, 0x4e0811a1);
                a = step(a, b, c, d, &i, block[ 4],  6, 0xf7537e82);
                d = step(d, a, b, c, &i, block[11], 10, 0xbd3af235);
                c = step(c, d, a, b, &i, block[ 2], 15, 0x2ad7d2bb);
                b = step(b, c, d, a, &i, block[ 9], 21, 0xeb86d391);

                // Update state

                let a = Wrapping(a) + Wrapping(self.a);
                self.a = a.0;

                let b = Wrapping(b) + Wrapping(self.b);
                self.b = b.0;

                let c = Wrapping(c) + Wrapping(self.c);
                self.c = c.0;

                let d = Wrapping(d) + Wrapping(self.d);
                self.d = d.0;

                // Update length

                self.length += block.len() * 4; // because we use u32, not u8
            }

            fn prepare_block(&self, data: Vec<u8>) -> [u32; 16] {
                // if data.len() != self.block_size() {
                //     panic!
                // }

                let mut block = [0u32; 16];
                for i in 0..16 {
                    let j = i * 4;
                    block[i] = ((data[j + 3] as u32) << 24)
                             | ((data[j + 2] as u32) << 16)
                             | ((data[j + 1] as u32) <<  8)
                             | ((data[j + 0] as u32) <<  0);
                }
                block
            }
        }

        impl super::Context for self::Context {
            fn block_size(&self) -> usize {
                64
            }

            fn update(&mut self, data: Vec<u8>) {
                self.block.extend(data);

                let iterations = self.block.len() / self.block_size();
                for _ in 0..iterations {
                    let block = self.block.drain(0..self.block_size()).collect();
                    let block = self.prepare_block(block);
                    self.process_block(block);
                }
            }

            fn finalize(&mut self) {
                let padding = self.block_size() - (self.block.len() % self.block_size());
                const MINIMUM: usize = 1  // for 0x80 byte
                                     + 8; // for 64-bit number
                let padding = if padding < MINIMUM { padding + self.block_size() } else { padding };
                let zeros = padding - MINIMUM;
                let zeros = vec![0u8; zeros];
                let mut padding = vec![0x80u8];
                padding.extend(zeros);
                let length = self.length + self.block.len();
                let length = length as u64;
                let length = length * 8; // bytes to binary count
                let length: [u8; 8] = [((length & 0x00000000000000FF) >>  0) as u8,
                                       ((length & 0x000000000000FF00) >>  8) as u8,
                                       ((length & 0x0000000000FF0000) >> 16) as u8,
                                       ((length & 0x00000000FF000000) >> 24) as u8,
                                       ((length & 0x000000FF00000000) >> 32) as u8,
                                       ((length & 0x0000FF0000000000) >> 40) as u8,
                                       ((length & 0x00FF000000000000) >> 48) as u8,
                                       ((length & 0xFF00000000000000) >> 56) as u8];
                let length = length.to_vec();
                padding.extend(length);
                self.update(padding);
            }

            fn digest(&self) -> Vec<u8> {
                let mut context = self.clone();
                context.finalize();

                let a = context.a;
                let a: [u8; 4] = [((a & 0x000000FF) >>  0) as u8,
                                  ((a & 0x0000FF00) >>  8) as u8,
                                  ((a & 0x00FF0000) >> 16) as u8,
                                  ((a & 0xFF000000) >> 24) as u8];
                let a = a.to_vec();

                let b = context.b;
                let b: [u8; 4] = [((b & 0x000000FF) >>  0) as u8,
                                  ((b & 0x0000FF00) >>  8) as u8,
                                  ((b & 0x00FF0000) >> 16) as u8,
                                  ((b & 0xFF000000) >> 24) as u8];
                let b = b.to_vec();

                let c = context.c;
                let c: [u8; 4] = [((c & 0x000000FF) >>  0) as u8,
                                  ((c & 0x0000FF00) >>  8) as u8,
                                  ((c & 0x00FF0000) >> 16) as u8,
                                  ((c & 0xFF000000) >> 24) as u8];
                let c = c.to_vec();

                let d = context.d;
                let d: [u8; 4] = [((d & 0x000000FF) >>  0) as u8,
                                  ((d & 0x0000FF00) >>  8) as u8,
                                  ((d & 0x00FF0000) >> 16) as u8,
                                  ((d & 0xFF000000) >> 24) as u8];
                let d = d.to_vec();

                let mut digest = Vec::<u8>::new();
                digest.extend(a);
                digest.extend(b);
                digest.extend(c);
                digest.extend(d);
                digest
            }
        }
    }
}

use std::process;
use hash::{Context as HashContext, md5};

enum Hash {
    MD5,
}

struct Context {
    pathnames: Vec<String>,
    hash: Hash,
}

fn usage() -> ! {
    println!("Usage: chksum [options] [--] (<file> | <directory>)...");
    process::exit(0);
}

fn help() -> ! {
    println!("
Usage: chksum [options] [--] (<file> | <directory>)...

Options:
  -h, --help\tShow this help
  -v, --version\tShow program version
");
    process::exit(0);
}

fn version() -> ! {
    const VERSION: &'static str = env!("CARGO_PKG_VERSION");
    println!("chksum v{}", VERSION);
    process::exit(0);
}

fn parse_arguments(args: Vec<String>) -> Context {
    let mut ignore_options = false;
    let mut pathnames = Vec::<String>::new();
    for arg in &args[1..] {
        match ignore_options {
            false => {
                match &arg[..] {
                    "--" => {
                        ignore_options = true;
                    },
                    "-h" | "--help" => {
                        help();
                    },
                    "-v" | "--version" => {
                        version();
                    },
                    _ => {
                        let pathname = String::from(arg);
                        pathnames.push(pathname);
                    }
                }
            },
            true => {
                let pathname = String::from(arg);
                pathnames.push(pathname);
            }
        }
    }
    let context = Context { pathnames: pathnames, hash: Hash::MD5, };
    context
}

use std::result::Result;
use std::path::Path;
use std::fs::{self, File};
use std::io::Read;

fn process_file(path: &Path, hash: &mut dyn HashContext) {
    const CHUNK: usize = 512;

    let mut file = File::open(path).unwrap(); // todo catch unwrap
    let metadata = fs::metadata(path).unwrap(); // todo catch unwrap
    let mut length: usize = metadata.len() as usize;
    loop {
        let buffer = if length > CHUNK { CHUNK } else { length };
        length -= buffer;
        let mut buffer = vec![0; buffer];
        file.read(&mut buffer).unwrap(); // todo catch unwrap
        hash.update(buffer);

        if length == 0 {
            break;
        }
    }
}

use std::io;

fn process_directory(path: &Path, hash: &mut dyn HashContext) {
    let mut entries = path.read_dir()
                          .unwrap() // todo catch unwrap
                          .map(|entries| entries.map(|entry| entry.path()))
                          .collect::<Result<Vec<_>, io::Error>>()
                          .unwrap(); // todo catch unwrap
    entries.sort();
    for entry in entries { // todo catch unwrap
        let path = Path::new(&entry);
        process_path(path, hash);
    }
}

fn process_path(path: &Path, hash: &mut dyn HashContext) {
    if path.is_file() {
        process_file(path, hash);
    } else if path.is_dir() {
        process_directory(path, hash);
    } else {
        // todo panic!
    }
}

fn process_pathname(pathname: &String, hash: &Hash) -> Result<Vec<u8>, String> {
    let path = Path::new(pathname);
    match path.exists() {
        true => {
            let mut hash = match hash {
                Hash::MD5 => md5::new(),
            };

            process_path(&path, &mut hash);

            Ok(hash.digest())
        },
        false => Err(format!("There is nothing under '{}'", pathname))
    }
}

fn main() {
    let context: Context;
    let args: Vec<String> = env::args().collect();
    match args.len() {
        1 => {
            usage();
        },
        _ => {
            context = parse_arguments(args);
        }
    }

    for pathname in &context.pathnames {
        match process_pathname(pathname, &context.hash) {
            Ok(digest) => {
                print!("{}\t", pathname);
                for byte in &digest {
                    print!("{:02x}", byte);
                }
                println!();
            },
            Err(e) => eprintln!("{}\t{}", pathname, e)
        }
    }
}
