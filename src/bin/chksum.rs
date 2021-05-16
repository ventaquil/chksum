// use chksum::arch::x86_64::u32x4;
// use chksum::hash::md5::Context as MD5;

// fn main() {
//     {
//         let data: [u32; 16] = [u32::from(0xABCD_u32); 16];
//         let mut md5 = MD5::<u32>::new();
//         md5.update(data);
//         let digest = md5.digest();
//         println!("single\t{:?}", digest);
//     }
//     {
//         let data: [u32x4; 16] = [u32x4::from(0xABCD_u32); 16];
//         let mut md5 = MD5::<u32x4>::new();
//         md5.update(data);
//         let digest = md5.digest();
//         let digest: [(u32, u32, u32, u32); 4] = [
//             digest[0].into(),
//             digest[1].into(),
//             digest[2].into(),
//             digest[3].into(),
//         ];
//         let digest: ([u32; 4], [u32; 4], [u32; 4], [u32; 4]) = (
//             [
//                 digest[0].0,
//                 digest[1].0,
//                 digest[2].0,
//                 digest[3].0,
//             ],
//             [
//                 digest[0].1,
//                 digest[1].1,
//                 digest[2].1,
//                 digest[3].1,
//             ],
//             [
//                 digest[0].2,
//                 digest[1].2,
//                 digest[2].2,
//                 digest[3].2,
//             ],
//             [
//                 digest[0].3,
//                 digest[1].3,
//                 digest[2].3,
//                 digest[3].3,
//             ],
//         );
//         println!("vector\t{:?}", digest.0);
//         println!("\t{:?}", digest.1);
//         println!("\t{:?}", digest.2);
//         println!("\t{:?}", digest.3);
//     }
//     // let y = u32x4::from((0_u8, 1_u8, 2_u8, 3_u8, 4_u8, 5_u8, 6_u8, 7_u8, 8_u8, 9_u8, 10_u8, 11_u8, 12_u8, 13_u8, 14_u8, 15_u8));
//     // println!("{:?}", y);
//     // let x = u32x4::from((0x00010203_u32, 0x04050607_u32, 0x08090A0B_u32, 0x0C0D0E0F_u32));
//     // println!("{:?}", x);
//     // println!("{:?}", x == y);
//     // let x = u32x4::from(1_u32);
//     // let y = u32x4::from(u8::MAX as u32);
//     // println!("{:?}", x);
//     // println!("{:?}", y);
//     // println!("{:?}", x + y);
//     // let a = u32x4::from((0_u32, 1_u32, 2_u32, 3_u32));
//     // let b = u32x4::from(u32::MAX);
//     // println!("{:?}", a);
//     // println!("{:?}", b);
//     // println!("{:?}", a + b);
//     // println!("{:?} {:?} {:?} {:?}", 0_u32.wrapping_add(u32::MAX), 1_u32.wrapping_add(u32::MAX), 2_u32.wrapping_add(u32::MAX), 3_u32.wrapping_add(u32::MAX));
//     // let a = u32x4::from((0_u32, 1_u32, 2_u32, 3_u32));
//     // println!("{:?}", a);
//     // println!("{:?}", a + 1_u32);
//     // let x = [u32x4::from(0_u32); 16];
//     // println!("{:?}", x);
//     // let x = [u32::from(0_u32); 16];
//     // println!("{:?}", x);
//     // let mut file = File::open("Makefile").unwrap();
//     // let length = file.metadata().map(|metadata| metadata.len()).unwrap() as usize;
//     // let mut buffer = vec![0; length];
//     // file.read(&mut buffer).unwrap();
//     // let data = u32x4::from([buffer[0] as u32, buffer[1] as u32, buffer[2] as u32, buffer[3] as u32]);
//     // println!("{:?}", data);
//     // let (a, b, c, d) = (0, 1, 2, 3);
//     // let x = foo(a, b, c, d);
//     // println!("{:?}", x);
// }

// // use std::error::Error;
// // use std::sync::mpsc;

// // use chksum::{self, hash, io};

// // extern crate clap;
// // use clap::{App, Arg};

// // extern crate num_cpus;

// // extern crate threadpool;
// // use threadpool::ThreadPool;

// // fn main() -> Result<(), Box<dyn Error>> {
// //     const NAME: &str = env!("CARGO_PKG_NAME");
// //     const VERSION: &str = env!("CARGO_PKG_VERSION");
// //     const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

// //     let matches = App::new(NAME)
// //         .version(VERSION)
// //         .about(DESCRIPTION)
// //         .arg(
// //             Arg::with_name("pathnames")
// //                 .value_name("pathname")
// //                 .help("Pathname of file or directory")
// //                 .index(1)
// //                 .multiple(true)
// //                 .required(true),
// //         )
// //         .arg(
// //             Arg::with_name("chunk size")
// //                 .value_name("size")
// //                 .long("chunk-size")
// //                 .short("s")
// //                 .help("Chunk size")
// //                 .default_value("512")
// //                 .validator(|value| match value.parse::<usize>() {
// //                     Ok(_) => Ok(()),
// //                     Err(_) => Err(String::from("The value is not a number")),
// //                 }),
// //         )
// //         .arg(
// //             Arg::with_name("with pathnames")
// //                 .long("with-pathnames")
// //                 .short("W")
// //                 .help("Use pathnames to calculate digests"),
// //         )
// //         .arg(
// //             Arg::with_name("hash")
// //                 .long("hash")
// //                 .short("H")
// //                 .help("Chosen hash algorithm")
// //                 .default_value("MD5")
// //                 .validator(|hash| hash::new(&hash).map(|_| ()).map_err(|error| error.to_string())),
// //         )
// //         .arg(
// //             Arg::with_name("workers")
// //                 .long("workers")
// //                 .short("w")
// //                 .help("Maximum number of working threads")
// //                 .default_value("auto")
// //                 .validator(|value| {
// //                     match &value as &str {
// //                         "auto" => Ok(()),
// //                         _ => match value.parse::<usize>() {
// //                             Ok(value) => {
// //                                 if value == 0 {
// //                                     Err(String::from("Value cannot be zero"))
// //                                 } else {
// //                                     Ok(())
// //                                 }
// //                             },
// //                             Err(_) => Err(String::from("Value must be a positive number")),
// //                         },
// //                     }
// //                 }),
// //         )
// //         .after_help("Implemented hash algorithms:\n - MD5,\n - SHA-1.") // todo implement generator
// //         .get_matches();

// //     let chunk_size = matches
// //         .value_of("chunk size")
// //         .unwrap()
// //         .parse::<usize>()?;

// //     let hash = matches
// //         .value_of("hash")
// //         .unwrap();
// //     let hash = hash::new(hash)?;

// //     let workers = matches.value_of("workers");
// //     let workers = match workers {
// //         Some("auto") | None => num_cpus::get(),
// //         _ => workers.unwrap().parse::<usize>()?,
// //     };

// //     let pathnames: Vec<String> = matches
// //         .values_of("pathnames")
// //         .unwrap()
// //         .map(String::from)
// //         .collect();

// //     let with_pathnames = matches.is_present("with pathnames");

// //     let io = io::new(
// //         chunk_size,
// //         with_pathnames,
// //     );

// //     let context = chksum::new(hash, io);

// //     let jobs = pathnames.len();

// //     let (tx, rx) = mpsc::channel();
// //     let pool = ThreadPool::new(workers);
// //     for pathname in pathnames {
// //         let context = context.clone();
// //         let tx = tx.clone();
// //         pool.execute(move || {
// //             let checksum = context.chksum(&pathname);
// //             tx.send((pathname, checksum)).unwrap();
// //         });
// //     }

// //     for _ in 0..jobs {
// //         let (pathname, result) = rx.recv()?;
// //         match result {
// //             Ok(digest) => println!("{}\t{}", pathname, digest),
// //             Err(error) => eprintln!("{}\t{}", pathname, error),
// //         }
// //     }

// //     Ok(())
// // }

// use std::thread;

// use chksum::arch::{self, x86_64::u8x4};
// use chksum::hash::{Digest as _, Finalize as _, Update as _, md5::Hash as MD5};
// use chksum::worker::worker;

use std::sync::mpsc;

extern crate spmc;

fn main() {
    // let data: [u8; 32] = [0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30];
    // println!("data: {:?}", &data[..]);
    // let mut md5: MD5<arch::x1::Arch> = MD5::new();
    // md5.update(&data);
    // md5.finalize();
    // let digest = md5.digest();
    // {
    //     let digest: [u8; 16] = digest.into();
    //     println!("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}", digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7], digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14], digest[15]);
    // }
    // println!("{:?}", digest);
    // let data: [u8x4; 32] = [u8x4::from(data[0]), u8x4::from(data[1]), u8x4::from(data[2]), u8x4::from(data[3]), u8x4::from(data[4]), u8x4::from(data[5]), u8x4::from(data[6]), u8x4::from(data[7]), u8x4::from(data[8]), u8x4::from(data[9]), u8x4::from(data[10]), u8x4::from(data[11]), u8x4::from(data[12]), u8x4::from(data[13]), u8x4::from(data[14]), u8x4::from(data[15]), u8x4::from(data[16]), u8x4::from(data[17]), u8x4::from(data[18]), u8x4::from(data[19]), u8x4::from(data[20]), u8x4::from(data[21]), u8x4::from(data[22]), u8x4::from(data[23]), u8x4::from(data[24]), u8x4::from(data[25]), u8x4::from(data[26]), u8x4::from(data[27]), u8x4::from(data[28]), u8x4::from(data[29]), u8x4::from(data[30]), u8x4::from(data[31])];
    // let mut md5: MD5<arch::x4::Arch> = MD5::new();
    // md5.update(&data);
    // md5.finalize();
    // let digest = md5.digest();
    // {
    //     let digest: [u8x4; 16] = digest.into();
    //     let digest: [(u8, u8, u8, u8); 16] = [digest[0].into(), digest[1].into(), digest[2].into(), digest[3].into(), digest[4].into(), digest[5].into(), digest[6].into(), digest[7].into(), digest[8].into(), digest[9].into(), digest[10].into(), digest[11].into(), digest[12].into(), digest[13].into(), digest[14].into(), digest[15].into()];
    //     {
    //         let digest: [u8; 16] = [digest[0].0, digest[1].0, digest[2].0, digest[3].0, digest[4].0, digest[5].0, digest[6].0, digest[7].0, digest[8].0, digest[9].0, digest[10].0, digest[11].0, digest[12].0, digest[13].0, digest[14].0, digest[15].0];
    //         println!("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}", digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7], digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14], digest[15]);
    //     }
    //     {
    //         let digest: [u8; 16] = [digest[0].1, digest[1].1, digest[2].1, digest[3].1, digest[4].1, digest[5].1, digest[6].1, digest[7].1, digest[8].1, digest[9].1, digest[10].1, digest[11].1, digest[12].1, digest[13].1, digest[14].1, digest[15].1];
    //         println!("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}", digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7], digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14], digest[15]);
    //     }
    //     {
    //         let digest: [u8; 16] = [digest[0].2, digest[1].2, digest[2].2, digest[3].2, digest[4].2, digest[5].2, digest[6].2, digest[7].2, digest[8].2, digest[9].2, digest[10].2, digest[11].2, digest[12].2, digest[13].2, digest[14].2, digest[15].2];
    //         println!("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}", digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7], digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14], digest[15]);
    //     }
    //     {
    //         let digest: [u8; 16] = [digest[0].3, digest[1].3, digest[2].3, digest[3].3, digest[4].3, digest[5].3, digest[6].3, digest[7].3, digest[8].3, digest[9].3, digest[10].3, digest[11].3, digest[12].3, digest[13].3, digest[14].3, digest[15].3];
    //         println!("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}", digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7], digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14], digest[15]);
    //     }
    // }
    // println!("{:?}", digest);

    // let (mut tx, rx) = spmc::channel();
    let pathnames = spmc::channel();

    let outputs = mpsc::channel();

    // let mut threads = Vec::new();
    // for _ in 0..2 {
    //     let rx = rx.clone();
    //     let length = threads.len();
    //     threads.push(thread::spawn(move || {
    //         use chksum::arch::{x1, x4};
    //         use chksum::hash::md5::Hash as MD5;
    //         let mut hash = MD5::<x1::Arch>::new();
    //         // worker::<x1::Arch, _>(rx, &mut hash);
    //         // let worker = match length {
    //         //     0 => {
    //         //         let mut hash = MD5::<x1::Arch>::new();
    //         //         worker::<x1::Arch, _>(rx, &mut hash);
    //         //     },
    //         //     _ => {
    //         //         let mut hash = MD5::<x4::Arch>::new();
    //         //         worker::<x4::Arch, _>(rx, &mut hash);
    //         //     },
    //         // };
    //     }));
    // }

    {
        let (mut tx, _) = pathnames;
        // tx.send(String::from("src/hash/md5.rs")).unwrap();
        // tx.send("test").unwrap();
        // tx.send("Makefile").unwrap();
        tx.send("Makefile").unwrap();
        tx.send("Makefile").unwrap();
        tx.send("Makefile").unwrap();
        tx.send("src/hash/md5.rs").unwrap();
        tx.send("src/hash.rs").unwrap();
        tx.send("src/hash/sha1.rs").unwrap();
        tx.send("src/hash/md5.rs").unwrap();
        tx.send("Makefile").unwrap();
    }

    // use chksum::worker::x4;
    // let outputs = x4::process(rx);
    // println!("outputs\t{:?}", outputs);
    {
        use chksum::arch::x4;
        use chksum::hash::md5::{Hash as MD5, Padding};
        use chksum::worker;

        let (_, rx) = pathnames;
        let (tx, _) = outputs;
        let tx = tx.clone();
        let hash = MD5::<x4::Arch>::new();
        let padding = Padding::new();
        worker::process_x4(rx, tx, hash, padding);
    }

    let (_, rx) = outputs;
    for i in 0..5 {
        let output = rx.recv();
        // println!("{:?}", output);
        use chksum::worker;
        if let Ok((pathname, output)) = output {
            if let worker::Output::Digest(digest) = output {
                println!("{}\t{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}", pathname, digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7], digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14], digest[15]);
            }
        }
    }

    // for thread in threads {
    //     thread.join().unwrap();
    //   }
    // {
    //     let rx = rx.clone();
    //     use chksum::worker::worker_x1;
    //     worker_x1(rx);
    // }
    // {
    //     let rx = rx.clone();
    //     use chksum::worker::worker_x4;
    //     worker_x4(rx);
    // }
    // {
    //     let rx = rx.clone();
    //     use chksum::worker::worker_x4;
    //     worker_x4(rx);
    // }

    // use std::io::Read;
    // let mut x = "abc".as_bytes();
    // let mut y = "xyz".as_bytes();
    // let mut z = &mut x[..].chain(&y[..]);
    // let mut buf = [0u8; 8];
    // println!("z {:?}", z);
    // println!("z {:?} {:?}", z.read(&mut buf), buf);
    // println!("z {:?}", z);
    // println!("z {:?} {:?}", z.read(&mut buf), buf);
    // println!("z {:?}", z);
    // println!("z {:?} {:?}", z.read(&mut buf), buf);
}
