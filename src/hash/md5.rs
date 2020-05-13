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

impl self::Context {
    #[inline]
    fn process_block(&mut self, block: [u32; 16]) {
        let (mut a, mut b, mut c, mut d) = (self.a, self.b, self.c, self.d);

        // round 1

        #[inline]
        fn f(x: u32, y: u32, z: u32) -> u32 {
            (x & y) | (!x & z)
        }

        #[inline]
        fn step_f(a: u32, b: u32, c: u32, d: u32, data: u32, rotation: u32, constant: u32) -> u32 {
            let a = Wrapping(a) + Wrapping(f(b, c, d)) + Wrapping(data) + Wrapping(constant);
            let a = a.0.rotate_left(rotation);
            let a = Wrapping(a) + Wrapping(b);
            a.0
        }

        a = step_f(a, b, c, d, block[ 0],  7, 0xd76aa478);
        d = step_f(d, a, b, c, block[ 1], 12, 0xe8c7b756);
        c = step_f(c, d, a, b, block[ 2], 17, 0x242070db);
        b = step_f(b, c, d, a, block[ 3], 22, 0xc1bdceee);
        a = step_f(a, b, c, d, block[ 4],  7, 0xf57c0faf);
        d = step_f(d, a, b, c, block[ 5], 12, 0x4787c62a);
        c = step_f(c, d, a, b, block[ 6], 17, 0xa8304613);
        b = step_f(b, c, d, a, block[ 7], 22, 0xfd469501);
        a = step_f(a, b, c, d, block[ 8],  7, 0x698098d8);
        d = step_f(d, a, b, c, block[ 9], 12, 0x8b44f7af);
        c = step_f(c, d, a, b, block[10], 17, 0xffff5bb1);
        b = step_f(b, c, d, a, block[11], 22, 0x895cd7be);
        a = step_f(a, b, c, d, block[12],  7, 0x6b901122);
        d = step_f(d, a, b, c, block[13], 12, 0xfd987193);
        c = step_f(c, d, a, b, block[14], 17, 0xa679438e);
        b = step_f(b, c, d, a, block[15], 22, 0x49b40821);

        // round 2

        #[inline]
        fn g(x: u32, y: u32, z: u32) -> u32 {
            (x & z) | (y & !z)
        }

        #[inline]
        fn step_g(a: u32, b: u32, c: u32, d: u32, data: u32, rotation: u32, constant: u32) -> u32 {
            let a = Wrapping(a) + Wrapping(g(b, c, d)) + Wrapping(data) + Wrapping(constant);
            let a = a.0.rotate_left(rotation);
            let a = Wrapping(a) + Wrapping(b);
            a.0
        }

        a = step_g(a, b, c, d, block[ 1],  5, 0xf61e2562);
        d = step_g(d, a, b, c, block[ 6],  9, 0xc040b340);
        c = step_g(c, d, a, b, block[11], 14, 0x265e5a51);
        b = step_g(b, c, d, a, block[ 0], 20, 0xe9b6c7aa);
        a = step_g(a, b, c, d, block[ 5],  5, 0xd62f105d);
        d = step_g(d, a, b, c, block[10],  9, 0x02441453);
        c = step_g(c, d, a, b, block[15], 14, 0xd8a1e681);
        b = step_g(b, c, d, a, block[ 4], 20, 0xe7d3fbc8);
        a = step_g(a, b, c, d, block[ 9],  5, 0x21e1cde6);
        d = step_g(d, a, b, c, block[14],  9, 0xc33707d6);
        c = step_g(c, d, a, b, block[ 3], 14, 0xf4d50d87);
        b = step_g(b, c, d, a, block[ 8], 20, 0x455a14ed);
        a = step_g(a, b, c, d, block[13],  5, 0xa9e3e905);
        d = step_g(d, a, b, c, block[ 2],  9, 0xfcefa3f8);
        c = step_g(c, d, a, b, block[ 7], 14, 0x676f02d9);
        b = step_g(b, c, d, a, block[12], 20, 0x8d2a4c8a);

        // round 3

        #[inline]
        fn h(x: u32, y: u32, z: u32) -> u32 {
            x ^ y ^ z
        }

        #[inline]
        fn step_h(a: u32, b: u32, c: u32, d: u32, data: u32, rotation: u32, constant: u32) -> u32 {
            let a = Wrapping(a) + Wrapping(h(b, c, d)) + Wrapping(data) + Wrapping(constant);
            let a = a.0.rotate_left(rotation);
            let a = Wrapping(a) + Wrapping(b);
            a.0
        }

        a = step_h(a, b, c, d, block[ 5],  4, 0xfffa3942);
        d = step_h(d, a, b, c, block[ 8], 11, 0x8771f681);
        c = step_h(c, d, a, b, block[11], 16, 0x6d9d6122);
        b = step_h(b, c, d, a, block[14], 23, 0xfde5380c);
        a = step_h(a, b, c, d, block[ 1],  4, 0xa4beea44);
        d = step_h(d, a, b, c, block[ 4], 11, 0x4bdecfa9);
        c = step_h(c, d, a, b, block[ 7], 16, 0xf6bb4b60);
        b = step_h(b, c, d, a, block[10], 23, 0xbebfbc70);
        a = step_h(a, b, c, d, block[13],  4, 0x289b7ec6);
        d = step_h(d, a, b, c, block[ 0], 11, 0xeaa127fa);
        c = step_h(c, d, a, b, block[ 3], 16, 0xd4ef3085);
        b = step_h(b, c, d, a, block[ 6], 23, 0x04881d05);
        a = step_h(a, b, c, d, block[ 9],  4, 0xd9d4d039);
        d = step_h(d, a, b, c, block[12], 11, 0xe6db99e5);
        c = step_h(c, d, a, b, block[15], 16, 0x1fa27cf8);
        b = step_h(b, c, d, a, block[ 2], 23, 0xc4ac5665);

        // round 4

        #[inline]
        fn i(x: u32, y: u32, z: u32) -> u32 {
            y ^ (x | !z)
        }

        #[inline]
        fn step_i(a: u32, b: u32, c: u32, d: u32, data: u32, rotation: u32, constant: u32) -> u32 {
            let a = Wrapping(a) + Wrapping(i(b, c, d)) + Wrapping(data) + Wrapping(constant);
            let a = a.0.rotate_left(rotation);
            let a = Wrapping(a) + Wrapping(b);
            a.0
        }

        a = step_i(a, b, c, d, block[ 0],  6, 0xf4292244);
        d = step_i(d, a, b, c, block[ 7], 10, 0x432aff97);
        c = step_i(c, d, a, b, block[14], 15, 0xab9423a7);
        b = step_i(b, c, d, a, block[ 5], 21, 0xfc93a039);
        a = step_i(a, b, c, d, block[12],  6, 0x655b59c3);
        d = step_i(d, a, b, c, block[ 3], 10, 0x8f0ccc92);
        c = step_i(c, d, a, b, block[10], 15, 0xffeff47d);
        b = step_i(b, c, d, a, block[ 1], 21, 0x85845dd1);
        a = step_i(a, b, c, d, block[ 8],  6, 0x6fa87e4f);
        d = step_i(d, a, b, c, block[15], 10, 0xfe2ce6e0);
        c = step_i(c, d, a, b, block[ 6], 15, 0xa3014314);
        b = step_i(b, c, d, a, block[13], 21, 0x4e0811a1);
        a = step_i(a, b, c, d, block[ 4],  6, 0xf7537e82);
        d = step_i(d, a, b, c, block[11], 10, 0xbd3af235);
        c = step_i(c, d, a, b, block[ 2], 15, 0x2ad7d2bb);
        b = step_i(b, c, d, a, block[ 9], 21, 0xeb86d391);

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

    #[inline]
    fn prepare_block(&self, data: Vec<u8>) -> [u32; 16] {
        // if data.len() != self.block_size() {
        //     panic!
        // }

        let mut block = [0u32; 16];
        for i in 0..16 {
            let j = i * 4;
            block[i] = u32::from_le_bytes([
                data[j + 0],
                data[j + 1],
                data[j + 2],
                data[j + 3],
            ]);
        }
        block
    }
}

impl super::Context for self::Context {
    #[inline]
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
        let mut padding = vec![0x80u8];
        if zeros > 0 {
            let zeros = vec![0u8; zeros];
            padding.extend(zeros);
        }
        let length = self.length + self.block.len();
        let length = length as u64;
        let length = length * 8; // bytes to binary count
        let length = length.to_le_bytes()
                           .to_vec();
        padding.extend(length);
        self.update(padding);
    }

    fn digest(&self) -> Vec<u8> {
        let mut context = self.clone();
        context.finalize();

        let a = context.a
                       .to_le_bytes()
                       .to_vec();

        let b = context.b
                       .to_le_bytes()
                       .to_vec();

        let c = context.c
                       .to_le_bytes()
                       .to_vec();

        let d = context.d
                       .to_le_bytes()
                       .to_vec();

        let mut digest = Vec::<u8>::new();
        digest.extend(a);
        digest.extend(b);
        digest.extend(c);
        digest.extend(d);
        digest
    }
}

#[cfg(test)]
mod tests {
    use super::super::Context;

    #[test]
    fn empty() {
        let context = super::new();
        assert_eq!(vec![0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e], context.digest());
    }

    #[test]
    fn hello_world() {
        let mut context = super::new();
        let text = "Hello World";
        let text = text.as_bytes()
                       .to_vec();
        context.update(text);
        assert_eq!(vec![0xb1, 0x0a, 0x8d, 0xb1, 0x64, 0xe0, 0x75, 0x41, 0x05, 0xb7, 0xa9, 0x9b, 0xe7, 0x2e, 0x3f, 0xe5], context.digest());
    }

    #[test]
    fn hello_world_by_parts() {
        let mut context = super::new();
        let text = "Hello";
        let text = text.as_bytes()
                       .to_vec();
        context.update(text);
        let text = " ";
        let text = text.as_bytes()
                       .to_vec();
        context.update(text);
        let text = "World";
        let text = text.as_bytes()
                       .to_vec();
        context.update(text);
        assert_eq!(vec![0xb1, 0x0a, 0x8d, 0xb1, 0x64, 0xe0, 0x75, 0x41, 0x05, 0xb7, 0xa9, 0x9b, 0xe7, 0x2e, 0x3f, 0xe5], context.digest());
    }

    #[test]
    fn lorem_ipsum() {
        let mut context = super::new();
        let text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus eget imperdiet libero. Quisque pulvinar lacinia turpis ac luctus. Suspendisse ut dui vehicula libero porttitor consectetur a quis felis. Praesent finibus efficitur justo a iaculis. Suspendisse rutrum sem sit amet lacus consequat ultrices. Duis blandit congue iaculis. Quisque eget quam enim. Cras tempor justo neque, dictum cursus mi facilisis nec. Donec tincidunt, felis non eleifend condimentum, mi tellus scelerisque nulla, vitae sagittis arcu libero vitae purus. Pellentesque pretium sem eu varius accumsan. Nullam vestibulum lacinia nisi, ac consequat erat volutpat et. Pellentesque eu imperdiet lorem. Vestibulum placerat condimentum sapien, a eleifend libero rutrum a. Cras eros tellus, consectetur vel ante et, pretium lacinia tortor. Quisque hendrerit orci neque, sed faucibus quam interdum quis.";
        let text = text.as_bytes()
                       .to_vec();
        context.update(text);
        assert_eq!(vec![0xb1, 0x32, 0xf2, 0x8a, 0xf8, 0x82, 0xb0, 0x65, 0x6a, 0x1f, 0x30, 0x97, 0xa1, 0x75, 0xeb, 0x72], context.digest());
    }
}
