use std::convert::TryInto;

pub const DIGEST_BYTE_LENGTH: usize = 16;
const BUFFER_BYTE_LENGTH: usize = 64;
const DATA_BYTE_MAX_LENGTH: usize = 8;

#[inline(always)]
fn little_endian_word(buffer: &[u8; BUFFER_BYTE_LENGTH], i: usize) -> u32 {
    u32::from_le_bytes(buffer[(i * 4)..(i * 4 + 4)].try_into().unwrap())
}

#[inline(always)]
fn f(x: u32, y: u32, z: u32) -> u32 {
    ((y ^ z) & x) ^ z
}

#[inline(always)]
fn g(x: u32, y: u32, z: u32) -> u32 {
    ((x ^ y) & z) ^ y
}

#[inline(always)]
fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[inline(always)]
fn i(x: u32, y: u32, z: u32) -> u32 {
    (!z | x) ^ y
}

#[inline(always)]
fn round_00_16(x1: &mut u32, x2: u32, x3: u32, x4: u32, k: u32, s: u32, t: u32) {
    *x1 = x1.wrapping_add(k).wrapping_add(t).wrapping_add(f(x2, x3, x4));
    *x1 = x1.rotate_left(s);
    *x1 = x1.wrapping_add(x2);
}

#[inline(always)]
fn round_16_32(x1: &mut u32, x2: u32, x3: u32, x4: u32, k: u32, s: u32, t: u32) {
    *x1 = x1.wrapping_add(k).wrapping_add(t).wrapping_add(g(x2, x3, x4));
    *x1 = x1.rotate_left(s);
    *x1 = x1.wrapping_add(x2);
}

#[inline(always)]
fn round_32_48(x1: &mut u32, x2: u32, x3: u32, x4: u32, k: u32, s: u32, t: u32) {
    *x1 = x1.wrapping_add(k).wrapping_add(t).wrapping_add(h(x2, x3, x4));
    *x1 = x1.rotate_left(s);
    *x1 = x1.wrapping_add(x2);
}

#[inline(always)]
fn round_48_64(x1: &mut u32, x2: u32, x3: u32, x4: u32, k: u32, s: u32, t: u32) {
    *x1 = x1.wrapping_add(k).wrapping_add(t).wrapping_add(i(x2, x3, x4));
    *x1 = x1.rotate_left(s);
    *x1 = x1.wrapping_add(x2);
}

#[inline(always)]
fn fill_to_bytes(digest_bytes: &mut [u8; DIGEST_BYTE_LENGTH], x: u32, index: usize) {
    let word_bytes = x.to_le_bytes();
    digest_bytes[index * 4 + 0] = word_bytes[0];
    digest_bytes[index * 4 + 1] = word_bytes[1];
    digest_bytes[index * 4 + 2] = word_bytes[2];
    digest_bytes[index * 4 + 3] = word_bytes[3];
}

#[inline(always)]
fn put_data_length(buffer: &mut [u8; BUFFER_BYTE_LENGTH], length: u64) {
    let length_bytes = length.to_le_bytes();
    buffer[BUFFER_BYTE_LENGTH - 1] = length_bytes[7];
    buffer[BUFFER_BYTE_LENGTH - 2] = length_bytes[6];
    buffer[BUFFER_BYTE_LENGTH - 3] = length_bytes[5];
    buffer[BUFFER_BYTE_LENGTH - 4] = length_bytes[4];
    buffer[BUFFER_BYTE_LENGTH - 5] = length_bytes[3];
    buffer[BUFFER_BYTE_LENGTH - 6] = length_bytes[2];
    buffer[BUFFER_BYTE_LENGTH - 7] = length_bytes[1];
    buffer[BUFFER_BYTE_LENGTH - 8] = length_bytes[0];
}

pub struct MD5Digest {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    total_length: u64,
    remains_data: Vec<u8>,
}

impl MD5Digest {
    pub fn new() -> MD5Digest {
        let instance = MD5Digest {
            a: 0x67452301,
            b: 0xefcdab89,
            c: 0x98badcfe,
            d: 0x10325476,
            total_length: 0,
            remains_data: Vec::new()
        };
        instance
    }

    pub fn get_digest_bytes(&mut self) -> [u8; DIGEST_BYTE_LENGTH] {
        let mut digest_bytes = [0; DIGEST_BYTE_LENGTH];
        fill_to_bytes(&mut digest_bytes, self.a, 0);
        fill_to_bytes(&mut digest_bytes, self.b, 1);
        fill_to_bytes(&mut digest_bytes, self.c, 2);
        fill_to_bytes(&mut digest_bytes, self.d, 3);
        digest_bytes
    }

    pub fn compute_digest(&mut self) {
        let remains_data_length = self.remains_data.len();
        let min_padding_byte_length = remains_data_length + DATA_BYTE_MAX_LENGTH + 1;
        let mut buffer: [u8; BUFFER_BYTE_LENGTH] = [0; BUFFER_BYTE_LENGTH];
        for i in 0..self.remains_data.len() {
            buffer[i] = self.remains_data[i];
        }
        self.remains_data.clear();
        buffer[remains_data_length] = 0x80;
        if min_padding_byte_length > BUFFER_BYTE_LENGTH {
            self.update(&buffer);
            buffer.fill(0x00);
            put_data_length(&mut buffer, self.total_length);
            self.update(&buffer);
        } else {
            put_data_length(&mut buffer, self.total_length);
            self.update(&buffer);
        }
    }

    pub fn push_data(&mut self, data: &[u8]) {
        let data_length = (data.len() as u64) << 3;
        self.total_length += data_length;
        let remains_data_length = self.remains_data.len();
        let mut offset: usize = 0;
        if remains_data_length > 0 && remains_data_length + data.len() >= BUFFER_BYTE_LENGTH {
            offset = BUFFER_BYTE_LENGTH - remains_data_length;
            let mut buffer: [u8; BUFFER_BYTE_LENGTH] = [0; BUFFER_BYTE_LENGTH];
            for i in 0..self.remains_data.len() {
                buffer[i] = self.remains_data[i];
            }
            self.remains_data.clear();
            for i in remains_data_length..BUFFER_BYTE_LENGTH {
                buffer[i] = data[i - remains_data_length];
            }
            self.update(&buffer);
        }
        let buffer_count = (data.len() - offset) / BUFFER_BYTE_LENGTH;
        for i in 0..buffer_count  {
            self.update(data[(i * BUFFER_BYTE_LENGTH + offset)..(i * BUFFER_BYTE_LENGTH + offset + BUFFER_BYTE_LENGTH)].try_into().unwrap());
        }
        for i in (buffer_count * BUFFER_BYTE_LENGTH + offset)..data.len() {
            self.remains_data.push(data[i]);
        }
    }

    fn update(&mut self, buffer: &[u8; BUFFER_BYTE_LENGTH]) {
        let mut a = self.a;
        let mut b = self.b;
        let mut c = self.c;
        let mut d = self.d;
        let mut w00 = little_endian_word(buffer, 0);
        let mut w01 = little_endian_word(buffer, 1);
        let mut w02 = little_endian_word(buffer, 2);
        let mut w03 = little_endian_word(buffer, 3);
        let mut w04 = little_endian_word(buffer, 4);
        let mut w05 = little_endian_word(buffer, 5);
        let mut w06 = little_endian_word(buffer, 6);
        let mut w07 = little_endian_word(buffer, 7);
        let mut w08 = little_endian_word(buffer, 8);
        let mut w09 = little_endian_word(buffer, 9);
        let mut w10 = little_endian_word(buffer, 10);
        let mut w11 = little_endian_word(buffer, 11);
        let mut w12 = little_endian_word(buffer, 12);
        let mut w13 = little_endian_word(buffer, 13);
        let mut w14 = little_endian_word(buffer, 14);
        let mut w15 = little_endian_word(buffer, 15);
        round_00_16(&mut a, b, c, d, w00, 07, 0xd76aa478);
        round_00_16(&mut d, a, b, c, w01, 12, 0xe8c7b756);
        round_00_16(&mut c, d, a, b, w02, 17, 0x242070db);
        round_00_16(&mut b, c, d, a, w03, 22, 0xc1bdceee);
        round_00_16(&mut a, b, c, d, w04, 07, 0xf57c0faf);
        round_00_16(&mut d, a, b, c, w05, 12, 0x4787c62a);
        round_00_16(&mut c, d, a, b, w06, 17, 0xa8304613);
        round_00_16(&mut b, c, d, a, w07, 22, 0xfd469501);
        round_00_16(&mut a, b, c, d, w08, 07, 0x698098d8);
        round_00_16(&mut d, a, b, c, w09, 12, 0x8b44f7af);
        round_00_16(&mut c, d, a, b, w10, 17, 0xffff5bb1);
        round_00_16(&mut b, c, d, a, w11, 22, 0x895cd7be);
        round_00_16(&mut a, b, c, d, w12, 07, 0x6b901122);
        round_00_16(&mut d, a, b, c, w13, 12, 0xfd987193);
        round_00_16(&mut c, d, a, b, w14, 17, 0xa679438e);
        round_00_16(&mut b, c, d, a, w15, 22, 0x49b40821);
        round_16_32(&mut a, b, c, d, w01, 05, 0xf61e2562);
        round_16_32(&mut d, a, b, c, w06, 09, 0xc040b340);
        round_16_32(&mut c, d, a, b, w11, 14, 0x265e5a51);
        round_16_32(&mut b, c, d, a, w00, 20, 0xe9b6c7aa);
        round_16_32(&mut a, b, c, d, w05, 05, 0xd62f105d);
        round_16_32(&mut d, a, b, c, w10, 09, 0x02441453);
        round_16_32(&mut c, d, a, b, w15, 14, 0xd8a1e681);
        round_16_32(&mut b, c, d, a, w04, 20, 0xe7d3fbc8);
        round_16_32(&mut a, b, c, d, w09, 05, 0x21e1cde6);
        round_16_32(&mut d, a, b, c, w14, 09, 0xc33707d6);
        round_16_32(&mut c, d, a, b, w03, 14, 0xf4d50d87);
        round_16_32(&mut b, c, d, a, w08, 20, 0x455a14ed);
        round_16_32(&mut a, b, c, d, w13, 05, 0xa9e3e905);
        round_16_32(&mut d, a, b, c, w02, 09, 0xfcefa3f8);
        round_16_32(&mut c, d, a, b, w07, 14, 0x676f02d9);
        round_16_32(&mut b, c, d, a, w12, 20, 0x8d2a4c8a);
        round_32_48(&mut a, b, c, d, w05, 04, 0xfffa3942);
        round_32_48(&mut d, a, b, c, w08, 11, 0x8771f681);
        round_32_48(&mut c, d, a, b, w11, 16, 0x6d9d6122);
        round_32_48(&mut b, c, d, a, w14, 23, 0xfde5380c);
        round_32_48(&mut a, b, c, d, w01, 04, 0xa4beea44);
        round_32_48(&mut d, a, b, c, w04, 11, 0x4bdecfa9);
        round_32_48(&mut c, d, a, b, w07, 16, 0xf6bb4b60);
        round_32_48(&mut b, c, d, a, w10, 23, 0xbebfbc70);
        round_32_48(&mut a, b, c, d, w13, 04, 0x289b7ec6);
        round_32_48(&mut d, a, b, c, w00, 11, 0xeaa127fa);
        round_32_48(&mut c, d, a, b, w03, 16, 0xd4ef3085);
        round_32_48(&mut b, c, d, a, w06, 23, 0x04881d05);
        round_32_48(&mut a, b, c, d, w09, 04, 0xd9d4d039);
        round_32_48(&mut d, a, b, c, w12, 11, 0xe6db99e5);
        round_32_48(&mut c, d, a, b, w15, 16, 0x1fa27cf8);
        round_32_48(&mut b, c, d, a, w02, 23, 0xc4ac5665);
        round_48_64(&mut a, b, c, d, w00, 06, 0xf4292244);
        round_48_64(&mut d, a, b, c, w07, 10, 0x432aff97);
        round_48_64(&mut c, d, a, b, w14, 15, 0xab9423a7);
        round_48_64(&mut b, c, d, a, w05, 21, 0xfc93a039);
        round_48_64(&mut a, b, c, d, w12, 06, 0x655b59c3);
        round_48_64(&mut d, a, b, c, w03, 10, 0x8f0ccc92);
        round_48_64(&mut c, d, a, b, w10, 15, 0xffeff47d);
        round_48_64(&mut b, c, d, a, w01, 21, 0x85845dd1);
        round_48_64(&mut a, b, c, d, w08, 06, 0x6fa87e4f);
        round_48_64(&mut d, a, b, c, w15, 10, 0xfe2ce6e0);
        round_48_64(&mut c, d, a, b, w06, 15, 0xa3014314);
        round_48_64(&mut b, c, d, a, w13, 21, 0x4e0811a1);
        round_48_64(&mut a, b, c, d, w04, 06, 0xf7537e82);
        round_48_64(&mut d, a, b, c, w11, 10, 0xbd3af235);
        round_48_64(&mut c, d, a, b, w02, 15, 0x2ad7d2bb);
        round_48_64(&mut b, c, d, a, w09, 21, 0xeb86d391);
        self.a = self.a.wrapping_add(a);
        self.b = self.b.wrapping_add(b);
        self.c = self.c.wrapping_add(c);
        self.d = self.d.wrapping_add(d);
    }
}
