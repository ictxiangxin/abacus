use std::convert::TryInto;
use super::sha2_256_type::SHA2_256Type;

pub const DIGEST_BYTE_LENGTH: usize = 32;
const BUFFER_BYTE_LENGTH: usize = 64;
const DATA_BYTE_MAX_LENGTH: usize = 8;

#[inline(always)]
fn sigma00(x: u32) -> u32 {
    x.rotate_left(30) ^ x.rotate_left(19) ^ x.rotate_left(10)
}

#[inline(always)]
fn sigma01(x: u32) -> u32 {
    x.rotate_left(26) ^ x.rotate_left(21) ^ x.rotate_left(7)
}

#[inline(always)]
fn sigma10(x: u32) -> u32 {
    x.rotate_left(25) ^ x.rotate_left(14) ^ (x >> 3)
}

#[inline(always)]
fn sigma11(x: u32) -> u32 {
    x.rotate_left(15) ^ x.rotate_left(13) ^ (x >> 10)
}

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    z ^ (x & (y ^ z))
}

#[inline(always)]
fn ma(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
fn expand(a: u32, b: u32, c: u32, d: u32) -> u32 {
    a.wrapping_add(sigma10(b)).wrapping_add(sigma11(c)).wrapping_add(d)
}

#[inline(always)]
fn big_endian_word(buffer: &[u8; BUFFER_BYTE_LENGTH], i: usize) -> u32 {
    u32::from_be_bytes(buffer[(i * 4)..(i * 4 + 4)].try_into().unwrap())
}

#[inline(always)]
fn round_00_64(x1: u32, x2: u32, x3: u32, x4: &mut u32, x5: u32, x6: u32, x7: u32, x8: &mut u32, t: u32, k: u32) {
    let tt = t.wrapping_add(*x8).wrapping_add(sigma01(x5)).wrapping_add(ch(x5, x6, x7)).wrapping_add(k);
    *x8 = sigma00(x1).wrapping_add(ma(x1, x2, x3)).wrapping_add(tt);
    *x4 = x4.wrapping_add(tt);
}

#[inline(always)]
fn fill_to_bytes(digest_bytes: &mut [u8; DIGEST_BYTE_LENGTH], x: u32, index: usize) {
    let word_bytes = x.to_be_bytes();
    digest_bytes[index * 4 + 0] = word_bytes[0];
    digest_bytes[index * 4 + 1] = word_bytes[1];
    digest_bytes[index * 4 + 2] = word_bytes[2];
    digest_bytes[index * 4 + 3] = word_bytes[3];
}

#[inline(always)]
fn put_data_length(buffer: &mut [u8; BUFFER_BYTE_LENGTH], length: u64) {
    let length_bytes = length.to_be_bytes();
    buffer[BUFFER_BYTE_LENGTH - 1] = length_bytes[7];
    buffer[BUFFER_BYTE_LENGTH - 2] = length_bytes[6];
    buffer[BUFFER_BYTE_LENGTH - 3] = length_bytes[5];
    buffer[BUFFER_BYTE_LENGTH - 4] = length_bytes[4];
    buffer[BUFFER_BYTE_LENGTH - 5] = length_bytes[3];
    buffer[BUFFER_BYTE_LENGTH - 6] = length_bytes[2];
    buffer[BUFFER_BYTE_LENGTH - 7] = length_bytes[1];
    buffer[BUFFER_BYTE_LENGTH - 8] = length_bytes[0];
}

pub struct SHA2_256Digest {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,
    f: u32,
    g: u32,
    h: u32,
    total_length: u64,
    remains_data: Vec<u8>,
}

impl SHA2_256Digest {
    pub fn new(sha256_type: SHA2_256Type) -> SHA2_256Digest {
        let init_value = sha256_type.init_value();
        let instance = SHA2_256Digest {
            a: init_value[0],
            b: init_value[1],
            c: init_value[2],
            d: init_value[3],
            e: init_value[4],
            f: init_value[5],
            g: init_value[6],
            h: init_value[7],
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
        fill_to_bytes(&mut digest_bytes, self.e, 4);
        fill_to_bytes(&mut digest_bytes, self.f, 5);
        fill_to_bytes(&mut digest_bytes, self.g, 6);
        fill_to_bytes(&mut digest_bytes, self.h, 7);
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
        let mut e = self.e;
        let mut f = self.f;
        let mut g = self.g;
        let mut h = self.h;
        let mut w00 = big_endian_word(buffer, 0);
        let mut w01 = big_endian_word(buffer, 1);
        let mut w02 = big_endian_word(buffer, 2);
        let mut w03 = big_endian_word(buffer, 3);
        let mut w04 = big_endian_word(buffer, 4);
        let mut w05 = big_endian_word(buffer, 5);
        let mut w06 = big_endian_word(buffer, 6);
        let mut w07 = big_endian_word(buffer, 7);
        let mut w08 = big_endian_word(buffer, 8);
        let mut w09 = big_endian_word(buffer, 9);
        let mut w10 = big_endian_word(buffer, 10);
        let mut w11 = big_endian_word(buffer, 11);
        let mut w12 = big_endian_word(buffer, 12);
        let mut w13 = big_endian_word(buffer, 13);
        let mut w14 = big_endian_word(buffer, 14);
        let mut w15 = big_endian_word(buffer, 15);
        round_00_64(a, b, c, &mut d, e, f, g, &mut h, w00, 0x428a2f98);
        round_00_64(h, a, b, &mut c, d, e, f, &mut g, w01, 0x71374491);
        round_00_64(g, h, a, &mut b, c, d, e, &mut f, w02, 0xb5c0fbcf);
        round_00_64(f, g, h, &mut a, b, c, d, &mut e, w03, 0xe9b5dba5);
        round_00_64(e, f, g, &mut h, a, b, c, &mut d, w04, 0x3956c25b);
        round_00_64(d, e, f, &mut g, h, a, b, &mut c, w05, 0x59f111f1);
        round_00_64(c, d, e, &mut f, g, h, a, &mut b, w06, 0x923f82a4);
        round_00_64(b, c, d, &mut e, f, g, h, &mut a, w07, 0xab1c5ed5);
        round_00_64(a, b, c, &mut d, e, f, g, &mut h, w08, 0xd807aa98);
        round_00_64(h, a, b, &mut c, d, e, f, &mut g, w09, 0x12835b01);
        round_00_64(g, h, a, &mut b, c, d, e, &mut f, w10, 0x243185be);
        round_00_64(f, g, h, &mut a, b, c, d, &mut e, w11, 0x550c7dc3);
        round_00_64(e, f, g, &mut h, a, b, c, &mut d, w12, 0x72be5d74);
        round_00_64(d, e, f, &mut g, h, a, b, &mut c, w13, 0x80deb1fe);
        round_00_64(c, d, e, &mut f, g, h, a, &mut b, w14, 0x9bdc06a7);
        round_00_64(b, c, d, &mut e, f, g, h, &mut a, w15, 0xc19bf174);
        w00 = expand(w00, w01, w14, w09);
        round_00_64(a, b, c, &mut d, e, f, g, &mut h, w00, 0xe49b69c1);
        w01 = expand(w01, w02, w15, w10);
        round_00_64(h, a, b, &mut c, d, e, f, &mut g, w01, 0xefbe4786);
        w02 = expand(w02, w03, w00, w11);
        round_00_64(g, h, a, &mut b, c, d, e, &mut f, w02, 0x0fc19dc6);
        w03 = expand(w03, w04, w01, w12);
        round_00_64(f, g, h, &mut a, b, c, d, &mut e, w03, 0x240ca1cc);
        w04 = expand(w04, w05, w02, w13);
        round_00_64(e, f, g, &mut h, a, b, c, &mut d, w04, 0x2de92c6f);
        w05 = expand(w05, w06, w03, w14);
        round_00_64(d, e, f, &mut g, h, a, b, &mut c, w05, 0x4a7484aa);
        w06 = expand(w06, w07, w04, w15);
        round_00_64(c, d, e, &mut f, g, h, a, &mut b, w06, 0x5cb0a9dc);
        w07 = expand(w07, w08, w05, w00);
        round_00_64(b, c, d, &mut e, f, g, h, &mut a, w07, 0x76f988da);
        w08 = expand(w08, w09, w06, w01);
        round_00_64(a, b, c, &mut d, e, f, g, &mut h, w08, 0x983e5152);
        w09 = expand(w09, w10, w07, w02);
        round_00_64(h, a, b, &mut c, d, e, f, &mut g, w09, 0xa831c66d);
        w10 = expand(w10, w11, w08, w03);
        round_00_64(g, h, a, &mut b, c, d, e, &mut f, w10, 0xb00327c8);
        w11 = expand(w11, w12, w09, w04);
        round_00_64(f, g, h, &mut a, b, c, d, &mut e, w11, 0xbf597fc7);
        w12 = expand(w12, w13, w10, w05);
        round_00_64(e, f, g, &mut h, a, b, c, &mut d, w12, 0xc6e00bf3);
        w13 = expand(w13, w14, w11, w06);
        round_00_64(d, e, f, &mut g, h, a, b, &mut c, w13, 0xd5a79147);
        w14 = expand(w14, w15, w12, w07);
        round_00_64(c, d, e, &mut f, g, h, a, &mut b, w14, 0x06ca6351);
        w15 = expand(w15, w00, w13, w08);
        round_00_64(b, c, d, &mut e, f, g, h, &mut a, w15, 0x14292967);
        w00 = expand(w00, w01, w14, w09);
        round_00_64(a, b, c, &mut d, e, f, g, &mut h, w00, 0x27b70a85);
        w01 = expand(w01, w02, w15, w10);
        round_00_64(h, a, b, &mut c, d, e, f, &mut g, w01, 0x2e1b2138);
        w02 = expand(w02, w03, w00, w11);
        round_00_64(g, h, a, &mut b, c, d, e, &mut f, w02, 0x4d2c6dfc);
        w03 = expand(w03, w04, w01, w12);
        round_00_64(f, g, h, &mut a, b, c, d, &mut e, w03, 0x53380d13);
        w04 = expand(w04, w05, w02, w13);
        round_00_64(e, f, g, &mut h, a, b, c, &mut d, w04, 0x650a7354);
        w05 = expand(w05, w06, w03, w14);
        round_00_64(d, e, f, &mut g, h, a, b, &mut c, w05, 0x766a0abb);
        w06 = expand(w06, w07, w04, w15);
        round_00_64(c, d, e, &mut f, g, h, a, &mut b, w06, 0x81c2c92e);
        w07 = expand(w07, w08, w05, w00);
        round_00_64(b, c, d, &mut e, f, g, h, &mut a, w07, 0x92722c85);
        w08 = expand(w08, w09, w06, w01);
        round_00_64(a, b, c, &mut d, e, f, g, &mut h, w08, 0xa2bfe8a1);
        w09 = expand(w09, w10, w07, w02);
        round_00_64(h, a, b, &mut c, d, e, f, &mut g, w09, 0xa81a664b);
        w10 = expand(w10, w11, w08, w03);
        round_00_64(g, h, a, &mut b, c, d, e, &mut f, w10, 0xc24b8b70);
        w11 = expand(w11, w12, w09, w04);
        round_00_64(f, g, h, &mut a, b, c, d, &mut e, w11, 0xc76c51a3);
        w12 = expand(w12, w13, w10, w05);
        round_00_64(e, f, g, &mut h, a, b, c, &mut d, w12, 0xd192e819);
        w13 = expand(w13, w14, w11, w06);
        round_00_64(d, e, f, &mut g, h, a, b, &mut c, w13, 0xd6990624);
        w14 = expand(w14, w15, w12, w07);
        round_00_64(c, d, e, &mut f, g, h, a, &mut b, w14, 0xf40e3585);
        w15 = expand(w15, w00, w13, w08);
        round_00_64(b, c, d, &mut e, f, g, h, &mut a, w15, 0x106aa070);
        w00 = expand(w00, w01, w14, w09);
        round_00_64(a, b, c, &mut d, e, f, g, &mut h, w00, 0x19a4c116);
        w01 = expand(w01, w02, w15, w10);
        round_00_64(h, a, b, &mut c, d, e, f, &mut g, w01, 0x1e376c08);
        w02 = expand(w02, w03, w00, w11);
        round_00_64(g, h, a, &mut b, c, d, e, &mut f, w02, 0x2748774c);
        w03 = expand(w03, w04, w01, w12);
        round_00_64(f, g, h, &mut a, b, c, d, &mut e, w03, 0x34b0bcb5);
        w04 = expand(w04, w05, w02, w13);
        round_00_64(e, f, g, &mut h, a, b, c, &mut d, w04, 0x391c0cb3);
        w05 = expand(w05, w06, w03, w14);
        round_00_64(d, e, f, &mut g, h, a, b, &mut c, w05, 0x4ed8aa4a);
        w06 = expand(w06, w07, w04, w15);
        round_00_64(c, d, e, &mut f, g, h, a, &mut b, w06, 0x5b9cca4f);
        w07 = expand(w07, w08, w05, w00);
        round_00_64(b, c, d, &mut e, f, g, h, &mut a, w07, 0x682e6ff3);
        w08 = expand(w08, w09, w06, w01);
        round_00_64(a, b, c, &mut d, e, f, g, &mut h, w08, 0x748f82ee);
        w09 = expand(w09, w10, w07, w02);
        round_00_64(h, a, b, &mut c, d, e, f, &mut g, w09, 0x78a5636f);
        w10 = expand(w10, w11, w08, w03);
        round_00_64(g, h, a, &mut b, c, d, e, &mut f, w10, 0x84c87814);
        w11 = expand(w11, w12, w09, w04);
        round_00_64(f, g, h, &mut a, b, c, d, &mut e, w11, 0x8cc70208);
        w12 = expand(w12, w13, w10, w05);
        round_00_64(e, f, g, &mut h, a, b, c, &mut d, w12, 0x90befffa);
        w13 = expand(w13, w14, w11, w06);
        round_00_64(d, e, f, &mut g, h, a, b, &mut c, w13, 0xa4506ceb);
        w14 = expand(w14, w15, w12, w07);
        round_00_64(c, d, e, &mut f, g, h, a, &mut b, w14, 0xbef9a3f7);
        w15 = expand(w15, w00, w13, w08);
        round_00_64(b, c, d, &mut e, f, g, h, &mut a, w15, 0xc67178f2);
        self.a = self.a.wrapping_add(a);
        self.b = self.b.wrapping_add(b);
        self.c = self.c.wrapping_add(c);
        self.d = self.d.wrapping_add(d);
        self.e = self.e.wrapping_add(e);
        self.f = self.f.wrapping_add(f);
        self.g = self.g.wrapping_add(g);
        self.h = self.h.wrapping_add(h);
    }
}
