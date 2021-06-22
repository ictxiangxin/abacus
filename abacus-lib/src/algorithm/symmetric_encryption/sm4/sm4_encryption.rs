use std::convert::TryInto;
use std::intrinsics::exact_div;
use super::sm4_constant::{S_TABLE, S_LINEAR_TABLE, FK, CK};

fn edge_t(x: u32) -> u32 {
    let xx = x.to_be_bytes();
    let t = u32::from_be_bytes([S_TABLE[xx[0]], S_TABLE[xx[1]], S_TABLE[xx[2]], S_TABLE[xx[3]]]);
    t ^ t.rotate_left(2) ^ t.rotate_left(10) ^ t.rotate_left(18) ^ t.rotate_left(24)
}

fn main_t(x: u32) -> u32 {
    let xx = x.to_be_bytes();
    S_LINEAR_TABLE[xx[0]] ^ S_LINEAR_TABLE[xx[1]].rotate_left(24) ^ S_LINEAR_TABLE[xx[2]].rotate_left(16) ^ S_LINEAR_TABLE[xx[3]].rotate_left(8)
}

#[inline(always)]
fn big_endian_word(buffer: &[u8; 16], i: usize) -> u32 {
    u32::from_be_bytes(buffer[(i * 4)..(i * 4 + 4)].try_into().unwrap())
}

#[inline(always)]
fn big_endian_bytes(w: u32, bytes: &mut [u8; 16], index: usize) {
    let ww = w.to_be_bytes();
    bytes[index * 4 + 0] = ww[0];
    bytes[index * 4 + 1] = ww[1];
    bytes[index * 4 + 2] = ww[2];
    bytes[index * 4 + 3] = ww[3];
}

#[inline(always)]
fn round_edge(x1: &mut u32, x2: &mut u32, x3: &mut u32, x4: &mut u32, k1: u32, k2: u32, k3: u32, k4: u32) {
    *x1 ^= edge_t(x2 ^ x3 ^ x4 ^ k1);
    *x2 ^= edge_t(x1 ^ x3 ^ x4 ^ k2);
    *x3 ^= edge_t(x1 ^ x2 ^ x4 ^ k3);
    *x4 ^= edge_t(x1 ^ x2 ^ x3 ^ k4);
}

fn round_main(x1: &mut u32, x2: &mut u32, x3: &mut u32, x4: &mut u32, k1: u32, k2: u32, k3: u32, k4: u32) {
    *x1 ^= main_t(x2 ^ x3 ^ x4 ^ k1);
    *x2 ^= main_t(x1 ^ x3 ^ x4 ^ k2);
    *x3 ^= main_t(x1 ^ x2 ^ x4 ^ k3);
    *x4 ^= main_t(x1 ^ x2 ^ x3 ^ k4);
}

pub struct SM4Encryption {

}

impl SM4Encryption {
    pub fn new() -> SM4Encryption {
        let instance = SM4Encryption {};
        instance
    }

    fn generate_sub_key(key: &[u8; 16]) -> [u32; 32] {
        let mut k : [u32; 4] = [0; 4];
        let mut sub_key: [u32; 32] = [0; 32];
        k[0] = big_endian_word(key, 0) ^ FK[0];
        k[1] = big_endian_word(key, 1) ^ FK[1];
        k[2] = big_endian_word(key, 2) ^ FK[2];
        k[3] = big_endian_word(key, 3) ^ FK[3];
        for i in 0..32 {
            let x = k[(i + 1) % 4] ^ k[(i + 2) % 4] ^ k[(i + 3) % 4] ^ CK[i];
            let xx = x.to_be_bytes();
            let t = u32::from_be_bytes([S_TABLE[xx[0]], S_TABLE[xx[1]], S_TABLE[xx[2]], S_TABLE[xx[3]]]);
            k[i % 4] ^= t ^ t.rotate_left(13) ^ t.rotate_left(23);
            sub_key[i] = k[i % 4];
        }
        sub_key
    }

    fn encrypt(data: &[u8; 16], sub_keys: [u32; 32]) -> [u8; 16] {
        let mut w0 = big_endian_word(data, 0);
        let mut w1 = big_endian_word(data, 1);
        let mut w2 = big_endian_word(data, 2);
        let mut w3 = big_endian_word(data, 3);
        round_edge(&mut w0, &mut w1, &mut w2, &mut w3, sub_keys[00], sub_keys[01], sub_keys[02], sub_keys[03]);
        round_main(&mut w0, &mut w1, &mut w2, &mut w3, sub_keys[04], sub_keys[05], sub_keys[06], sub_keys[07]);
        round_main(&mut w0, &mut w1, &mut w2, &mut w3, sub_keys[08], sub_keys[09], sub_keys[10], sub_keys[11]);
        round_main(&mut w0, &mut w1, &mut w2, &mut w3, sub_keys[12], sub_keys[13], sub_keys[14], sub_keys[15]);
        round_main(&mut w0, &mut w1, &mut w2, &mut w3, sub_keys[16], sub_keys[17], sub_keys[18], sub_keys[19]);
        round_main(&mut w0, &mut w1, &mut w2, &mut w3, sub_keys[20], sub_keys[21], sub_keys[22], sub_keys[23]);
        round_main(&mut w0, &mut w1, &mut w2, &mut w3, sub_keys[24], sub_keys[25], sub_keys[26], sub_keys[27]);
        round_edge(&mut w0, &mut w1, &mut w2, &mut w3, sub_keys[28], sub_keys[29], sub_keys[30], sub_keys[31]);
        let mut result: [u8; 16] = [0; 16];
        big_endian_bytes(w0, &mut result, 0);
        big_endian_bytes(w1, &mut result, 1);
        big_endian_bytes(w2, &mut result, 2);
        big_endian_bytes(w3, &mut result, 3);
        result
    }

    fn decrypt(data: &[u8; 16], sub_keys: [u32; 32]) -> [u8; 16] {
        let mut w0 = big_endian_word(data, 0);
        let mut w1 = big_endian_word(data, 1);
        let mut w2 = big_endian_word(data, 2);
        let mut w3 = big_endian_word(data, 3);
        round_edge(&mut w0, &mut w1, &mut w2, &mut w3, sub_keys[31], sub_keys[30], sub_keys[29], sub_keys[28]);
        round_main(&mut w0, &mut w1, &mut w2, &mut w3, sub_keys[27], sub_keys[26], sub_keys[25], sub_keys[24]);
        round_main(&mut w0, &mut w1, &mut w2, &mut w3, sub_keys[23], sub_keys[22], sub_keys[21], sub_keys[20]);
        round_main(&mut w0, &mut w1, &mut w2, &mut w3, sub_keys[19], sub_keys[18], sub_keys[17], sub_keys[16]);
        round_main(&mut w0, &mut w1, &mut w2, &mut w3, sub_keys[15], sub_keys[14], sub_keys[13], sub_keys[12]);
        round_main(&mut w0, &mut w1, &mut w2, &mut w3, sub_keys[11], sub_keys[10], sub_keys[09], sub_keys[08]);
        round_main(&mut w0, &mut w1, &mut w2, &mut w3, sub_keys[07], sub_keys[06], sub_keys[05], sub_keys[04]);
        round_edge(&mut w0, &mut w1, &mut w2, &mut w3, sub_keys[03], sub_keys[02], sub_keys[01], sub_keys[00]);
        let mut result: [u8; 16] = [0; 16];
        big_endian_bytes(w0, &mut result, 0);
        big_endian_bytes(w1, &mut result, 1);
        big_endian_bytes(w2, &mut result, 2);
        big_endian_bytes(w3, &mut result, 3);
        result
    }
}
