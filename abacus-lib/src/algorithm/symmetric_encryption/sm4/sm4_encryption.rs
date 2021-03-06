use super::sm4_constant::{KEY_BYTE_LENGTH, SM4_KEY_BYTE_LENGTH, SM4_BLOCK_BYTE_LENGTH, SM4_S, SM4_S_BOX_T0, SM4_S_BOX_T1, SM4_S_BOX_T2, SM4_S_BOX_T3, FK, CK};

#[inline(always)]
fn edge_t(x: u32) -> u32 {
    let xx = x.to_be_bytes();
    let t = u32::from_be_bytes([SM4_S[xx[0] as usize], SM4_S[xx[1] as usize], SM4_S[xx[2] as usize], SM4_S[xx[3] as usize]]);
    t ^ t.rotate_left(2) ^ t.rotate_left(10) ^ t.rotate_left(18) ^ t.rotate_left(24)
}

#[inline(always)]
fn main_t(x: u32) -> u32 {
    let xx = x.to_be_bytes();
    SM4_S_BOX_T0[xx[0] as usize] ^ SM4_S_BOX_T1[xx[1] as usize] ^ SM4_S_BOX_T2[xx[2] as usize] ^ SM4_S_BOX_T3[xx[3] as usize]
}

#[inline(always)]
fn big_endian_word(buffer: &[u8; SM4_BLOCK_BYTE_LENGTH], i: usize) -> u32 {
    u32::from_be_bytes(buffer[(i * 4)..(i * 4 + 4)].try_into().unwrap())
}

#[inline(always)]
fn big_endian_bytes(w: u32, bytes: &mut [u8; SM4_BLOCK_BYTE_LENGTH], index: usize) {
    let ww = w.to_be_bytes();
    bytes[index * 4 + 0] = ww[0];
    bytes[index * 4 + 1] = ww[1];
    bytes[index * 4 + 2] = ww[2];
    bytes[index * 4 + 3] = ww[3];
}

#[inline(always)]
fn round_edge(x1: &mut u32, x2: &mut u32, x3: &mut u32, x4: &mut u32, k1: u32, k2: u32, k3: u32, k4: u32) {
    *x1 ^= edge_t(*x2 ^ *x3 ^ *x4 ^ k1);
    *x2 ^= edge_t(*x1 ^ *x3 ^ *x4 ^ k2);
    *x3 ^= edge_t(*x1 ^ *x2 ^ *x4 ^ k3);
    *x4 ^= edge_t(*x1 ^ *x2 ^ *x3 ^ k4);
}

#[inline(always)]
fn round_main(x1: &mut u32, x2: &mut u32, x3: &mut u32, x4: &mut u32, k1: u32, k2: u32, k3: u32, k4: u32) {
    *x1 ^= main_t(*x2 ^ *x3 ^ *x4 ^ k1);
    *x2 ^= main_t(*x1 ^ *x3 ^ *x4 ^ k2);
    *x3 ^= main_t(*x1 ^ *x2 ^ *x4 ^ k3);
    *x4 ^= main_t(*x1 ^ *x2 ^ *x3 ^ k4);
}

pub struct SM4Encryption {
    key: [u8; KEY_BYTE_LENGTH],
    sm4_key: [u32; SM4_KEY_BYTE_LENGTH],
}

impl SM4Encryption {
    pub fn new() -> SM4Encryption {
        let instance = SM4Encryption {
            key: [0; KEY_BYTE_LENGTH],
            sm4_key: [0; SM4_KEY_BYTE_LENGTH],
        };
        instance
    }

    pub fn with_key(key: [u8; KEY_BYTE_LENGTH]) -> SM4Encryption {
        let mut instance = SM4Encryption::new();
        instance.set_key(key);
        instance
    }

    pub fn set_key(&mut self, key: [u8; KEY_BYTE_LENGTH]) {
        self.key = key;
        self.generate_sm4_key();
    }

    fn generate_sm4_key(&mut self) {
        let mut k: [u32; 4] = [0; 4];
        k[0] = big_endian_word(&self.key, 0) ^ FK[0];
        k[1] = big_endian_word(&self.key, 1) ^ FK[1];
        k[2] = big_endian_word(&self.key, 2) ^ FK[2];
        k[3] = big_endian_word(&self.key, 3) ^ FK[3];
        for i in 0..SM4_KEY_BYTE_LENGTH {
            let x = k[(i + 1) % 4] ^ k[(i + 2) % 4] ^ k[(i + 3) % 4] ^ CK[i];
            let xx = x.to_be_bytes();
            let t = u32::from_be_bytes([SM4_S[xx[0] as usize], SM4_S[xx[1] as usize], SM4_S[xx[2] as usize], SM4_S[xx[3] as usize]]);
            k[i % 4] ^= t ^ t.rotate_left(13) ^ t.rotate_left(23);
            self.sm4_key[i] = k[i % 4];
        }
    }

    pub fn encrypt_block(&self, origin_data: &[u8; SM4_BLOCK_BYTE_LENGTH], enciphered_data: &mut [u8; SM4_BLOCK_BYTE_LENGTH]) {
        let mut w0 = big_endian_word(origin_data, 0);
        let mut w1 = big_endian_word(origin_data, 1);
        let mut w2 = big_endian_word(origin_data, 2);
        let mut w3 = big_endian_word(origin_data, 3);
        round_edge(&mut w0, &mut w1, &mut w2, &mut w3, self.sm4_key[00], self.sm4_key[01], self.sm4_key[02], self.sm4_key[03]);
        round_main(&mut w0, &mut w1, &mut w2, &mut w3, self.sm4_key[04], self.sm4_key[05], self.sm4_key[06], self.sm4_key[07]);
        round_main(&mut w0, &mut w1, &mut w2, &mut w3, self.sm4_key[08], self.sm4_key[09], self.sm4_key[10], self.sm4_key[11]);
        round_main(&mut w0, &mut w1, &mut w2, &mut w3, self.sm4_key[12], self.sm4_key[13], self.sm4_key[14], self.sm4_key[15]);
        round_main(&mut w0, &mut w1, &mut w2, &mut w3, self.sm4_key[16], self.sm4_key[17], self.sm4_key[18], self.sm4_key[19]);
        round_main(&mut w0, &mut w1, &mut w2, &mut w3, self.sm4_key[20], self.sm4_key[21], self.sm4_key[22], self.sm4_key[23]);
        round_main(&mut w0, &mut w1, &mut w2, &mut w3, self.sm4_key[24], self.sm4_key[25], self.sm4_key[26], self.sm4_key[27]);
        round_edge(&mut w0, &mut w1, &mut w2, &mut w3, self.sm4_key[28], self.sm4_key[29], self.sm4_key[30], self.sm4_key[31]);
        big_endian_bytes(w3, enciphered_data, 0);
        big_endian_bytes(w2, enciphered_data, 1);
        big_endian_bytes(w1, enciphered_data, 2);
        big_endian_bytes(w0, enciphered_data, 3);
    }

    pub fn decrypt_block(&self, enciphered_data: &[u8; SM4_BLOCK_BYTE_LENGTH], origin_data: &mut [u8; SM4_BLOCK_BYTE_LENGTH]) {
        let mut w0 = big_endian_word(enciphered_data, 0);
        let mut w1 = big_endian_word(enciphered_data, 1);
        let mut w2 = big_endian_word(enciphered_data, 2);
        let mut w3 = big_endian_word(enciphered_data, 3);
        round_edge(&mut w0, &mut w1, &mut w2, &mut w3, self.sm4_key[31], self.sm4_key[30], self.sm4_key[29], self.sm4_key[28]);
        round_main(&mut w0, &mut w1, &mut w2, &mut w3, self.sm4_key[27], self.sm4_key[26], self.sm4_key[25], self.sm4_key[24]);
        round_main(&mut w0, &mut w1, &mut w2, &mut w3, self.sm4_key[23], self.sm4_key[22], self.sm4_key[21], self.sm4_key[20]);
        round_main(&mut w0, &mut w1, &mut w2, &mut w3, self.sm4_key[19], self.sm4_key[18], self.sm4_key[17], self.sm4_key[16]);
        round_main(&mut w0, &mut w1, &mut w2, &mut w3, self.sm4_key[15], self.sm4_key[14], self.sm4_key[13], self.sm4_key[12]);
        round_main(&mut w0, &mut w1, &mut w2, &mut w3, self.sm4_key[11], self.sm4_key[10], self.sm4_key[09], self.sm4_key[08]);
        round_main(&mut w0, &mut w1, &mut w2, &mut w3, self.sm4_key[07], self.sm4_key[06], self.sm4_key[05], self.sm4_key[04]);
        round_edge(&mut w0, &mut w1, &mut w2, &mut w3, self.sm4_key[03], self.sm4_key[02], self.sm4_key[01], self.sm4_key[00]);
        big_endian_bytes(w3, origin_data, 0);
        big_endian_bytes(w2, origin_data, 1);
        big_endian_bytes(w1, origin_data, 2);
        big_endian_bytes(w0, origin_data, 3);
    }
}
