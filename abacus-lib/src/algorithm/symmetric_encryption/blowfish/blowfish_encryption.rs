use super::blowfish_constant::{KEY_P_BYTE_LENGTH, KEY_S_BYTE_LENGTH, BLOWFISH_BLOCK_BYTE_LENGTH, P, S};

#[inline(always)]
fn round(y: &mut u32, x: u32, s: &[u32; KEY_S_BYTE_LENGTH], p: u32) {
    let xx = x.to_be_bytes();
    *y ^= p ^ (s[xx[0] as usize].wrapping_add(s[0x0100 + xx[1] as usize] ^ s[0x0200 + xx[2] as usize]).wrapping_add(s[0x0300 + xx[3] as usize]));
}

pub struct BlowFishEncryption {
    key_data: Vec<u8>,
    p: [u32; KEY_P_BYTE_LENGTH],
    s: [u32; KEY_S_BYTE_LENGTH],
}

impl BlowFishEncryption {
    pub fn new() -> BlowFishEncryption {
        let instance = BlowFishEncryption {
            key_data: Vec::new(),
            p: P,
            s: S,
        };
        instance
    }

    pub fn with_key_data(key_data: Vec<u8>) -> BlowFishEncryption {
        let mut instance = BlowFishEncryption::new();
        instance.set_key_data(key_data);
        instance
    }

    pub fn set_key_data(&mut self, key_data: Vec<u8>) {
        self.key_data = key_data;
        self.generate_blowfish_key();
    }

    fn generate_blowfish_key(&mut self) {
        let key_data_length = if self.key_data.len() > KEY_P_BYTE_LENGTH * 4 {KEY_P_BYTE_LENGTH * 4} else {self.key_data.len()};
        let mut index: usize = 0;
        let mut ri: [u8; 4] = [0; 4];
        for i in 0..KEY_P_BYTE_LENGTH {
            for j in 0..4 {
                ri[j] = self.key_data[index];
                index += 1;
                if index == key_data_length {
                    index = 0;
                }
            }
            self.p[i] ^= u32::from_be_bytes(ri);
        }
        let mut init: [u8; BLOWFISH_BLOCK_BYTE_LENGTH] = [0; BLOWFISH_BLOCK_BYTE_LENGTH];
        let mut init_encrypted: [u8; BLOWFISH_BLOCK_BYTE_LENGTH] = [0; BLOWFISH_BLOCK_BYTE_LENGTH];
        for i in 0..(KEY_P_BYTE_LENGTH / 2) {
            self.encrypt_block(&init, &mut init_encrypted);
            self.p[i * 2] = u32::from_be_bytes(init_encrypted[0..4].try_into().unwrap());
            self.p[i * 2 + 1] = u32::from_be_bytes(init_encrypted[4..8].try_into().unwrap());
            init = init_encrypted;
        }
        for i in 0..(KEY_S_BYTE_LENGTH / 2) {
            self.encrypt_block(&init, &mut init_encrypted);
            self.s[i * 2] = u32::from_be_bytes(init_encrypted[0..4].try_into().unwrap());
            self.s[i * 2 + 1] = u32::from_be_bytes(init_encrypted[4..8].try_into().unwrap());
            init = init_encrypted;
        }
    }

    pub fn encrypt_block(&self, origin_data: &[u8; BLOWFISH_BLOCK_BYTE_LENGTH], enciphered_data: &mut [u8; BLOWFISH_BLOCK_BYTE_LENGTH]) {
        let mut l = u32::from_be_bytes(origin_data[0..4].try_into().unwrap());
        let mut r = u32::from_be_bytes(origin_data[4..8].try_into().unwrap());
        l ^= self.p[0];
        round(&mut r, l, &self.s, self.p[1]);
        round(&mut l, r, &self.s, self.p[2]);
        round(&mut r, l, &self.s, self.p[3]);
        round(&mut l, r, &self.s, self.p[4]);
        round(&mut r, l, &self.s, self.p[5]);
        round(&mut l, r, &self.s, self.p[6]);
        round(&mut r, l, &self.s, self.p[7]);
        round(&mut l, r, &self.s, self.p[8]);
        round(&mut r, l, &self.s, self.p[9]);
        round(&mut l, r, &self.s, self.p[10]);
        round(&mut r, l, &self.s, self.p[11]);
        round(&mut l, r, &self.s, self.p[12]);
        round(&mut r, l, &self.s, self.p[13]);
        round(&mut l, r, &self.s, self.p[14]);
        round(&mut r, l, &self.s, self.p[15]);
        round(&mut l, r, &self.s, self.p[16]);
        r ^= self.p[KEY_P_BYTE_LENGTH - 1];
        let r_bytes = r.to_be_bytes();
        enciphered_data[0] = r_bytes[0];
        enciphered_data[1] = r_bytes[1];
        enciphered_data[2] = r_bytes[2];
        enciphered_data[3] = r_bytes[3];
        let l_bytes = l.to_be_bytes();
        enciphered_data[4] = l_bytes[0];
        enciphered_data[5] = l_bytes[1];
        enciphered_data[6] = l_bytes[2];
        enciphered_data[7] = l_bytes[3];
    }

    pub fn decrypt_block(&self, origin_data: &[u8; BLOWFISH_BLOCK_BYTE_LENGTH], enciphered_data: &mut [u8; BLOWFISH_BLOCK_BYTE_LENGTH]) {
        let mut l = u32::from_be_bytes(origin_data[0..4].try_into().unwrap());
        let mut r = u32::from_be_bytes(origin_data[4..8].try_into().unwrap());
        l ^= self.p[KEY_P_BYTE_LENGTH - 1];
        round(&mut r, l, &self.s, self.p[16]);
        round(&mut l, r, &self.s, self.p[15]);
        round(&mut r, l, &self.s, self.p[14]);
        round(&mut l, r, &self.s, self.p[13]);
        round(&mut r, l, &self.s, self.p[12]);
        round(&mut l, r, &self.s, self.p[11]);
        round(&mut r, l, &self.s, self.p[10]);
        round(&mut l, r, &self.s, self.p[9]);
        round(&mut r, l, &self.s, self.p[8]);
        round(&mut l, r, &self.s, self.p[7]);
        round(&mut r, l, &self.s, self.p[6]);
        round(&mut l, r, &self.s, self.p[5]);
        round(&mut r, l, &self.s, self.p[4]);
        round(&mut l, r, &self.s, self.p[3]);
        round(&mut r, l, &self.s, self.p[2]);
        round(&mut l, r, &self.s, self.p[1]);
        r ^= self.p[0];
        let r_bytes = r.to_be_bytes();
        enciphered_data[0] = r_bytes[0];
        enciphered_data[1] = r_bytes[1];
        enciphered_data[2] = r_bytes[2];
        enciphered_data[3] = r_bytes[3];
        let l_bytes = l.to_be_bytes();
        enciphered_data[4] = l_bytes[0];
        enciphered_data[5] = l_bytes[1];
        enciphered_data[6] = l_bytes[2];
        enciphered_data[7] = l_bytes[3];
    }
}
