use super::blowfish_constant::{BLOWFISH_BLOCK_BYTE_LENGTH};
use super::blowfish_encryption::BlowFishEncryption;

pub fn blowfish_ofb_encrypt_data(origin_data: &[u8], key_data: Vec<u8>, iv: [u8; BLOWFISH_BLOCK_BYTE_LENGTH]) -> Vec<u8> {
    let blowfish = BlowFishEncryption::with_key_data(key_data);
    let block_sum = origin_data.len() / BLOWFISH_BLOCK_BYTE_LENGTH;
    let enciphered_data_length = block_sum * BLOWFISH_BLOCK_BYTE_LENGTH;
    let mut key_with_iv = iv;
    let mut key_with_iv_encrypted = [0; BLOWFISH_BLOCK_BYTE_LENGTH];
    let mut enciphered_data: Vec<u8> = Vec::with_capacity(enciphered_data_length);
    enciphered_data.resize(enciphered_data_length, 0);
    for i in 0..block_sum {
        blowfish.encrypt_block(&key_with_iv, &mut key_with_iv_encrypted);
        key_with_iv = key_with_iv_encrypted;
        let origin_data_block: &[u8; BLOWFISH_BLOCK_BYTE_LENGTH] = (&origin_data[(i * BLOWFISH_BLOCK_BYTE_LENGTH)..((i + 1) * BLOWFISH_BLOCK_BYTE_LENGTH)]).try_into().unwrap();
        let enciphered_data_block: &mut [u8; BLOWFISH_BLOCK_BYTE_LENGTH] = (&mut enciphered_data[(i * BLOWFISH_BLOCK_BYTE_LENGTH)..((i + 1) * BLOWFISH_BLOCK_BYTE_LENGTH)]).try_into().unwrap();
        for j in 0..BLOWFISH_BLOCK_BYTE_LENGTH {
            enciphered_data_block[j] = origin_data_block[j] ^ key_with_iv[j]
        }
    }
    enciphered_data
}

pub fn blowfish_ofb_decrypt_data(enciphered_data: &[u8], key_data: Vec<u8>, iv: [u8; BLOWFISH_BLOCK_BYTE_LENGTH]) -> Vec<u8> {
    blowfish_ofb_encrypt_data(enciphered_data, key_data, iv)
}
