use super::blowfish_constant::{BLOWFISH_BLOCK_BYTE_LENGTH};
use super::blowfish_encryption::BlowFishEncryption;

pub fn blowfish_ecb_encrypt_data(origin_data: &[u8], key_data: Vec<u8>) -> Vec<u8> {
    let blowfish = BlowFishEncryption::with_key_data(key_data);
    let block_sum = origin_data.len() / BLOWFISH_BLOCK_BYTE_LENGTH;
    let enciphered_data_length = block_sum * BLOWFISH_BLOCK_BYTE_LENGTH;
    let mut enciphered_data: Vec<u8> = Vec::with_capacity(enciphered_data_length);
    enciphered_data.resize(enciphered_data_length, 0);
    for i in 0..block_sum {
        let origin_data_block: &[u8; BLOWFISH_BLOCK_BYTE_LENGTH] = (&origin_data[(i * BLOWFISH_BLOCK_BYTE_LENGTH)..((i + 1) * BLOWFISH_BLOCK_BYTE_LENGTH)]).try_into().unwrap();
        let enciphered_data_block: &mut [u8; BLOWFISH_BLOCK_BYTE_LENGTH] = (&mut enciphered_data[(i * BLOWFISH_BLOCK_BYTE_LENGTH)..((i + 1) * BLOWFISH_BLOCK_BYTE_LENGTH)]).try_into().unwrap();
        blowfish.encrypt_block(origin_data_block, enciphered_data_block);
    }
    enciphered_data
}

pub fn blowfish_ecb_decrypt_data(enciphered_data: &[u8], key_data: Vec<u8>) -> Vec<u8> {
    let blowfish = BlowFishEncryption::with_key_data(key_data);
    let block_sum = enciphered_data.len() / BLOWFISH_BLOCK_BYTE_LENGTH;
    let enciphered_data_length = block_sum * BLOWFISH_BLOCK_BYTE_LENGTH;
    let mut origin_data: Vec<u8> = Vec::with_capacity(enciphered_data_length);
    origin_data.resize(enciphered_data_length, 0);
    for i in 0..block_sum {
        let enciphered_data_block: &[u8; BLOWFISH_BLOCK_BYTE_LENGTH] = (&enciphered_data[(i * BLOWFISH_BLOCK_BYTE_LENGTH)..((i + 1) * BLOWFISH_BLOCK_BYTE_LENGTH)]).try_into().unwrap();
        let origin_data_block: &mut [u8; BLOWFISH_BLOCK_BYTE_LENGTH] = (&mut origin_data[(i * BLOWFISH_BLOCK_BYTE_LENGTH)..((i + 1) * BLOWFISH_BLOCK_BYTE_LENGTH)]).try_into().unwrap();
        blowfish.decrypt_block(enciphered_data_block, origin_data_block);
    }
    origin_data
}
