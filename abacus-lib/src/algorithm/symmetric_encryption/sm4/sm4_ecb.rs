use super::sm4_constant::{KEY_BYTE_LENGTH, SM4_BLOCK_BYTE_LENGTH};
use super::sm4_encryption::SM4Encryption;

pub fn sm4_ecb_encrypt_data(origin_data: &[u8], key: [u8; KEY_BYTE_LENGTH]) -> Vec<u8> {
    let sm4 = SM4Encryption::with_key(key);
    let block_sum = origin_data.len() / SM4_BLOCK_BYTE_LENGTH;
    let enciphered_data_length = block_sum * SM4_BLOCK_BYTE_LENGTH;
    let mut enciphered_data: Vec<u8> = Vec::with_capacity(enciphered_data_length);
    enciphered_data.resize(enciphered_data_length, 0);
    for i in 0..block_sum {
        let origin_data_block: &[u8; SM4_BLOCK_BYTE_LENGTH] = (&origin_data[(i * SM4_BLOCK_BYTE_LENGTH)..((i + 1) * SM4_BLOCK_BYTE_LENGTH)]).try_into().unwrap();
        let enciphered_data_block: &mut [u8; SM4_BLOCK_BYTE_LENGTH] = (&mut enciphered_data[(i * SM4_BLOCK_BYTE_LENGTH)..((i + 1) * SM4_BLOCK_BYTE_LENGTH)]).try_into().unwrap();
        sm4.encrypt(origin_data_block, enciphered_data_block);
    }
    enciphered_data
}

pub fn sm4_ecb_decrypt_data(enciphered_data: &[u8], key: [u8; KEY_BYTE_LENGTH]) -> Vec<u8> {
    let sm4 = SM4Encryption::with_key(key);
    let block_sum = enciphered_data.len() / SM4_BLOCK_BYTE_LENGTH;
    let enciphered_data_length = block_sum * SM4_BLOCK_BYTE_LENGTH;
    let mut origin_data: Vec<u8> = Vec::with_capacity(enciphered_data_length);
    origin_data.resize(enciphered_data_length, 0);
    for i in 0..block_sum {
        let enciphered_data_block: &[u8; SM4_BLOCK_BYTE_LENGTH] = (&enciphered_data[(i * SM4_BLOCK_BYTE_LENGTH)..((i + 1) * SM4_BLOCK_BYTE_LENGTH)]).try_into().unwrap();
        let origin_data_block: &mut [u8; SM4_BLOCK_BYTE_LENGTH] = (&mut origin_data[(i * SM4_BLOCK_BYTE_LENGTH)..((i + 1) * SM4_BLOCK_BYTE_LENGTH)]).try_into().unwrap();
        sm4.decrypt(enciphered_data_block, origin_data_block);
    }
    origin_data
}
