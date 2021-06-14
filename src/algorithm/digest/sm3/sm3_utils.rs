use std::fs::File;
use std::io::Read;
use super::sm3_digest::{DIGEST_BYTE_LENGTH, SM3Digest};

const FILE_READ_SIZE: usize = 0x40000;

pub(crate) struct SM3Utils;

impl SM3Utils {
    pub fn data_digest(data: &[u8]) -> [u8; DIGEST_BYTE_LENGTH] {
        let mut sm3 = SM3Digest::new();
        sm3.push_data(data);
        sm3.compute_digest();
        sm3.get_digest_bytes()
    }

    pub fn file_digest(file_path: String) -> Result<[u8; DIGEST_BYTE_LENGTH], std::io::Error> {
        let mut file = File::open(file_path)?;
        let mut buffer = [0; FILE_READ_SIZE];
        let mut sm3 = SM3Digest::new();
        loop {
            let read_size = file.read(&mut buffer)?;
            if read_size < FILE_READ_SIZE {
                sm3.push_data(&buffer[..read_size]);
                break;
            }
            sm3.push_data(&buffer);
        }
        sm3.compute_digest();
        Ok(sm3.get_digest_bytes())
    }
}