use std::fs::File;
use std::io::Read;
use super::sha256_digest::{DIGEST_BYTE_LENGTH, SHA256Digest};
use super::sha256_type::SHA256Type;

const FILE_READ_SIZE: usize = 0x40000;

pub(crate) struct SHA256Utils;

impl SHA256Utils {
    pub fn data_digest(data: &[u8]) -> [u8; DIGEST_BYTE_LENGTH] {
        let mut sha256 = SHA256Digest::new(SHA256Type::SHA256);
        sha256.push_data(data);
        sha256.compute_digest();
        sha256.get_digest_bytes()
    }

    pub fn file_digest(file_path: String) -> Result<[u8; DIGEST_BYTE_LENGTH], std::io::Error> {
        let mut file = File::open(file_path)?;
        let mut buffer = [0; FILE_READ_SIZE];
        let mut sha256 = SHA256Digest::new(SHA256Type::SHA256);
        loop {
            let read_size = file.read(&mut buffer)?;
            if read_size < FILE_READ_SIZE {
                sha256.push_data(&buffer[..read_size]);
                break;
            }
            sha256.push_data(&buffer);
        }
        sha256.compute_digest();
        Ok(sha256.get_digest_bytes())
    }
}
