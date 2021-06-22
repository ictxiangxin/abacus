use std::fs::File;
use std::io::Read;
use super::sha2_256_type::SHA2_256Type;
use super::sha2_256_digest::SHA2_256Digest;
use super::sha2_224_digest::SHA2_224Digest;
use super::sha2_constant::{SHA2_256_DIGEST_BYTE_LENGTH, SHA2_224_DIGEST_BYTE_LENGTH};

const FILE_READ_SIZE: usize = 0x40000;

pub(crate) struct SHA2Utils;

impl SHA2Utils {
    pub fn sha2_256_data_digest(data: &[u8]) -> [u8; SHA2_256_DIGEST_BYTE_LENGTH] {
        let mut sha256 = SHA2_256Digest::new();
        sha256.push_data(data);
        sha256.compute_digest();
        sha256.get_digest_bytes()
    }

    pub fn sha2_224_data_digest(data: &[u8]) -> [u8; SHA2_224_DIGEST_BYTE_LENGTH] {
        let mut sha256 = SHA2_224Digest::new();
        sha256.push_data(data);
        sha256.compute_digest();
        sha256.get_digest_bytes()
    }

    pub fn sha2_256_file_digest(file_path: String) -> Result<[u8; SHA2_256_DIGEST_BYTE_LENGTH], std::io::Error> {
        let mut file = File::open(file_path)?;
        let mut buffer = [0; FILE_READ_SIZE];
        let mut sha256 = SHA2_256Digest::new();
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

    pub fn sha2_224_file_digest(file_path: String) -> Result<[u8; SHA2_224_DIGEST_BYTE_LENGTH], std::io::Error> {
        let mut file = File::open(file_path)?;
        let mut buffer = [0; FILE_READ_SIZE];
        let mut sha256 = SHA2_224Digest::new();
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
