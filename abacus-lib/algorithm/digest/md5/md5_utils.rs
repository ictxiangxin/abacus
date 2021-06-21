use std::fs::File;
use std::io::Read;
use super::md5_digest::MD5Digest;
use super::md5_constant::MD5_DIGEST_BYTE_LENGTH;

const FILE_READ_SIZE: usize = 0x40000;

pub(crate) struct MD5Utils;

impl MD5Utils {
    pub fn md5_data_digest(data: &[u8]) -> [u8; MD5_DIGEST_BYTE_LENGTH] {
        let mut md5 = MD5Digest::new();
        md5.push_data(data);
        md5.compute_digest();
        md5.get_digest_bytes()
    }

    pub fn md5_file_digest(file_path: String) -> Result<[u8; MD5_DIGEST_BYTE_LENGTH], std::io::Error> {
        let mut file = File::open(file_path)?;
        let mut buffer = [0; FILE_READ_SIZE];
        let mut md5 = MD5Digest::new();
        loop {
            let read_size = file.read(&mut buffer)?;
            if read_size < FILE_READ_SIZE {
                md5.push_data(&buffer[..read_size]);
                break;
            }
            md5.push_data(&buffer);
        }
        md5.compute_digest();
        Ok(md5.get_digest_bytes())
    }
}
