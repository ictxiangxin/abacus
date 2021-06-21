use std::convert::TryInto;
use crate::algorithm::digest::sha2::sha2_256_base_digest::SHA2_256BaseDigest;
use crate::algorithm::digest::sha2::sha2_256_type::SHA2_256Type;
use crate::algorithm::digest::sha2::sha2_constant::SHA2_224_DIGEST_BYTE_LENGTH;

pub struct SHA2_224Digest {
    sha2_256_base_digest: SHA2_256BaseDigest
}

impl SHA2_224Digest {
    pub fn new() -> SHA2_224Digest {
        let instance = SHA2_224Digest {
            sha2_256_base_digest: SHA2_256BaseDigest::new(SHA2_256Type::SHA224)
        };
        instance
    }

    pub fn get_digest_bytes(&mut self) -> [u8; SHA2_224_DIGEST_BYTE_LENGTH] {
        self.sha2_256_base_digest.get_digest_bytes()[..SHA2_224_DIGEST_BYTE_LENGTH].try_into().unwrap()
    }

    pub fn compute_digest(&mut self) {
        self.sha2_256_base_digest.compute_digest()
    }

    pub fn push_data(&mut self, data: &[u8]) {
        self.sha2_256_base_digest.push_data(data)
    }
}
