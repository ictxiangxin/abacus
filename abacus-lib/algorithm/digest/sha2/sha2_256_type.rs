use crate::algorithm::digest::sha2::sha2_constant::SHA2_256_DIGEST_INIT_VALUE_LENGTH;

pub enum SHA2_256Type {
    SHA224,
    SHA256,
}

impl SHA2_256Type {
    pub fn init_value(&self) -> [u32; SHA2_256_DIGEST_INIT_VALUE_LENGTH] {
        match self {
            SHA2_256Type::SHA224 => [
                0xc1059ed8,
                0x367cd507,
                0x3070dd17,
                0xf70e5939,
                0xffc00b31,
                0x68581511,
                0x64f98fa7,
                0xbefa4fa4,
            ],
            SHA2_256Type::SHA256 => [
                0x6a09e667,
                0xbb67ae85,
                0x3c6ef372,
                0xa54ff53a,
                0x510e527f,
                0x9b05688c,
                0x1f83d9ab,
                0x5be0cd19,
            ]
        }
    }
}
