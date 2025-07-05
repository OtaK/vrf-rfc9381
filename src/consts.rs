#![allow(dead_code)]

pub mod ecvrf {
    pub mod ciphersuites {
        pub const ECVRF_P256_SHA256_TAI: u8 = 0x01;
        pub const ECVRF_P256_SHA256_SSWU: u8 = 0x02;
        pub const ECVRF_EDWARDS25519_SHA512_TAI: u8 = 0x03;
        pub const ECVRF_EDWARDS25519_SHA512_ELL2: u8 = 0x04;
    }
    pub mod e2c {
        pub const ECVRF_E2C_H2C_DST: &[u8; 6] = b"ECVRF_";
        pub const ECVRF_EDWARDS25519_ELL2_DST: &[u8; 33] = b"edwards25519_XMD:SHA-512_ELL2_NU_";
        pub const ECVRF_P256_SSWU_DST: &[u8; 25] = b"P256_XMD:SHA-256_SSWU_NU_";
        pub const ECVRF_E2C_DST_FRONT: u8 = 0x01;
        pub const ECVRF_E2C_DST_BACK: u8 = 0x00;
    }
    pub mod challenge {
        pub const ECVRF_CHAL_GEN_DST_FRONT: u8 = 0x02;
        pub const ECVRF_CHAL_GEN_DST_BACK: u8 = 0x00;
    }
    pub mod proof {
        pub const ECVRF_PROOF_DST_FRONT: u8 = 0x03;
        pub const ECVRF_PROOF_DST_BACK: u8 = 0x00;
    }
}

#[allow(dead_code)]
pub mod rsavrf {
    pub const MGF_DST: u8 = 0x01;

    pub mod ciphersuites {
        pub const RSA_FDH_VRF_SHA256: u8 = 0x01;
        pub const RSA_FDH_VRF_SHA384: u8 = 0x02;
        pub const RSA_FDH_VRF_SHA512: u8 = 0x03;
    }
}
