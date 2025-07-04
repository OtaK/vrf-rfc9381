use p256::{PublicKey, SecretKey};
use sha2::Sha256;

use crate::{
    ec::util,
    error::{VrfError, VrfResult},
};

const CHALLENGE_LEN: usize = 16;
const Q_LEN: usize = 32;
const PT_LEN: usize = 33;

pub mod tai {
    use sha2::Sha256;

    use crate::{
        Ciphersuite,
        ec::p256::{
            EcVrfProof,
            internal::{EcVrfP256PublicKey, EcVrfP256SecretKey},
        },
        error::VrfResult,
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct EcVrfP256Tai;

    impl crate::VRF for EcVrfP256Tai {
        type Hash = Sha256;
        type Proof = EcVrfProof;
        type Verifier = EcVrfP256TaiPublicKey;
        type Prover = EcVrfP256TaiSecretKey;

        fn ciphersuite(&self) -> Ciphersuite {
            Ciphersuite::ECVRF_P256_SHA256_TAI
        }
    }

    #[derive(zeroize::ZeroizeOnDrop, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct EcVrfP256TaiSecretKey(EcVrfP256SecretKey);

    impl crate::Prover<sha2::Sha256> for EcVrfP256TaiSecretKey {
        type Proof = EcVrfProof;

        type Verifier = EcVrfP256TaiPublicKey;

        fn from_slice(bytes: &[u8]) -> VrfResult<Self>
        where
            Self: Sized,
        {
            Ok(Self(EcVrfP256SecretKey::from_sk(bytes.try_into()?)?))
        }

        #[cfg(feature = "hazmat")]
        fn x_equals(&self, value: &[u8]) -> bool {
            self.0.x_equals(value)
        }

        fn verifier(&self) -> Self::Verifier {
            EcVrfP256TaiPublicKey(self.0.public_key())
        }

        fn prove(&self, alpha: &[u8]) -> VrfResult<Self::Proof> {
            self.0.prove(Ciphersuite::ECVRF_P256_SHA256_TAI, alpha)
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct EcVrfP256TaiPublicKey(EcVrfP256PublicKey);

    impl crate::Verifier<Sha256> for EcVrfP256TaiPublicKey {
        type Proof = EcVrfProof;

        fn from_slice(bytes: &[u8]) -> VrfResult<Self>
        where
            Self: Sized,
        {
            Ok(Self(EcVrfP256PublicKey::from_bytes(bytes)?))
        }

        fn verify(&self, alpha: &[u8], proof: Self::Proof) -> VrfResult<digest::Output<Sha256>> {
            use crate::Proof as _;
            self.0
                .verify(Ciphersuite::ECVRF_P256_SHA256_TAI, alpha, proof)?
                .proof_to_hash(Ciphersuite::ECVRF_P256_SHA256_TAI)
        }
    }
}

pub mod sswu {
    use sha2::Sha256;

    use crate::{
        Ciphersuite,
        ec::p256::{
            EcVrfProof,
            internal::{EcVrfP256PublicKey, EcVrfP256SecretKey},
        },
        error::VrfResult,
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct EcVrfP256Sswu;

    impl crate::VRF for EcVrfP256Sswu {
        type Hash = Sha256;
        type Proof = EcVrfProof;
        type Verifier = EcVrfP256SswuPublicKey;
        type Prover = EcVrfP256SswuSecretKey;

        fn ciphersuite(&self) -> Ciphersuite {
            Ciphersuite::ECVRF_P256_SHA256_SSWU
        }
    }

    #[derive(zeroize::ZeroizeOnDrop, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct EcVrfP256SswuSecretKey(EcVrfP256SecretKey);

    impl crate::Prover<sha2::Sha256> for EcVrfP256SswuSecretKey {
        type Proof = EcVrfProof;

        type Verifier = EcVrfP256SswuPublicKey;

        fn from_slice(bytes: &[u8]) -> VrfResult<Self>
        where
            Self: Sized,
        {
            Ok(Self(EcVrfP256SecretKey::from_sk(bytes.try_into()?)?))
        }

        #[cfg(feature = "hazmat")]
        fn x_equals(&self, value: &[u8]) -> bool {
            self.0.x_equals(value)
        }

        fn verifier(&self) -> Self::Verifier {
            EcVrfP256SswuPublicKey(self.0.public_key())
        }

        fn prove(&self, alpha: &[u8]) -> VrfResult<Self::Proof> {
            self.0.prove(Ciphersuite::ECVRF_P256_SHA256_SSWU, alpha)
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct EcVrfP256SswuPublicKey(EcVrfP256PublicKey);

    impl crate::Verifier<Sha256> for EcVrfP256SswuPublicKey {
        type Proof = EcVrfProof;

        fn from_slice(bytes: &[u8]) -> VrfResult<Self>
        where
            Self: Sized,
        {
            Ok(Self(EcVrfP256PublicKey::from_bytes(bytes)?))
        }

        fn verify(&self, alpha: &[u8], proof: Self::Proof) -> VrfResult<digest::Output<Sha256>> {
            use crate::Proof as _;
            self.0
                .verify(Ciphersuite::ECVRF_P256_SHA256_SSWU, alpha, proof)?
                .proof_to_hash(Ciphersuite::ECVRF_P256_SHA256_SSWU)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct EcVrfProof {
    gamma: PublicKey,
    c: SecretKey,
    s: SecretKey,
}

impl EcVrfProof {
    const PROOF_LEN: usize = CHALLENGE_LEN + Q_LEN + PT_LEN;

    #[inline]
    fn compressed_gamma(&self) -> p256::EncodedPoint {
        p256::EncodedPoint::from(self.gamma).compress()
    }
}

impl crate::Proof<Sha256> for EcVrfProof {
    fn decode_pi(pi: &[u8]) -> VrfResult<Self>
    where
        Self: Sized,
    {
        if pi.len() != Self::PROOF_LEN {
            return Err(VrfError::IncorrectPiLength {
                expected: Self::PROOF_LEN,
                actual: pi.len(),
            });
        }

        let gamma_string = &pi[..PT_LEN];
        let c_string = &pi[PT_LEN..PT_LEN + CHALLENGE_LEN];
        let s_string = &pi[PT_LEN + CHALLENGE_LEN..];
        debug_assert_eq!(s_string.len(), Q_LEN);
        let gamma = PublicKey::from_sec1_bytes(gamma_string)?;

        let c = internal::sk_from_slice(c_string)?;
        let s = internal::sk_from_slice(s_string)?;

        Ok(EcVrfProof { gamma, c, s })
    }

    fn encode_to_pi(&self) -> Vec<u8> {
        let c_bytes = self.c.to_bytes();
        let c_slice = &c_bytes[c_bytes.len() - CHALLENGE_LEN..];
        let ret = [
            self.compressed_gamma().as_bytes(),
            c_slice,
            &self.s.to_bytes(),
        ]
        .concat();

        debug_assert_eq!(ret.len(), Self::PROOF_LEN);

        ret
    }

    fn proof_to_hash(&self, suite: crate::Ciphersuite) -> VrfResult<digest::Output<Sha256>> {
        Ok(util::proof_to_hash::<Sha256>(
            suite,
            self.compressed_gamma().as_bytes(),
        ))
    }
}

mod internal {
    use p256::{
        EncodedPoint, NistP256, PublicKey, SecretKey,
        elliptic_curve::{ScalarPrimitive, bigint::ArrayEncoding, hash2curve::ExpandMsgXmd},
    };
    use sha2::{Digest as _, Sha256};

    use crate::{
        Ciphersuite,
        consts::ecvrf::{
            ciphersuites::ECVRF_P256_SHA256_SSWU,
            e2c::{ECVRF_E2C_H2C_DST, ECVRF_P256_SSWU_DST},
        },
        ec::{
            p256::{CHALLENGE_LEN, EcVrfProof, PT_LEN, Q_LEN},
            util,
        },
        error::{VrfError, VrfResult},
    };

    pub(super) fn sk_from_slice(slice: &[u8]) -> VrfResult<SecretKey> {
        assert!(slice.len() <= Q_LEN);
        let offset = Q_LEN.saturating_sub(slice.len());
        let mut c_scalar_bytes: p256::FieldBytes = Default::default();
        c_scalar_bytes[offset..].copy_from_slice(slice);
        Ok(SecretKey::from_bytes(&c_scalar_bytes)?)
    }

    #[derive(zeroize::ZeroizeOnDrop, PartialEq, Eq)]
    pub struct EcVrfP256SecretKey(SecretKey);

    impl EcVrfP256SecretKey {
        pub(super) fn from_sk(sk: [u8; 32]) -> VrfResult<Self> {
            Ok(SecretKey::from_bytes(&sk.into()).map(Self)?)
        }

        #[cfg(feature = "hazmat")]
        pub fn x_equals(&self, value: &[u8]) -> bool {
            use subtle::ConstantTimeEq as _;
            self.0.to_bytes().as_slice().ct_eq(value).into()
        }

        pub(super) fn public_key(&self) -> EcVrfP256PublicKey {
            let point = self.0.public_key();
            let compressed = EncodedPoint::from(point).compress();
            EcVrfP256PublicKey { point, compressed }
        }

        fn generate_nonce(&self, h_string: &[u8]) -> VrfResult<SecretKey> {
            let q = ScalarPrimitive::<NistP256>::MODULUS.to_be_byte_array();
            let h = Sha256::digest(h_string);
            let k = rfc6979::generate_k::<Sha256, _>(&self.0.to_bytes(), &q, &h, b"");

            Ok(SecretKey::from_bytes(&k)?)
        }

        pub(super) fn prove(&self, suite: Ciphersuite, alpha: &[u8]) -> VrfResult<EcVrfProof> {
            // 1. Use SK to derive the VRF secret scalar x and the VRF public key Y = x*B
            let y = self.public_key();
            // 2. H = ECVRF_encode_to_curve(encode_to_curve_salt, alpha_string) (see Section 5.4.1)
            let h = y.encode_to_curve(suite, alpha)?;

            let x = self.0.to_nonzero_scalar();
            // 3. Gamma = x*H
            let gamma = h.point.to_projective() * x.as_ref();
            let gamma = PublicKey::from_affine(gamma.to_affine())?;

            // 4. k = ECVRF_nonce_generation(SK, h_string) (see Section 5.4.2)
            let k = self.generate_nonce(h.encode_to_curve_salt())?;
            let k_nz = k.to_nonzero_scalar();
            // 5. c = ECVRF_challenge_generation(Y, H, Gamma, k*B, k*H) (see Section 5.4.3)
            let k_h =
                PublicKey::from_affine((h.point.to_projective() * k_nz.as_ref()).to_affine())?;
            let c =
                EcChallenge::generate(suite, &[&y.point, &h.point, &gamma, &k.public_key(), &k_h])?;

            // 7. s = (k + c*x) mod q
            let c_x = c.to_nonzero_scalar() * x;
            let Some(s_scalar) =
                p256::NonZeroScalar::new(k_nz.as_ref() + c_x.as_ref()).into_option()
            else {
                unreachable!()
            };
            let s = SecretKey::from(s_scalar);

            // 8. pi_string = point_to_string(Gamma) || int_to_string(c, cLen) || int_to_string(s, qLen)
            // EdProof here can be encoded into pi_string at any point so we return the struct as-is
            Ok(EcVrfProof { gamma, c, s })
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct EcVrfP256PublicKey {
        point: PublicKey,
        compressed: EncodedPoint,
    }

    impl EcVrfP256PublicKey {
        pub(super) fn from_bytes(bytes: &[u8]) -> VrfResult<Self> {
            let point = PublicKey::from_sec1_bytes(bytes)?;
            if point.as_affine().is_identity().into() {
                return Err(VrfError::InvalidEcPoint);
            }

            let compressed = EncodedPoint::from(point).compress();

            Ok(Self { point, compressed })
        }

        fn encode_to_curve_salt(&self) -> &[u8] {
            self.compressed.as_bytes()
        }

        fn encode_to_curve(&self, suite: Ciphersuite, alpha: &[u8]) -> VrfResult<Self> {
            Ok(match suite {
                Ciphersuite::ECVRF_P256_SHA256_TAI => self.encode_to_curve_tai(alpha)?,
                Ciphersuite::ECVRF_P256_SHA256_SSWU => self.h2c_encode_to_curve_sswu(alpha)?,
                _ => return Err(VrfError::UnsupportedCiphersuite(suite)),
            })
        }

        fn encode_to_curve_tai(&self, alpha: &[u8]) -> VrfResult<Self> {
            let salt = self.encode_to_curve_salt();

            for candidate in util::encode_to_curve_tai_generator::<Sha256>(
                Ciphersuite::ECVRF_P256_SHA256_TAI,
                salt,
                alpha,
            ) {
                // 5. While H is "INVALID" or H is the identity element of the elliptic curve group:
                // H = interpret_hash_value_as_a_point(hash_string)
                // Addendum: "interpret_hash_value_as_a_point(s) = string_to_point(0x02 || s)."
                let mut point = [0u8; PT_LEN];
                point[0] = 0x02;
                point[1..].copy_from_slice(&candidate[..32]);

                let Ok(pk) = Self::from_bytes(&point) else {
                    continue;
                };

                // 6. Output H
                return Ok(pk);
            }

            Err(VrfError::TryAndIncrementNoCandidatesFound)
        }

        fn h2c_encode_to_curve_sswu(&self, alpha: &[u8]) -> VrfResult<Self> {
            // string_to_be_hashed = encode_to_curve_salt || alpha_string
            let string_to_be_hashed = [self.encode_to_curve_salt(), alpha].concat();
            // "ECVRF_" || h2c_suite_ID_string || suite_string
            let dst = [
                &ECVRF_E2C_H2C_DST[..],
                &ECVRF_P256_SSWU_DST[..],
                &[ECVRF_P256_SHA256_SSWU],
            ]
            .concat();

            use p256::elliptic_curve::hash2curve::GroupDigest as _;

            let point = p256::NistP256::encode_from_bytes::<ExpandMsgXmd<Sha256>>(
                &[&string_to_be_hashed],
                &[&dst],
            )?
            .to_affine();

            let point = PublicKey::from_affine(point)?;
            let compressed = EncodedPoint::from(point).compress();

            Ok(Self { compressed, point })
        }

        pub(super) fn verify(
            &self,
            suite: Ciphersuite,
            alpha: &[u8],
            proof: EcVrfProof,
        ) -> VrfResult<EcVrfProof> {
            // 4. D = ECVRF_decode_proof(pi_string) (see Section 5.4.4)
            // 6. (Gamma, c, s) = D
            let EcVrfProof { gamma, c, s } = proof;
            // 7. H = ECVRF_encode_to_curve(encode_to_curve_salt, alpha_string) (see Section 5.4.1)
            let h = self.encode_to_curve(suite, alpha)?;

            let c_nz = c.to_nonzero_scalar();
            let s_nz = s.to_nonzero_scalar();

            // 8. U = s*B - c*Y
            let u = s.public_key().to_projective() - (self.point.to_projective() * c_nz.as_ref());
            let u = PublicKey::from_affine(u.to_affine())?;
            // 9. V = s*H - c*Gamma
            let v = h.point.to_projective() * s_nz.as_ref() - gamma.to_projective() * c_nz.as_ref();
            let v = PublicKey::from_affine(v.to_affine())?;
            // 10. c' = ECVRF_challenge_generation(Y, H, Gamma, U, V) (see Section 5.4.3)
            let c_prime = EcChallenge::generate(suite, &[&self.point, &h.point, &gamma, &u, &v])?;

            // 11.  If c and c' are equal, output ("VALID", ECVRF_proof_to_hash(pi_string)); else output "INVALID"
            if c_prime != c {
                return Err(VrfError::ProofVerificationFailure);
            }

            Ok(EcVrfProof { gamma, c, s })
        }
    }

    pub struct EcChallenge;

    impl EcChallenge {
        fn from_challenge_bytes(c_string: &[u8; CHALLENGE_LEN]) -> VrfResult<SecretKey> {
            sk_from_slice(&c_string[..])
        }

        fn generate(suite: Ciphersuite, points: &[&PublicKey; 5]) -> VrfResult<SecretKey> {
            let compressed = points.map(|pk| EncodedPoint::from(pk).compress());

            Self::from_challenge_bytes(&util::challenge_bytes::<CHALLENGE_LEN, Sha256>(
                suite,
                compressed.iter().map(|c| c.as_bytes()),
            ))
        }
    }
}
