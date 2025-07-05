use curve25519_dalek::{EdwardsPoint, Scalar};
use sha2::Sha512;

use crate::{
    Ciphersuite,
    ec::util,
    error::{VrfError, VrfResult},
};

const CHALLENGE_LEN: usize = 16;
const Q_LEN: usize = 32;
const PT_LEN: usize = 32;

pub mod tai {
    use sha2::Sha512;

    use crate::{
        Ciphersuite,
        ec::edwards25519::{
            EdVrfProof,
            internal::{EdVrfEdwards25519PublicKey, EdVrfEdwards25519SecretKey},
        },
        error::VrfResult,
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct EdVrfEdwards25519Tai;

    impl crate::VRF for EdVrfEdwards25519Tai {
        type Hash = Sha512;
        type Proof = EdVrfProof;
        type Verifier = EdVrfEdwards25519TaiPublicKey;
        type Prover = EdVrfEdwards25519TaiSecretKey;

        fn ciphersuite(&self) -> Ciphersuite {
            Ciphersuite::ECVRF_EDWARDS25519_SHA512_TAI
        }
    }

    #[derive(zeroize::ZeroizeOnDrop, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct EdVrfEdwards25519TaiSecretKey(EdVrfEdwards25519SecretKey);

    impl crate::Prover<Sha512> for EdVrfEdwards25519TaiSecretKey {
        type Proof = EdVrfProof;
        type Verifier = EdVrfEdwards25519TaiPublicKey;

        fn from_slice(bytes: &[u8]) -> VrfResult<Self>
        where
            Self: Sized,
        {
            Ok(Self(EdVrfEdwards25519SecretKey::from_sk(bytes.try_into()?)))
        }

        #[cfg(feature = "hazmat")]
        fn x_equals(&self, value: &[u8]) -> bool {
            self.0.x_equals(value)
        }

        fn verifier(&self) -> Self::Verifier {
            EdVrfEdwards25519TaiPublicKey(self.0.public_key())
        }

        fn prove(&self, alpha: &[u8]) -> VrfResult<Self::Proof> {
            self.0
                .prove(Ciphersuite::ECVRF_EDWARDS25519_SHA512_TAI, alpha)
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct EdVrfEdwards25519TaiPublicKey(EdVrfEdwards25519PublicKey);

    impl crate::Verifier<Sha512> for EdVrfEdwards25519TaiPublicKey {
        type Proof = EdVrfProof;

        fn from_slice(bytes: &[u8]) -> VrfResult<Self>
        where
            Self: Sized,
        {
            Ok(Self(EdVrfEdwards25519PublicKey::from_bytes(bytes)?))
        }

        fn verify(&self, alpha: &[u8], proof: Self::Proof) -> VrfResult<digest::Output<Sha512>> {
            use crate::Proof as _;
            self.0
                .verify(Ciphersuite::ECVRF_EDWARDS25519_SHA512_TAI, alpha, proof)?
                .proof_to_hash(Ciphersuite::ECVRF_EDWARDS25519_SHA512_TAI)
        }
    }
}

pub mod elligator2 {
    use sha2::Sha512;

    use crate::{
        Ciphersuite,
        ec::edwards25519::{
            EdVrfProof,
            internal::{EdVrfEdwards25519PublicKey, EdVrfEdwards25519SecretKey},
        },
        error::VrfResult,
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct EdVrfEdwards25519Ell2;

    impl crate::VRF for EdVrfEdwards25519Ell2 {
        type Hash = Sha512;
        type Proof = EdVrfProof;
        type Verifier = EdVrfEdwards25519Ell2PublicKey;
        type Prover = EdVrfEdwards25519Ell2SecretKey;

        fn ciphersuite(&self) -> Ciphersuite {
            Ciphersuite::ECVRF_EDWARDS25519_SHA512_ELL2
        }
    }

    #[derive(zeroize::ZeroizeOnDrop, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct EdVrfEdwards25519Ell2SecretKey(EdVrfEdwards25519SecretKey);

    impl crate::Prover<Sha512> for EdVrfEdwards25519Ell2SecretKey {
        type Proof = EdVrfProof;
        type Verifier = EdVrfEdwards25519Ell2PublicKey;

        fn from_slice(bytes: &[u8]) -> VrfResult<Self>
        where
            Self: Sized,
        {
            Ok(Self(EdVrfEdwards25519SecretKey::from_sk(bytes.try_into()?)))
        }

        #[cfg(feature = "hazmat")]
        fn x_equals(&self, value: &[u8]) -> bool {
            self.0.x_equals(value)
        }

        fn verifier(&self) -> Self::Verifier {
            EdVrfEdwards25519Ell2PublicKey(self.0.public_key())
        }

        fn prove(&self, alpha: &[u8]) -> VrfResult<Self::Proof> {
            self.0
                .prove(Ciphersuite::ECVRF_EDWARDS25519_SHA512_ELL2, alpha)
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct EdVrfEdwards25519Ell2PublicKey(EdVrfEdwards25519PublicKey);

    impl crate::Verifier<Sha512> for EdVrfEdwards25519Ell2PublicKey {
        type Proof = EdVrfProof;

        fn from_slice(bytes: &[u8]) -> VrfResult<Self>
        where
            Self: Sized,
        {
            Ok(Self(EdVrfEdwards25519PublicKey::from_bytes(bytes)?))
        }

        fn verify(&self, alpha: &[u8], proof: Self::Proof) -> VrfResult<digest::Output<Sha512>> {
            use crate::Proof as _;
            self.0
                .verify(Ciphersuite::ECVRF_EDWARDS25519_SHA512_ELL2, alpha, proof)?
                .proof_to_hash(Ciphersuite::ECVRF_EDWARDS25519_SHA512_ELL2)
        }
    }
}

#[derive(Debug, PartialEq, Eq, zeroize::ZeroizeOnDrop)]
pub struct EdVrfProof {
    gamma: EdwardsPoint,
    c: Scalar,
    s: Scalar,
}

impl crate::Proof<Sha512> for EdVrfProof {
    const PROOF_LEN: usize = CHALLENGE_LEN + Q_LEN + PT_LEN;

    fn decode_pi(pi: &[u8]) -> VrfResult<Self> {
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
        let gamma = curve25519_dalek::edwards::CompressedEdwardsY(gamma_string.try_into()?);
        let gamma = gamma.decompress().ok_or(VrfError::InvalidEcPoint)?;

        // Extend the bytes to a 32-byte array, mimicking Scalar's impl of `From<u128>`
        let mut c_bytes = [0u8; 32];
        c_bytes[..c_string.len()].copy_from_slice(c_string);

        let c = Scalar::from_bytes_mod_order(c_bytes);
        let s = Scalar::from_bytes_mod_order(s_string.try_into()?);

        Ok(EdVrfProof { gamma, c, s })
    }

    fn encode_to_pi(&self) -> Vec<u8> {
        let ret = [
            self.gamma.compress().as_bytes(),
            &self.c.as_bytes()[..CHALLENGE_LEN],
            self.s.as_bytes(),
        ]
        .concat();

        debug_assert_eq!(ret.len(), Self::PROOF_LEN);

        ret
    }

    fn proof_to_hash(&self, suite: Ciphersuite) -> VrfResult<digest::Output<Sha512>> {
        Ok(util::proof_to_hash::<Sha512>(
            suite,
            self.gamma.mul_by_cofactor().compress().as_bytes(),
        ))
    }
}

mod internal {
    use curve25519_dalek::{
        EdwardsPoint, Scalar, edwards::CompressedEdwardsY, scalar::clamp_integer,
    };
    use digest::Digest as _;
    use sha2::Sha512;
    use subtle::ConstantTimeEq;

    use crate::{
        Ciphersuite,
        consts::ecvrf::{
            ciphersuites::ECVRF_EDWARDS25519_SHA512_ELL2,
            e2c::{ECVRF_E2C_H2C_DST, ECVRF_EDWARDS25519_ELL2_DST},
        },
        ec::{
            edwards25519::{CHALLENGE_LEN, EdVrfProof},
            util,
        },
        error::{VrfError, VrfResult},
    };

    #[derive(zeroize::ZeroizeOnDrop)]
    pub struct EdVrfEdwards25519SecretKey {
        pub(super) x: Scalar,
        hash_prefix: [u8; 32],
    }

    impl std::cmp::PartialEq for EdVrfEdwards25519SecretKey {
        fn eq(&self, other: &Self) -> bool {
            (self.hash_prefix.ct_eq(&other.hash_prefix) & self.x.ct_eq(&other.x)).into()
        }
    }

    impl std::cmp::Eq for EdVrfEdwards25519SecretKey {}

    impl EdVrfEdwards25519SecretKey {
        pub fn from_sk(sk: [u8; 32]) -> Self {
            let hashed = Sha512::digest(sk);
            let mut x_bytes = [0u8; 32];
            x_bytes.copy_from_slice(&hashed[..32]);
            let mut hash_prefix = [0u8; 32];
            hash_prefix.copy_from_slice(&hashed[32..]);
            #[allow(deprecated)]
            let x = Scalar::from_bits(clamp_integer(x_bytes));
            Self { x, hash_prefix }
        }

        #[cfg(feature = "hazmat")]
        pub fn x_equals(&self, value: &[u8]) -> bool {
            self.x.as_bytes().as_slice().ct_eq(value).into()
        }

        pub fn public_key(&self) -> EdVrfEdwards25519PublicKey {
            let point = EdwardsPoint::mul_base(&self.x);
            EdVrfEdwards25519PublicKey {
                compressed: point.compress(),
                point,
            }
        }

        fn generate_nonce(&self, h_string: &[u8]) -> Scalar {
            let k_string = Sha512::new()
                .chain_update(self.hash_prefix)
                .chain_update(h_string)
                .finalize();

            Scalar::from_bytes_mod_order_wide(&k_string.into())
        }

        pub(super) fn prove(&self, suite: Ciphersuite, alpha: &[u8]) -> VrfResult<EdVrfProof> {
            // 1. Use SK to derive the VRF secret scalar x and the VRF public key Y = x*B
            let y = self.public_key();
            // 2. H = ECVRF_encode_to_curve(encode_to_curve_salt, alpha_string) (see Section 5.4.1)
            let h = y.encode_to_curve(suite, alpha)?;
            // 3. Gamma = x*H
            let gamma = self.x * h.point;

            // 4. k = ECVRF_nonce_generation(SK, h_string) (see Section 5.4.2)
            let k = self.generate_nonce(h.encode_to_curve_salt());
            // 5. c = ECVRF_challenge_generation(Y, H, Gamma, k*B, k*H) (see Section 5.4.3)
            let c = EdChallenge::generate(
                suite,
                &[
                    &y.point,
                    &h.point,
                    &gamma,
                    &EdwardsPoint::mul_base(&k),
                    &(k * h.point),
                ],
            );

            // Note: all scalar math on dalek is done mod q so we don't need to explicit it
            // 7. s = (k + c*x) mod q
            let s = k + c * self.x;

            // 8. pi_string = point_to_string(Gamma) || int_to_string(c, cLen) || int_to_string(s, qLen)
            // EdProof here can be encoded into pi_string at any point so we return the struct as-is
            Ok(EdVrfProof { gamma, c, s })
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct EdVrfEdwards25519PublicKey {
        compressed: CompressedEdwardsY,
        point: EdwardsPoint,
    }

    impl EdVrfEdwards25519PublicKey {
        pub fn from_bytes(bytes: &[u8]) -> VrfResult<Self> {
            let compressed = CompressedEdwardsY::from_slice(bytes)?;
            let point = compressed.decompress().ok_or(VrfError::InvalidEcPoint)?;
            if point.is_small_order() {
                return Err(VrfError::InvalidEcPoint);
            }

            Ok(Self { compressed, point })
        }

        pub fn encode_to_curve(&self, suite: Ciphersuite, alpha: &[u8]) -> VrfResult<Self> {
            Ok(match suite {
                Ciphersuite::ECVRF_EDWARDS25519_SHA512_TAI => self.encode_to_curve_tai(alpha)?,
                Ciphersuite::ECVRF_EDWARDS25519_SHA512_ELL2 => self.h2c_encode_to_curve_ell2(alpha),
                _ => return Err(VrfError::UnsupportedCiphersuite(suite)),
            })
        }

        pub fn encode_to_curve_salt(&self) -> &[u8] {
            self.compressed.as_bytes().as_slice()
        }

        fn encode_to_curve_tai(&self, alpha: &[u8]) -> VrfResult<Self> {
            let salt = self.encode_to_curve_salt();

            for candidate in util::encode_to_curve_tai_generator::<Sha512>(
                Ciphersuite::ECVRF_EDWARDS25519_SHA512_TAI,
                salt,
                alpha,
            ) {
                // 5. While H is "INVALID" or H is the identity element of the elliptic curve group:
                // H = interpret_hash_value_as_a_point(hash_string)
                // Addendum: "With interpret_hash_value_as_a_point(s) = string_to_point(s[0]...s[31])."
                let Ok(mut pk) = Self::from_bytes(&candidate[..32]) else {
                    continue;
                };

                // 6. Output H
                pk.point = pk.point.mul_by_cofactor();
                pk.compressed = pk.point.compress();
                return Ok(pk);
            }

            Err(VrfError::TryAndIncrementNoCandidatesFound)
        }

        fn h2c_encode_to_curve_ell2(&self, alpha: &[u8]) -> Self {
            // string_to_be_hashed = encode_to_curve_salt || alpha_string
            let string_to_be_hashed = [self.encode_to_curve_salt(), alpha].concat();
            // "ECVRF_" || h2c_suite_ID_string || suite_string
            let dst = [
                &ECVRF_E2C_H2C_DST[..],
                &ECVRF_EDWARDS25519_ELL2_DST[..],
                &[ECVRF_EDWARDS25519_SHA512_ELL2],
            ]
            .concat();

            let point =
                EdwardsPoint::hash_to_curve::<sha2::Sha512>(&[&string_to_be_hashed], &[&dst]);

            Self {
                compressed: point.compress(),
                point,
            }
        }

        pub(super) fn verify(
            &self,
            suite: Ciphersuite,
            alpha: &[u8],
            proof: EdVrfProof,
        ) -> VrfResult<EdVrfProof> {
            // 4. D = ECVRF_decode_proof(pi_string) (see Section 5.4.4)
            // 6. (Gamma, c, s) = D
            let EdVrfProof { gamma, c, s } = proof;
            // 7. H = ECVRF_encode_to_curve(encode_to_curve_salt, alpha_string) (see Section 5.4.1)
            let h = self.encode_to_curve(suite, alpha)?;

            // 8. U = s*B - c*Y
            let u = EdwardsPoint::mul_base(&s) - c * self.point;
            // 9. V = s*H - c*Gamma
            let v = s * h.point - c * gamma;
            // 10. c' = ECVRF_challenge_generation(Y, H, Gamma, U, V) (see Section 5.4.3)
            let c_prime = EdChallenge::generate(suite, &[&self.point, &h.point, &gamma, &u, &v]);

            // 11.  If c and c' are equal, output ("VALID", ECVRF_proof_to_hash(pi_string)); else output "INVALID"
            if c_prime != c {
                return Err(VrfError::ProofVerificationFailure);
            }

            Ok(EdVrfProof { gamma, c, s })
        }
    }

    pub struct EdChallenge;

    impl EdChallenge {
        pub fn from_challenge_bytes(c_string: &[u8; CHALLENGE_LEN]) -> Scalar {
            let mut c_scalar_bytes = [0u8; 32];
            c_scalar_bytes[..CHALLENGE_LEN].copy_from_slice(c_string);
            Scalar::from_bytes_mod_order(c_scalar_bytes)
        }

        pub fn generate(suite: Ciphersuite, points: &[&EdwardsPoint; 5]) -> Scalar {
            let compressed = points.map(EdwardsPoint::compress);

            Self::from_challenge_bytes(&util::challenge_bytes::<CHALLENGE_LEN, Sha512>(
                suite,
                compressed.iter().map(|c| c.as_bytes().as_slice()),
            ))
        }
    }
}
