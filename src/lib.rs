#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]

use crate::error::VrfResult;
// #[cfg(feature = "rsa")]
// compile_error!(
//     "The `rsa` feature isn't implemented yet. Please express support for it in the repo for it to be implemented."
// );

pub(crate) mod consts;

pub mod error;

#[cfg(feature = "ec")]
pub mod ec;
// No support yet
// #[cfg(feature = "rsa")]
// pub mod rsa;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Ciphersuite(u8);

impl Ciphersuite {
    pub const ECVRF_P256_SHA256_TAI: Ciphersuite =
        Ciphersuite(crate::consts::ecvrf::ciphersuites::ECVRF_P256_SHA256_TAI);
    pub const ECVRF_P256_SHA256_SSWU: Ciphersuite =
        Ciphersuite(crate::consts::ecvrf::ciphersuites::ECVRF_P256_SHA256_SSWU);
    pub const ECVRF_EDWARDS25519_SHA512_TAI: Ciphersuite =
        Ciphersuite(crate::consts::ecvrf::ciphersuites::ECVRF_EDWARDS25519_SHA512_TAI);
    pub const ECVRF_EDWARDS25519_SHA512_ELL2: Ciphersuite =
        Ciphersuite(crate::consts::ecvrf::ciphersuites::ECVRF_EDWARDS25519_SHA512_ELL2);

    pub const RSA_FDH_VRF_SHA256: Ciphersuite =
        Ciphersuite(crate::consts::rsavrf::ciphersuites::RSA_FDH_VRF_SHA256);
    pub const RSA_FDH_VRF_SHA384: Ciphersuite =
        Ciphersuite(crate::consts::rsavrf::ciphersuites::RSA_FDH_VRF_SHA384);
    pub const RSA_FDH_VRF_SHA512: Ciphersuite =
        Ciphersuite(crate::consts::rsavrf::ciphersuites::RSA_FDH_VRF_SHA512);
}

impl From<u8> for Ciphersuite {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for Ciphersuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ciphersuite[{:#2X}]", self.0)
    }
}

impl std::ops::Deref for Ciphersuite {
    type Target = u8;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub trait Proof<H: digest::Digest>: PartialEq + Eq {
    const PROOF_LEN: usize;
    /// Decodes the `pi_string` to a concrete Proof
    fn decode_pi(pi: &[u8]) -> VrfResult<Self>
    where
        Self: Sized;
    /// Encodes this proof to `pi_string`
    fn encode_to_pi(&self) -> Vec<u8>;
    /// Performs the proof to hash operation on the VRF Proof
    fn proof_to_hash(&self, suite: Ciphersuite) -> VrfResult<digest::Output<H>>;
}

pub trait Prover<H: digest::Digest>: PartialEq + Eq {
    /// The Proof emitted by this Prover
    type Proof: Proof<H>;
    /// The public counterpart (Verifier) of this Prover
    type Verifier: Verifier<H, Proof = Self::Proof>;

    #[cfg(feature = "hazmat")]
    /// Hazmat internal allowing to check if the scalar x equals a value. Do not use!
    fn x_equals(&self, value: &[u8]) -> bool;

    /// Deserialize a Prover from its byte representation
    fn from_slice(bytes: &[u8]) -> VrfResult<Self>
    where
        Self: Sized;

    /// Get the public counterpart of this Prover
    fn verifier(&self) -> Self::Verifier;
    /// Proves `alpha` as a VRF Proof
    fn prove(&self, alpha: &[u8]) -> VrfResult<Self::Proof>;
}

pub trait Verifier<H: digest::Digest>: PartialEq + Eq {
    /// The Proof that this Verifier can verify
    type Proof: Proof<H>;
    fn from_slice(bytes: &[u8]) -> VrfResult<Self>
    where
        Self: Sized;
    /// Verifies a (alpha, proof) combo, and outputs the VRF_proof_to_hash if successful
    fn verify(&self, alpha: &[u8], proof: Self::Proof) -> VrfResult<digest::Output<H>>;
}

/// Supertrait that combines all the features of Proof, Verifier and Prover in an easy-to-use package
pub trait VRF {
    /// Hash algorithm in use
    type Hash: digest::Digest;
    /// The Proof type for this VRF.
    type Proof: Proof<Self::Hash>;
    /// The Verifier in use for this VRF; It's usually some sort of Public Key
    type Verifier: Verifier<Self::Hash, Proof = Self::Proof>;
    /// The Prover in use for this VRF; It's usually some sort of Secret Key
    type Prover: Prover<Self::Hash, Proof = Self::Proof, Verifier = Self::Verifier>;
    /// The Ciphersuite in use for this VRF
    fn ciphersuite(&self) -> Ciphersuite;

    /// Outputs pi
    fn prove(&self, prover: &Self::Prover, alpha: &[u8]) -> VrfResult<Vec<u8>> {
        Ok(prover.prove(alpha)?.encode_to_pi())
    }

    /// Outputs VRF_proof_to_hash(pi)
    fn verify(
        &self,
        verifier: &Self::Verifier,
        alpha: &[u8],
        pi: &[u8],
    ) -> VrfResult<digest::Output<Self::Hash>> {
        verifier.verify(alpha, Self::Proof::decode_pi(pi)?)
    }
}
