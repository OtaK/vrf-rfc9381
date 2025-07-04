use pretty_assertions::assert_eq;
use vrf_rfc9381::{
    Ciphersuite, VRF,
    ec::{
        edwards25519::{elligator2::EdVrfEdwards25519Ell2, tai::EdVrfEdwards25519Tai},
        p256::{sswu::EcVrfP256Sswu, tai::EcVrfP256Tai},
    },
};

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EcVrfTestVectorMethodDetails {
    #[serde(rename = "tai")]
    TryAndIncrement { expected_tai_ctr: u8 },
    #[serde(rename = "h2c")]
    Hash2Curve {
        #[serde(with = "faster_hex::nopfx_ignorecase")]
        uniform_bytes: Vec<u8>,
        #[serde(with = "faster_hex::nopfx_ignorecase")]
        u: Vec<u8>,
        #[serde(with = "faster_hex::nopfx_ignorecase")]
        gx1: Vec<u8>,
        gx1_is_square: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct EcVrfTestVector {
    pub name: String,
    pub suite: u8,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub sk: Vec<u8>,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub x: Vec<u8>,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub pk: Vec<u8>,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub alpha: Vec<u8>,
    #[serde(flatten)]
    pub details: EcVrfTestVectorMethodDetails,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub h: Vec<u8>,
    #[serde(
        with = "faster_hex::option_nopfx_ignorecase",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub k_string: Option<Vec<u8>>,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub k: Vec<u8>,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub u: Vec<u8>,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub v: Vec<u8>,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub pi: Vec<u8>,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub beta: Vec<u8>,
}

impl EcVrfTestVector {
    pub fn run_test_vector_for_vrf<V: VRF>(&self, vrf_alg: V) -> color_eyre::eyre::Result<()>
    where
        V::Proof: std::fmt::Debug,
        V::Verifier: std::fmt::Debug,
    {
        use vrf_rfc9381::{Proof, Prover, Verifier};

        let suite = vrf_alg.ciphersuite();

        // Deserialize Prover
        let prover = V::Prover::from_slice(&self.sk)?;

        // Check if the internal scalar is equal `x`
        assert!(prover.x_equals(&self.x));

        // Generate the Verifier from the Prover
        let verifier = prover.verifier();
        // Deserialize the Verifier from TV
        let tv_verifier = V::Verifier::from_slice(&self.pk)?;
        // And check if they're the same
        assert_eq!(verifier, tv_verifier);

        // Deserialize the Proof from TV
        let tv_proof = V::Proof::decode_pi(&self.pi)?;
        // Compute ProofToHash and check if equals TV.beta
        let tv_proof_hash = tv_proof.proof_to_hash(suite)?;
        assert_eq!(tv_proof_hash.as_slice(), self.beta);
        // Run Prover.prove() and check if it equals the TV proof
        let proof = prover.prove(&self.alpha)?;
        assert_eq!(proof, tv_proof);
        // Encode the Proof to pi and check if it equals TV.pi
        let proof_pi = proof.encode_to_pi();
        assert_eq!(proof_pi, self.pi);

        // Verify the proof using Verifier and output Beta
        let proof_beta = verifier.verify(&self.alpha, proof)?;
        assert_eq!(proof_beta.as_slice(), &self.beta);

        Ok(())
    }
}

impl crate::TestVector for EcVrfTestVector {
    fn file_names() -> Vec<&'static str> {
        vec![
            "edwards25519_tai.json",
            "edwards25519_ell2.json",
            "p256_tai.json",
            "p256_sswu.json",
        ]
    }

    fn execute(self) -> color_eyre::eyre::Result<()> {
        match Ciphersuite::from(self.suite) {
            Ciphersuite::ECVRF_P256_SHA256_TAI => {
                self.run_test_vector_for_vrf(EcVrfP256Tai)?;
            }
            Ciphersuite::ECVRF_P256_SHA256_SSWU => {
                self.run_test_vector_for_vrf(EcVrfP256Sswu)?;
            }
            Ciphersuite::ECVRF_EDWARDS25519_SHA512_TAI => {
                self.run_test_vector_for_vrf(EdVrfEdwards25519Tai)?;
            }
            Ciphersuite::ECVRF_EDWARDS25519_SHA512_ELL2 => {
                self.run_test_vector_for_vrf(EdVrfEdwards25519Ell2)?;
            }
            _ => unreachable!("Unknown ciphersuite"),
        }

        Ok(())
    }

    fn name(&self) -> String {
        self.name.clone()
    }
}
