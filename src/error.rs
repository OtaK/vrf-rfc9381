use crate::Ciphersuite;

#[derive(Debug, thiserror::Error)]
pub enum VrfError {
    #[error(transparent)]
    IncorrectSliceSize(#[from] std::array::TryFromSliceError),
    #[error("The length of `pi_string` is incorrect, expected: {expected} but got {actual}")]
    IncorrectPiLength { expected: usize, actual: usize },
    #[error("The TryAndIncrement algorithm (TAI) could not find any suitable candidate")]
    TryAndIncrementNoCandidatesFound,
    #[error("The requested ciphersuite ({0}) isn't supported")]
    UnsupportedCiphersuite(Ciphersuite),
    #[error("The verification of the Proof has failed")]
    ProofVerificationFailure,
    #[cfg(feature = "p256")]
    #[error(transparent)]
    P256Error(#[from] p256::elliptic_curve::Error),
    #[cfg(feature = "p256")]
    #[error(transparent)]
    P256Hash2CurveError(#[from] hash2curve::ExpandMsgXmdError),
    #[cfg(feature = "ec")]
    #[error("Invalid Elliptic Curve point")]
    InvalidEcPoint,
}

pub type VrfResult<T> = Result<T, VrfError>;
