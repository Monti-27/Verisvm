use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid base64 payload: {0}")]
    InvalidPayloadEncoding(#[source] base64::DecodeError),
    #[error("invalid attestation payload: {0}")]
    InvalidPayload(#[source] serde_json::Error),
    #[error("unsupported payload type: {0}")]
    UnsupportedPayloadType(String),
    #[error("unsupported statement type: {0}")]
    UnsupportedStatementType(String),
    #[error("unsupported predicate type: {0}")]
    UnsupportedPredicateType(String),
    #[error("an attestation must contain exactly one signature")]
    InvalidSignatureCount,
    #[error("invalid operator public key")]
    InvalidPublicKey,
    #[error("invalid signature encoding")]
    InvalidSignatureEncoding,
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    #[error("invalid SHA-256 digest: {0}")]
    InvalidDigest(String),
    #[error("invalid Solana address: {0}")]
    InvalidSolanaAddress(String),
    #[error("statement subject does not describe the job deployment")]
    InvalidSubject,
    #[error("attestation result is inconsistent with the deployed executable")]
    InvalidBuildResult,
    #[error("invalid verification job: {0}")]
    InvalidJob(String),
    #[error("invalid worker identity: {0}")]
    InvalidWorker(String),
    #[error("invalid quorum policy: {0}")]
    InvalidPolicy(String),
}

pub type Result<T> = std::result::Result<T, Error>;
