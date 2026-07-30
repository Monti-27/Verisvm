use thiserror::Error;
use verisvm_core::{Digest, SolanaAddress};

pub type AdapterError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid worker configuration: {0}")]
    InvalidConfiguration(String),
    #[error("invalid repository: {0}")]
    InvalidRepository(String),
    #[error("invalid verification job: {0}")]
    InvalidJob(#[source] verisvm_core::Error),
    #[error("unsupported verification job: {0}")]
    UnsupportedJob(String),
    #[error("build executor failed")]
    Executor(#[source] AdapterError),
    #[error("deployment reader failed")]
    DeploymentReader(#[source] AdapterError),
    #[error("evidence signer failed")]
    Signer(#[source] AdapterError),
    #[error("execution identity mismatch for {field}: expected {expected}, observed {observed}")]
    ExecutionIdentity {
        field: &'static str,
        expected: String,
        observed: String,
    },
    #[error("invalid execution report: {0}")]
    InvalidExecutionReport(String),
    #[error("transcript exceeds the configured byte limit")]
    TranscriptTooLarge,
    #[error("artifact exceeds the configured byte limit")]
    ArtifactTooLarge,
    #[error("invalid deployment observation: {0}")]
    InvalidDeploymentObservation(String),
    #[error("signed attestation is invalid")]
    InvalidSignedAttestation(#[source] verisvm_core::Error),
    #[error("attestation signer mismatch: expected {expected}, observed {observed}")]
    UnexpectedSigner {
        expected: SolanaAddress,
        observed: SolanaAddress,
    },
    #[error("attestation payload differs from the worker statement")]
    SignedStatementMismatch,
    #[error("source tree digest mismatch: expected {expected}, observed {observed}")]
    SourceTreeDigest { expected: Digest, observed: Digest },
}

pub type Result<T> = std::result::Result<T, Error>;
