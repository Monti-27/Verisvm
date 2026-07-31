use std::future::Future;

use verisvm_core::{
    Deployment, Digest, DsseEnvelope, ObservedDeployment, Statement, VerificationJob,
};

use crate::{AdapterError, ExecutionLimits, Transcript};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionIdentity {
    pub source_repository: String,
    pub source_commit: String,
    pub source_tree_digest: Digest,
    pub builder_image_digest: Digest,
    pub solana_verify_version: String,
    pub rust_toolchain: String,
    pub solana_toolchain: String,
    pub command: Vec<String>,
    pub cargo_lock_digest: Option<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionReport {
    pub identity: ExecutionIdentity,
    pub transcript: Transcript,
    pub artifact: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug)]
pub struct ExecutionRequest<'a> {
    pub job: &'a VerificationJob,
    pub limits: &'a ExecutionLimits,
}

pub trait BuildExecutor: Send + Sync {
    fn execute(
        &self,
        request: ExecutionRequest<'_>,
    ) -> impl Future<Output = std::result::Result<ExecutionReport, AdapterError>> + Send;
}

pub trait DeploymentReader: Send + Sync {
    fn read_finalized(
        &self,
        expected: &Deployment,
    ) -> impl Future<Output = std::result::Result<ObservedDeployment, AdapterError>> + Send;
}

pub trait EvidenceSigner: Send + Sync {
    fn sign(
        &self,
        statement: &Statement,
    ) -> impl Future<Output = std::result::Result<DsseEnvelope, AdapterError>> + Send;
}
