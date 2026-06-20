use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{Digest, SolanaAddress};

pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const PREDICATE_TYPE: &str = "https://verisvm.org/attestation/reproducible-build/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseEnvelope {
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<DsseSignature>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DsseSignature {
    pub keyid: String,
    pub sig: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Statement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<ResourceDescriptor>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: BuildPredicate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceDescriptor {
    pub name: String,
    pub digest: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildPredicate {
    pub job: VerificationJob,
    pub worker: WorkerIdentity,
    pub evidence: BuildEvidence,
    pub observed_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationJob {
    pub id: String,
    pub deployment: Deployment,
    pub source: SourceRevision,
    pub recipe: BuildRecipe,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Cluster {
    MainnetBeta,
    Devnet,
    Testnet,
    Localnet,
}

impl Cluster {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::MainnetBeta => "mainnet_beta",
            Self::Devnet => "devnet",
            Self::Testnet => "testnet",
            Self::Localnet => "localnet",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Deployment {
    pub cluster: Cluster,
    pub program_id: SolanaAddress,
    pub program_data_address: Option<SolanaAddress>,
    pub deployment_slot: u64,
    pub executable_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceRevision {
    pub repository: String,
    pub commit: String,
    pub tree_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildRecipe {
    pub builder_image_digest: Digest,
    pub solana_verify_version: String,
    pub rust_toolchain: String,
    pub solana_toolchain: String,
    pub command: Vec<String>,
    pub cargo_lock_digest: Option<Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerIdentity {
    pub id: String,
    pub failure_domain: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildEvidence {
    pub outcome: BuildOutcome,
    pub executable_digest: Option<Digest>,
    pub transcript_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildOutcome {
    Match,
    Mismatch,
    BuildFailed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedAttestation {
    pub operator: SolanaAddress,
    pub statement: Statement,
    pub payload_digest: Digest,
}
