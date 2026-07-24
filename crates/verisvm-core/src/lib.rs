mod attestation;
mod error;
mod model;
mod policy;
mod value;

pub use attestation::{
    build_statement, decode_and_verify, dsse_pae, sign_statement, statement_payload_digest,
    validate_job,
};
pub use error::{Error, Result};
pub use model::{
    BuildEvidence, BuildOutcome, BuildPredicate, BuildRecipe, Cluster, DSSE_PAYLOAD_TYPE,
    Deployment, DsseEnvelope, DsseSignature, PREDICATE_TYPE, ResourceDescriptor, STATEMENT_TYPE,
    SourceRevision, Statement, VerificationJob, VerifiedAttestation, WorkerIdentity,
};
pub use policy::{
    EvidenceIssue, EvidenceIssueKind, IntegrityStatus, ObservedDeployment, QuorumDecision,
    QuorumPolicy, evaluate,
};
pub use value::{Digest, SolanaAddress};
