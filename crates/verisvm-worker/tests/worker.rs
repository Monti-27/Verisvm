use std::{collections::BTreeSet, future};

use ed25519_dalek::SigningKey;
use verisvm_core::{
    BuildOutcome, BuildRecipe, Cluster, Deployment, Digest, ObservedDeployment, SolanaAddress,
    SourceRevision, Statement, VerificationJob, WorkerIdentity, decode_and_verify, sign_statement,
};
use verisvm_worker::{
    AdapterError, BuildExecutor, BuilderPolicy, DeploymentReader, EvidenceSigner,
    ExecutionIdentity, ExecutionLimits, ExecutionReport, ExecutionRequest, RepositoryPolicy,
    Termination, Transcript, TranscriptEntry, TranscriptStream, Worker, WorkerConfig,
};

fn digest(byte: u8) -> Digest {
    Digest::new([byte; 32])
}

fn address(byte: u8) -> SolanaAddress {
    SolanaAddress::new([byte; 32])
}

fn artifact() -> Vec<u8> {
    b"compiled program".to_vec()
}

fn artifact_digest() -> Digest {
    use sha2::{Digest as _, Sha256};

    Digest::new(Sha256::digest(artifact()).into())
}

fn job() -> VerificationJob {
    VerificationJob {
        id: "job-01".to_owned(),
        deployment: Deployment {
            cluster: Cluster::MainnetBeta,
            program_id: address(9),
            program_data_address: Some(address(10)),
            deployment_slot: 300,
            executable_digest: artifact_digest(),
        },
        source: SourceRevision {
            repository: "https://github.com/example/program".to_owned(),
            commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            tree_digest: digest(12),
        },
        recipe: BuildRecipe {
            builder_image_digest: digest(13),
            solana_verify_version: "0.5.1".to_owned(),
            rust_toolchain: "1.86.0".to_owned(),
            solana_toolchain: "3.0.0".to_owned(),
            command: vec!["solana-verify".to_owned(), "build".to_owned()],
            cargo_lock_digest: Some(digest(14)),
        },
    }
}

fn transcript(termination: Termination) -> Transcript {
    Transcript::new(
        termination,
        vec![
            TranscriptEntry {
                sequence: 0,
                stream: TranscriptStream::System,
                data: b"executor started".to_vec(),
            },
            TranscriptEntry {
                sequence: 1,
                stream: TranscriptStream::Stdout,
                data: b"build complete".to_vec(),
            },
        ],
    )
    .expect("valid transcript")
}

fn report(job: &VerificationJob, termination: Termination) -> ExecutionReport {
    ExecutionReport {
        identity: ExecutionIdentity {
            source_repository: job.source.repository.clone(),
            source_commit: job.source.commit.clone(),
            source_tree_digest: job.source.tree_digest,
            builder_image_digest: job.recipe.builder_image_digest,
            solana_verify_version: job.recipe.solana_verify_version.clone(),
            rust_toolchain: job.recipe.rust_toolchain.clone(),
            solana_toolchain: job.recipe.solana_toolchain.clone(),
            command: job.recipe.command.clone(),
            cargo_lock_digest: job.recipe.cargo_lock_digest,
        },
        transcript: transcript(termination),
        artifact: termination.succeeded().then(artifact),
    }
}

#[derive(Clone)]
struct MockExecutor {
    report: ExecutionReport,
}

impl BuildExecutor for MockExecutor {
    fn execute(
        &self,
        _request: ExecutionRequest<'_>,
    ) -> impl Future<Output = std::result::Result<ExecutionReport, AdapterError>> + Send {
        future::ready(Ok(self.report.clone()))
    }
}

#[derive(Clone)]
struct MockDeploymentReader {
    observed: ObservedDeployment,
}

impl DeploymentReader for MockDeploymentReader {
    fn read_finalized(
        &self,
        _expected: &Deployment,
    ) -> impl Future<Output = std::result::Result<ObservedDeployment, AdapterError>> + Send {
        future::ready(Ok(self.observed.clone()))
    }
}

struct LocalSigner(SigningKey);

impl EvidenceSigner for LocalSigner {
    fn sign(
        &self,
        statement: &Statement,
    ) -> impl Future<Output = std::result::Result<verisvm_core::DsseEnvelope, AdapterError>> + Send
    {
        future::ready(sign_statement(statement, &self.0).map_err(Into::into))
    }
}

fn worker(
    job: &VerificationJob,
    report: ExecutionReport,
) -> Worker<MockExecutor, MockDeploymentReader, LocalSigner> {
    let signing_key = SigningKey::from_bytes(&[1; 32]);
    let operator = SolanaAddress::new(signing_key.verifying_key().to_bytes());
    Worker::new(
        WorkerConfig {
            operator,
            identity: WorkerIdentity {
                id: "worker-01".to_owned(),
                failure_domain: "aws:us-east-1".to_owned(),
            },
            repositories: RepositoryPolicy::new(BTreeSet::from(["github.com".to_owned()]))
                .expect("valid repository policy"),
            builders: BuilderPolicy::new(BTreeSet::from([(
                job.recipe.solana_verify_version.clone(),
                job.recipe.builder_image_digest,
            )]))
            .expect("valid builder policy"),
            limits: ExecutionLimits::default(),
        },
        MockExecutor { report },
        MockDeploymentReader {
            observed: ObservedDeployment {
                deployment: job.deployment.clone(),
                observed_at_slot: 350,
            },
        },
        LocalSigner(signing_key),
    )
}

#[tokio::test]
async fn matching_build_produces_verified_attestation() {
    let job = job();
    let completed = worker(&job, report(&job, Termination::Exited(0)))
        .run(&job)
        .await
        .expect("worker should complete");
    let verified = decode_and_verify(&completed.envelope).expect("valid attestation");

    assert_eq!(completed.evidence.outcome, BuildOutcome::Match);
    assert_eq!(
        completed.evidence.executable_digest,
        Some(job.deployment.executable_digest)
    );
    assert_eq!(verified.statement.predicate.evidence, completed.evidence);
}

#[tokio::test]
async fn different_artifact_produces_mismatch() {
    let job = job();
    let mut execution = report(&job, Termination::Exited(0));
    execution.artifact = Some(b"different program".to_vec());
    let completed = worker(&job, execution)
        .run(&job)
        .await
        .expect("worker should complete");

    assert_eq!(completed.evidence.outcome, BuildOutcome::Mismatch);
    assert_ne!(
        completed.evidence.executable_digest,
        Some(job.deployment.executable_digest)
    );
}

#[tokio::test]
async fn failed_build_produces_failure_evidence() {
    let job = job();
    let completed = worker(&job, report(&job, Termination::Exited(101)))
        .run(&job)
        .await
        .expect("worker should complete");

    assert_eq!(completed.evidence.outcome, BuildOutcome::BuildFailed);
    assert_eq!(completed.evidence.executable_digest, None);
}

#[tokio::test]
async fn source_identity_mismatch_is_rejected() {
    let job = job();
    let mut execution = report(&job, Termination::Exited(0));
    execution.identity.source_tree_digest = digest(99);

    assert!(worker(&job, execution).run(&job).await.is_err());
}

#[tokio::test]
async fn runtime_identity_mismatch_is_rejected() {
    let job = job();
    let mut execution = report(&job, Termination::Exited(0));
    execution.identity.builder_image_digest = digest(99);

    assert!(worker(&job, execution).run(&job).await.is_err());
}

#[tokio::test]
async fn repository_outside_the_operator_allowlist_is_rejected() {
    let mut job = job();
    job.source.repository = "https://localhost/program".to_owned();
    let execution = report(&job, Termination::Exited(0));

    assert!(worker(&job, execution).run(&job).await.is_err());
}

#[tokio::test]
async fn successful_build_without_artifact_is_rejected() {
    let job = job();
    let mut execution = report(&job, Termination::Exited(0));
    execution.artifact = None;

    assert!(worker(&job, execution).run(&job).await.is_err());
}

#[tokio::test]
async fn signer_identity_is_verified() {
    let job = job();
    let execution = report(&job, Termination::Exited(0));
    let instance = Worker::new(
        WorkerConfig {
            operator: address(88),
            identity: WorkerIdentity {
                id: "worker-01".to_owned(),
                failure_domain: "aws:us-east-1".to_owned(),
            },
            repositories: RepositoryPolicy::github_only(),
            builders: BuilderPolicy::new(BTreeSet::from([(
                job.recipe.solana_verify_version.clone(),
                job.recipe.builder_image_digest,
            )]))
            .expect("valid builder policy"),
            limits: ExecutionLimits::default(),
        },
        MockExecutor { report: execution },
        MockDeploymentReader {
            observed: ObservedDeployment {
                deployment: job.deployment.clone(),
                observed_at_slot: 350,
            },
        },
        LocalSigner(SigningKey::from_bytes(&[1; 32])),
    );

    assert!(instance.run(&job).await.is_err());
}

#[tokio::test]
async fn source_commit_mismatch_is_rejected() {
    let job = job();
    let mut execution = report(&job, Termination::Exited(0));
    execution.identity.source_commit = "abcdef0123456789abcdef0123456789abcdef01".to_owned();

    assert!(worker(&job, execution).run(&job).await.is_err());
}

#[tokio::test]
async fn direct_build_command_is_rejected() {
    let mut job = job();
    job.recipe.command = vec!["cargo".to_owned(), "build-sbf".to_owned()];
    let execution = report(&job, Termination::Exited(0));

    assert!(worker(&job, execution).run(&job).await.is_err());
}
