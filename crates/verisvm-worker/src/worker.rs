use sha2::{Digest as _, Sha256};
use verisvm_core::{
    BuildEvidence, BuildOutcome, BuildPredicate, Digest, DsseEnvelope, ObservedDeployment,
    VerificationJob, build_statement, decode_and_verify, validate_job,
};

use crate::{
    BuildExecutor, DeploymentReader, Error, EvidenceSigner, ExecutionIdentity, ExecutionReport,
    ExecutionRequest, Result, WorkerConfig,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletedJob {
    pub envelope: DsseEnvelope,
    pub observed_deployment: ObservedDeployment,
    pub evidence: BuildEvidence,
    pub transcript: crate::Transcript,
    pub artifact: Option<Vec<u8>>,
}

pub struct Worker<E, D, S> {
    config: WorkerConfig,
    executor: E,
    deployments: D,
    signer: S,
}

impl<E, D, S> Worker<E, D, S>
where
    E: BuildExecutor,
    D: DeploymentReader,
    S: EvidenceSigner,
{
    #[must_use]
    pub const fn new(config: WorkerConfig, executor: E, deployments: D, signer: S) -> Self {
        Self {
            config,
            executor,
            deployments,
            signer,
        }
    }

    pub async fn run(&self, job: &VerificationJob) -> Result<CompletedJob> {
        self.config.validate()?;
        validate_job(job).map_err(Error::InvalidJob)?;
        self.config.repositories.validate(&job.source.repository)?;
        validate_worker_job(&self.config, job)?;
        let report = self
            .executor
            .execute(ExecutionRequest {
                job,
                limits: &self.config.limits,
            })
            .await
            .map_err(Error::Executor)?;
        validate_report(job, &self.config.limits, &report)?;
        let observed = self
            .deployments
            .read_finalized(&job.deployment)
            .await
            .map_err(Error::DeploymentReader)?;
        validate_observation(job, &observed)?;
        let evidence = build_evidence(job, &report);
        let statement = build_statement(BuildPredicate {
            job: job.clone(),
            worker: self.config.identity.clone(),
            evidence: evidence.clone(),
            observed_at_slot: observed.observed_at_slot,
        });
        let envelope = self.signer.sign(&statement).await.map_err(Error::Signer)?;
        let verified = decode_and_verify(&envelope).map_err(Error::InvalidSignedAttestation)?;
        if verified.operator != self.config.operator {
            return Err(Error::UnexpectedSigner {
                expected: self.config.operator,
                observed: verified.operator,
            });
        }
        if verified.statement != statement {
            return Err(Error::SignedStatementMismatch);
        }
        Ok(CompletedJob {
            envelope,
            observed_deployment: observed,
            evidence,
            transcript: report.transcript,
            artifact: report.artifact,
        })
    }
}

fn validate_worker_job(config: &WorkerConfig, job: &VerificationJob) -> Result<()> {
    if !config.builders.allows(job) {
        return Err(Error::UnsupportedJob(
            "builder image and Solana Verify version are not approved".to_owned(),
        ));
    }
    if job.recipe.command.first().map(String::as_str) != Some("solana-verify")
        || job.recipe.command.get(1).map(String::as_str) != Some("build")
    {
        return Err(Error::UnsupportedJob(
            "worker command must invoke solana-verify build".to_owned(),
        ));
    }
    if job.recipe.cargo_lock_digest.is_none() {
        return Err(Error::UnsupportedJob(
            "worker jobs require a Cargo.lock digest".to_owned(),
        ));
    }
    Ok(())
}

fn validate_report(
    job: &VerificationJob,
    limits: &crate::ExecutionLimits,
    report: &ExecutionReport,
) -> Result<()> {
    if report.identity.source_tree_digest != job.source.tree_digest {
        return Err(Error::SourceTreeDigest {
            expected: job.source.tree_digest,
            observed: report.identity.source_tree_digest,
        });
    }
    validate_identity(job, &report.identity)?;
    if report.transcript.byte_len() > limits.transcript_bytes {
        return Err(Error::TranscriptTooLarge);
    }
    if report
        .artifact
        .as_ref()
        .is_some_and(|artifact| artifact.len() > limits.artifact_bytes)
    {
        return Err(Error::ArtifactTooLarge);
    }
    match (
        report.transcript.termination().succeeded(),
        &report.artifact,
    ) {
        (true, Some(artifact)) if artifact.is_empty() => Err(Error::InvalidExecutionReport(
            "successful build returned an empty artifact".to_owned(),
        )),
        (true, None) => Err(Error::InvalidExecutionReport(
            "successful build did not return an artifact".to_owned(),
        )),
        (false, Some(_)) => Err(Error::InvalidExecutionReport(
            "failed build returned an artifact".to_owned(),
        )),
        _ => Ok(()),
    }
}

fn validate_identity(job: &VerificationJob, observed: &ExecutionIdentity) -> Result<()> {
    compare(
        "source repository",
        &job.source.repository,
        &observed.source_repository,
    )?;
    compare("source commit", &job.source.commit, &observed.source_commit)?;
    compare(
        "builder image digest",
        &job.recipe.builder_image_digest.to_string(),
        &observed.builder_image_digest.to_string(),
    )?;
    compare(
        "Solana Verify version",
        &job.recipe.solana_verify_version,
        &observed.solana_verify_version,
    )?;
    compare(
        "Rust toolchain",
        &job.recipe.rust_toolchain,
        &observed.rust_toolchain,
    )?;
    compare(
        "Solana toolchain",
        &job.recipe.solana_toolchain,
        &observed.solana_toolchain,
    )?;
    compare(
        "build command",
        &format!("{:?}", job.recipe.command),
        &format!("{:?}", observed.command),
    )?;
    compare(
        "Cargo.lock digest",
        &format!("{:?}", job.recipe.cargo_lock_digest),
        &format!("{:?}", observed.cargo_lock_digest),
    )
}

fn compare(field: &'static str, expected: &str, observed: &str) -> Result<()> {
    if expected != observed {
        return Err(Error::ExecutionIdentity {
            field,
            expected: expected.to_owned(),
            observed: observed.to_owned(),
        });
    }
    Ok(())
}

fn validate_observation(job: &VerificationJob, observed: &ObservedDeployment) -> Result<()> {
    if observed.deployment.cluster != job.deployment.cluster
        || observed.deployment.program_id != job.deployment.program_id
    {
        return Err(Error::InvalidDeploymentObservation(
            "cluster or program address differs from the job".to_owned(),
        ));
    }
    if observed.observed_at_slot < observed.deployment.deployment_slot
        || observed.observed_at_slot < job.deployment.deployment_slot
    {
        return Err(Error::InvalidDeploymentObservation(
            "finalized observation predates a deployment".to_owned(),
        ));
    }
    Ok(())
}

fn build_evidence(job: &VerificationJob, report: &ExecutionReport) -> BuildEvidence {
    let executable_digest = report.artifact.as_ref().map(|artifact| {
        let digest: [u8; 32] = Sha256::digest(artifact).into();
        Digest::new(digest)
    });
    let outcome = if report.transcript.termination().succeeded() {
        if executable_digest == Some(job.deployment.executable_digest) {
            BuildOutcome::Match
        } else {
            BuildOutcome::Mismatch
        }
    } else {
        BuildOutcome::BuildFailed
    };
    BuildEvidence {
        outcome,
        executable_digest,
        transcript_digest: report.transcript.digest(),
    }
}
