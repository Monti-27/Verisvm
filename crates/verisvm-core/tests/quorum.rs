use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use serde::Deserialize;
use verisvm_core::{
    BuildEvidence, BuildOutcome, BuildPredicate, BuildRecipe, Cluster, Deployment, Digest,
    DsseEnvelope, EvidenceIssueKind, IntegrityStatus, ObservedDeployment, QuorumPolicy,
    SolanaAddress, SourceRevision, VerificationJob, WorkerIdentity, build_statement, evaluate,
    sign_statement,
};

fn digest(byte: u8) -> Digest {
    Digest::new([byte; 32])
}

fn address(byte: u8) -> SolanaAddress {
    SolanaAddress::new([byte; 32])
}

fn job() -> VerificationJob {
    VerificationJob {
        id: "job-01".to_owned(),
        deployment: Deployment {
            cluster: Cluster::MainnetBeta,
            program_id: address(9),
            program_data_address: Some(address(10)),
            deployment_slot: 300,
            executable_digest: digest(11),
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
            command: vec!["cargo".to_owned(), "build-sbf".to_owned()],
            cargo_lock_digest: Some(digest(14)),
        },
    }
}

fn envelope(
    job: &VerificationJob,
    key_byte: u8,
    failure_domain: &str,
    outcome: BuildOutcome,
) -> DsseEnvelope {
    let executable_digest = match outcome {
        BuildOutcome::Match => Some(job.deployment.executable_digest),
        BuildOutcome::Mismatch => Some(digest(99)),
        BuildOutcome::BuildFailed => None,
    };
    let statement = build_statement(BuildPredicate {
        job: job.clone(),
        worker: WorkerIdentity {
            id: format!("worker-{key_byte}"),
            failure_domain: failure_domain.to_owned(),
        },
        evidence: BuildEvidence {
            outcome,
            executable_digest,
            transcript_digest: digest(key_byte),
        },
        observed_at_slot: 350,
    });
    sign_statement(&statement, &SigningKey::from_bytes(&[key_byte; 32]))
        .expect("statement should sign")
}

fn observed(job: &VerificationJob) -> ObservedDeployment {
    ObservedDeployment {
        deployment: job.deployment.clone(),
        observed_at_slot: 400,
    }
}

fn policy() -> QuorumPolicy {
    QuorumPolicy {
        minimum_operators: 3,
        minimum_failure_domains: 3,
        maximum_age_slots: Some(100),
        operator_failure_domains: BTreeMap::from([
            (operator(1), "aws:us-east-1".to_owned()),
            (operator(2), "gcp:us-central1".to_owned()),
            (operator(3), "bare-metal:hel1".to_owned()),
            (operator(4), "azure:westeurope".to_owned()),
        ]),
    }
}

fn operator(key_byte: u8) -> SolanaAddress {
    SolanaAddress::new(
        SigningKey::from_bytes(&[key_byte; 32])
            .verifying_key()
            .to_bytes(),
    )
}

#[test]
fn three_independent_matches_reach_quorum() {
    let job = job();
    let envelopes = vec![
        envelope(&job, 1, "aws:us-east-1", BuildOutcome::Match),
        envelope(&job, 2, "gcp:us-central1", BuildOutcome::Match),
        envelope(&job, 3, "bare-metal:hel1", BuildOutcome::Match),
    ];

    let decision = evaluate(&job, &observed(&job), &policy(), &envelopes).expect("valid policy");

    assert_eq!(decision.status, IntegrityStatus::Verified);
    assert_eq!(decision.matching_operators, 3);
    assert_eq!(decision.matching_failure_domains, 3);
}

#[test]
fn a_valid_mismatch_disputes_the_result() {
    let job = job();
    let envelopes = vec![
        envelope(&job, 1, "aws:us-east-1", BuildOutcome::Match),
        envelope(&job, 2, "gcp:us-central1", BuildOutcome::Match),
        envelope(&job, 3, "bare-metal:hel1", BuildOutcome::Match),
        envelope(&job, 4, "azure:westeurope", BuildOutcome::Mismatch),
    ];

    let decision = evaluate(&job, &observed(&job), &policy(), &envelopes).expect("valid policy");

    assert_eq!(decision.status, IntegrityStatus::Disputed);
    assert_eq!(decision.mismatches, 1);
}

#[test]
fn an_upgrade_makes_the_entire_job_stale() {
    let job = job();
    let envelopes = vec![envelope(&job, 1, "aws:us-east-1", BuildOutcome::Match)];
    let mut current = observed(&job);
    current.deployment.deployment_slot += 1;
    current.deployment.executable_digest = digest(42);

    let decision = evaluate(&job, &current, &policy(), &envelopes).expect("valid policy");

    assert_eq!(decision.status, IntegrityStatus::Stale);
    assert_eq!(decision.stale, 1);
}

#[test]
fn duplicate_operator_evidence_counts_once() {
    let job = job();
    let first = envelope(&job, 1, "aws:us-east-1", BuildOutcome::Match);
    let decision =
        evaluate(&job, &observed(&job), &policy(), &[first.clone(), first]).expect("valid policy");

    assert_eq!(decision.status, IntegrityStatus::InsufficientEvidence);
    assert_eq!(decision.matching_operators, 1);
    assert_eq!(decision.rejected, 1);
    assert_eq!(decision.issues[0].kind, EvidenceIssueKind::Duplicate);
}

#[test]
fn a_tampered_payload_is_rejected() {
    let job = job();
    let mut attestation = envelope(&job, 1, "aws:us-east-1", BuildOutcome::Match);
    attestation.payload.push('A');

    let decision =
        evaluate(&job, &observed(&job), &policy(), &[attestation]).expect("valid policy");

    assert_eq!(decision.status, IntegrityStatus::InsufficientEvidence);
    assert_eq!(decision.rejected, 1);
    assert_eq!(decision.issues[0].kind, EvidenceIssueKind::Invalid);
}

#[test]
fn allowlist_rejects_unknown_operators() {
    let job = job();
    let attestation = envelope(&job, 1, "aws:us-east-1", BuildOutcome::Match);
    let mut policy = policy();
    policy.minimum_operators = 1;
    policy.minimum_failure_domains = 1;
    policy.operator_failure_domains = BTreeMap::from([(address(77), "test".to_owned())]);

    let decision = evaluate(&job, &observed(&job), &policy, &[attestation]).expect("valid policy");

    assert_eq!(decision.status, IntegrityStatus::InsufficientEvidence);
    assert_eq!(
        decision.issues[0].kind,
        EvidenceIssueKind::UntrustedOperator
    );
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    job: VerificationJob,
    deployment: ObservedDeployment,
    policy: QuorumPolicy,
    attestations: Vec<DsseEnvelope>,
}

#[test]
fn shared_wire_fixture_verifies_in_rust() {
    let fixture: Fixture = serde_json::from_str(include_str!("../../../fixtures/quorum.json"))
        .expect("fixture should parse");
    let decision = evaluate(
        &fixture.job,
        &fixture.deployment,
        &fixture.policy,
        &fixture.attestations,
    )
    .expect("valid fixture policy");
    assert_eq!(decision.status, IntegrityStatus::Verified);
}

#[test]
fn worker_cannot_self_assign_a_failure_domain() {
    let job = job();
    let attestation = envelope(&job, 1, "aws:us-east-1", BuildOutcome::Match);
    let mut policy = policy();
    policy.minimum_operators = 1;
    policy.minimum_failure_domains = 1;
    policy
        .operator_failure_domains
        .insert(operator(1), "gcp:us-central1".to_owned());

    let decision =
        evaluate(&job, &observed(&job), &policy, &[attestation]).expect("policy should be valid");

    assert_eq!(decision.status, IntegrityStatus::InsufficientEvidence);
    assert_eq!(
        decision.issues[0].kind,
        EvidenceIssueKind::FailureDomainMismatch
    );
}

#[test]
fn policy_must_have_enough_registered_operators() {
    let job = job();
    let mut policy = policy();
    policy.operator_failure_domains.clear();

    assert!(evaluate(&job, &observed(&job), &policy, &[]).is_err());
}
