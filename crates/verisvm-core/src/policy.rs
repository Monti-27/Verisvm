use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    BuildOutcome, Deployment, DsseEnvelope, Error, Result, SolanaAddress, VerificationJob,
    attestation::validate_job, decode_and_verify,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservedDeployment {
    pub deployment: Deployment,
    pub observed_at_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumPolicy {
    pub minimum_operators: usize,
    pub minimum_failure_domains: usize,
    pub maximum_age_slots: Option<u64>,
    pub operator_failure_domains: BTreeMap<SolanaAddress, String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityStatus {
    Verified,
    Disputed,
    Stale,
    InsufficientEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumDecision {
    pub status: IntegrityStatus,
    pub job_id: String,
    pub matching_operators: usize,
    pub matching_failure_domains: usize,
    pub mismatches: usize,
    pub build_failures: usize,
    pub stale: usize,
    pub rejected: usize,
    pub issues: Vec<EvidenceIssue>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceIssue {
    pub index: usize,
    pub kind: EvidenceIssueKind,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceIssueKind {
    Invalid,
    WrongJob,
    UntrustedOperator,
    FailureDomainMismatch,
    FutureObservation,
    Expired,
    Duplicate,
    Equivocation,
}

pub fn evaluate(
    job: &VerificationJob,
    observed: &ObservedDeployment,
    policy: &QuorumPolicy,
    envelopes: &[DsseEnvelope],
) -> Result<QuorumDecision> {
    validate_job(job)?;
    validate_policy(policy)?;
    let mut decision = QuorumDecision {
        status: IntegrityStatus::InsufficientEvidence,
        job_id: job.id.clone(),
        matching_operators: 0,
        matching_failure_domains: 0,
        mismatches: 0,
        build_failures: 0,
        stale: 0,
        rejected: 0,
        issues: Vec::new(),
    };

    if job.deployment != observed.deployment {
        decision.status = IntegrityStatus::Stale;
        decision.stale = envelopes.len();
        return Ok(decision);
    }

    let votes = collect_votes(job, observed, policy, envelopes, &mut decision);

    let mut failure_domains = BTreeSet::new();
    for (outcome, failure_domain) in votes.values() {
        match outcome {
            BuildOutcome::Match => {
                decision.matching_operators += 1;
                failure_domains.insert(failure_domain);
            }
            BuildOutcome::Mismatch => decision.mismatches += 1,
            BuildOutcome::BuildFailed => decision.build_failures += 1,
        }
    }
    decision.matching_failure_domains = failure_domains.len();

    let equivocation = decision
        .issues
        .iter()
        .any(|issue| issue.kind == EvidenceIssueKind::Equivocation);
    decision.status = if decision.mismatches > 0 || equivocation {
        IntegrityStatus::Disputed
    } else if decision.matching_operators >= policy.minimum_operators
        && decision.matching_failure_domains >= policy.minimum_failure_domains
    {
        IntegrityStatus::Verified
    } else {
        IntegrityStatus::InsufficientEvidence
    };
    Ok(decision)
}

fn validate_policy(policy: &QuorumPolicy) -> Result<()> {
    if policy.minimum_operators == 0 {
        return Err(Error::InvalidPolicy(
            "minimum operators must be greater than zero".to_owned(),
        ));
    }
    if policy.minimum_failure_domains == 0
        || policy.minimum_failure_domains > policy.minimum_operators
    {
        return Err(Error::InvalidPolicy(
            "minimum failure domains must be between one and minimum operators".to_owned(),
        ));
    }
    if policy.operator_failure_domains.len() < policy.minimum_operators {
        return Err(Error::InvalidPolicy(
            "operator registry cannot satisfy the minimum operator count".to_owned(),
        ));
    }
    if policy
        .operator_failure_domains
        .values()
        .any(|failure_domain| failure_domain.trim().is_empty())
    {
        return Err(Error::InvalidPolicy(
            "operator failure domains cannot be empty".to_owned(),
        ));
    }
    Ok(())
}

fn collect_votes(
    job: &VerificationJob,
    observed: &ObservedDeployment,
    policy: &QuorumPolicy,
    envelopes: &[DsseEnvelope],
    decision: &mut QuorumDecision,
) -> BTreeMap<SolanaAddress, (BuildOutcome, String)> {
    let mut votes = BTreeMap::new();
    for (index, envelope) in envelopes.iter().enumerate() {
        let verified = match decode_and_verify(envelope) {
            Ok(value) => value,
            Err(error) => {
                reject(
                    decision,
                    index,
                    EvidenceIssueKind::Invalid,
                    error.to_string(),
                );
                continue;
            }
        };

        if verified.statement.predicate.job != *job {
            reject(
                decision,
                index,
                EvidenceIssueKind::WrongJob,
                "attestation does not match the requested verification job".to_owned(),
            );
            continue;
        }

        let Some(expected_failure_domain) = policy.operator_failure_domains.get(&verified.operator)
        else {
            reject(
                decision,
                index,
                EvidenceIssueKind::UntrustedOperator,
                verified.operator.to_string(),
            );
            continue;
        };

        let predicate = verified.statement.predicate;
        if predicate.worker.failure_domain != *expected_failure_domain {
            reject(
                decision,
                index,
                EvidenceIssueKind::FailureDomainMismatch,
                verified.operator.to_string(),
            );
            continue;
        }
        if predicate.observed_at_slot > observed.observed_at_slot {
            reject(
                decision,
                index,
                EvidenceIssueKind::FutureObservation,
                predicate.observed_at_slot.to_string(),
            );
            continue;
        }

        if policy
            .maximum_age_slots
            .is_some_and(|maximum| observed.observed_at_slot - predicate.observed_at_slot > maximum)
        {
            reject(
                decision,
                index,
                EvidenceIssueKind::Expired,
                predicate.observed_at_slot.to_string(),
            );
            continue;
        }

        let vote = (predicate.evidence.outcome, predicate.worker.failure_domain);
        if let Some(existing) = votes.get(&verified.operator) {
            if existing == &vote {
                reject(
                    decision,
                    index,
                    EvidenceIssueKind::Duplicate,
                    verified.operator.to_string(),
                );
            } else {
                decision.issues.push(EvidenceIssue {
                    index,
                    kind: EvidenceIssueKind::Equivocation,
                    detail: verified.operator.to_string(),
                });
                decision.rejected += 1;
            }
            continue;
        }
        votes.insert(verified.operator, vote);
    }
    votes
}

fn reject(decision: &mut QuorumDecision, index: usize, kind: EvidenceIssueKind, detail: String) {
    decision.rejected += 1;
    decision.issues.push(EvidenceIssue {
        index,
        kind,
        detail,
    });
}
