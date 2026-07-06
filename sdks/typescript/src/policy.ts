import { decodeAndVerify } from "./attestation.js";
import { observedDeploymentSchema, quorumPolicySchema, verificationJobSchema } from "./schema.js";
import type {
  BuildOutcome,
  DsseEnvelope,
  EvidenceIssueKind,
  ObservedDeployment,
  QuorumDecision,
  QuorumPolicy,
  VerificationJob,
} from "./types.js";

export function evaluate(
  jobInput: unknown,
  deploymentInput: unknown,
  policyInput: unknown,
  envelopes: readonly DsseEnvelope[],
): QuorumDecision {
  const job = verificationJobSchema.parse(jobInput) as VerificationJob;
  const observed = observedDeploymentSchema.parse(deploymentInput) as ObservedDeployment;
  const policy = quorumPolicySchema.parse(policyInput) as QuorumPolicy;
  const decision = emptyDecision(job.id);

  if (!sameDeployment(job.deployment, observed.deployment)) {
    return { ...decision, status: "stale", stale: envelopes.length };
  }

  const votes = new Map<string, { outcome: BuildOutcome; failureDomain: string }>();
  for (const [index, envelope] of envelopes.entries()) {
    let verified;
    try {
      verified = decodeAndVerify(envelope);
    } catch (error) {
      reject(decision, index, "invalid", error instanceof Error ? error.message : String(error));
      continue;
    }

    if (!sameJob(verified.statement.predicate.job, job)) {
      reject(decision, index, "wrong_job", "attestation does not match the requested verification job");
      continue;
    }
    const expectedFailureDomain = policy.operatorFailureDomains[verified.operator];
    if (expectedFailureDomain === undefined) {
      reject(decision, index, "untrusted_operator", verified.operator);
      continue;
    }

    const predicate = verified.statement.predicate;
    if (predicate.worker.failureDomain !== expectedFailureDomain) {
      reject(decision, index, "failure_domain_mismatch", verified.operator);
      continue;
    }
    if (predicate.observedAtSlot > observed.observedAtSlot) {
      reject(decision, index, "future_observation", String(predicate.observedAtSlot));
      continue;
    }
    if (
      policy.maximumAgeSlots !== null &&
      observed.observedAtSlot - predicate.observedAtSlot > policy.maximumAgeSlots
    ) {
      reject(decision, index, "expired", String(predicate.observedAtSlot));
      continue;
    }

    const vote = {
      outcome: predicate.evidence.outcome,
      failureDomain: predicate.worker.failureDomain,
    };
    const existing = votes.get(verified.operator);
    if (existing !== undefined) {
      if (existing.outcome === vote.outcome && existing.failureDomain === vote.failureDomain) {
        reject(decision, index, "duplicate", verified.operator);
      } else {
        decision.issues.push({ index, kind: "equivocation", detail: verified.operator });
        decision.rejected += 1;
      }
      continue;
    }
    votes.set(verified.operator, vote);
  }

  const failureDomains = new Set<string>();
  for (const vote of votes.values()) {
    if (vote.outcome === "match") {
      decision.matchingOperators += 1;
      failureDomains.add(vote.failureDomain);
    } else if (vote.outcome === "mismatch") {
      decision.mismatches += 1;
    } else {
      decision.buildFailures += 1;
    }
  }
  decision.matchingFailureDomains = failureDomains.size;

  if (decision.mismatches > 0 || decision.issues.some((issue) => issue.kind === "equivocation")) {
    decision.status = "disputed";
  } else if (
    decision.matchingOperators >= policy.minimumOperators &&
    decision.matchingFailureDomains >= policy.minimumFailureDomains
  ) {
    decision.status = "verified";
  }
  return decision;
}

function emptyDecision(jobId: string): QuorumDecision {
  return {
    status: "insufficient_evidence",
    jobId,
    matchingOperators: 0,
    matchingFailureDomains: 0,
    mismatches: 0,
    buildFailures: 0,
    stale: 0,
    rejected: 0,
    issues: [],
  };
}

function reject(
  decision: QuorumDecision,
  index: number,
  kind: EvidenceIssueKind,
  detail: string,
): void {
  decision.rejected += 1;
  decision.issues.push({ index, kind, detail });
}

function sameJob(left: VerificationJob, right: VerificationJob): boolean {
  return (
    left.id === right.id &&
    sameDeployment(left.deployment, right.deployment) &&
    left.source.repository === right.source.repository &&
    left.source.commit === right.source.commit &&
    left.source.treeDigest === right.source.treeDigest &&
    left.recipe.builderImageDigest === right.recipe.builderImageDigest &&
    left.recipe.solanaVerifyVersion === right.recipe.solanaVerifyVersion &&
    left.recipe.rustToolchain === right.recipe.rustToolchain &&
    left.recipe.solanaToolchain === right.recipe.solanaToolchain &&
    left.recipe.cargoLockDigest === right.recipe.cargoLockDigest &&
    sameStrings(left.recipe.command, right.recipe.command)
  );
}

function sameDeployment(
  left: ObservedDeployment["deployment"],
  right: ObservedDeployment["deployment"],
): boolean {
  return (
    left.cluster === right.cluster &&
    left.programId === right.programId &&
    left.programDataAddress === right.programDataAddress &&
    left.deploymentSlot === right.deploymentSlot &&
    left.executableDigest === right.executableDigest
  );
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}
