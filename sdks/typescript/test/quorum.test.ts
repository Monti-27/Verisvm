import { readFileSync } from "node:fs";

import { ed25519 } from "@noble/curves/ed25519.js";
import { base58, base64, base64urlnopad } from "@scure/base";
import { describe, expect, it } from "vitest";

import {
  DSSE_PAYLOAD_TYPE,
  PREDICATE_TYPE,
  STATEMENT_TYPE,
  decodeAndVerify,
  dssePae,
  evaluate,
  verificationJobSchema,
  type BuildOutcome,
  type BuildPredicate,
  type DsseEnvelope,
  type ObservedDeployment,
  type QuorumPolicy,
  type Statement,
  type VerificationJob,
} from "../src/index.js";

const encoder = new TextEncoder();

function hex(byte: number): string {
  return byte.toString(16).padStart(2, "0").repeat(32);
}

function job(): VerificationJob {
  return {
    id: "job-01",
    deployment: {
      cluster: "mainnet_beta",
      programId: base58.encode(new Uint8Array(32).fill(9)),
      programDataAddress: base58.encode(new Uint8Array(32).fill(10)),
      deploymentSlot: 300,
      executableDigest: hex(11),
    },
    source: {
      repository: "https://github.com/example/program",
      commit: "0123456789abcdef0123456789abcdef01234567",
      treeDigest: hex(12),
    },
    recipe: {
      builderImageDigest: hex(13),
      solanaVerifyVersion: "0.5.1",
      rustToolchain: "1.86.0",
      solanaToolchain: "3.0.0",
      command: ["cargo", "build-sbf"],
      cargoLockDigest: hex(14),
    },
  };
}

function envelope(
  verificationJob: VerificationJob,
  keyByte: number,
  failureDomain: string,
  outcome: BuildOutcome,
): DsseEnvelope {
  const executableDigest = outcome === "match" ? verificationJob.deployment.executableDigest : outcome === "mismatch" ? hex(99) : null;
  const predicate: BuildPredicate = {
    job: verificationJob,
    worker: { id: `worker-${keyByte}`, failureDomain },
    evidence: {
      outcome,
      executableDigest,
      transcriptDigest: hex(keyByte),
    },
    observedAtSlot: 350,
  };
  const statement: Statement = {
    _type: STATEMENT_TYPE,
    subject: [
      {
        name: `solana:mainnet_beta:program:${verificationJob.deployment.programId}`,
        digest: { sha256: verificationJob.deployment.executableDigest },
      },
    ],
    predicateType: PREDICATE_TYPE,
    predicate,
  };
  const payload = encoder.encode(JSON.stringify(statement));
  const privateKey = new Uint8Array(32).fill(keyByte);
  return {
    payloadType: DSSE_PAYLOAD_TYPE,
    payload: base64.encode(payload),
    signatures: [
      {
        keyid: base58.encode(ed25519.getPublicKey(privateKey)),
        sig: base64.encode(ed25519.sign(dssePae(DSSE_PAYLOAD_TYPE, payload), privateKey)),
      },
    ],
  };
}

function deployment(verificationJob: VerificationJob): ObservedDeployment {
  return { deployment: verificationJob.deployment, observedAtSlot: 400 };
}

function policy(): QuorumPolicy {
  return {
    minimumOperators: 3,
    minimumFailureDomains: 3,
    maximumAgeSlots: 100,
    operatorFailureDomains: Object.fromEntries([
      [operator(1), "aws:us-east-1"],
      [operator(2), "gcp:us-central1"],
      [operator(3), "bare-metal:hel1"],
      [operator(4), "azure:westeurope"],
    ]),
  };
}

function operator(keyByte: number): string {
  return base58.encode(ed25519.getPublicKey(new Uint8Array(32).fill(keyByte)));
}

describe("VeriSVM policy", () => {
  it("requires canonical lowercase commit ids", () => {
    const verificationJob = job();
    verificationJob.source.commit = "0123456789ABCDEF0123456789ABCDEF01234567";

    expect(verificationJobSchema.safeParse(verificationJob).success).toBe(false);
  });

  it("verifies the Rust-generated wire fixture", () => {
    const fixture = JSON.parse(
      readFileSync(new URL("../../../fixtures/quorum.json", import.meta.url), "utf8"),
    ) as {
      job: VerificationJob;
      deployment: ObservedDeployment;
      policy: QuorumPolicy;
      attestations: DsseEnvelope[];
    };

    const decision = evaluate(fixture.job, fixture.deployment, fixture.policy, fixture.attestations);

    expect(decision.status).toBe("verified");
  });

  it("verifies a signed envelope", () => {
    const verificationJob = job();
    const verified = decodeAndVerify(envelope(verificationJob, 1, "aws:us-east-1", "match"));
    expect(verified.statement.predicate.job).toEqual(verificationJob);
  });

  it("accepts URL-safe DSSE encoding", () => {
    const verificationJob = job();
    const attestation = envelope(verificationJob, 1, "aws:us-east-1", "match");
    attestation.payload = base64urlnopad.encode(base64.decode(attestation.payload));
    attestation.signatures[0]!.sig = base64urlnopad.encode(base64.decode(attestation.signatures[0]!.sig));

    const verified = decodeAndVerify(attestation);

    expect(verified.statement.predicate.job).toEqual(verificationJob);
  });

  it("reaches quorum across independent failure domains", () => {
    const verificationJob = job();
    const attestations = [
      envelope(verificationJob, 1, "aws:us-east-1", "match"),
      envelope(verificationJob, 2, "gcp:us-central1", "match"),
      envelope(verificationJob, 3, "bare-metal:hel1", "match"),
    ];

    const decision = evaluate(verificationJob, deployment(verificationJob), policy(), attestations);

    expect(decision.status).toBe("verified");
    expect(decision.matchingOperators).toBe(3);
    expect(decision.matchingFailureDomains).toBe(3);
  });

  it("marks the result disputed when one worker reports a mismatch", () => {
    const verificationJob = job();
    const attestations = [
      envelope(verificationJob, 1, "aws:us-east-1", "match"),
      envelope(verificationJob, 2, "gcp:us-central1", "match"),
      envelope(verificationJob, 3, "bare-metal:hel1", "match"),
      envelope(verificationJob, 4, "azure:westeurope", "mismatch"),
    ];

    const decision = evaluate(verificationJob, deployment(verificationJob), policy(), attestations);

    expect(decision.status).toBe("disputed");
    expect(decision.mismatches).toBe(1);
  });

  it("rejects a tampered envelope", () => {
    const verificationJob = job();
    const attestation = envelope(verificationJob, 1, "aws:us-east-1", "match");
    attestation.payload = `${attestation.payload.slice(0, -4)}AAAA`;

    const decision = evaluate(verificationJob, deployment(verificationJob), policy(), [attestation]);

    expect(decision.status).toBe("insufficient_evidence");
    expect(decision.rejected).toBe(1);
  });

  it("does not trust a worker's self-declared failure domain", () => {
    const verificationJob = job();
    const attestation = envelope(verificationJob, 1, "aws:us-east-1", "match");
    const quorumPolicy = policy();
    quorumPolicy.minimumOperators = 1;
    quorumPolicy.minimumFailureDomains = 1;
    quorumPolicy.operatorFailureDomains[operator(1)] = "gcp:us-central1";

    const decision = evaluate(verificationJob, deployment(verificationJob), quorumPolicy, [attestation]);

    expect(decision.status).toBe("insufficient_evidence");
    expect(decision.issues[0]?.kind).toBe("failure_domain_mismatch");
  });
});
