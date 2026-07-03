export const DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json";
export const STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
export const PREDICATE_TYPE = "https://verisvm.org/attestation/reproducible-build/v1";

export type HexDigest = string;
export type SolanaAddress = string;
export type Cluster = "mainnet_beta" | "devnet" | "testnet" | "localnet";
export type BuildOutcome = "match" | "mismatch" | "build_failed";

export interface Deployment {
  cluster: Cluster;
  programId: SolanaAddress;
  programDataAddress: SolanaAddress | null;
  deploymentSlot: number;
  executableDigest: HexDigest;
}

export interface SourceRevision {
  repository: string;
  commit: string;
  treeDigest: HexDigest;
}

export interface BuildRecipe {
  builderImageDigest: HexDigest;
  solanaVerifyVersion: string;
  rustToolchain: string;
  solanaToolchain: string;
  command: string[];
  cargoLockDigest: HexDigest | null;
}

export interface VerificationJob {
  id: string;
  deployment: Deployment;
  source: SourceRevision;
  recipe: BuildRecipe;
}

export interface WorkerIdentity {
  id: string;
  failureDomain: string;
}

export interface BuildEvidence {
  outcome: BuildOutcome;
  executableDigest: HexDigest | null;
  transcriptDigest: HexDigest;
}

export interface BuildPredicate {
  job: VerificationJob;
  worker: WorkerIdentity;
  evidence: BuildEvidence;
  observedAtSlot: number;
}

export interface ResourceDescriptor {
  name: string;
  digest: Record<string, string>;
}

export interface Statement {
  _type: string;
  subject: ResourceDescriptor[];
  predicateType: string;
  predicate: BuildPredicate;
}

export interface DsseSignature {
  keyid: string;
  sig: string;
}

export interface DsseEnvelope {
  payloadType: string;
  payload: string;
  signatures: DsseSignature[];
}

export interface VerifiedAttestation {
  operator: SolanaAddress;
  statement: Statement;
  payloadDigest: HexDigest;
}

export interface ObservedDeployment {
  deployment: Deployment;
  observedAtSlot: number;
}

export interface QuorumPolicy {
  minimumOperators: number;
  minimumFailureDomains: number;
  maximumAgeSlots: number | null;
  operatorFailureDomains: Record<SolanaAddress, string>;
}

export type IntegrityStatus = "verified" | "disputed" | "stale" | "insufficient_evidence";

export type EvidenceIssueKind =
  | "invalid"
  | "wrong_job"
  | "untrusted_operator"
  | "failure_domain_mismatch"
  | "future_observation"
  | "expired"
  | "duplicate"
  | "equivocation";

export interface EvidenceIssue {
  index: number;
  kind: EvidenceIssueKind;
  detail: string;
}

export interface QuorumDecision {
  status: IntegrityStatus;
  jobId: string;
  matchingOperators: number;
  matchingFailureDomains: number;
  mismatches: number;
  buildFailures: number;
  stale: number;
  rejected: number;
  issues: EvidenceIssue[];
}
