# Architecture

## Boundary

VeriSVM starts after a verification job has been defined and before a consumer decides whether to trust the result. Solana Verify remains the deterministic builder. Otter Verify remains an existing source of build metadata. VeriSVM adds portable evidence, independent execution, quorum semantics, and policy evaluation.

## First vertical slice

```text
VerificationJob
  -> bounded Git object resolution
  -> isolated Solana Verify workers
  -> in-toto statements in DSSE envelopes
  -> signature and schema validation
  -> upgrade-aware quorum policy
  -> Rust and TypeScript consumers
```

Every job pins the repository, commit, source-tree digest, build image digest, toolchains, command, program address, deployment slot, and deployed executable digest. A worker may report a match, mismatch, or build failure. Only matching results count toward quorum. A valid mismatch makes the result disputed. Build failures remain visible but do not assert a conflicting binary.

The evaluator rejects evidence with an invalid signature, unsupported schema, unexpected job specification, untrusted operator, impossible slot, or inconsistent result fields. Duplicate evidence from the same operator counts once. Distinct failure domains are counted separately from distinct signing identities.

## Upgrade awareness

The evaluation call includes the program state observed at finalized commitment. If its executable digest or deployment slot differs from the job snapshot, every attestation for that job is stale. Old evidence is preserved for audit history but cannot satisfy the current policy.

## Standards

Build evidence uses an in-toto Statement v1 payload and a DSSE envelope. DSSE signs the payload type and exact payload bytes, avoiding JSON canonicalization as a security dependency. Operator key IDs are base58-encoded Ed25519 public keys so existing Solana identities can be used.

## Later services

- Worker supervisor with secure Git object acquisition, pinned images, no-network build execution, and secret-free logs
- Indexer for upgradeable loader state and Otter Verify PDAs
- API and webhook service for program status and upgrade invalidation
- GitHub Action for job submission and policy checks
- Devnet registry for compact commitment, reveal, quorum, and challenge state

The worker controller and untrusted build executor are separate trust domains. The controller validates every observed execution input before signing. The executor runs Solana Verify inside a disposable microVM and never receives signing keys or control-plane credentials. The detailed contract is in [worker.md](worker.md).
