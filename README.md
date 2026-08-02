# VeriSVM

Independent integrity proofs for Solana programs.

VeriSVM combines signed reproducible-build evidence from independent workers and evaluates it against an explicit trust policy. It is compatible with the existing Solana Verify build workflow and Otter Verify metadata. It does not claim that a reproducible program is audited or safe.

## Current milestone

The repository currently contains the protocol and worker-controller foundation:

- an in-toto Statement v1 profile for Solana build evidence
- DSSE signing and Ed25519 verification compatible with Solana identities
- upgrade-aware quorum evaluation
- explicit `verified`, `disputed`, `stale`, and `insufficient_evidence` states
- matching Rust and TypeScript SDKs
- a CLI for inspecting attestations and evaluating a quorum
- finalized upgradeable-program snapshots and existing Otter Verify record discovery
- an isolated executor contract with source, builder, transcript, deployment, and signer verification
- bounded Git object acquisition and content-addressed source materialization

The microVM build runner, Otter Verify indexer, API service, GitHub Action, and on-chain registry follow in later milestones.

## Workspace

```text
crates/verisvm-core     Rust protocol types, signature verification, and policy engine
crates/verisvm-cli      Local inspection and policy evaluation CLI
crates/verisvm-executor Guest-side source acquisition and execution components
crates/verisvm-solana   Finalized deployment snapshots and Otter Verify compatibility
crates/verisvm-worker   Trusted worker controller and executor boundary
sdks/typescript         Browser and server TypeScript policy SDK
fixtures                Cross-language protocol fixtures
docs                    Architecture, protocol profile, and roadmap
```

## Development

Requirements:

- Rust 1.94.1
- Node.js 24 or newer
- pnpm 10

```bash
pnpm install
pnpm check
```

Evaluate the shared protocol fixture:

```bash
cargo run -p verisvm-cli -- evaluate-bundle --bundle fixtures/quorum.json
```

Read a finalized mainnet deployment snapshot:

```bash
cargo run -p verisvm-cli -- snapshot --program-id <PROGRAM_ID>
```

Read existing Otter Verify records without changing their trust meaning:

```bash
cargo run -p verisvm-cli -- otter-records --program-id <PROGRAM_ID>
```

## Trust boundary

VeriSVM proves that identified workers produced signed evidence about a reproducible build. Consumers choose the required operator count, failure-domain diversity, signer allowlist, and freshness. A `verified` result means the configured provenance policy passed. It does not mean the source code is secure.

## Upstream foundations

- [Solana verified builds](https://solana.com/docs/programs/verified-builds)
- [Solana Verify](https://github.com/solana-foundation/solana-verifiable-build)
- [Otter Verify](https://github.com/otter-sec/otter-verify)
- [in-toto Attestation Framework](https://github.com/in-toto/attestation)
- [DSSE](https://github.com/secure-systems-lab/dsse)

## License

Apache-2.0
