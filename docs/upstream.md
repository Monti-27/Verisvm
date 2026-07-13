# Upstream compatibility baseline

Reviewed on 2026-08-23.

| Project | Revision | Used for | License treatment |
|---|---|---|---|
| `solana-foundation/solana-verifiable-build` | `17e839a8d5911cea3cac1bb5a810bcb2f6a13293` | CLI behavior, pinned image model, deployed binary hashing | Cargo metadata declares MIT; integrated through its CLI contract |
| `otter-sec/otter-verify` | `3d66225910d2f8a7a79ca0efbc88a3a978521a23` | Program ID, account discriminator, PDA account wire layout | No repository license found; only public on-chain interface facts were implemented |
| `otter-sec/solana-verified-programs-api` | `bbb4c312ce1b1a33bce6fb2c29eb775c474d1a6a` | Current signer policy and upgrade-aware indexing behavior | No repository license found; no source code copied |
| `solana-foundation/explorer` | `7569022979174897723520b233ff491e58619315` | Current consumer trust model | MIT; no source code copied |
| `in-toto/attestation` | `051624ce466deaed4c5a66e66877f69b471fccbe` | Statement v1 and DSSE envelope profile | Apache-2.0 specification |
| `sigstore/sigstore-rs` | `038e36aefac21dd4ae608cda33736a494250fd1f` | Independent confirmation of DSSE pre-authentication encoding | Apache-2.0; no source code copied |

The implementation in this repository is original. It uses published formats and public on-chain layouts so existing Solana verification data remains interoperable.

