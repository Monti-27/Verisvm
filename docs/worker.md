# Evidence worker

## Product boundary

The evidence worker executes an immutable verification job and returns portable signed evidence. Solana Verify remains the build engine. VeriSVM owns source identity, isolation, execution policy, transcript integrity, chain reconciliation, and signing.

The worker controller never treats an executor result as trusted merely because the process exited successfully. Before signing, it compares the observed source tree, builder image, Solana Verify version, Rust and Solana toolchains, build command, and lockfile digest with the submitted job. It then reads the program again at finalized commitment so an upgrade during the build cannot be hidden.

## Researched baseline

The initial contract was reviewed against these sources on 2026-08-23:

- [Solana verified builds documentation](https://solana.com/docs/programs/verified-builds)
- [Solana Verify v0.5.1](https://github.com/solana-foundation/solana-verifiable-build/releases/tag/v0.5.1)
- [Solana Verify revision 17e839a](https://github.com/solana-foundation/solana-verifiable-build/tree/17e839a8d5911cea3cac1bb5a810bcb2f6a13293)
- [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
- [DSSE protocol 1.0.2](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
- [Docker run isolation controls](https://docs.docker.com/reference/cli/docker/container/run/)
- [Firecracker isolation design](https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md)
- [Git transport policy](https://git-scm.com/docs/git-config#Documentation/git-config.txt-protocolallow)
- [Git ls-tree](https://git-scm.com/docs/git-ls-tree)
- [Git cat-file batch mode](https://git-scm.com/docs/git-cat-file#Documentation/git-cat-file.txt---batchltformatgt)
- [Git fetch](https://git-scm.com/docs/git-fetch)

Solana Verify selects versioned builder images by digest and supports exact commit checkout. Its local workflow is designed for developer machines, not hostile multi-tenant execution: it clones directly, mounts the checkout writable, may resolve dependencies over the network, and makes resource limits optional. VeriSVM therefore integrates the CLI inside an isolated executor instead of exposing the host Docker daemon or copying its build logic.

## Execution boundary

The controller, executor, finalized deployment reader, and signer communicate through narrow asynchronous contracts. This allows the hosted service to use remote microVM scheduling, RPC, and HSM or KMS signing without blocking its request runtime.

The controller supplies:

- the complete immutable verification job
- CPU, memory, process, disk, duration, transcript, and artifact limits
- an operator repository allowlist
- an operator-maintained allowlist of Solana Verify versions and builder image digests

The executor returns:

- the observed source tree digest
- the resolved builder image digest
- the observed toolchain and Solana Verify versions
- the exact argument vector it executed
- an ordered byte transcript with process termination status
- the built executable only when the process succeeds

The controller checks the observed repository and exact commit as well as the source-tree digest. It only accepts `solana-verify build` jobs with a pinned `Cargo.lock` digest. It hashes the executable and transcript itself, classifies the result, reconciles finalized deployment state, builds the in-toto statement, asks an external signer to sign it, and verifies the returned envelope and signer identity before publishing it.

## Isolation target

Production workers run one job per ephemeral microVM. Docker and Solana Verify run inside that microVM. The control plane does not mount its Docker socket, signing keys, cloud credentials, or database credentials into the guest.

The source-fetch phase has narrowly scoped outbound access. Dependency preparation has registry-only outbound access. The build phase has no network. Every phase has hard CPU, memory, process, disk, output, and wall-clock limits. The guest is destroyed after artifacts and transcripts have been content-addressed.

Plain Docker remains useful for local compatibility testing. It is not the production security boundary for repositories controlled by an attacker.

## Source identity

VeriSVM v1 hashes the complete committed Git tree with SHA-256. Records are ordered by raw path bytes and commit to path, executable mode, symlink mode, and file content. Commit IDs use their full canonical lowercase SHA-1 or SHA-256 representation.

The guest initializes a fresh bare object database and fetches only the requested commit. System and global Git configuration, credentials, prompts, hooks, LFS smudge behavior, redirects, submodule recursion, and every transport except HTTPS are disabled. The resolved object must be a commit with the requested ID.

The executor reads NUL-delimited `git ls-tree` records and streams blobs through `git cat-file --batch`. It bounds file count, path length, metadata, individual file size, and total source bytes before or during extraction. It never invokes checkout filters and does not expose a `.git` directory to the build workspace.

Absolute paths, empty components, parent traversal, repository control paths, duplicate paths, unsupported modes, and Git submodules are rejected. Symlinks are hashed as link targets and may not escape the source root. Submodules require a later profile that pins and hashes every nested repository independently.

## Signing boundary

The worker controller depends on a signer interface rather than a raw key file. Production adapters can use an HSM, KMS, or isolated signing service. A signature is accepted only when the resulting DSSE envelope verifies, contains the exact statement supplied to the signer, and resolves to the configured operator identity.

## Next adapter

The next implementation layer creates one fresh microVM per job, imports the validated source tree, prepares registry dependencies, runs Solana Verify without network access, exports the executable and transcript, and destroys the guest. No hosted job should be accepted until that adapter passes malicious-repository tests and the twenty-program reproducibility corpus.
