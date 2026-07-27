# Attestation profile

## Envelope

The payload type is `application/vnd.in-toto+json`. The payload is an in-toto Statement v1 JSON document. Each VeriSVM v1 envelope contains exactly one Ed25519 signature. The DSSE `keyid` is the base58 public key of the signing operator.

The signed bytes are:

```text
DSSEv1 <payload-type-length> <payload-type> <payload-length> <payload>
```

## Statement

The statement type is `https://in-toto.io/Statement/v1`. The predicate type is `https://verisvm.org/attestation/reproducible-build/v1`.

The subject identifies the deployed program binary with a SHA-256 digest. The predicate contains the immutable verification job, worker failure domain, build outcome, output digest when available, transcript digest, and observation slot.

## Source tree digest

The source tree digest is SHA-256 over this byte sequence:

```text
"VERISVM-SOURCE-TREE-V1\0"
u64be(entry count)
for each entry in raw bytewise path order:
  u8(mode tag)
  u64be(path length)
  path bytes
  u64be(content length)
  content bytes
```

Mode tags are `0` for a regular file, `1` for an executable file, and `2` for a symlink. Symlink content is its link target. The digest is derived from committed Git objects rather than a mutable working tree.

## Quorum rules

- Only valid signatures from operators in the policy registry are considered.
- Failure-domain diversity comes from the policy registry and must match the signed worker claim.
- The attested job must exactly equal the requested job.
- The job deployment must equal the current finalized deployment.
- A matching output must equal the deployed executable digest.
- A mismatching output must differ from the deployed executable digest.
- A build failure must not claim an executable digest.
- One operator contributes at most one vote.
- Operator equivocation or any valid mismatch produces `disputed`.
- Quorum requires both the configured operator count and failure-domain count.
