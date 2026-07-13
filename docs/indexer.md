# Upgrade indexer design

## Ingestion

The prototype reads finalized account state through standard Solana JSON-RPC. The first hosted service should subscribe to each registered ProgramData account for low-latency signals and reconcile every account at finalized commitment. A managed Yellowstone-compatible stream becomes useful only when the monitored program set makes individual subscriptions operationally expensive.

The real-time path is advisory until finalized reconciliation succeeds. A notification at confirmed commitment cannot invalidate a previously finalized attestation by itself.

## Idempotency

Deployment snapshots use `(cluster, program_id, deployment_slot, executable_digest)` as their identity. Replaying a notification or backfill writes the same row and cannot duplicate an upgrade. Otter Verify records use their PDA address as identity and preserve the slot at which they were observed.

## Backfill

On startup, the service reads its finalized cursor, fetches signatures involving monitored ProgramData accounts after that point, and reconstructs missed upgrades before opening subscriptions. It then performs a current finalized account read to close any gap left by pruned transaction history.

## Monitoring

The service exposes its latest observed finalized slot, the cluster finalized slot, reconciliation failures, subscription reconnects, and the number of programs awaiting refresh. Alerting is based on slot lag rather than wall-clock time.

