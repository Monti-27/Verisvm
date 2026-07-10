CREATE TABLE programs (
    cluster TEXT NOT NULL,
    program_id VARCHAR(44) NOT NULL,
    program_data_address VARCHAR(44),
    latest_deployment_slot BIGINT NOT NULL CHECK (latest_deployment_slot >= 0),
    latest_executable_digest CHAR(64) NOT NULL,
    observed_at_slot BIGINT NOT NULL CHECK (observed_at_slot >= latest_deployment_slot),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (cluster, program_id)
);

CREATE TABLE deployment_snapshots (
    cluster TEXT NOT NULL,
    program_id VARCHAR(44) NOT NULL,
    program_data_address VARCHAR(44),
    deployment_slot BIGINT NOT NULL CHECK (deployment_slot >= 0),
    executable_digest CHAR(64) NOT NULL,
    observed_at_slot BIGINT NOT NULL CHECK (observed_at_slot >= deployment_slot),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (cluster, program_id, deployment_slot, executable_digest)
);

CREATE TABLE otter_verify_records (
    cluster TEXT NOT NULL,
    pda_address VARCHAR(44) NOT NULL,
    program_id VARCHAR(44) NOT NULL,
    signer VARCHAR(44) NOT NULL,
    deployment_slot BIGINT NOT NULL CHECK (deployment_slot >= 0),
    repository TEXT NOT NULL,
    commit_hash TEXT NOT NULL,
    solana_version TEXT NOT NULL,
    arguments JSONB NOT NULL,
    observed_at_slot BIGINT NOT NULL CHECK (observed_at_slot >= deployment_slot),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (cluster, pda_address)
);

CREATE INDEX otter_verify_records_program_idx
    ON otter_verify_records (cluster, program_id, deployment_slot DESC);

CREATE TABLE verification_jobs (
    job_id VARCHAR(128) PRIMARY KEY,
    cluster TEXT NOT NULL,
    program_id VARCHAR(44) NOT NULL,
    deployment_slot BIGINT NOT NULL CHECK (deployment_slot >= 0),
    executable_digest CHAR(64) NOT NULL,
    specification JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE attestations (
    payload_digest CHAR(64) PRIMARY KEY,
    job_id VARCHAR(128) NOT NULL REFERENCES verification_jobs(job_id),
    operator VARCHAR(44) NOT NULL,
    failure_domain TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('match', 'mismatch', 'build_failed')),
    observed_at_slot BIGINT NOT NULL CHECK (observed_at_slot >= 0),
    envelope JSONB NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX attestations_job_idx ON attestations (job_id, operator);

CREATE TABLE sync_cursors (
    source TEXT PRIMARY KEY,
    finalized_slot BIGINT NOT NULL CHECK (finalized_slot >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
