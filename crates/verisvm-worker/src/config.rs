use std::collections::BTreeSet;

use url::Url;
use verisvm_core::{Digest, SolanaAddress, VerificationJob, WorkerIdentity};

use crate::{Error, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionLimits {
    pub timeout_seconds: u64,
    pub memory_bytes: u64,
    pub cpu_millis: u32,
    pub pids: u32,
    pub writable_bytes: u64,
    pub source_files: usize,
    pub source_path_bytes: usize,
    pub source_file_bytes: u64,
    pub source_bytes: u64,
    pub source_metadata_bytes: usize,
    pub transcript_bytes: usize,
    pub artifact_bytes: usize,
}

impl Default for ExecutionLimits {
    fn default() -> Self {
        Self {
            timeout_seconds: 5_400,
            memory_bytes: 16 * 1_024 * 1_024 * 1_024,
            cpu_millis: 4_000,
            pids: 4_096,
            writable_bytes: 30 * 1_024 * 1_024 * 1_024,
            source_files: 100_000,
            source_path_bytes: 4_096,
            source_file_bytes: 512 * 1_024 * 1_024,
            source_bytes: 4 * 1_024 * 1_024 * 1_024,
            source_metadata_bytes: 64 * 1_024 * 1_024,
            transcript_bytes: 16 * 1_024 * 1_024,
            artifact_bytes: 32 * 1_024 * 1_024,
        }
    }
}

impl ExecutionLimits {
    pub fn validate(&self) -> Result<()> {
        if self.timeout_seconds == 0
            || self.memory_bytes == 0
            || self.cpu_millis == 0
            || self.pids == 0
            || self.writable_bytes == 0
            || self.source_files == 0
            || self.source_path_bytes == 0
            || self.source_file_bytes == 0
            || self.source_bytes == 0
            || self.source_metadata_bytes == 0
            || self.transcript_bytes == 0
            || self.artifact_bytes == 0
        {
            return Err(Error::InvalidConfiguration(
                "execution limits must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryPolicy {
    allowed_hosts: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuilderPolicy {
    allowed: BTreeSet<(String, Digest)>,
}

impl BuilderPolicy {
    pub fn new(allowed: BTreeSet<(String, Digest)>) -> Result<Self> {
        if allowed.is_empty() || allowed.iter().any(|(version, _)| version.trim().is_empty()) {
            return Err(Error::InvalidConfiguration(
                "builder allowlist is empty or contains an invalid version".to_owned(),
            ));
        }
        Ok(Self { allowed })
    }

    #[must_use]
    pub fn allows(&self, job: &VerificationJob) -> bool {
        self.allowed.iter().any(|(version, digest)| {
            version == &job.recipe.solana_verify_version
                && *digest == job.recipe.builder_image_digest
        })
    }
}

impl RepositoryPolicy {
    pub fn new(allowed_hosts: BTreeSet<String>) -> Result<Self> {
        if allowed_hosts.is_empty()
            || allowed_hosts.iter().any(|host| {
                host.is_empty()
                    || host.starts_with('.')
                    || host.ends_with('.')
                    || !host
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
            })
        {
            return Err(Error::InvalidConfiguration(
                "repository allowlist contains an invalid host".to_owned(),
            ));
        }
        Ok(Self {
            allowed_hosts: allowed_hosts
                .into_iter()
                .map(|host| host.to_ascii_lowercase())
                .collect(),
        })
    }

    #[must_use]
    pub fn github_only() -> Self {
        Self {
            allowed_hosts: BTreeSet::from(["github.com".to_owned()]),
        }
    }

    pub fn validate(&self, repository: &str) -> Result<()> {
        let url = Url::parse(repository)
            .map_err(|_| Error::InvalidRepository("repository URL is invalid".to_owned()))?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::InvalidRepository(
                "repository URL must be canonical HTTPS without credentials, ports, queries, or fragments"
                    .to_owned(),
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| Error::InvalidRepository("repository host is missing".to_owned()))?
            .to_ascii_lowercase();
        if !self.allowed_hosts.contains(&host) {
            return Err(Error::InvalidRepository(format!(
                "repository host is not allowed: {host}"
            )));
        }
        if url.path().trim_matches('/').is_empty() {
            return Err(Error::InvalidRepository(
                "repository path is missing".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerConfig {
    pub operator: SolanaAddress,
    pub identity: WorkerIdentity,
    pub repositories: RepositoryPolicy,
    pub builders: BuilderPolicy,
    pub limits: ExecutionLimits,
}

impl WorkerConfig {
    pub fn validate(&self) -> Result<()> {
        if self.identity.id.trim().is_empty() || self.identity.id.len() > 128 {
            return Err(Error::InvalidConfiguration(
                "worker id has an invalid length".to_owned(),
            ));
        }
        if self.identity.failure_domain.trim().is_empty()
            || self.identity.failure_domain.len() > 256
        {
            return Err(Error::InvalidConfiguration(
                "worker failure domain has an invalid length".to_owned(),
            ));
        }
        self.limits.validate()
    }
}
