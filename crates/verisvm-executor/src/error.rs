use std::io;

use thiserror::Error;
use verisvm_core::Digest;
use verisvm_worker::SourceTreeError;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Git executable is invalid: {0}")]
    InvalidGitExecutable(String),
    #[error("repository is invalid")]
    InvalidRepository(#[source] verisvm_worker::Error),
    #[error("execution limits are invalid")]
    InvalidLimits(#[source] verisvm_worker::Error),
    #[error("commit must be a full lowercase hexadecimal object id")]
    InvalidCommit,
    #[error("failed to create the source workspace")]
    Workspace(#[source] io::Error),
    #[error("Git {operation} I/O failed")]
    GitIo {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("Git {operation} failed with status {status}: {stderr}")]
    GitFailed {
        operation: &'static str,
        status: String,
        stderr: String,
    },
    #[error("Git {operation} output exceeded {limit} bytes")]
    GitOutputTooLarge {
        operation: &'static str,
        limit: usize,
    },
    #[error("Git {operation} returned invalid output: {detail}")]
    InvalidGitOutput {
        operation: &'static str,
        detail: String,
    },
    #[error("resolved commit differs from the requested commit")]
    CommitMismatch,
    #[error("source tree digest mismatch: expected {expected}, observed {observed}")]
    SourceDigestMismatch { expected: Digest, observed: Digest },
    #[error("source tree is empty")]
    EmptyTree,
    #[error("source tree exceeds the file limit of {limit}")]
    TooManyFiles { limit: usize },
    #[error("source tree metadata exceeds {limit} bytes")]
    MetadataTooLarge { limit: usize },
    #[error("source path exceeds {limit} bytes")]
    PathTooLong { limit: usize },
    #[error("source tree contains an invalid record")]
    InvalidTreeRecord,
    #[error("source tree contains unsupported mode {mode} and type {kind} at {path}")]
    UnsupportedTreeEntry {
        mode: String,
        kind: String,
        path: String,
    },
    #[error("source tree contains a Git submodule at {0}")]
    Submodule(String),
    #[error("source file {path} exceeds {limit} bytes")]
    FileTooLarge { path: String, size: u64, limit: u64 },
    #[error("source tree content exceeds {limit} bytes")]
    SourceTooLarge { limit: u64 },
    #[error("source tree contains a path collision at {0}")]
    PathCollision(String),
    #[error("source symlink target at {path} exceeds {limit} bytes")]
    SymlinkTooLarge { path: String, size: u64, limit: u64 },
    #[error("source tree contains an unsafe symlink at {0}")]
    UnsafeSymlink(String),
    #[error("failed to materialize source path {path}")]
    Materialize {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("source tree hash is invalid")]
    SourceTree(#[from] SourceTreeError),
}

pub type Result<T> = std::result::Result<T, Error>;
