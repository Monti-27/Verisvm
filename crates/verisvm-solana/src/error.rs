use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid RPC URL: {0}")]
    InvalidRpcUrl(String),
    #[error("RPC transport failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("RPC returned {code}: {message}")]
    Rpc { code: i64, message: String },
    #[error("account not found: {0}")]
    AccountNotFound(String),
    #[error("account has unsupported owner: {0}")]
    UnsupportedOwner(String),
    #[error("account is not executable")]
    ProgramNotExecutable,
    #[error("invalid account encoding")]
    InvalidAccountEncoding,
    #[error("invalid upgradeable-loader account: {0}")]
    InvalidLoaderAccount(String),
    #[error("invalid Otter Verify account: {0}")]
    InvalidOtterAccount(String),
    #[error(transparent)]
    Core(#[from] verisvm_core::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
