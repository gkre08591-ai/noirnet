// error.rs — глобальні помилки NoirNet

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NoirNetError {
    #[error("Consensus error: {0}")]
    Consensus(String),

    #[error("Transaction error: {0}")]
    Transaction(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("ZK proof error: {0}")]
    ZkProof(String),

    #[error("VM error: {0}")]
    Vm(String),

    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("Invalid block: {0}")]
    InvalidBlock(String),

    #[error("Double spend detected")]
    DoubleSpend,

    #[error("Invalid anchor")]
    InvalidAnchor,

    #[error("Insufficient funds")]
    InsufficientFunds,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, NoirNetError>;
