// noirnet-mempool/src/lib.rs

pub mod fee_market;
pub mod pool;

pub use fee_market::FeeMarket;
pub use pool::PrivateMempool;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MempoolError {
    #[error("Mempool is full")]
    Full,
    #[error("Transaction already in mempool")]
    AlreadyExists,
    #[error("Fee too low (min {0} nNOIR)")]
    FeeTooLow(u64),
    #[error("Invalid transaction format: {0}")]
    InvalidFormat(String),
    #[error("Double spend detected in mempool")]
    DoubleSpend,
    #[error("Nullifier already spent in blockchain")]
    AlreadySpent,
}

pub type MempoolResult<T> = Result<T, MempoolError>;
