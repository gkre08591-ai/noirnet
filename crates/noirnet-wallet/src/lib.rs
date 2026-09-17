// noirnet-wallet/src/lib.rs

pub mod builder;
pub mod keys;
pub mod sync;

pub use builder::TxBuilder;
pub use sync::WalletSync;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("Database error: {0}")]
    Database(String),
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Insufficient funds")]
    InsufficientFunds,
    #[error("Sync error: {0}")]
    Sync(String),
}

pub type WalletResult<T> = Result<T, WalletError>;
