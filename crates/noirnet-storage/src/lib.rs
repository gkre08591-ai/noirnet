// noirnet-storage/src/lib.rs

pub mod block_store;
pub mod db;
pub mod merkle;
pub mod nullifier_store;
pub mod state;

pub use block_store::BlockStore;
pub use db::*;
pub use merkle::NoteCommitmentTree;
pub use nullifier_store::NullifierStore;
pub use state::StateStore;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Storage error: {0}")]
    Sled(#[from] sled::Error),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Key not found: {0}")]
    NotFound(String),
    #[error("Double spend: nullifier already in set")]
    DoubleSpend,
    #[error("Invalid state transition: {0}")]
    InvalidTransition(String),
}

pub type StorageResult<T> = Result<T, StorageError>;
