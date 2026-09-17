// noirnet-consensus/src/lib.rs

pub mod bft;
pub mod block_builder;
pub mod engine;
pub mod epoch;
pub mod leader;
pub mod slashing;
pub mod sync;

pub use engine::{ConsensusEngine, ConsensusState};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConsensusError {
    #[error("Not a leader for this round")]
    NotLeader,
    #[error("Invalid block proposal: {0}")]
    InvalidProposal(String),
    #[error("Invalid ZK aggregate proof")]
    InvalidAggregateProof,
    #[error("Insufficient pre-commits")]
    InsufficientPrecommits,
    #[error("Double sign detected")]
    DoubleSign,
}

pub type ConsensusResult<T> = Result<T, ConsensusError>;
