// noirnet-network/src/lib.rs

pub mod behaviour;
pub mod dandelion;
pub mod p2p;

pub use dandelion::{DandelionPhase, DandelionRouter};
pub use p2p::NetworkService;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("P2P error: {0}")]
    P2p(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Not connected to peer")]
    NotConnected,
}

pub type NetworkResult<T> = Result<T, NetworkError>;
