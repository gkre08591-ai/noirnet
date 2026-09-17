//! NoirNet P2P protocol implementation
//!
//! Libp2p protocol handlers and message types for NoirNet P2P network.
//! Includes gossip, block propagation, and transaction distribution.

#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

pub mod handler;
pub mod message;
pub mod protocol;

#[cfg(test)]
mod tests;

pub use handler::P2pHandler;
pub use message::P2pMessage;
pub use protocol::P2pProtocol;

/// P2P protocol configuration
pub mod config {
    /// Protocol ID
    pub const PROTOCOL_ID: &str = "/noirnet/1.0.0";

    /// Topic name for block gossip
    pub const BLOCK_TOPIC: &str = "/noirnet/blocks";

    /// Topic name for transaction gossip
    pub const TX_TOPIC: &str = "/noirnet/transactions";

    /// Message compression threshold
    pub const COMPRESSION_THRESHOLD: usize = 1024;
}

/// P2P message types
pub mod types {
    use serde::{Deserialize, Serialize};

    /// Block announcement
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct BlockAnnouncement {
        /// Block hash
        pub hash: [u8; 32],
        /// Block height
        pub height: u64,
        /// Timestamp
        pub timestamp: u64,
    }

    /// Transaction announcement
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct TransactionAnnouncement {
        /// Transaction hash
        pub hash: [u8; 32],
        /// Gas price
        pub gas_price: u64,
    }

    /// Get blocks request
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct GetBlocks {
        /// Starting height
        pub from: u64,
        /// Number of blocks
        pub count: u64,
    }

    /// Get transactions request
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct GetTransactions {
        /// Transaction hashes
        pub hashes: Vec<[u8; 32]>,
    }
}

/// P2P errors
pub mod error {
    use thiserror::Error;

    /// P2P-related errors
    #[derive(Error, Debug)]
    pub enum P2pError {
        /// Protocol error
        #[error("Protocol error: {0}")]
        Protocol(String),

        /// Message handling error
        #[error("Message error: {0}")]
        Message(String),

        /// Peer error
        #[error("Peer error: {0}")]
        Peer(String),
    }
}
