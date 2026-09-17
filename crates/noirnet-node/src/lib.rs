//! NoirNet full node implementation

pub use error::NodeError;

/// Node errors
pub mod error {
    use thiserror::Error;

    /// Node-related errors
    #[derive(Error, Debug)]
    pub enum NodeError {
        /// Configuration error
        #[error("Configuration error: {0}")]
        Config(String),

        /// Startup error
        #[error("Startup error: {0}")]
        Startup(String),

        /// Runtime error
        #[error("Runtime error: {0}")]
        Runtime(String),
    }
}
