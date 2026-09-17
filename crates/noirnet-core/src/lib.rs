//! NoirNet core types and utilities

#![warn(missing_docs)]

use thiserror::Error;

/// Core error type for NoirNet
#[derive(Debug, Error)]
pub enum Error {
    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
    /// Crypto error
    #[error("Crypto error: {0}")]
    Crypto(String),
    /// Storage error
    #[error("Storage error: {0}")]
    Storage(String),
}

/// Core result type for NoirNet
pub type Result<T> = std::result::Result<T, Error>;

/// Common NoirNet utilities
pub mod utils {
    /// Macro for creating NoirNet results
    #[macro_export]
    macro_rules! noirnet_result {
        ($expr:expr) => {
            $expr.map_err(Into::into)
        };
    }
}

/// The NoirNet prelude - import commonly used items
pub mod prelude {
    pub use crate::Error;
    pub use crate::Result;
}
