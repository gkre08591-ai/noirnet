// noirnet-zk/src/lib.rs

pub mod output;
pub mod proof;
pub mod spend;

pub use output::OutputCircuit;
pub use proof::{generate_multi_spend_proof, setup_nova, verify_spend_proof, ZkError};
pub use spend::SpendCircuit;
