// noirnet-vm/src/lib.rs

pub mod host;
pub mod runtime;

pub use runtime::{ExecutionContext, ExecutionResult, WasmRuntime};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VmError {
    #[error("Wasmtime error: {0}")]
    Wasmtime(#[from] wasmtime::Error),
    #[error("Out of gas")]
    OutOfGas,
    #[error("Memory access violation")]
    MemoryViolation,
    #[error("Invalid WASM module")]
    InvalidModule,
}

pub type VmResult<T> = Result<T, VmError>;
