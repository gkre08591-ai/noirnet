use super::{VmError, VmResult};
use crate::host;
use noirnet_types::hash::Hash32;
use std::collections::HashMap;
use wasmtime::{Caller, Config, Engine, Linker, Memory, Module, Store};

pub struct WasmRuntime { pub engine: Engine, }

#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub return_data: Vec<u8>,
    pub gas_used: u64,
    pub state_changes: HashMap<Vec<u8>, Vec<u8>>,
    pub events: Vec<ContractEvent>,
}
#[derive(Debug, Clone)]
pub struct ContractEvent {
    pub contract: Hash32,
    pub data: Vec<u8>,
}
pub struct ExecutionContext {
    pub contract_id: Hash32,
    pub caller_commitment: [u8; 32],
    pub gas_remaining: u64,
    pub state_diff: HashMap<Vec<u8>, Vec<u8>>,
    pub existing_state: HashMap<Vec<u8>, Vec<u8>>,
    pub events: Vec<ContractEvent>,
    pub memory: Option<Memory>,
}

impl ExecutionContext {
    pub fn charge_gas(&mut self, amount: u64) -> VmResult<()> {
        if self.gas_remaining < amount { return Err(VmError::OutOfGas); }
        self.gas_remaining -= amount; Ok(())
    }
    pub fn read_memory(&self, caller: &Caller<'_, Self>, ptr: u32, len: u32) -> VmResult<Vec<u8>> {
        let mem = self.memory.as_ref().expect("Memory not initialized");
        let data = mem.data(caller);
        let (start, end) = (ptr as usize, ptr as usize + len as usize);
        if end > data.len() { return Err(VmError::MemoryViolation); }
        Ok(data[start..end].to_vec())
    }
    pub fn write_memory(caller: &mut Caller<'_, Self>, ptr: u32, bytes: &[u8]) -> VmResult<()> {
        let (start, end) = (ptr as usize, ptr as usize + bytes.len());
        let mem = caller.data().memory.expect("Memory not initialized");
        let mem_size = mem.data_size(&*caller);
        if end > mem_size { return Err(VmError::MemoryViolation); }
        let data = mem.data_mut(caller);
        data[start..end].copy_from_slice(bytes);
        Ok(())
    }
}

impl WasmRuntime {
    pub fn new() -> VmResult<Self> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);
        let engine = Engine::new(&config)?;
        
        let engine_clone = engine.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(10));
                engine_clone.increment_epoch();
            }
        });

        Ok(Self { engine })
    }
    pub fn execute(&self, code: &[u8], method: &str, _args: &[u8], ctx: ExecutionContext) -> VmResult<ExecutionResult> {
        let module = Module::new(&self.engine, code)?;
        let mut linker = Linker::new(&self.engine);
        host::register_host_functions(&mut linker)?;
        let mut store = Store::new(&self.engine, ctx);
        let gas_limit = store.data().gas_remaining;
        store.set_fuel(gas_limit)?;
        store.epoch_deadline_trap();
        store.set_epoch_deadline(100);
        let instance = linker.instantiate(&mut store, &module)?;
        let memory = instance.get_memory(&mut store, "memory").ok_or(VmError::MemoryViolation)?;
        store.data_mut().memory = Some(memory);
        let func = instance.get_typed_func::<(), ()>(&mut store, method).map_err(|_| VmError::MemoryViolation)?;
        let result = func.call(&mut store, ());
        let remaining = store.get_fuel().unwrap_or(0);
        let gas_used = gas_limit.saturating_sub(remaining);
        match result {
            Ok(()) => {
                let ctx = store.into_data();
                Ok(ExecutionResult { return_data: vec![], gas_used, state_changes: ctx.state_diff, events: ctx.events })
            }
            Err(e) => {
                if e.to_string().contains("out of fuel") { Err(VmError::OutOfGas) }
                else { Err(VmError::Wasmtime(e)) }
            }
        }
    }
}
