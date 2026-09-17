// host.rs — хост функції для WASM (production-hardened)

use super::{runtime::ContractEvent, ExecutionContext, VmError};
use wasmtime::{Caller, Linker};

/// Допоміжна функція: конвертувати VmError в wasmtime::Error (trap)
fn vm_trap(e: VmError) -> wasmtime::Error {
    wasmtime::Error::msg(e.to_string())
}

pub fn register_host_functions(linker: &mut Linker<ExecutionContext>) -> Result<(), VmError> {
    // storage_set(key_ptr, key_len, val_ptr, val_len)
    linker.func_wrap(
        "env",
        "storage_set",
        |mut caller: Caller<'_, ExecutionContext>,
         k_ptr: u32,
         k_len: u32,
         v_ptr: u32,
         v_len: u32|
         -> Result<(), wasmtime::Error> {
            let key = caller.data().read_memory(&caller, k_ptr, k_len).map_err(vm_trap)?;
            let val = caller.data().read_memory(&caller, v_ptr, v_len).map_err(vm_trap)?;

            caller
                .data_mut()
                .charge_gas(500 + val.len() as u64 * 10)
                .map_err(vm_trap)?;
            caller.data_mut().state_diff.insert(key, val);
            Ok(())
        },
    )?;

    // emit_event(data_ptr, data_len)
    linker.func_wrap(
        "env",
        "emit_event",
        |mut caller: Caller<'_, ExecutionContext>,
         d_ptr: u32,
         d_len: u32|
         -> Result<(), wasmtime::Error> {
            let data = caller.data().read_memory(&caller, d_ptr, d_len).map_err(vm_trap)?;
            caller
                .data_mut()
                .charge_gas(100 + data.len() as u64 * 5)
                .map_err(vm_trap)?;

            let contract = caller.data().contract_id;
            caller
                .data_mut()
                .events
                .push(ContractEvent { contract, data });
            Ok(())
        },
    )?;

    // sha3_256(in_ptr, in_len, out_ptr)
    linker.func_wrap(
        "env",
        "sha3_256",
        |mut caller: Caller<'_, ExecutionContext>,
         in_ptr: u32,
         in_len: u32,
         out_ptr: u32|
         -> Result<(), wasmtime::Error> {
            let data = caller.data().read_memory(&caller, in_ptr, in_len).map_err(vm_trap)?;
            caller
                .data_mut()
                .charge_gas(50 + data.len() as u64 * 5)
                .map_err(vm_trap)?;

            let hash = noirnet_types::hash::Hash32::blake3_of(&data);
            ExecutionContext::write_memory(&mut caller, out_ptr, hash.as_bytes()).map_err(vm_trap)?;
            Ok(())
        },
    )?;

    // storage_get(key_ptr, key_len, out_ptr) -> i32 (value length, -1 if not found)
    linker.func_wrap(
        "env",
        "storage_get",
        |mut caller: Caller<'_, ExecutionContext>,
         k_ptr: u32,
         k_len: u32,
         out_ptr: u32|
         -> Result<i32, wasmtime::Error> {
            let key = caller.data().read_memory(&caller, k_ptr, k_len).map_err(vm_trap)?;
            caller
                .data_mut()
                .charge_gas(200 + key.len() as u64 * 5)
                .map_err(vm_trap)?;

            // Спочатку перевіряємо незакомічені записи (state_diff)
            // Потім фолбек на попередньо завантажений стан (existing_state)
            let value = if let Some(v) = caller.data().state_diff.get(&key) {
                Some(v.clone())
            } else {
                caller.data().existing_state.get(&key).cloned()
            };

            match value {
                Some(val) => {
                    let len = val.len() as i32;
                    ExecutionContext::write_memory(&mut caller, out_ptr, &val).map_err(vm_trap)?;
                    Ok(len)
                }
                None => Ok(-1),
            }
        },
    )?;

    Ok(())
}
