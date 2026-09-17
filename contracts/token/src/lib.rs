#![cfg_attr(target_arch = "wasm32", no_std)]

#[cfg(target_arch = "wasm32")]
use core::panic::PanicInfo;

// Оголошуємо хост-функції, які надає `noirnet-vm` (визначені в `host.rs`)
extern "C" {
    fn storage_set(k_ptr: *const u8, k_len: u32, v_ptr: *const u8, v_len: u32);
    fn storage_get(k_ptr: *const u8, k_len: u32, out_ptr: *mut u8) -> i32;
    fn emit_event(d_ptr: *const u8, d_len: u32);
    #[allow(dead_code)]
    fn sha3_256(in_ptr: *const u8, in_len: u32, out_ptr: *mut u8);
}

// --- Обгортки над хост-функціями ---

fn set_state(key: &[u8], value: &[u8]) {
    unsafe {
        storage_set(
            key.as_ptr(),
            key.len() as u32,
            value.as_ptr(),
            value.len() as u32,
        );
    }
}

fn get_state(key: &[u8], buf: &mut [u8]) -> i32 {
    unsafe { storage_get(key.as_ptr(), key.len() as u32, buf.as_mut_ptr()) }
}

fn emit(data: &[u8]) {
    unsafe {
        emit_event(data.as_ptr(), data.len() as u32);
    }
}

// --- Утилітні функції ---

fn u64_to_bytes(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

fn bytes_to_u64(b: &[u8; 8]) -> u64 {
    u64::from_le_bytes(*b)
}

fn get_balance(account: &[u8; 32]) -> u64 {
    // Ключ = "bal:" + account (36 bytes)
    let mut key = [0u8; 36];
    key[0..4].copy_from_slice(b"bal:");
    key[4..36].copy_from_slice(account);

    let mut buf = [0u8; 8];
    let len = get_state(&key, &mut buf);
    if len < 0 {
        0 // Немає запису = баланс 0
    } else {
        bytes_to_u64(&buf)
    }
}

fn set_balance(account: &[u8; 32], amount: u64) {
    let mut key = [0u8; 36];
    key[0..4].copy_from_slice(b"bal:");
    key[4..36].copy_from_slice(account);
    set_state(&key, &u64_to_bytes(amount));
}

// --- Публічні функції контракту ---

/// Ініціалізація токена: перший аккаунт (32 zero bytes) отримує TOTAL_SUPPLY
#[no_mangle]
pub extern "C" fn init() {
    let total_supply: u64 = 1_000_000_000; // 1 мільярд nNOIR
    let treasury = [0u8; 32]; // Treasury = нульовий акаунт

    set_balance(&treasury, total_supply);
    set_state(b"TOTAL_SUPPLY", &u64_to_bytes(total_supply));
    set_state(b"DECIMALS", &[8]); // 8 десяткових знаків
    set_state(b"SYMBOL", b"NOIR");
    set_state(b"NAME", b"NoirNet Token");

    emit(b"TokenInitialized:1000000000");
}

/// Трансфер токенів
/// ABI (спрощений): перші 32 байти — from, наступні 32 — to, останні 8 — amount
/// Аргументи зчитуються з пам'яті WASM через хост. Тут для POC хардкоджено.
#[no_mangle]
pub extern "C" fn transfer() {
    // В реальному контракті аргументи зчитуються з лінійної пам'яті WASM.
    // Для POC ми використовуємо фіксовані адреси.
    let from = [0u8; 32]; // Treasury
    let to = [1u8; 32];   // Recipient

    let amount: u64 = 1000;

    let from_balance = get_balance(&from);
    if from_balance < amount {
        emit(b"TransferFailed:InsufficientBalance");
        return;
    }

    let to_balance = get_balance(&to);

    set_balance(&from, from_balance - amount);
    set_balance(&to, to_balance + amount);

    emit(b"Transfer:1000");
}

// Потрібно для `#![no_std]` при збірці контракту у WASM.
#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}
