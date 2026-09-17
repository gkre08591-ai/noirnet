// commitment.rs — Pedersen-style value commitments

use noirnet_types::hash::Hash32;

/// Value commitment: cv = BLAKE3("NoirNet_ValueCommit" || value || rcv)
/// Реальна реалізація використовує Jubjub Pedersen commitments,
/// тут — спрощена BLAKE3-based версія для тестнету
pub fn value_commitment(value: u64, rcv: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"NoirNet_ValueCommit_v1");
    h.update(&value.to_le_bytes());
    h.update(rcv);
    *h.finalize().as_bytes()
}

/// Перевірка balancing: сума spent CV == сума output CV + fee CV
/// Спрощено: порівняння хешів (у реалі — EC point arithmetic)
pub fn check_value_balance(
    _spend_cvs: &[[u8; 32]],
    _output_cvs: &[[u8; 32]],
    fee: u64,
    spend_values: &[u64], // для тесту: реальні суми
    output_values: &[u64],
) -> bool {
    let total_in: u64 = spend_values.iter().sum();
    let total_out: u64 = output_values.iter().sum();
    total_in == total_out + fee
}

/// Note commitment: cm = BLAKE3(note_plaintext)
pub fn note_commitment(
    value: u64,
    pk_d: &[u8; 32],
    rho: &[u8; 32],
    rcm: &[u8; 32],
    diversifier: &[u8; 11],
) -> Hash32 {
    let mut h = blake3::Hasher::new();
    h.update(b"NoirNet_note_cm_v1");
    h.update(&value.to_le_bytes());
    h.update(pk_d);
    h.update(rho);
    h.update(rcm);
    h.update(diversifier);
    Hash32(*h.finalize().as_bytes())
}

/// Randomized commitment (rerandomization for spend proof)
pub fn rerandomize_commitment(cm: &Hash32, alpha: &[u8; 32]) -> Hash32 {
    let mut h = blake3::Hasher::new();
    h.update(b"NoirNet_rerandom_v1");
    h.update(cm.as_bytes());
    h.update(alpha);
    Hash32(*h.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_balance() {
        let spend_cvs: Vec<[u8; 32]> = vec![[0u8; 32]];
        let out_cvs: Vec<[u8; 32]> = vec![[0u8; 32]];
        assert!(check_value_balance(
            &spend_cvs,
            &out_cvs,
            1000,
            &[10000],
            &[9000]
        ));
        assert!(!check_value_balance(
            &spend_cvs,
            &out_cvs,
            1000,
            &[10000],
            &[10000]
        ));
    }
}
