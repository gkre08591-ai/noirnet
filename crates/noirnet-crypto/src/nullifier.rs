// nullifier.rs — обчислення nullifier-ів

use noirnet_types::hash::Hash32;

/// Обчислити nullifier для нотатки
/// nf = BLAKE3("NoirNet_Nullifier_v1" || nk || rho || commitment)
pub fn compute_nullifier(nk: &[u8; 32], rho: &[u8; 32], note_commitment: &Hash32) -> Hash32 {
    let mut h = blake3::Hasher::new();
    h.update(b"NoirNet_Nullifier_v1");
    h.update(nk);
    h.update(rho);
    h.update(note_commitment.as_bytes());
    Hash32(*h.finalize().as_bytes())
}

/// Верифікувати nullifier
pub fn verify_nullifier(
    nk: &[u8; 32],
    rho: &[u8; 32],
    note_commitment: &Hash32,
    claimed_nullifier: &Hash32,
) -> bool {
    compute_nullifier(nk, rho, note_commitment) == *claimed_nullifier
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullifier_deterministic() {
        let nk = [1u8; 32];
        let rho = [2u8; 32];
        let cm = Hash32([3u8; 32]);
        let nf1 = compute_nullifier(&nk, &rho, &cm);
        let nf2 = compute_nullifier(&nk, &rho, &cm);
        assert_eq!(nf1, nf2);
    }

    #[test]
    fn test_nullifier_unique_per_note() {
        let nk = [1u8; 32];
        let rho1 = [2u8; 32];
        let rho2 = [3u8; 32];
        let cm = Hash32([4u8; 32]);
        let nf1 = compute_nullifier(&nk, &rho1, &cm);
        let nf2 = compute_nullifier(&nk, &rho2, &cm);
        assert_ne!(nf1, nf2);
    }
}
