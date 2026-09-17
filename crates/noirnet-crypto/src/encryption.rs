// encryption.rs — шифрування memo та загальні утиліти

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use noirnet_types::constants::MAX_MEMO_SIZE;

/// Зашифрувати memo
pub fn encrypt_memo(key: &[u8; 32], memo: &[u8]) -> Option<Vec<u8>> {
    if memo.len() > MAX_MEMO_SIZE {
        return None;
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_bytes = random_bytes::<12>();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut result = nonce_bytes.to_vec();
    result.extend(cipher.encrypt(nonce, memo).ok()?);
    Some(result)
}

/// Розшифрувати memo
pub fn decrypt_memo(key: &[u8; 32], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() < 12 {
        return None;
    }
    let (nonce_bytes, cipher_text) = ciphertext.split_at(12);
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, cipher_text).ok()
}

/// BLAKE3-based KDF (HKDF-like)
pub fn kdf(ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let mut h = blake3::Hasher::new_keyed(&{
        let mut key = [0u8; 32];
        let k = blake3::hash(ikm);
        key.copy_from_slice(k.as_bytes());
        key
    });
    h.update(info);
    let xof = h.finalize_xof();
    let mut reader = xof;
    reader.fill(out);
}

/// Secure random bytes
pub fn random_bytes<const N: usize>() -> [u8; N] {
    use rand_core::{OsRng, RngCore};
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Constant-time compare
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memo_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let memo = b"Hello NoirNet!";
        let encrypted = encrypt_memo(&key, memo).unwrap();
        let decrypted = decrypt_memo(&key, &encrypted).unwrap();
        assert_eq!(decrypted, memo);
    }

    #[test]
    fn test_memo_wrong_key_fails() {
        let key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let memo = b"secret message";
        let encrypted = encrypt_memo(&key, memo).unwrap();
        assert!(decrypt_memo(&wrong_key, &encrypted).is_none());
    }

    #[test]
    fn test_memo_max_size_rejection() {
        let key = [42u8; 32];
        let oversized = vec![0u8; MAX_MEMO_SIZE + 1];
        assert!(encrypt_memo(&key, &oversized).is_none());
    }

    #[test]
    fn test_kdf_deterministic() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        kdf(b"input key material", b"info", &mut out1);
        kdf(b"input key material", b"info", &mut out2);
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_kdf_different_info() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        kdf(b"same ikm", b"info1", &mut out1);
        kdf(b"same ikm", b"info2", &mut out2);
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_random_bytes_unique() {
        let a = random_bytes::<32>();
        let b = random_bytes::<32>();
        assert_ne!(a, b);
    }

    #[test]
    fn test_ct_eq_equal() {
        assert!(ct_eq(b"hello", b"hello"));
    }

    #[test]
    fn test_ct_eq_not_equal() {
        assert!(!ct_eq(b"hello", b"world"));
    }

    #[test]
    fn test_ct_eq_different_length() {
        assert!(!ct_eq(b"short", b"longer string"));
    }
}
