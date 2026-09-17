// address.rs — адреси та ключі NoirNet

use crate::hash::Hash32;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Публічна адреса для отримання платежів (stealth)
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentAddress {
    /// Diversifier (11 bytes) — дозволяє мати багато адрес з одного ключа
    pub diversifier: [u8; 11],
    /// Публічний ключ диверсифікатора (32 bytes, Jubjub/Ed25519 point)
    pub pk_d: [u8; 32],
}

impl PaymentAddress {
    pub fn new(diversifier: [u8; 11], pk_d: [u8; 32]) -> Self {
        Self { diversifier, pk_d }
    }

    /// Закодувати адресу в Base58Check рядок (внутрішня реалізація)
    fn to_base58_string(&self) -> String {
        let mut raw = [0u8; 43];
        raw[..11].copy_from_slice(&self.diversifier);
        raw[11..43].copy_from_slice(&self.pk_d);
        // Prefix "NR" = [0x21, 0x89]
        let mut prefixed = vec![0x21, 0x89];
        prefixed.extend_from_slice(&raw);
        bs58_encode_check(&prefixed)
    }
}

impl std::fmt::Display for PaymentAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base58_string())
    }
}

impl std::fmt::Debug for PaymentAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PaymentAddress({}...)", hex::encode(&self.pk_d[..4]))
    }
}

fn bs58_encode_check(data: &[u8]) -> String {
    // Simple base58 with checksum
    let checksum = Hash32::blake3_of(data);
    let mut payload = data.to_vec();
    payload.extend_from_slice(&checksum.0[..4]);
    bs58::encode(payload).into_string()
}

/// Повний перегляд ключ — бачить всі вхідні та вихідні транзакції
#[derive(Clone, Serialize, Deserialize)]
pub struct FullViewingKey {
    pub ak: [u8; 32],  // Authorization key
    pub nk: [u8; 32],  // Nullifier key
    pub ovk: [u8; 32], // Outgoing viewing key
}

/// Вхідний ключ перегляду — тільки вхідні транзакції
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct IncomingViewKey {
    pub ivk: [u8; 32],
}

impl IncomingViewKey {
    pub fn from_fvk(fvk: &FullViewingKey) -> Self {
        // ivk = CRH(ak, nk) mod r_Jubjub  (simplified: BLAKE3)
        let mut h = blake3::Hasher::new();
        h.update(b"NoirNet_ivk_v1");
        h.update(&fvk.ak);
        h.update(&fvk.nk);
        let out = h.finalize();
        Self {
            ivk: *out.as_bytes(),
        }
    }

    /// Derive payment address for a given diversifier index
    pub fn payment_address(&self, diversifier_index: u64) -> PaymentAddress {
        // Derive diversifier bytes from index
        let mut div = [0u8; 11];
        div[..8].copy_from_slice(&diversifier_index.to_le_bytes());
        // pk_d = hash(ivk || diversifier)
        let mut h = blake3::Hasher::new();
        h.update(b"NoirNet_pkd_v1");
        h.update(&self.ivk);
        h.update(&div);
        let pk_d: [u8; 32] = *h.finalize().as_bytes();
        PaymentAddress::new(div, pk_d)
    }
}

/// Вихідний ключ перегляду
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct OutgoingViewKey {
    pub ovk: [u8; 32],
}

/// Spending Key — приватний ключ витрат (зберігати тільки в гаманці!)
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SpendingKey {
    pub sk: [u8; 32],
}

impl SpendingKey {
    /// Генерація з seed
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"NoirNet_sk_v1");
        h.update(seed);
        Self {
            sk: *h.finalize().as_bytes(),
        }
    }

    /// Похідні ключі
    pub fn to_fvk(&self) -> FullViewingKey {
        let ak = prf(&self.sk, b"ak");
        let nk = prf(&self.sk, b"nk");
        let ovk = prf(&self.sk, b"ovk");
        FullViewingKey { ak, nk, ovk }
    }
}

fn prf(sk: &[u8; 32], tag: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"NoirNet_prf_v1");
    h.update(sk);
    h.update(tag);
    *h.finalize().as_bytes()
}

/// Ідентифікатор валідатора (публічний ключ BLS у вигляді Hash32)
#[derive(Clone, Debug, PartialEq, Eq, std::hash::Hash, Serialize, Deserialize)]
pub struct ValidatorId(#[serde(with = "serde_big_array::BigArray")] pub [u8; 48]); // BLS12-381 pubkey compressed

impl ValidatorId {
    pub fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spending_key_from_seed_deterministic() {
        let sk1 = SpendingKey::from_seed(b"test seed 1234567890123456");
        let sk2 = SpendingKey::from_seed(b"test seed 1234567890123456");
        assert_eq!(sk1.sk, sk2.sk);
    }

    #[test]
    fn test_spending_key_different_seeds() {
        let sk1 = SpendingKey::from_seed(b"seed_a");
        let sk2 = SpendingKey::from_seed(b"seed_b");
        assert_ne!(sk1.sk, sk2.sk);
    }

    #[test]
    fn test_fvk_derivation_deterministic() {
        let sk = SpendingKey::from_seed(b"deterministic seed");
        let fvk1 = sk.to_fvk();
        let fvk2 = sk.to_fvk();
        assert_eq!(fvk1.ak, fvk2.ak);
        assert_eq!(fvk1.nk, fvk2.nk);
        assert_eq!(fvk1.ovk, fvk2.ovk);
    }

    #[test]
    fn test_fvk_keys_are_distinct() {
        let sk = SpendingKey::from_seed(b"key distinction test");
        let fvk = sk.to_fvk();
        assert_ne!(fvk.ak, fvk.nk);
        assert_ne!(fvk.nk, fvk.ovk);
        assert_ne!(fvk.ak, fvk.ovk);
    }

    #[test]
    fn test_ivk_from_fvk() {
        let sk = SpendingKey::from_seed(b"ivk test seed!!!");
        let fvk = sk.to_fvk();
        let ivk1 = IncomingViewKey::from_fvk(&fvk);
        let ivk2 = IncomingViewKey::from_fvk(&fvk);
        assert_eq!(ivk1.ivk, ivk2.ivk);
        assert_ne!(ivk1.ivk, [0u8; 32]);
    }

    #[test]
    fn test_payment_address_derivation() {
        let sk = SpendingKey::from_seed(b"payment address test");
        let fvk = sk.to_fvk();
        let ivk = IncomingViewKey::from_fvk(&fvk);
        let addr0 = ivk.payment_address(0);
        let addr1 = ivk.payment_address(1);
        // Different diversifier indices produce different addresses
        assert_ne!(addr0.pk_d, addr1.pk_d);
        assert_ne!(addr0.diversifier, addr1.diversifier);
    }

    #[test]
    fn test_payment_address_to_string() {
        let sk = SpendingKey::from_seed(b"address encoding test!");
        let fvk = sk.to_fvk();
        let ivk = IncomingViewKey::from_fvk(&fvk);
        let addr = ivk.payment_address(0);
        let s = addr.to_string();
        assert!(!s.is_empty());
        assert!(s.len() > 20); // Base58 encoded should be at least ~60 chars
    }

    #[test]
    fn test_validator_id() {
        let vid = ValidatorId([42u8; 48]);
        assert_eq!(vid.as_bytes(), &[42u8; 48]);
    }
}
