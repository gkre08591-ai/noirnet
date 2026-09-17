// hash.rs — типи хешів та ідентифікаторів

use serde::{Deserialize, Serialize};
use std::fmt;

/// 32-байтний хеш (SHA3-256 або BLAKE3)
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    pub const ZERO: Self = Self([0u8; 32]);

    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn blake3_of(data: &[u8]) -> Self {
        Self(*blake3::hash(data).as_bytes())
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash32({})", hex::encode(self.0))
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl From<[u8; 32]> for Hash32 {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl From<Hash32> for [u8; 32] {
    fn from(h: Hash32) -> Self {
        h.0
    }
}

/// Ідентифікатор транзакції
pub type TxId = Hash32;
/// Ідентифікатор блоку
pub type BlockHash = Hash32;
/// Ідентифікатор контракту
pub type ContractId = Hash32;
/// Commitment нотатки
pub type NoteCommitment = Hash32;
/// Nullifier
pub type Nullifier = Hash32;
/// Корінь дерева стану
pub type StateRoot = Hash32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash32_zero() {
        assert_eq!(Hash32::ZERO.0, [0u8; 32]);
    }

    #[test]
    fn test_hash32_blake3_deterministic() {
        let data = b"NoirNet test data";
        let h1 = Hash32::blake3_of(data);
        let h2 = Hash32::blake3_of(data);
        assert_eq!(h1, h2);
        assert_ne!(h1, Hash32::ZERO);
    }

    #[test]
    fn test_hash32_blake3_different_data() {
        let h1 = Hash32::blake3_of(b"data1");
        let h2 = Hash32::blake3_of(b"data2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash32_display_hex() {
        let h = Hash32([0xAB; 32]);
        let s = format!("{}", h);
        assert_eq!(s.len(), 64); // 32 bytes = 64 hex chars
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash32_from_bytes_roundtrip() {
        let bytes = [42u8; 32];
        let h = Hash32::from(bytes);
        let back: [u8; 32] = h.into();
        assert_eq!(bytes, back);
    }
}
