// note.rs — конфіденційна нотатка (UTXO)

use crate::hash::Hash32;
use serde::{Deserialize, Serialize};

/// Розшифрована нотатка (note) — зберігається в гаманці
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Note {
    /// Значення в nNOIR
    pub value: u64,
    /// Randomness (для commitment)
    pub rcm: [u8; 32],
    /// Nullifier randomness
    pub rho: [u8; 32],
    /// Одержувач (diversified public key)
    pub pk_d: [u8; 32],
    /// Diversifier
    pub diversifier: [u8; 11],
}

impl Note {
    pub fn new(
        value: u64,
        rcm: [u8; 32],
        rho: [u8; 32],
        pk_d: [u8; 32],
        diversifier: [u8; 11],
    ) -> Self {
        Self {
            value,
            rcm,
            rho,
            pk_d,
            diversifier,
        }
    }

    /// Обчислити commitment нотатки: cm = BLAKE3(value || rcm || rho || pk_d || diversifier)
    pub fn commitment(&self) -> Hash32 {
        let mut h = blake3::Hasher::new();
        h.update(b"NoirNet_note_cm_v1");
        h.update(&self.value.to_le_bytes());
        h.update(&self.rcm);
        h.update(&self.rho);
        h.update(&self.pk_d);
        h.update(&self.diversifier);
        Hash32(*h.finalize().as_bytes())
    }

    /// Серіалізувати для шифрування (enc_ciphertext payload)
    pub fn to_plaintext(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(11 + 8 + 32 + 32);
        out.extend_from_slice(&self.diversifier);
        out.extend_from_slice(&self.value.to_le_bytes());
        out.extend_from_slice(&self.rcm);
        out.extend_from_slice(&self.rho);
        out
    }

    /// Десеріалізувати з plaintext
    pub fn from_plaintext(data: &[u8], pk_d: [u8; 32]) -> Option<Self> {
        if data.len() < 83 {
            return None;
        }
        let diversifier: [u8; 11] = data[..11].try_into().ok()?;
        let value = u64::from_le_bytes(data[11..19].try_into().ok()?);
        let rcm: [u8; 32] = data[19..51].try_into().ok()?;
        let rho: [u8; 32] = data[51..83].try_into().ok()?;
        Some(Self {
            value,
            rcm,
            rho,
            pk_d,
            diversifier,
        })
    }
}

/// Зашифрований вихід транзакції
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputDescription {
    /// Commitment нової нотатки
    pub note_commitment: Hash32,
    /// Ephemeral public key (для ECDH розшифрування)
    pub ephemeral_key: [u8; 32],
    /// Зашифрована нотатка для отримувача (580 байт)
    pub enc_ciphertext: Vec<u8>,
    /// Зашифровано для відправника/аудитора (80 байт)
    pub out_ciphertext: Vec<u8>,
    /// Доказ коректності output (zk-SNARK, спрощено: commitment hash)
    pub cv: [u8; 32], // Value commitment
}

/// Опис витрати нотатки (spend input)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendDescription {
    /// Корінь дерева нотаток (anchor)
    pub anchor: Hash32,
    /// Nullifier (публічно розкривається)
    pub nullifier: Hash32,
    /// Rerandomized authorization key
    pub rk: [u8; 32],
    /// Value commitment
    pub cv: [u8; 32],
    /// Підпис spend auth
    #[serde(with = "serde_big_array::BigArray")]
    pub spend_auth_sig: [u8; 64],
}

/// Зашифрований memo
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedMemo(pub Vec<u8>); // max 512 bytes

impl EncryptedMemo {
    pub fn new(data: Vec<u8>) -> Option<Self> {
        if data.len() > crate::constants::MAX_MEMO_SIZE {
            None
        } else {
            Some(Self(data))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_note(value: u64) -> Note {
        Note::new(value, [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 11])
    }

    #[test]
    fn test_note_commitment_deterministic() {
        let n1 = make_note(1000);
        let n2 = make_note(1000);
        assert_eq!(n1.commitment(), n2.commitment());
    }

    #[test]
    fn test_note_commitment_unique_per_value() {
        let n1 = make_note(1000);
        let n2 = make_note(2000);
        assert_ne!(n1.commitment(), n2.commitment());
    }

    #[test]
    fn test_note_commitment_unique_per_rcm() {
        let n1 = Note::new(1000, [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 11]);
        let n2 = Note::new(1000, [9u8; 32], [2u8; 32], [3u8; 32], [4u8; 11]);
        assert_ne!(n1.commitment(), n2.commitment());
    }

    #[test]
    fn test_note_plaintext_roundtrip() {
        let note = make_note(5_000_000_000);
        let plaintext = note.to_plaintext();
        let recovered = Note::from_plaintext(&plaintext, note.pk_d).unwrap();
        assert_eq!(recovered.value, note.value);
        assert_eq!(recovered.rcm, note.rcm);
        assert_eq!(recovered.rho, note.rho);
        assert_eq!(recovered.diversifier, note.diversifier);
    }

    #[test]
    fn test_note_from_plaintext_too_short() {
        let short = vec![0u8; 10];
        assert!(Note::from_plaintext(&short, [0u8; 32]).is_none());
    }

    #[test]
    fn test_encrypted_memo_valid() {
        let data = vec![0u8; 100];
        assert!(EncryptedMemo::new(data).is_some());
    }

    #[test]
    fn test_encrypted_memo_max_size() {
        let data = vec![0u8; crate::constants::MAX_MEMO_SIZE + 1];
        assert!(EncryptedMemo::new(data).is_none());
    }

    #[test]
    fn test_encrypted_memo_exact_max() {
        let data = vec![0u8; crate::constants::MAX_MEMO_SIZE];
        assert!(EncryptedMemo::new(data).is_some());
    }
}
