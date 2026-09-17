// bls.rs — Реалізація BLS12-381 підписів за допомогою бібліотеки blst
// Використовуємо схему "min_pk" (PublicKey у G1, Signature у G2)

use blst::min_pk as bls;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BlsError {
    #[error("Invalid secret key")]
    InvalidSecretKey,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Aggregation failed")]
    AggregationFailed,
    #[error("Verification failed")]
    VerificationFailed,
}

pub type BlsResult<T> = Result<T, BlsError>;

/// Секретний ключ BLS (32 байти)
pub struct BlsSecretKey(bls::SecretKey);

impl BlsSecretKey {
    pub fn generate() -> Self {
        let mut ikm = [0u8; 32];
        rand::Rng::fill(&mut rand::thread_rng(), &mut ikm);
        Self(bls::SecretKey::key_gen(&ikm, &[]).expect("key_gen failed"))
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> BlsResult<Self> {
        bls::SecretKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| BlsError::InvalidSecretKey)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public_key(&self) -> BlsPublicKey {
        BlsPublicKey(self.0.sk_to_pk())
    }

    pub fn sign(&self, msg: &[u8]) -> BlsSignature {
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
        BlsSignature(self.0.sign(msg, dst, &[]))
    }
}

/// Публічний ключ BLS (48 байт у G1)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlsPublicKey(#[serde(with = "serde_bytes_48")] pub bls::PublicKey);

impl BlsPublicKey {
    pub fn from_bytes(bytes: &[u8; 48]) -> BlsResult<Self> {
        bls::PublicKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| BlsError::InvalidPublicKey)
    }

    pub fn to_bytes(&self) -> [u8; 48] {
        self.0.to_bytes()
    }
}

/// Одиночний підпис BLS (96 байт у G2)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlsSignature(#[serde(with = "serde_bytes_96")] pub bls::Signature);

impl BlsSignature {
    pub fn from_bytes(bytes: &[u8; 96]) -> BlsResult<Self> {
        bls::Signature::from_bytes(bytes)
            .map(Self)
            .map_err(|_| BlsError::InvalidSignature)
    }

    pub fn to_bytes(&self) -> [u8; 96] {
        self.0.to_bytes()
    }

    pub fn verify(&self, msg: &[u8], pk: &BlsPublicKey) -> bool {
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
        self.0.verify(true, msg, dst, &[], &pk.0, true) == blst::BLST_ERROR::BLST_SUCCESS
    }
}

/// Агрегований підпис BLS (96 байт у G2)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlsAggregateSignature(#[serde(with = "serde_bytes_96")] pub bls::Signature);

impl BlsAggregateSignature {
    pub fn from_bytes(bytes: &[u8; 96]) -> BlsResult<Self> {
        bls::Signature::from_bytes(bytes)
            .map(Self)
            .map_err(|_| BlsError::InvalidSignature)
    }

    pub fn to_bytes(&self) -> [u8; 96] {
        self.0.to_bytes()
    }

    /// Створити агрегований підпис із списку одиночних
    pub fn aggregate(sigs: &[BlsSignature]) -> BlsResult<Self> {
        if sigs.is_empty() {
            return Err(BlsError::AggregationFailed);
        }
        let sigs_refs: Vec<&bls::Signature> = sigs.iter().map(|s| &s.0).collect();
        bls::AggregateSignature::aggregate(&sigs_refs, true)
            .map(|agg| Self(agg.to_signature()))
            .map_err(|_| BlsError::AggregationFailed)
    }

    /// Верифікувати агрегований підпис проти списку публічних ключів (одне повідомлення)
    pub fn verify_batch(&self, msg: &[u8], pks: &[BlsPublicKey]) -> bool {
        if pks.is_empty() {
            return false;
        }
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
        let pks_refs: Vec<&bls::PublicKey> = pks.iter().map(|p| &p.0).collect();
        self.0.fast_aggregate_verify(true, msg, dst, &pks_refs) == blst::BLST_ERROR::BLST_SUCCESS
    }
}

mod serde_bytes_48 {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(val: &bls::PublicKey, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        s.serialize_bytes(&val.to_bytes())
    }

    pub fn deserialize<'de, D>(d: D) -> Result<bls::PublicKey, D::Error>
    where D: Deserializer<'de> {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(d)?;
        bls::PublicKey::from_bytes(&bytes).map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
    }
}

mod serde_bytes_96 {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(val: &bls::Signature, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        s.serialize_bytes(&val.to_bytes())
    }

    pub fn deserialize<'de, D>(d: D) -> Result<bls::Signature, D::Error>
    where D: Deserializer<'de> {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(d)?;
        bls::Signature::from_bytes(&bytes).map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bls_sign_verify() {
        let sk = BlsSecretKey::generate();
        let pk = sk.public_key();
        let msg = b"NoirNet block 123";
        let sig = sk.sign(msg);
        assert!(sig.verify(msg, &pk));
    }

    #[test]
    fn test_bls_aggregation() {
        let msg = b"Common message";
        let sks: Vec<_> = (0..5).map(|_| BlsSecretKey::generate()).collect();
        let pks: Vec<_> = sks.iter().map(|sk| sk.public_key()).collect();
        let sigs: Vec<_> = sks.iter().map(|sk| sk.sign(msg)).collect();

        let agg_sig = BlsAggregateSignature::aggregate(&sigs).unwrap();
        assert!(agg_sig.verify_batch(msg, &pks));
    }
}
