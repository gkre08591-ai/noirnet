// transaction.rs — конфіденційна транзакція NoirNet

use crate::hash::Hash32;
use crate::note::{EncryptedMemo, OutputDescription, SpendDescription};
use serde::{Deserialize, Serialize};

/// Основна структура конфіденційної транзакції
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    /// Версія протоколу
    pub version: u8,
    /// Chain ID (захист від replay)
    pub chain_id: u32,
    /// Vitrati (inputs)
    pub spends: Vec<SpendDescription>,
    /// Нові нотатки (outputs)
    pub outputs: Vec<OutputDescription>,
    /// Комісія (відкрита, в nNOIR)
    pub fee: u64,
    /// Gas ліміт
    pub gas_limit: u64,
    /// Зашифрований memo (опційно)
    pub memo: Option<EncryptedMemo>,
    /// Виклик смарт-контракту (опційно)
    pub contract_call: Option<ContractCall>,
    /// Розгортання нового смарт-контракту (WASM байткод)
    pub deploy_contract: Option<Vec<u8>>,
    /// Binding signature (64 bytes, запобігає підробці балансу)
    #[serde(with = "serde_big_array::BigArray")]
    pub binding_sig: [u8; 64],
    /// Timestamp (anti-replay, Unix seconds)
    pub timestamp: u64,
    /// Aggregate ZK Spend Proof (Nova RecursiveSNARK bytes)
    pub aggregate_spend_proof: Vec<u8>,
}

impl Transaction {
    /// Отримати поточний час, округлений до 15 хвилин (захист від деанонімізації)
    pub fn now_obfuscated() -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Округлюємо до найближчих 15 хвилин (900 секунд)
        (now / 900) * 900
    }

    /// Обчислити TxId (BLAKE3 hash від серіалізованої транзакції)
    pub fn tx_id(&self) -> Hash32 {
        let bytes = bincode::serialize(self).expect("tx serialize");
        Hash32::blake3_of(&bytes)
    }

    /// Базова валідація формату
    pub fn validate_format(&self) -> Result<(), TxFormatError> {
        if self.version != 1 {
            return Err(TxFormatError::UnsupportedVersion(self.version));
        }
        if self.spends.is_empty() && self.contract_call.is_none() && self.deploy_contract.is_none() {
            return Err(TxFormatError::NoInputs);
        }
        if self.outputs.is_empty() && self.contract_call.is_none() && self.deploy_contract.is_none() {
            return Err(TxFormatError::NoOutputs);
        }

        // CVE-001 FIX: Prevent Merkle Glob Attack (OOM via excessive spends/outputs)
        if self.spends.len() > crate::constants::MAX_SPENDS_PER_TX {
            return Err(TxFormatError::TooManySpends);
        }
        if self.outputs.len() > crate::constants::MAX_OUTPUTS_PER_TX {
            return Err(TxFormatError::TooManyOutputs);
        }

        // CVE-005 FIX: Fee must be one of the allowed tiers (anti-fingerprinting)
        if !crate::constants::FEE_TIERS.contains(&self.fee) {
            return Err(TxFormatError::InvalidFeeTier);
        }

        if self.gas_limit > crate::constants::MAX_TX_GAS {
            return Err(TxFormatError::GasLimitTooHigh);
        }
        
        // Red Team Patch: Timestamp Fingerprinting Protection
        if self.timestamp % 900 != 0 {
            return Err(TxFormatError::InvalidTimestamp);
        }

        // Red Team Patch: Prevent WASM Bomb / OOM Attacks
        if let Some(code) = &self.deploy_contract {
            if code.len() > crate::constants::MAX_CONTRACT_SIZE {
                return Err(TxFormatError::ContractTooLarge);
            }
        }
        
        let tx_size = bincode::serialized_size(self).unwrap_or(u64::MAX);
        if tx_size > crate::constants::MAX_P2P_MESSAGE_SIZE {
            return Err(TxFormatError::TooLarge);
        }

        Ok(())
    }

    /// Серіалізація для підпису (без binding_sig)
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.chain_id.to_le_bytes());
        bytes.extend_from_slice(&self.fee.to_le_bytes());
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        for spend in &self.spends {
            bytes.extend_from_slice(spend.nullifier.as_bytes());
            bytes.extend_from_slice(&spend.cv);
        }
        for out in &self.outputs {
            bytes.extend_from_slice(out.note_commitment.as_bytes());
            bytes.extend_from_slice(&out.cv);
        }
        if let Some(call) = &self.contract_call {
            bytes.extend_from_slice(call.contract_id.as_bytes());
            bytes.extend_from_slice(call.method.as_bytes());
            bytes.extend_from_slice(&call.args);
        }
        if let Some(code) = &self.deploy_contract {
            bytes.extend_from_slice(code);
        }
        bytes
    }

    /// CVE-003 FIX: Створює безпечний fingerprint транзакції для pruning
    pub fn to_pruned_index(&self, block_height: u64) -> PrunedTxIndex {
        let mut h = blake3::Hasher::new();
        h.update(b"NoirNet_PrunedTx_v2");
        for out in &self.outputs {
            h.update(out.note_commitment.as_bytes());
        }
        PrunedTxIndex {
            tx_hash: self.tx_id().0,
            block_height,
            num_spends: self.spends.len() as u32,
            num_outputs: self.outputs.len() as u32,
            commitments_blake3: *h.finalize().as_bytes(),
        }
    }

    /// Отримати TxId з raw bytes (без десеріалізації) - SAFE P2P OOM protection
    pub fn tx_id_from_raw(data: &[u8]) -> Hash32 {
        if data.len() > crate::constants::MAX_P2P_MESSAGE_SIZE as usize {
            return Hash32::ZERO;
        }
        Hash32::blake3_of(data)
    }
}

/// Структура для зберігання транзакції після pruning
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrunedTxIndex {
    pub tx_hash: [u8; 32],
    pub block_height: u64,
    pub num_spends: u32,
    pub num_outputs: u32,
    pub commitments_blake3: [u8; 32],
}

/// Виклик смарт-контракту
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractCall {
    pub contract_id: Hash32,
    pub method: String,
    pub args: Vec<u8>,
    pub gas_limit: u64,
    pub caller_commitment: [u8; 32],
}

/// Помилки формату транзакції
#[derive(Debug, thiserror::Error)]
pub enum TxFormatError {
    #[error("Unsupported transaction version: {0}")]
    UnsupportedVersion(u8),
    #[error("Transaction has no inputs")]
    NoInputs,
    #[error("Transaction has no outputs")]
    NoOutputs,
    #[error("Fee too low")]
    FeeTooLow,
    #[error("Gas limit too high")]
    GasLimitTooHigh,
    #[error("Transaction too large")]
    TooLarge,
    #[error("Contract bytecode exceeds MAX_CONTRACT_SIZE")]
    ContractTooLarge,
    #[error("Invalid nullifier")]
    InvalidNullifier,
    #[error("Duplicate nullifier in transaction")]
    DuplicateNullifier,
    #[error("Invalid timestamp (must be rounded to 15 minutes)")]
    InvalidTimestamp,
    #[error("Too many spends (max {})", crate::constants::MAX_SPENDS_PER_TX)]
    TooManySpends,
    #[error("Too many outputs (max {})", crate::constants::MAX_OUTPUTS_PER_TX)]
    TooManyOutputs,
    #[error("Fee must be one of the allowed tiers")]
    InvalidFeeTier,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::{OutputDescription, SpendDescription};

    fn make_valid_tx() -> Transaction {
        Transaction {
            version: 1,
            chain_id: 1,
            spends: vec![SpendDescription {
                anchor: Hash32::ZERO,
                nullifier: Hash32([1u8; 32]),
                rk: [0u8; 32],
                cv: [0u8; 32],
                spend_auth_sig: [0u8; 64],
            }],
            outputs: vec![OutputDescription {
                note_commitment: Hash32([2u8; 32]),
                ephemeral_key: [0u8; 32],
                enc_ciphertext: vec![0u8; 580],
                out_ciphertext: vec![0u8; 80],
                cv: [0u8; 32],
            }],
            fee: crate::constants::MIN_FEE,
            gas_limit: 21000,
            memo: None,
            contract_call: None,
            deploy_contract: None,
            binding_sig: [0u8; 64],
            timestamp: 1700000100,
            aggregate_spend_proof: vec![],
        }
    }

    #[test]
    fn test_tx_id_deterministic() {
        let tx1 = make_valid_tx();
        let tx2 = make_valid_tx();
        assert_eq!(tx1.tx_id(), tx2.tx_id());
        assert_ne!(tx1.tx_id(), Hash32::ZERO);
    }

    #[test]
    fn test_validate_format_valid() {
        let tx = make_valid_tx();
        tx.validate_format().unwrap();
    }

    #[test]
    fn test_validate_format_unsupported_version() {
        let mut tx = make_valid_tx();
        tx.version = 2;
        assert!(matches!(
            tx.validate_format(),
            Err(TxFormatError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn test_validate_format_no_inputs() {
        let mut tx = make_valid_tx();
        tx.spends.clear();
        tx.contract_call = None;
        tx.deploy_contract = None;
        assert!(matches!(tx.validate_format(), Err(TxFormatError::NoInputs)));
    }

    #[test]
    fn test_validate_format_no_outputs() {
        let mut tx = make_valid_tx();
        tx.outputs.clear();
        tx.contract_call = None;
        tx.deploy_contract = None;
        assert!(matches!(tx.validate_format(), Err(TxFormatError::NoOutputs)));
    }

    #[test]
    fn test_validate_format_invalid_fee() {
        let mut tx = make_valid_tx();
        tx.fee = 500;
        assert!(matches!(tx.validate_format(), Err(TxFormatError::InvalidFeeTier)));
    }

    #[test]
    fn test_validate_format_gas_limit_too_high() {
        let mut tx = make_valid_tx();
        tx.gas_limit = crate::constants::MAX_TX_GAS + 1;
        assert!(matches!(
            tx.validate_format(),
            Err(TxFormatError::GasLimitTooHigh)
        ));
    }

    #[test]
    fn test_signing_bytes_deterministic() {
        let tx = make_valid_tx();
        assert_eq!(tx.signing_bytes(), tx.signing_bytes());
    }

    #[test]
    fn test_signing_bytes_different_for_different_tx() {
        let tx1 = make_valid_tx();
        let mut tx2 = make_valid_tx();
        tx2.fee = 9999;
        assert_ne!(tx1.signing_bytes(), tx2.signing_bytes());
    }
}
