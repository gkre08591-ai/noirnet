// validator.rs — типи валідатора

use crate::address::ValidatorId;
use crate::hash::Hash32;
use serde::{Deserialize, Serialize};

/// Тип голосу в BFT консенсусі
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteType {
    Prevote,
    Precommit,
}

/// Голос валідатора за блок
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub height: u64,
    pub round: u32,
    pub block_hash: Hash32,
    pub vote_type: VoteType,
    pub validator_id: [u8; 32], // First 32 bytes of BLS pubkey
    #[serde(with = "serde_big_array::BigArray")]
    pub signature: [u8; 96], // BLS12-381 signature
}

/// Статус валідатора
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorStatus {
    Active,
    Waiting,
    Jailed { jailed_until_epoch: u64 },
    Tombstoned,
}

/// Реєстрація валідатора
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorRegistration {
    /// BLS12-381 pubkey (48 bytes)
    #[serde(with = "serde_big_array::BigArray")]
    pub bls_pubkey: [u8; 48],
    /// Ed25519 pubkey для networking
    pub network_pubkey: [u8; 32],
    /// Сума ставки (nNOIR)
    pub stake: u128,
    /// Комісія (basis points, 0–10000)
    pub commission_bps: u16,
    /// Номер epoch реєстрації
    pub epoch: u64,
    /// Підпис реєстрації (ed25519, 64 bytes)
    #[serde(with = "serde_big_array::BigArray")]
    pub signature: [u8; 64],
}

impl ValidatorRegistration {
    pub fn validator_id(&self) -> ValidatorId {
        ValidatorId(self.bls_pubkey)
    }
}

/// Повний стан валідатора
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorState {
    pub registration: ValidatorRegistration,
    pub status: ValidatorStatus,
    /// Власна ставка
    pub own_stake: u128,
    /// Делегована ставка
    pub delegated_stake: u128,
    /// Пропущені блоки поспіль
    pub consecutive_misses: u32,
    /// Висота останнього підписаного блоку
    pub last_signed_height: u64,
    /// Нараховані нагороди (nNOIR)
    pub pending_rewards: u128,
    /// Нарахований slash (nNOIR)
    pub total_slashed: u128,
}

impl ValidatorState {
    pub fn total_stake(&self) -> u128 {
        self.own_stake + self.delegated_stake
    }

    pub fn is_active(&self) -> bool {
        self.status == ValidatorStatus::Active
    }
}

/// Доказ подвійного підпису (slashing evidence)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DoubleSignEvidence {
    pub validator_id: ValidatorId,
    pub height: u64,
    /// Два різних блоки на одній висоті
    pub block_hash_1: Hash32,
    pub block_hash_2: Hash32,
    /// BLS підписи обох
    pub sig_1: Vec<u8>,
    pub sig_2: Vec<u8>,
}

/// Делегування
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Delegation {
    pub delegator: [u8; 32], // commitment (encrypted)
    pub validator_id: ValidatorId,
    pub amount: u128,
    pub epoch_start: u64,
    /// None = активна, Some = unbonding до цього epoch
    pub unbonding_epoch: Option<u64>,
}

/// Slash параметри
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashParams {
    /// Подвійний підпис: 5% (500 bps)
    pub double_sign_bps: u64,
    /// Downtime >50%: 0.5% (50 bps)
    pub downtime_bps: u64,
    /// Невалідний zk-proof: 2% (200 bps)
    pub invalid_proof_bps: u64,
}

impl Default for SlashParams {
    fn default() -> Self {
        Self {
            double_sign_bps: 500,
            downtime_bps: 50,
            invalid_proof_bps: 200,
        }
    }
}

/// Мінімальний запис для швидкого вибору лідера та кворуму
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StakeEntry {
    /// BLS12-381 pubkey (48 bytes) — первинний ID валідатора
    #[serde(with = "serde_big_array::BigArray")]
    pub bls_pubkey: [u8; 48],
    /// Ed25519 для networking
    pub network_pubkey: [u8; 32],
    /// Загальний stake (own + delegated) в nNOIR
    pub total_stake: u128,
    /// Статус
    pub status: ValidatorStatus,
    /// Epoch, коли валідатор приєднався
    pub epoch_joined: u64,
}

impl StakeEntry {
    /// Validator ID = перші 32 байти BLS pubkey
    pub fn id(&self) -> [u8; 32] {
        let mut id = [0u8; 32];
        id.copy_from_slice(&self.bls_pubkey[..32]);
        id
    }

    pub fn is_active(&self) -> bool {
        self.status == ValidatorStatus::Active
    }

    pub fn voting_power(&self, total_stake: u128) -> f64 {
        if total_stake == 0 { return 0.0; }
        self.total_stake as f64 / total_stake as f64
    }
}

/// Набір активних валідаторів для конкретної epoch
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ValidatorSet {
    /// Epoch, для якої діє цей набір
    pub epoch: u64,
    /// Активні валідатори, відсортовані за stake (спадно)
    pub validators: Vec<StakeEntry>,
    /// Загальний stake всіх активних валідаторів
    pub total_stake: u128,
    /// Мінімальна кількість підписів для BFT кворуму (>2/3)
    pub quorum_threshold: usize,
}

impl ValidatorSet {
    pub fn new(epoch: u64, mut validators: Vec<StakeEntry>) -> Self {
        // Включаємо тільки активних
        validators.retain(|v| v.status == ValidatorStatus::Active);
        // Сортуємо за stake (спадно) для детермінізму
        validators.sort_by(|a, b| b.total_stake.cmp(&a.total_stake));
        let total_stake = validators.iter().map(|v| v.total_stake).sum();
        let n = validators.len();
        // BFT кворум: >2/3 кількості валідаторів (для однорідного voting power)
        let quorum_threshold = (n * 2) / 3 + 1;
        Self { epoch, validators, total_stake, quorum_threshold }
    }

    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Знайти валідатора за ID
    pub fn get_by_id(&self, id: &[u8; 32]) -> Option<&StakeEntry> {
        self.validators.iter().find(|v| &v.id() == id)
    }

    /// Перевірити, чи кількість підписів досягає кворуму
    pub fn has_quorum(&self, signed_count: usize) -> bool {
        signed_count >= self.quorum_threshold
    }

    /// Stake-weighted quorum: >2/3 загального stake
    pub fn has_stake_quorum(&self, signed_stake: u128) -> bool {
        signed_stake * 3 > self.total_stake * 2
    }

    /// Вибрати лідера на основі VRF output та epoch
    /// Pseudo-random, але детермінований для всіх вузлів
    pub fn elect_leader(&self, vrf_output: &[u8; 32], _epoch: u64) -> Option<&StakeEntry> {
        if self.validators.is_empty() { return None; }

        // Зважений VRF: конвертуємо vrf_output у число
        let rand_val = u128::from_le_bytes(vrf_output[..16].try_into().unwrap_or([0u8; 16]));

        // Вибираємо пропорційно до stake
        let threshold = rand_val % self.total_stake.max(1);
        let mut cumulative = 0u128;
        for v in &self.validators {
            cumulative += v.total_stake;
            if threshold < cumulative {
                return Some(v);
            }
        }
        // Fallback до першого (не повинно виникати)
        self.validators.first()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_registration() -> ValidatorRegistration {
        ValidatorRegistration {
            bls_pubkey: [1u8; 48],
            network_pubkey: [2u8; 32],
            stake: 10_000_000_000_000,
            commission_bps: 1000,
            epoch: 0,
            signature: [0u8; 64],
        }
    }

    fn make_validator(status: ValidatorStatus, own: u128, delegated: u128) -> ValidatorState {
        ValidatorState {
            registration: make_registration(),
            status,
            own_stake: own,
            delegated_stake: delegated,
            consecutive_misses: 0,
            last_signed_height: 0,
            pending_rewards: 0,
            total_slashed: 0,
        }
    }

    #[test]
    fn test_total_stake() {
        let v = make_validator(ValidatorStatus::Active, 1000, 500);
        assert_eq!(v.total_stake(), 1500);
    }

    #[test]
    fn test_is_active() {
        assert!(make_validator(ValidatorStatus::Active, 100, 0).is_active());
        assert!(!make_validator(ValidatorStatus::Waiting, 100, 0).is_active());
        assert!(!make_validator(ValidatorStatus::Tombstoned, 100, 0).is_active());
        assert!(!make_validator(
            ValidatorStatus::Jailed { jailed_until_epoch: 10 },
            100,
            0,
        ).is_active());
    }

    #[test]
    fn test_slash_params_default() {
        let p = SlashParams::default();
        assert_eq!(p.double_sign_bps, 500);
        assert_eq!(p.downtime_bps, 50);
        assert_eq!(p.invalid_proof_bps, 200);
    }

    #[test]
    fn test_validator_id_from_registration() {
        let reg = make_registration();
        let id = reg.validator_id();
        assert_eq!(id.0, [1u8; 48]);
    }
}
