// leader.rs — вибір лідера на основі VRF (Proof-of-Stake)

use noirnet_types::{address::ValidatorId, validator::ValidatorState};

pub struct LeaderSelector {
    pub active_validators: Vec<ValidatorState>,
}

impl LeaderSelector {
    pub fn new(mut validators: Vec<ValidatorState>) -> Self {
        // Сортуємо валідаторів детерміновано за ID щоб порядок був однаковий на всіх нодах
        validators.sort_by(|a, b| {
            a.registration
                .validator_id()
                .0
                .cmp(&b.registration.validator_id().0)
        });
        Self {
            active_validators: validators,
        }
    }

    /// Вибрати лідера використовуючи entropy
    pub fn select_leader(&self, entropy: &[u8; 32], round: u32) -> ValidatorId {
        if self.active_validators.is_empty() {
            panic!("No active validators");
        }

        let mut h = blake3::Hasher::new();
        h.update(b"NoirNet_leader_selection_v1");
        h.update(entropy);
        h.update(&round.to_le_bytes());
        let seed = h.finalize();

        // Загальна ставка
        let total_stake: u128 = self.active_validators.iter().map(|v| v.total_stake()).sum();
        if total_stake == 0 {
            // Фолбек якщо немає ставок (Genesis)
            let idx = (u32::from_le_bytes(seed.as_bytes()[..4].try_into().unwrap()) as usize)
                % self.active_validators.len();
            return self.active_validators[idx].registration.validator_id();
        }

        // Weighted random
        let mut target_bytes = [0u8; 16];
        target_bytes.copy_from_slice(&seed.as_bytes()[..16]);
        let target = u128::from_le_bytes(target_bytes) % total_stake;

        let mut cumulative = 0u128;
        for v in &self.active_validators {
            cumulative += v.total_stake();
            if cumulative > target {
                return v.registration.validator_id();
            }
        }

        self.active_validators
            .last()
            .unwrap()
            .registration
            .validator_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noirnet_types::validator::{ValidatorRegistration, ValidatorStatus};

    fn make_validator(id: u8, stake: u128) -> ValidatorState {
        ValidatorState {
            registration: ValidatorRegistration {
                bls_pubkey: [id; 48],
                network_pubkey: [id; 32],
                stake,
                commission_bps: 1000,
                epoch: 0,
                signature: [0u8; 64],
            },
            status: ValidatorStatus::Active,
            own_stake: stake,
            delegated_stake: 0,
            consecutive_misses: 0,
            last_signed_height: 0,
            pending_rewards: 0,
            total_slashed: 0,
        }
    }

    #[test]
    fn test_select_leader_deterministic() {
        let validators = vec![
            make_validator(1, 100),
            make_validator(2, 200),
            make_validator(3, 300),
        ];
        let selector = LeaderSelector::new(validators.clone());
        let entropy = [42u8; 32];
        
        let l1 = selector.select_leader(&entropy, 1);
        let l2 = selector.select_leader(&entropy, 1);
        assert_eq!(l1, l2);
    }

    #[test]
    fn test_select_leader_changes_with_round() {
        let validators = vec![
            make_validator(1, 100),
            make_validator(2, 200),
            make_validator(3, 300),
        ];
        let selector = LeaderSelector::new(validators.clone());
        let entropy = [42u8; 32];
        
        // With only 3 validators, we might get the same leader in different rounds,
        // but we'll test a few rounds to ensure it's not always identical.
        let mut leaders = std::collections::HashSet::new();
        for round in 0..10 {
            leaders.insert(selector.select_leader(&entropy, round));
        }
        assert!(leaders.len() > 1);
    }

    #[test]
    fn test_select_leader_fallback_zero_stake() {
        let validators = vec![
            make_validator(1, 0),
            make_validator(2, 0),
        ];
        let selector = LeaderSelector::new(validators.clone());
        let entropy = [42u8; 32];
        // Should fallback and not panic
        let l = selector.select_leader(&entropy, 1);
        assert!(l.0[0] == 1 || l.0[0] == 2);
    }
}
