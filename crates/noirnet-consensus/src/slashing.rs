use noirnet_types::{
    address::ValidatorId,
    validator::{DoubleSignEvidence, SlashParams, ValidatorState, ValidatorStatus},
};

use crate::{ConsensusError, ConsensusResult};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashOutcome {
    pub validator_id: ValidatorId,
    pub amount: u128,
    pub tombstoned: bool,
}

pub fn calculate_slash(stake: u128, slash_bps: u64) -> u128 {
    stake.saturating_mul(slash_bps as u128) / 10_000
}

pub fn apply_double_sign_evidence(
    validator: &mut ValidatorState,
    evidence: &DoubleSignEvidence,
    params: &SlashParams,
) -> ConsensusResult<SlashOutcome> {
    if validator.registration.validator_id() != evidence.validator_id {
        return Err(ConsensusError::InvalidProposal(
            "evidence validator does not match validator state".to_string(),
        ));
    }

    if evidence.block_hash_1 == evidence.block_hash_2 {
        return Err(ConsensusError::InvalidProposal(
            "double-sign evidence must contain two different block hashes".to_string(),
        ));
    }

    let amount = calculate_slash(validator.total_stake(), params.double_sign_bps);
    validator.total_slashed = validator.total_slashed.saturating_add(amount);
    validator.status = ValidatorStatus::Tombstoned;

    Ok(SlashOutcome {
        validator_id: evidence.validator_id.clone(),
        amount,
        tombstoned: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use noirnet_types::hash::Hash32;
    use noirnet_types::validator::{ValidatorRegistration, ValidatorState};

    fn make_validator_state() -> ValidatorState {
        ValidatorState {
            registration: ValidatorRegistration {
                bls_pubkey: [1u8; 48],
                network_pubkey: [2u8; 32],
                stake: 10_000_000_000_000,
                commission_bps: 1000,
                epoch: 0,
                signature: [0u8; 64],
            },
            status: ValidatorStatus::Active,
            own_stake: 10_000_000_000_000,
            delegated_stake: 5_000_000_000_000,
            consecutive_misses: 0,
            last_signed_height: 100,
            pending_rewards: 0,
            total_slashed: 0,
        }
    }

    #[test]
    fn test_calculate_slash_5_percent() {
        // 500 bps = 5%
        let slash = calculate_slash(10_000, 500);
        assert_eq!(slash, 500);
    }

    #[test]
    fn test_calculate_slash_zero_stake() {
        let slash = calculate_slash(0, 500);
        assert_eq!(slash, 0);
    }

    #[test]
    fn test_apply_double_sign() {
        let mut v = make_validator_state();
        let evidence = DoubleSignEvidence {
            validator_id: v.registration.validator_id(),
            height: 100,
            block_hash_1: Hash32([1u8; 32]),
            block_hash_2: Hash32([2u8; 32]),
            sig_1: vec![0u8; 64],
            sig_2: vec![0u8; 64],
        };
        let params = SlashParams::default();
        let outcome = apply_double_sign_evidence(&mut v, &evidence, &params).unwrap();
        assert!(outcome.tombstoned);
        assert!(outcome.amount > 0);
        assert_eq!(v.status, ValidatorStatus::Tombstoned);
        assert_eq!(v.total_slashed, outcome.amount);
    }

    #[test]
    fn test_apply_double_sign_same_hashes_rejected() {
        let mut v = make_validator_state();
        let evidence = DoubleSignEvidence {
            validator_id: v.registration.validator_id(),
            height: 100,
            block_hash_1: Hash32([1u8; 32]),
            block_hash_2: Hash32([1u8; 32]), // Same hash!
            sig_1: vec![],
            sig_2: vec![],
        };
        let params = SlashParams::default();
        assert!(apply_double_sign_evidence(&mut v, &evidence, &params).is_err());
    }

    #[test]
    fn test_apply_double_sign_wrong_validator() {
        let mut v = make_validator_state();
        let evidence = DoubleSignEvidence {
            validator_id: ValidatorId([99u8; 48]), // Different ID
            height: 100,
            block_hash_1: Hash32([1u8; 32]),
            block_hash_2: Hash32([2u8; 32]),
            sig_1: vec![],
            sig_2: vec![],
        };
        let params = SlashParams::default();
        assert!(apply_double_sign_evidence(&mut v, &evidence, &params).is_err());
    }
}
