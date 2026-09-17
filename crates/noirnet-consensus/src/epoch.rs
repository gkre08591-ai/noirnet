use noirnet_types::validator::ValidatorState;

pub const DEFAULT_EPOCH_LENGTH: u64 = 1_000;

#[derive(Clone, Debug)]
pub struct EpochSchedule {
    pub epoch_length: u64,
}

impl Default for EpochSchedule {
    fn default() -> Self {
        Self {
            epoch_length: DEFAULT_EPOCH_LENGTH,
        }
    }
}

impl EpochSchedule {
    pub fn epoch_at_height(&self, height: u64) -> u64 {
        height / self.epoch_length.max(1)
    }

    pub fn first_height(&self, epoch: u64) -> u64 {
        epoch.saturating_mul(self.epoch_length.max(1))
    }

    pub fn is_epoch_boundary(&self, height: u64) -> bool {
        height > 0 && height % self.epoch_length.max(1) == 0
    }
}

pub fn active_validators(validators: &[ValidatorState]) -> Vec<ValidatorState> {
    validators
        .iter()
        .filter(|validator| validator.is_active())
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use noirnet_types::validator::{ValidatorRegistration, ValidatorStatus};

    fn make_validator(status: ValidatorStatus) -> ValidatorState {
        ValidatorState {
            registration: ValidatorRegistration {
                bls_pubkey: [1u8; 48],
                network_pubkey: [2u8; 32],
                stake: 10_000,
                commission_bps: 1000,
                epoch: 0,
                signature: [0u8; 64],
            },
            status,
            own_stake: 10_000,
            delegated_stake: 0,
            consecutive_misses: 0,
            last_signed_height: 0,
            pending_rewards: 0,
            total_slashed: 0,
        }
    }

    #[test]
    fn test_epoch_at_height() {
        let sched = EpochSchedule::default();
        assert_eq!(sched.epoch_at_height(0), 0);
        assert_eq!(sched.epoch_at_height(999), 0);
        assert_eq!(sched.epoch_at_height(1000), 1);
        assert_eq!(sched.epoch_at_height(2500), 2);
    }

    #[test]
    fn test_first_height() {
        let sched = EpochSchedule::default();
        assert_eq!(sched.first_height(0), 0);
        assert_eq!(sched.first_height(1), 1000);
        assert_eq!(sched.first_height(5), 5000);
    }

    #[test]
    fn test_is_epoch_boundary() {
        let sched = EpochSchedule::default();
        assert!(!sched.is_epoch_boundary(0)); // 0 is not a boundary
        assert!(sched.is_epoch_boundary(1000));
        assert!(sched.is_epoch_boundary(2000));
        assert!(!sched.is_epoch_boundary(999));
    }

    #[test]
    fn test_active_validators_filter() {
        let validators = vec![
            make_validator(ValidatorStatus::Active),
            make_validator(ValidatorStatus::Waiting),
            make_validator(ValidatorStatus::Active),
            make_validator(ValidatorStatus::Tombstoned),
        ];
        let active = active_validators(&validators);
        assert_eq!(active.len(), 2);
    }
}
