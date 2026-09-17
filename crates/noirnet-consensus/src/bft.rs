// bft.rs — Tendermint-style BFT State Machine

use noirnet_types::hash::Hash32;
use noirnet_types::validator::{Vote, VoteType};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BftPhase {
    Propose,
    Prevote,
    Precommit,
    Commit,
}

pub struct BftRoundState {
    pub height: u64,
    pub round: u32,
    pub phase: BftPhase,
    
    // Hash -> Set of validator IDs who voted
    pub prevotes: HashMap<Hash32, HashSet<[u8; 32]>>,
    pub precommits: HashMap<Hash32, HashSet<[u8; 32]>>,
    
    pub total_validators: usize,
}

impl BftRoundState {
    pub fn new(height: u64, round: u32, total_validators: usize) -> Self {
        Self {
            height,
            round,
            phase: BftPhase::Propose,
            prevotes: HashMap::new(),
            precommits: HashMap::new(),
            total_validators,
        }
    }

    /// Обробляє голос. Повертає true, якщо голос новий і доданий.
    pub fn add_vote(&mut self, vote: Vote) -> bool {
        if vote.height != self.height || vote.round != self.round {
            return false;
        }

        match vote.vote_type {
            VoteType::Prevote => {
                let entry = self.prevotes.entry(vote.block_hash).or_insert_with(HashSet::new);
                entry.insert(vote.validator_id)
            }
            VoteType::Precommit => {
                let entry = self.precommits.entry(vote.block_hash).or_insert_with(HashSet::new);
                entry.insert(vote.validator_id)
            }
        }
    }

    /// Перевіряє чи маємо >2/3 prevotes за певний блок
pub fn has_quorum_prevote(&self, block_hash: &Hash32) -> bool {
        if let Some(voters) = self.prevotes.get(block_hash) {
            voters.len() * 3 > self.total_validators * 2
        } else {
            false
        }
    }

    pub fn has_quorum_precommit(&self, block_hash: &Hash32) -> bool {
        if let Some(voters) = self.precommits.get(block_hash) {
            voters.len() * 3 > self.total_validators * 2
        } else {
            false
        }
    }

    /// Спробувати перейти до наступної фази
    pub fn try_advance_phase(&mut self, block_hash: &Hash32) -> Option<BftPhase> {
        if self.phase == BftPhase::Propose {
            // Перехід Propose -> Prevote ініціюється зовні при отриманні блоку
            self.phase = BftPhase::Prevote;
            return Some(BftPhase::Prevote);
        }

        if self.phase == BftPhase::Prevote && self.has_quorum_prevote(block_hash) {
            self.phase = BftPhase::Precommit;
            return Some(BftPhase::Precommit);
        }

        if self.phase == BftPhase::Precommit && self.has_quorum_precommit(block_hash) {
            self.phase = BftPhase::Commit;
            return Some(BftPhase::Commit);
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bft_quorum() {
        let mut state = BftRoundState::new(1, 0, 4);
        let hash = Hash32::ZERO;

        let v1 = [1u8; 32];
        let v2 = [2u8; 32];
        let v3 = [3u8; 32];

        // 1 vote = no quorum (>2/3 of 4 is >= 3)
        state.add_vote(Vote {
            height: 1,
            round: 0,
            block_hash: hash,
            vote_type: VoteType::Prevote,
            validator_id: v1,
            signature: [0u8; 96],
        });
        assert!(!state.has_quorum_prevote(&hash));

        // 2 votes = no quorum
        state.add_vote(Vote {
            height: 1,
            round: 0,
            block_hash: hash,
            vote_type: VoteType::Prevote,
            validator_id: v2,
            signature: [0u8; 96],
        });
        assert!(!state.has_quorum_prevote(&hash));

        // 3 votes = quorum!
        state.add_vote(Vote {
            height: 1,
            round: 0,
            block_hash: hash,
            vote_type: VoteType::Prevote,
            validator_id: v3,
            signature: [0u8; 96],
        });
        assert!(state.has_quorum_prevote(&hash));

        // Move from Propose to Prevote
        assert_eq!(state.try_advance_phase(&hash), Some(BftPhase::Prevote));
        
        assert_eq!(state.try_advance_phase(&hash), Some(BftPhase::Precommit));
    }
}
