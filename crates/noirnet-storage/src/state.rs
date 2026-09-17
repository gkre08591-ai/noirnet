// state.rs — управління станом блокчейну

use super::{
    block_store::BlockStore,
    merkle::NoteCommitmentTree,
    nullifier_store::NullifierStore,
    StorageError, StorageResult,
};
use noirnet_types::{
    block::Block,
    hash::{Hash32, StateRoot},
};
use std::sync::{Arc, Mutex};
use sled::Db;

/// Головний менеджер стану
pub struct StateStore {
    db: Arc<Db>,
    pub tree: Mutex<NoteCommitmentTree>,
    pub nullifiers: NullifierStore,
    pub blocks: BlockStore,
}

impl StateStore {
    pub fn open(db: Arc<Db>) -> StorageResult<Self> {
        let tree = NoteCommitmentTree::open(db.clone())?;
        let nullifiers = NullifierStore::new(db.clone());
        let blocks = BlockStore::new(db.clone());

        Ok(Self {
            db,
            tree: Mutex::new(tree),
            nullifiers,
            blocks,
        })
    }

    /// Отримати поточний корінь стану
    pub fn state_root(&self) -> StateRoot {
        self.tree.lock().unwrap().root()
    }

    /// Отримати висоту ланцюга
    pub fn get_chain_height(&self) -> StorageResult<u64> {
        if let Some(bytes) = crate::db::cf_get(&self.db, crate::db::CF_META, b"chain_height")? {
            Ok(u64::from_le_bytes(
                bytes.as_slice().try_into().unwrap_or([0; 8]),
            ))
        } else {
            Ok(0)
        }
    }

    /// Перевірити чи є в базі блоки (навіть genesis)
    pub fn has_blocks(&self) -> StorageResult<bool> {
        Ok(crate::db::cf_get(&self.db, crate::db::CF_META, b"chain_height")?.is_some())
    }

    /// Застосувати блок до стану
    pub fn apply_block(
        &self, 
        block: &Block,
        contract_state_changes: std::collections::HashMap<Vec<u8>, Vec<u8>>,
        new_contracts: Vec<(Hash32, Vec<u8>)>,
    ) -> StorageResult<StateRoot> {
        let mut tree_lock = self.tree.lock().unwrap();
        let current_height = self.get_chain_height()?;
        let has_blocks = self.has_blocks()?;
        let expected_height = if !has_blocks {
            0 // genesis
        } else {
            current_height + 1
        };

        if block.header.height != expected_height {
            return Err(StorageError::InvalidTransition(format!(
                "Expected height {}, got {}",
                expected_height, block.header.height
            )));
        }

        let tree_nullifiers = self.db.open_tree(super::db::CF_NULLIFIERS)?;
        let tree_commitments = self.db.open_tree(super::db::CF_COMMITMENTS)?;
        let tree_anchors = self.db.open_tree(super::db::CF_ANCHORS)?;

        for tx in &block.transactions {
            for spend in &tx.spends {
                if self.nullifiers.contains(&spend.nullifier)? {
                    return Err(StorageError::DoubleSpend);
                }
                tree_nullifiers.insert(spend.nullifier.as_bytes(), &block.header.height.to_le_bytes())?;
            }

            for out in &tx.outputs {
                let leaf_idx = tree_lock.size;
                tree_lock.append(out.note_commitment.0)?;
                tree_commitments.insert(leaf_idx.to_be_bytes(), out.note_commitment.as_bytes())?;
            }
        }

        let new_state_root = tree_lock.root();
        let expiry = block.header.height + noirnet_types::constants::ANCHOR_EXPIRY_BLOCKS;
        tree_anchors.insert(new_state_root.as_bytes(), &expiry.to_le_bytes())?;

        let tree_contracts = self.db.open_tree(super::db::CF_CONTRACTS)?;
        for (contract_id, bytecode) in new_contracts {
            tree_contracts.insert(contract_id.as_bytes(), bytecode)?;
        }

        let tree_contract_state = self.db.open_tree(super::db::CF_CONTRACT_STATE)?;
        for (composite_key, value) in contract_state_changes {
            tree_contract_state.insert(composite_key, value)?;
        }

        self.blocks.put_block(block)?;

        let tree_meta = self.db.open_tree(super::db::CF_META)?;
        tree_meta.insert(b"chain_height", &block.header.height.to_le_bytes())?;
        
        let mut height_key = b"height_hash_".to_vec();
        height_key.extend_from_slice(&block.header.height.to_le_bytes());
        tree_meta.insert(height_key, block.block_hash().as_bytes())?;

        Ok(new_state_root)
    }

    /// Перевірити чи anchor є валідним
    pub fn is_valid_anchor(&self, anchor: &StateRoot, current_height: u64) -> StorageResult<bool> {
        if let Some(bytes) = crate::db::cf_get(&self.db, crate::db::CF_ANCHORS, anchor.as_bytes())? {
            let expiry = u64::from_le_bytes(bytes.as_slice().try_into().unwrap_or([0; 8]));
            Ok(current_height <= expiry)
        } else {
            Ok(false)
        }
    }

    /// Отримати блок за висотою
    pub fn get_block_by_height(&self, height: u64) -> StorageResult<Option<Block>> {
        let mut height_key = b"height_hash_".to_vec();
        height_key.extend_from_slice(&height.to_le_bytes());
        
        if let Some(hash_bytes) = crate::db::cf_get(&self.db, crate::db::CF_META, &height_key)? {
            let mut hash_array = [0u8; 32];
            hash_array.copy_from_slice(&hash_bytes);
            let hash = Hash32(hash_array);
            self.blocks.get_block(&hash)
        } else {
            Ok(None)
        }
    }

    /// Отримати код контракту
    pub fn get_contract_code(&self, contract_id: &Hash32) -> StorageResult<Option<Vec<u8>>> {
        crate::db::cf_get(&self.db, crate::db::CF_CONTRACTS, contract_id.as_bytes())
    }

    /// Отримати стан контракту
    pub fn get_contract_state(&self, contract_id: &Hash32, key: &[u8]) -> StorageResult<Option<Vec<u8>>> {
        let mut composite_key = Vec::with_capacity(32 + key.len());
        composite_key.extend_from_slice(contract_id.as_bytes());
        composite_key.extend_from_slice(key);
        crate::db::cf_get(&self.db, crate::db::CF_CONTRACT_STATE, &composite_key)
    }

    /// Отримати ВЕСЬ стан контракту
    pub fn get_contract_state_all(&self, contract_id: &Hash32) -> StorageResult<std::collections::HashMap<Vec<u8>, Vec<u8>>> {
        let tree = self.db.open_tree(crate::db::CF_CONTRACT_STATE)?;
        let prefix = contract_id.as_bytes();
        let mut result = std::collections::HashMap::new();

        for item in tree.scan_prefix(prefix) {
            let (key, value) = item?;
            if key.len() >= 32 {
                let original_key = key[32..].to_vec();
                result.insert(original_key, value.to_vec());
            }
        }
        Ok(result)
    }

    /// Отримати всіх валідаторів
    pub fn get_all_validators(&self) -> StorageResult<Vec<noirnet_types::validator::ValidatorState>> {
        let tree = self.db.open_tree(crate::db::CF_VALIDATORS)?;
        let mut result = Vec::new();
        for item in tree.iter() {
            let (_key, value) = item?;
            let vs: noirnet_types::validator::ValidatorState = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            result.push(vs);
        }
        Ok(result)
    }

    /// Побудувати ValidatorSet для epoch
    pub fn get_validator_set(&self, epoch: u64) -> StorageResult<noirnet_types::validator::ValidatorSet> {
        let all = self.get_all_validators()?;
        let entries: Vec<noirnet_types::validator::StakeEntry> = all
            .into_iter()
            .filter(|v| v.registration.epoch <= epoch)
            .map(|v| noirnet_types::validator::StakeEntry {
                bls_pubkey: v.registration.bls_pubkey,
                network_pubkey: v.registration.network_pubkey,
                total_stake: v.total_stake(),
                status: v.status,
                epoch_joined: v.registration.epoch,
            })
            .collect();

        Ok(noirnet_types::validator::ValidatorSet::new(epoch, entries))
    }

    /// Видалити стару історію блоків (Pruning)
    pub fn prune_history(&self, keep_last: u64) -> StorageResult<u64> {
        let height = self.get_chain_height()?;
        if height <= keep_last {
            return Ok(0);
        }

        let prune_up_to = height - keep_last;
        let mut pruned_count = 0;
        let tree_meta = self.db.open_tree(super::db::CF_META)?;

        for h in 0..prune_up_to {
            let mut height_key = b"height_hash_".to_vec();
            height_key.extend_from_slice(&h.to_le_bytes());
            
            if let Some(hash_bytes) = tree_meta.remove(&height_key)? {
                let mut hash_array = [0u8; 32];
                hash_array.copy_from_slice(&hash_bytes);
                let hash = Hash32(hash_array);
                self.blocks.delete_block(&hash)?;
                pruned_count += 1;
            }
        }

        if pruned_count > 0 {
            tracing::info!("Pruned {} blocks from storage", pruned_count);
        }
        Ok(pruned_count)
    }
}
