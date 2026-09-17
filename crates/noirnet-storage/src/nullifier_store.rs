// nullifier_store.rs — набір використаних nullifier-ів

use super::{
    db::{cf_get, cf_put, CF_NULLIFIERS},
    StorageError, StorageResult,
};
use noirnet_types::hash::Hash32;
use sled::Db;
use std::sync::Arc;

/// Сховище використаних nullifier-ів
pub struct NullifierStore {
    db: Arc<Db>,
}

impl NullifierStore {
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    /// Перевірити чи nullifier вже використаний
    pub fn contains(&self, nullifier: &Hash32) -> StorageResult<bool> {
        let opt = cf_get(&self.db, CF_NULLIFIERS, nullifier.as_bytes())?;
        Ok(opt.is_some())
    }

    /// Додати nullifier до сховища
    pub fn insert(&self, nullifier: &Hash32, block_height: u64) -> StorageResult<()> {
        if self.contains(nullifier)? {
            return Err(StorageError::DoubleSpend);
        }
        cf_put(
            &self.db,
            CF_NULLIFIERS,
            nullifier.as_bytes(),
            &block_height.to_le_bytes(),
        )?;
        Ok(())
    }
}
