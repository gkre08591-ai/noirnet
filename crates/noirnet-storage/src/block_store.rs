// block_store.rs — зберігання блоків та транзакцій

use super::{
    db::{cf_get, cf_put, deserialize, serialize, CF_BLOCKS, CF_TXS}, StorageResult,
};
use noirnet_types::{
    block::Block,
    hash::{BlockHash, TxId},
    transaction::Transaction,
};
use sled::Db;
use std::sync::Arc;

pub struct BlockStore {
    db: Arc<Db>,
}

impl BlockStore {
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    /// Зберегти блок
    pub fn put_block(&self, block: &Block) -> StorageResult<()> {
        let block_hash = block.block_hash();

        cf_put(&self.db, CF_BLOCKS, block_hash.as_bytes(), &serialize(block)?)?;

        for tx in &block.transactions {
            cf_put(&self.db, CF_TXS, tx.tx_id().as_bytes(), &serialize(tx)?)?;
        }

        Ok(())
    }

    /// Отримати повний блок за хешем
    pub fn get_block(&self, hash: &BlockHash) -> StorageResult<Option<Block>> {
        if let Some(bytes) = cf_get(&self.db, CF_BLOCKS, hash.as_bytes())? {
            let block = deserialize::<Block>(&bytes)?;
            Ok(Some(block))
        } else {
            Ok(None)
        }
    }

    /// Отримати транзакцію за TxId
    pub fn get_transaction(&self, txid: &TxId) -> StorageResult<Option<Transaction>> {
        if let Some(bytes) = cf_get(&self.db, CF_TXS, txid.as_bytes())? {
            let tx = deserialize::<Transaction>(&bytes)?;
            Ok(Some(tx))
        } else {
            Ok(None)
        }
    }

    /// Видалити блок та його транзакції (для pruning)
    pub fn delete_block(&self, hash: &BlockHash) -> StorageResult<()> {
        if let Some(block) = self.get_block(hash)? {
            let tree_txs = self.db.open_tree(CF_TXS)?;
            for tx in block.transactions {
                tree_txs.remove(tx.tx_id().as_bytes())?;
            }
            let tree_blocks = self.db.open_tree(CF_BLOCKS)?;
            tree_blocks.remove(hash.as_bytes())?;
        }
        Ok(())
    }
}
