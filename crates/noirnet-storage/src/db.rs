// db.rs — Sled ініціалізація та дерева (замість column families)

use super::StorageResult;
use std::path::Path;
use sled::Db;

/// Назви дерев (аналог column families)
pub const CF_BLOCKS: &str = "blocks";
pub const CF_TXS: &str = "txs";
pub const CF_NULLIFIERS: &str = "nullifiers";
pub const CF_COMMITMENTS: &str = "commitments";
pub const CF_TREE: &str = "tree";
pub const CF_VALIDATORS: &str = "validators";
pub const CF_CONTRACTS: &str = "contracts";
pub const CF_CONTRACT_STATE: &str = "contract_state";
pub const CF_STAKES: &str = "stakes";
pub const CF_ANCHORS: &str = "anchors";
pub const CF_META: &str = "meta";

/// Відкрити або створити базу даних
pub fn open_db(path: &Path) -> StorageResult<Db> {
    sled::open(path).map_err(super::StorageError::Sled)
}

/// Допоміжна функція: get з дерева
pub fn cf_get(db: &Db, cf_name: &str, key: &[u8]) -> StorageResult<Option<Vec<u8>>> {
    let tree = db.open_tree(cf_name)?;
    Ok(tree.get(key)?.map(|v| v.to_vec()))
}

/// Допоміжна функція: put до дерева
pub fn cf_put(db: &Db, cf_name: &str, key: &[u8], value: &[u8]) -> StorageResult<()> {
    let tree = db.open_tree(cf_name)?;
    tree.insert(key, value)?;
    Ok(())
}

/// Серіалізація з bincode
pub fn serialize<T: serde::Serialize>(v: &T) -> StorageResult<Vec<u8>> {
    bincode::serialize(v).map_err(|e| super::StorageError::Serialization(e.to_string()))
}

/// Десеріалізація з bincode
pub fn deserialize<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> StorageResult<T> {
    bincode::deserialize(bytes).map_err(|e| super::StorageError::Serialization(e.to_string()))
}
