// merkle.rs — Incremental Merkle Tree для нотаток

use super::{
    db::{cf_get, cf_put, deserialize, serialize, CF_COMMITMENTS, CF_TREE}, StorageResult,
};
use noirnet_types::{constants::NOTE_COMMITMENT_TREE_DEPTH, hash::Hash32};
use sled::Db;
use std::sync::Arc;

/// Шлях у дереві Merkle
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MerklePath {
    pub auth_path: Vec<([u8; 32], bool)>, // (sibling_hash, is_left)
    pub position: u64,
}

/// Incremental Merkle Tree (глибина = NOTE_COMMITMENT_TREE_DEPTH)
pub struct NoteCommitmentTree {
    pub frontier: Vec<Option<[u8; 32]>>,
    pub size: u64,
    db: Arc<Db>,
}

impl NoteCommitmentTree {
    pub fn open(db: Arc<Db>) -> StorageResult<Self> {
        let frontier = if let Some(bytes) = cf_get(&db, CF_TREE, b"frontier")? {
            deserialize::<Vec<Option<[u8; 32]>>>(&bytes)?
        } else {
            vec![None; NOTE_COMMITMENT_TREE_DEPTH]
        };

        let size = if let Some(bytes) = cf_get(&db, CF_TREE, b"size")? {
            u64::from_le_bytes(bytes.as_slice().try_into().unwrap_or([0; 8]))
        } else {
            0
        };

        Ok(Self { frontier, size, db })
    }

    pub fn append(&mut self, commitment: [u8; 32]) -> StorageResult<u64> {
        let leaf_index = self.size;

        cf_put(&self.db, CF_COMMITMENTS, &leaf_index.to_be_bytes(), &commitment)?;

        let mut current = commitment;
        for i in 0..NOTE_COMMITMENT_TREE_DEPTH {
            if let Some(left) = self.frontier[i] {
                current = hash_pair(&left, &current);
                self.frontier[i] = None;
            } else {
                self.frontier[i] = Some(current);
                break;
            }
        }

        self.size += 1;

        cf_put(&self.db, CF_TREE, b"frontier", &serialize(&self.frontier)?)?;
        cf_put(&self.db, CF_TREE, b"size", &self.size.to_le_bytes())?;

        Ok(leaf_index)
    }

    pub fn root(&self) -> Hash32 {
        let mut current = empty_root(0);
        for i in 0..NOTE_COMMITMENT_TREE_DEPTH {
            let sibling = self.frontier[i].unwrap_or_else(|| empty_root(i));
            if (self.size >> i) & 1 == 1 {
                current = hash_pair(&sibling, &current);
            } else {
                current = hash_pair(&current, &sibling);
            }
        }
        Hash32(current)
    }

    pub fn get_commitment(&self, leaf_index: u64) -> StorageResult<Option<Hash32>> {
        cf_get(&self.db, CF_COMMITMENTS, &leaf_index.to_be_bytes()).map(|opt| {
            opt.map(|bytes| {
                let arr: [u8; 32] = bytes.as_slice().try_into().unwrap_or([0; 32]);
                Hash32(arr)
            })
        })
    }
}

pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"NoirNet_tree_node_v1");
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

fn empty_root(depth: usize) -> [u8; 32] {
    let mut node = [0u8; 32];
    for _ in 0..depth {
        node = hash_pair(&node, &node);
    }
    node
}
