// block.rs — Структури блоку та синхронізації

use crate::hash::Hash32;
use crate::transaction::Transaction;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: u64,
    pub parent_hash: Hash32,
    pub state_root: Hash32,
    pub tx_root: Hash32,
    pub nullifier_root: Hash32,
    pub timestamp: u64,
    pub epoch: u64,
    pub vrf_output: [u8; 32],
    pub proposer: [u8; 32],
    pub chain_id: u32,
    pub gas_used: u64,
    pub gas_limit: u64,
}

impl BlockHeader {
    pub fn hash(&self) -> Hash32 {
        let bytes = bincode::serialize(self).expect("header serialize");
        Hash32::blake3_of(&bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub aggregate_proof: Vec<u8>,
    pub bls_aggregate_sig: Vec<u8>,
    pub validator_bitfield: u64,
}

impl Block {
    pub fn block_hash(&self) -> Hash32 {
        self.header.hash()
    }

    /// Спрощене обчислення tx_root (просто хеш всіх tx_id)
    pub fn compute_tx_root(txs: &[Transaction]) -> Hash32 {
        if txs.is_empty() {
            return Hash32::ZERO;
        }
        let mut hasher = blake3::Hasher::new();
        for tx in txs {
            hasher.update(tx.tx_id().as_bytes());
        }
        Hash32(hasher.finalize().into())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompactBlock {
    pub height: u64,
    pub hash: Hash32,
    pub compact_outputs: Vec<CompactOutput>,
    pub nullifiers: Vec<Hash32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompactOutput {
    pub ephemeral_key: [u8; 32],
    #[serde(with = "serde_big_array::BigArray")]
    pub enc_ciphertext_prefix: [u8; 52],
    pub note_commitment: Hash32,
    pub leaf_index: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncRequest {
    pub start_height: u64,
    pub limit: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncResponse {
    pub blocks: Vec<Block>,
}

/// Обчислити поточну винагороду за блок на основі висоти
pub fn compute_block_reward(height: u64) -> u128 {
    use crate::constants::{INITIAL_BLOCK_REWARD, HALVING_INTERVAL, TAIL_EMISSION};
    if height == 0 { return 0; }
    let halvings = height / HALVING_INTERVAL;
    if halvings >= 64 { return TAIL_EMISSION; }
    let reward = INITIAL_BLOCK_REWARD >> halvings;
    reward.max(TAIL_EMISSION)
}
