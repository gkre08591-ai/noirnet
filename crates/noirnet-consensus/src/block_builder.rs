use noirnet_storage::state::StateStore;
use noirnet_types::{
    block::{Block, BlockHeader},
    hash::Hash32,
    transaction::Transaction,
};
use std::sync::Arc;

pub struct BlockBuilder {
    state: Arc<StateStore>,
}

impl BlockBuilder {
    pub fn new(state: Arc<StateStore>) -> Self {
        Self { state }
    }

    /// Створити новий блок з транзакцій
    pub fn build_block(
        &self,
        txs: Vec<Transaction>,
        proposer: [u8; 32],
        vrf_output: [u8; 32],
        timestamp: u64,
        epoch: u64,
    ) -> Block {
        let parent_height = self.state.get_chain_height().unwrap_or(0);
        let has_blocks = self.state.has_blocks().unwrap_or(false);
        let current_height = if !has_blocks {
            0
        } else {
            parent_height + 1
        };

        let parent_hash = if has_blocks {
            self.state.get_block_by_height(parent_height)
                .unwrap_or(None)
                .map(|b| b.block_hash())
                .unwrap_or(Hash32::ZERO)
        } else {
            Hash32::ZERO
        };

        let tx_root = Block::compute_tx_root(&txs);
        
        // Calculate Nullifier Root (hash of all nullifiers in block)
        let mut n_hasher = blake3::Hasher::new();
        n_hasher.update(b"NoirNet_NullifierRoot_v1");
        for tx in &txs {
            for spend in &tx.spends {
                n_hasher.update(spend.nullifier.as_bytes());
            }
        }
        let nullifier_root = Hash32(*n_hasher.finalize().as_bytes());

        // Validate total gas used
        let mut gas_used = 0;
        let mut valid_txs = Vec::new();
        for tx in txs {
            if tx.gas_limit > noirnet_types::constants::MAX_TX_GAS {
                tracing::warn!("TX {} exceeds max gas limit, skipping", tx.tx_id());
                continue;
            }
            if gas_used + tx.gas_limit > noirnet_types::constants::MAX_BLOCK_GAS {
                tracing::warn!("Block gas limit {} exceeded, truncating txs", noirnet_types::constants::MAX_BLOCK_GAS);
                break;
            }
            gas_used += tx.gas_limit;
            valid_txs.push(tx);
        }

        let state_root = self.state.state_root();

        let header = BlockHeader {
            height: current_height,
            parent_hash,
            state_root,
            tx_root,
            nullifier_root,
            timestamp,
            epoch,
            vrf_output,
            proposer,
            chain_id: noirnet_types::constants::DEVNET_CHAIN_ID,
            gas_used,
            gas_limit: noirnet_types::constants::MAX_BLOCK_GAS,
        };

        Block {
            header,
            transactions: valid_txs,
            aggregate_proof: vec![], // Future integration: Plonky2 STARK recursive proof
            bls_aggregate_sig: vec![],
            validator_bitfield: 0,
        }
    }
}
