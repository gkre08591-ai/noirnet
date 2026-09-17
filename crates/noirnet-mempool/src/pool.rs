// pool.rs — Приватний mempool

use super::{MempoolError, MempoolResult};
use dashmap::DashMap;
use noirnet_storage::state::StateStore;
use noirnet_types::{
    constants::MAX_MEMPOOL_SIZE,
    hash::{Hash32, TxId},
    transaction::Transaction,
};
use rand::seq::SliceRandom;
use rayon::prelude::*;
use std::sync::Arc;

pub struct PrivateMempool {
    /// Транзакції в пам'яті
    txs: DashMap<TxId, Transaction>,
    /// Зайняті nullifier-и (щоб уникати подвійних витрат в межах mempool)
    pending_nullifiers: DashMap<Hash32, TxId>,
    /// Зв'язок зі сховищем (для перевірки чи не витрачено вже в блоці)
    state: Arc<StateStore>,
}

impl PrivateMempool {
    pub fn new(state: Arc<StateStore>) -> Self {
        Self {
            txs: DashMap::new(),
            pending_nullifiers: DashMap::new(),
            state,
        }
    }

    /// Додати транзакцію до mempool
    pub fn insert(&self, tx: Transaction) -> MempoolResult<()> {
        if self.txs.len() >= MAX_MEMPOOL_SIZE {
            // Для простоти поки що просто відкидаємо, в реальності треба eviction policy (викидати з найменшою fee)
            return Err(MempoolError::Full);
        }

        let txid = tx.tx_id();
        if self.txs.contains_key(&txid) {
            return Err(MempoolError::AlreadyExists);
        }

        // Валідація формату транзакції (структурна коректність)
        tx.validate_format().map_err(|e| MempoolError::InvalidFormat(e.to_string()))?;

        // VULN-003 FIX: Перевірка мінімальної комісії для захисту від спаму (DoS)
        if tx.fee < noirnet_types::constants::MIN_FEE {
            return Err(MempoolError::FeeTooLow(noirnet_types::constants::MIN_FEE));
        }

        // Перевірка nullifier-ів
        for spend in &tx.spends {
            // 1. В базі даних
            if self
                .state
                .nullifiers
                .contains(&spend.nullifier)
                .unwrap_or(true)
            {
                return Err(MempoolError::AlreadySpent);
            }
            // 2. В mempool
            if self.pending_nullifiers.contains_key(&spend.nullifier) {
                return Err(MempoolError::DoubleSpend);
            }
        }

        // Резервуємо nullifier-и
        for spend in &tx.spends {
            self.pending_nullifiers.insert(spend.nullifier, txid);
        }

        self.txs.insert(txid, tx);
        Ok(())
    }

    /// Вибір транзакцій для нового блоку
    /// Використовуємо перемішування + сортування за комісією (private mempool)
    /// Паралельна валідація через rayon для використання всіх ядер CPU
    pub fn select_for_block(&self, max_txs: usize, max_gas: u64) -> Vec<Transaction> {
        let all_txs: Vec<Transaction> =
            self.txs.iter().map(|kv| kv.value().clone()).collect();

        // Rayon: паралельна перевірка формату всіх транзакцій
        let mut candidates: Vec<Transaction> = all_txs
            .into_par_iter()
            .filter(|tx| tx.validate_format().is_ok())
            .collect();

        let mut rng = rand::thread_rng();
        // Рандомізація (щоб приховати час надходження)
        candidates.shuffle(&mut rng);
        // Stable сортування за комісією
        candidates.sort_by(|a, b| b.fee.cmp(&a.fee));

        let mut selected = Vec::new();
        let mut total_gas = 0;

        for tx in candidates {
            if selected.len() >= max_txs {
                break;
            }
            if total_gas + tx.gas_limit > max_gas {
                continue;
            }

            total_gas += tx.gas_limit;
            selected.push(tx);
        }

        selected
    }

    /// Видалення транзакцій (після додавання їх у блок)
    pub fn remove_mined(&self, txs: &[Transaction]) {
        for tx in txs {
            self.txs.remove(&tx.tx_id());
            for spend in &tx.spends {
                self.pending_nullifiers.remove(&spend.nullifier);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn get_all_transactions(&self) -> Vec<Transaction> {
        self.txs.iter().map(|kv| kv.value().clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noirnet_storage::db::open_db;
    use tempdir::TempDir;
    use noirnet_types::note::{OutputDescription, SpendDescription};

    fn setup_mempool() -> (Arc<StateStore>, PrivateMempool, TempDir) {
        let tmp_dir = TempDir::new("noirnet_mempool_tests").unwrap();
        let db = Arc::new(open_db(tmp_dir.path()).unwrap());
        let state = Arc::new(StateStore::open(db).unwrap());
        let pool = PrivateMempool::new(state.clone());
        (state, pool, tmp_dir)
    }

    fn make_test_tx(nullifier_byte: u8, fee: u64, gas_limit: u64) -> Transaction {
        Transaction {
            version: 1,
            chain_id: 1,
            spends: vec![SpendDescription {
                anchor: Hash32::ZERO,
                nullifier: Hash32([nullifier_byte; 32]),
                rk: [0u8; 32],
                cv: [0u8; 32],
                spend_auth_sig: [0u8; 64],
            }],
            outputs: vec![OutputDescription {
                note_commitment: Hash32([nullifier_byte + 100; 32]),
                ephemeral_key: [0u8; 32],
                enc_ciphertext: vec![0u8; 580],
                out_ciphertext: vec![0u8; 80],
                cv: [0u8; 32],
            }],
            fee,
            gas_limit,
            memo: None,
            contract_call: None,
            deploy_contract: None,
            binding_sig: [0u8; 64],
            timestamp: 1700000100, // Must be divisible by 900 (Phase 5 timestamp obfuscation)
            aggregate_spend_proof: vec![],
        }
    }

    #[test]
    fn test_insert_valid_tx() {
        let (_state, pool, _tmp) = setup_mempool();
        let tx = make_test_tx(1, 1000, 21000);
        assert!(pool.insert(tx).is_ok());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_insert_duplicate_rejected() {
        let (_state, pool, _tmp) = setup_mempool();
        let tx = make_test_tx(1, 1000, 21000);
        assert!(pool.insert(tx.clone()).is_ok());
        assert!(matches!(pool.insert(tx), Err(MempoolError::AlreadyExists)));
    }

    #[test]
    fn test_insert_double_spend_in_mempool_rejected() {
        let (_state, pool, _tmp) = setup_mempool();
        let tx1 = make_test_tx(1, 1000, 21000);
        let tx2 = make_test_tx(1, 5000, 21000); // Same nullifier, different fee (so different tx_id)
        
        assert!(pool.insert(tx1).is_ok());
        assert!(matches!(pool.insert(tx2), Err(MempoolError::DoubleSpend)));
    }

    #[test]
    fn test_select_for_block_respects_gas_limit() {
        let (_state, pool, _tmp) = setup_mempool();
        pool.insert(make_test_tx(1, 1000, 50000)).unwrap();
        pool.insert(make_test_tx(2, 5000, 50000)).unwrap();
        pool.insert(make_test_tx(3, 10000, 50000)).unwrap();

        // Max gas is 120k. Each tx is 50k. So only 2 txs should fit (100k).
        let selected = pool.select_for_block(10, 120_000);
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn test_select_for_block_respects_max_txs() {
        let (_state, pool, _tmp) = setup_mempool();
        for i in 1..=5 {
            pool.insert(make_test_tx(i as u8, 1000, 21000)).unwrap();
        }

        // Limit to 3 txs
        let selected = pool.select_for_block(3, 10_000_000);
        assert_eq!(selected.len(), 3);
    }

    #[test]
    fn test_select_for_block_sorts_by_fee() {
        let (_state, pool, _tmp) = setup_mempool();
        pool.insert(make_test_tx(1, 1000, 21000)).unwrap();
        pool.insert(make_test_tx(2, 10000, 21000)).unwrap();
        pool.insert(make_test_tx(3, 5000, 21000)).unwrap();

        let selected = pool.select_for_block(3, 10_000_000);
        assert_eq!(selected.len(), 3);
        // Fees should be sorted descending
        assert_eq!(selected[0].fee, 10000);
        assert_eq!(selected[1].fee, 5000);
        assert_eq!(selected[2].fee, 1000);
    }

    #[test]
    fn test_remove_mined() {
        let (_state, pool, _tmp) = setup_mempool();
        let tx1 = make_test_tx(1, 1000, 21000);
        let tx2 = make_test_tx(2, 1000, 21000);
        
        pool.insert(tx1.clone()).unwrap();
        pool.insert(tx2.clone()).unwrap();
        assert_eq!(pool.len(), 2);

        // Mine tx1
        pool.remove_mined(&[tx1.clone()]);
        
        assert_eq!(pool.len(), 1);
        
        // Ensure we can now insert a new tx with tx1's nullifier (since it was removed from pending_nullifiers)
        // (In reality, the StateStore check would prevent this, but here the mock state doesn't automatically update)
        let tx3 = make_test_tx(1, 5000, 21000);
        assert!(pool.insert(tx3).is_ok());
    }
}
