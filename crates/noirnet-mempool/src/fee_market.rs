// fee_market.rs — динамічна модель комісій (EIP-1559 style)

use noirnet_types::constants::{BASE_TX_GAS, MIN_FEE};

pub struct FeeMarket {
    pub base_fee: u64, // nNOIR per gas
    pub target_block_gas: u64,
}

impl FeeMarket {
    pub fn new(target_gas: u64) -> Self {
        Self {
            base_fee: std::cmp::max(1, MIN_FEE / BASE_TX_GAS),
            target_block_gas: target_gas,
        }
    }

    /// Оновити base_fee на основі заповненості попереднього блоку
    pub fn adjust_base_fee(&mut self, gas_used: u64) {
        let target = self.target_block_gas as f64;
        let used = gas_used as f64;

        // Зміна до ±12.5% за блок
        let ratio = (used - target) / target;
        let adjustment = (self.base_fee as f64 * ratio * 0.125) as i64;

        let min_base_fee = std::cmp::max(1, MIN_FEE / BASE_TX_GAS); // Ensure base fee is at least 1
        self.base_fee = (self.base_fee as i64 + adjustment).max(min_base_fee as i64) as u64;
    }

    /// Розрахувати burn та tip
    pub fn split_fee(&self, total_fee: u64, gas_used: u64) -> (u64, u64) {
        let base_cost = self.base_fee * gas_used;
        if total_fee < base_cost {
            // Транзакція не мала б пройти валідацію, але про всяк випадок
            return (total_fee, 0);
        }
        let tip = total_fee - base_cost;
        (base_cost, tip) // (burn, tip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_fee_increase_on_full_block() {
        let target = 5_000_000;
        let mut fm = FeeMarket::new(target);
        fm.base_fee = 10; // set explicit non-zero base fee
        let initial = fm.base_fee;
        // Use 2x target gas (very full block)
        fm.adjust_base_fee(target * 2);
        assert!(fm.base_fee > initial);
    }

    #[test]
    fn test_base_fee_decrease_on_empty_block() {
        let target = 5_000_000;
        let mut fm = FeeMarket::new(target);
        // Set a higher base fee first
        fm.base_fee = 100;
        let initial = fm.base_fee;
        // Use 0 gas (empty block)
        fm.adjust_base_fee(0);
        assert!(fm.base_fee < initial);
    }

    #[test]
    fn test_base_fee_floor() {
        let target = 5_000_000;
        let mut fm = FeeMarket::new(target);
        // Repeatedly decrease
        for _ in 0..100 {
            fm.adjust_base_fee(0);
        }
        let min_base_fee = MIN_FEE / BASE_TX_GAS;
        assert!(fm.base_fee >= min_base_fee);
    }

    #[test]
    fn test_split_fee_correct() {
        let fm = FeeMarket { base_fee: 10, target_block_gas: 5_000_000 };
        let (burn, tip) = fm.split_fee(1000, 50); // base_cost = 10*50 = 500
        assert_eq!(burn, 500);
        assert_eq!(tip, 500);
    }

    #[test]
    fn test_split_fee_no_tip() {
        let fm = FeeMarket { base_fee: 10, target_block_gas: 5_000_000 };
        let (burn, tip) = fm.split_fee(500, 50); // exact base cost
        assert_eq!(burn, 500);
        assert_eq!(tip, 0);
    }

    #[test]
    fn test_split_fee_underpay() {
        let fm = FeeMarket { base_fee: 10, target_block_gas: 5_000_000 };
        let (burn, tip) = fm.split_fee(100, 50); // less than base cost
        assert_eq!(burn, 100);
        assert_eq!(tip, 0);
    }
}
