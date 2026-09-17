// constants.rs

/// Devnet Chain ID
pub const DEVNET_CHAIN_ID: u32 = 42;

/// Mainnet Chain ID
pub const MAINNET_CHAIN_ID: u32 = 1;

/// Мінімальний стейк для реєстрації валідатора (10,000 NOIR)
pub const MIN_VALIDATOR_STAKE: u128 = 10_000_000_000_000;

/// Кількість блоків в одній епосі
pub const EPOCH_BLOCKS: u64 = 100;

/// Максимальний ліміт газу на блок
pub const MAX_BLOCK_GAS: u64 = 100_000_000;

/// Максимальний ліміт газу на одну транзакцію
pub const MAX_TX_GAS: u64 = 10_000_000;

/// Базова вартість газу за транзакцію
pub const BASE_TX_GAS: u64 = 10_000;

/// Мінімальна комісія (nNOIR)
pub const MIN_FEE: u64 = 10_000;

/// Максимальна кількість транзакцій у мемпулі
pub const MAX_MEMPOOL_SIZE: usize = 10_000;

/// Кількість блоків до halving
pub const HALVING_INTERVAL: u64 = 40_320_000;

/// Початкова винагорода за блок (nNOIR) — 40 NOIR
pub const INITIAL_BLOCK_REWARD: u128 = 40_000_000_000;

/// Tail emission після досягнення max supply
pub const TAIL_EMISSION: u128 = 10_000_000;

/// Максимальна емісія (21,000,000 NOIR)
pub const MAX_SUPPLY: u128 = 21_000_000_000_000_000;

/// Доступні рівні комісій (nNOIR)
pub const FEE_TIERS: [u64; 3] = [10_000, 100_000, 1_000_000];

/// Максимальний розмір P2P повідомлення (10 MB)
pub const MAX_P2P_MESSAGE_SIZE: u64 = 10_485_760;

/// Максимальний розмір завантаженого контракту (1 MB)
pub const MAX_CONTRACT_SIZE: usize = 1_048_576;

/// Максимальний розмір memo-поля в ноті
pub const MAX_MEMO_SIZE: usize = 512;

/// Максимальна кількість spend proofs у транзакції
pub const MAX_SPENDS_PER_TX: usize = 16;

/// Максимальна кількість нових виходів у транзакції
pub const MAX_OUTPUTS_PER_TX: usize = 16;

/// Глибина дерева зобов'язань нот (Merkle Tree depth)
pub const NOTE_COMMITMENT_TREE_DEPTH: usize = 32;

/// Скільки блоків дійсний anchor (старий корінь дерева)
pub const ANCHOR_EXPIRY_BLOCKS: u64 = 100;