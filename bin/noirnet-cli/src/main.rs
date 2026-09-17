// noirnet-cli — CLI гаманець для NoirNet
//
// Команди:
//   generate-keys  — Генерація нового гаманця (SpendingKey → FVK → PaymentAddress)
//   send           — Побудова та відправка транзакції через RPC
//   status         — Перевірка висоти блокчейну та стану синхронізації
//   balance        — Перевірка балансу контракту (через getStorage)

use clap::{Parser, Subcommand};
use noirnet_types::address::{IncomingViewKey, SpendingKey};
use std::io::Write;

#[derive(Parser)]
#[command(name = "noirnet-cli")]
#[command(version = "0.1.0")]
#[command(about = "NoirNet Privacy Blockchain — CLI Wallet", long_about = None)]
struct Cli {
    /// RPC server URL
    #[arg(long, default_value = "http://127.0.0.1:7777")]
    rpc: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Генерувати новий набір ключів (spending key, viewing key, payment address)
    GenerateKeys {
        /// Seed phrase (hex) для детермінованої генерації. Якщо не вказано — випадковий.
        #[arg(long)]
        seed: Option<String>,
    },
    /// Відправити транзакцію (mock transfer) на RPC-ноду
    Send {
        /// Hex-кодована адреса отримувача (pk_d)
        #[arg(long)]
        to: String,
        /// Сума переказу (nNOIR)
        #[arg(long)]
        amount: u64,
        /// Комісія (nNOIR)
        #[arg(long, default_value = "1000")]
        fee: u64,
        /// Spending key (hex)
        #[arg(long)]
        key: String,
    },
    /// Перевірити статус ноди (висота блоків, кількість пірів, синхронізація)
    Status,
    /// Отримати значення зі стейту контракту
    GetStorage {
        /// Contract ID (hex, 32 bytes)
        #[arg(long)]
        contract: String,
        /// Storage key (hex)
        #[arg(long)]
        key: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateKeys { seed } => cmd_generate_keys(seed)?,
        Commands::Send { to, amount, fee, key } => cmd_send(&cli.rpc, &to, amount, fee, &key).await?,
        Commands::Status => cmd_status(&cli.rpc).await?,
        Commands::GetStorage { contract, key } => cmd_get_storage(&cli.rpc, &contract, &key).await?,
    }

    Ok(())
}

/// Генерація ключів
fn cmd_generate_keys(seed: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let seed_bytes: [u8; 32] = if let Some(hex_seed) = seed {
        let decoded = hex::decode(&hex_seed)?;
        if decoded.len() != 32 {
            return Err("Seed must be exactly 32 bytes (64 hex chars)".into());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decoded);
        arr
    } else {
        // Випадковий seed
        let mut arr = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut arr);
        arr
    };

    let sk = SpendingKey::from_seed(&seed_bytes);
    let fvk = sk.to_fvk();
    let ivk = IncomingViewKey::from_fvk(&fvk);
    let addr = ivk.payment_address(0);

    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║              NoirNet Wallet — Key Generation                    ║");
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║ Seed (KEEP SECRET):                                            ║");
    println!("║  {}  ║", hex::encode(seed_bytes));
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║ Spending Key (KEEP SECRET):                                    ║");
    println!("║  {}  ║", hex::encode(sk.sk));
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║ Full Viewing Key:                                              ║");
    println!("║  ak: {}  ║", hex::encode(fvk.ak));
    println!("║  nk: {}  ║", hex::encode(fvk.nk));
    println!("║  ovk: {} ║", hex::encode(fvk.ovk));
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║ Payment Address:                                               ║");
    println!("║  {}  ║", addr);
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    // Зберегти ключі у файл
    let key_file = "noirnet_wallet.json";
    let key_data = serde_json::json!({
        "seed": hex::encode(seed_bytes),
        "spending_key": hex::encode(sk.sk),
        "fvk": {
            "ak": hex::encode(fvk.ak),
            "nk": hex::encode(fvk.nk),
            "ovk": hex::encode(fvk.ovk),
        },
        "payment_address": addr.to_string(),
    });

    let mut file = std::fs::File::create(key_file)?;
    file.write_all(serde_json::to_string_pretty(&key_data)?.as_bytes())?;
    println!("Keys saved to: {}", key_file);

    Ok(())
}

/// Відправка транзакції
async fn cmd_send(
    rpc_url: &str,
    to_hex: &str,
    amount: u64,
    fee: u64,
    key_hex: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Відновити SpendingKey з hex
    let sk_bytes = hex::decode(key_hex)?;
    if sk_bytes.len() != 32 {
        return Err("Spending key must be 32 bytes".into());
    }
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&sk_bytes);
    let sk = SpendingKey { sk: sk_arr };

    // Створити адресу отримувача (спрощено: використовуємо pk_d напряму)
    let to_bytes = hex::decode(to_hex)?;
    if to_bytes.len() != 32 {
        return Err("Recipient address (pk_d) must be 32 bytes".into());
    }
    let mut pk_d = [0u8; 32];
    pk_d.copy_from_slice(&to_bytes);
    let recipient = noirnet_types::address::PaymentAddress::new([0u8; 11], pk_d);

    println!("Building shielded transaction...");
    println!("  To:     0x{}", to_hex);
    println!("  Amount: {} nNOIR", amount);
    println!("  Fee:    {} nNOIR", fee);

    // Побудувати транзакцію
    let tx = noirnet_wallet::TxBuilder::build_transfer(
        &sk,
        &recipient,
        amount,
        fee,
        amount + fee, // mock input value
    )?;

    // Серіалізувати та відправити
    let tx_bytes = bincode::serialize(&tx)?;
    let tx_hex = hex::encode(&tx_bytes);

    println!("  TxId:   {}", tx.tx_id());
    println!("  Size:   {} bytes", tx_bytes.len());
    println!("  Timestamp (obfuscated): {}", tx.timestamp);
    println!();
    println!("Submitting to RPC: {}...", rpc_url);

    let rpc_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "noirnet_sendTransaction",
        "params": [tx_hex],
        "id": 1
    });

    let client = reqwest::Client::new();
    let resp = client.post(rpc_url)
        .json(&rpc_payload)
        .send()
        .await?;

    let body: serde_json::Value = resp.json().await?;
    if let Some(result) = body.get("result") {
        println!("✅ Transaction submitted! TxId: {}", result);
    } else if let Some(error) = body.get("error") {
        println!("❌ RPC Error: {}", error);
    }

    Ok(())
}

/// Перевірка статусу ноди
async fn cmd_status(rpc_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Querying node status at {}...", rpc_url);

    // getBlockHeight
    let height_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "noirnet_getBlockHeight",
        "params": [],
        "id": 1
    });

    let client = reqwest::Client::new();
    let resp = client.post(rpc_url)
        .json(&height_payload)
        .send()
        .await?;

    let body: serde_json::Value = resp.json().await?;

    // getSyncStatus
    let sync_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "noirnet_getSyncStatus",
        "params": [],
        "id": 2
    });

    let sync_resp = client.post(rpc_url)
        .json(&sync_payload)
        .send()
        .await?;

    let sync_body: serde_json::Value = sync_resp.json().await?;

    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║                 NoirNet Node Status                             ║");
    println!("╠══════════════════════════════════════════════════════════════════╣");
    if let Some(height) = body.get("result") {
        println!("║  Block Height:  {:<48}║", height);
    }
    if let Some(sync) = sync_body.get("result") {
        if let Some(synced) = sync.get("synced") {
            println!("║  Synced:        {:<48}║", synced);
        }
        if let Some(peers) = sync.get("peers") {
            println!("║  Peers:         {:<48}║", peers);
        }
    }
    println!("║  RPC Endpoint:  {:<48}║", rpc_url);
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    Ok(())
}

/// Читання стейту контракту
async fn cmd_get_storage(
    rpc_url: &str,
    contract_hex: &str,
    key_hex: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "noirnet_getStorage",
        "params": [contract_hex, key_hex],
        "id": 1
    });

    let client = reqwest::Client::new();
    let resp = client.post(rpc_url)
        .json(&payload)
        .send()
        .await?;

    let body: serde_json::Value = resp.json().await?;

    if let Some(result) = body.get("result") {
        if result.is_null() {
            println!("Storage value: (empty / not found)");
        } else {
            println!("Storage value: {}", result);
        }
    } else if let Some(error) = body.get("error") {
        println!("❌ RPC Error: {}", error);
    }

    Ok(())
}
