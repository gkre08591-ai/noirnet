use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use libp2p::identity;
use noirnet_consensus::ConsensusEngine;
use noirnet_mempool::PrivateMempool;
use noirnet_network::p2p::{NetworkCommand, NetworkService, PriorityNetworkSender};
use noirnet_rpc::start_rpc_server;
use noirnet_storage::{db::open_db, state::StateStore};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "./data")]
    data_dir: PathBuf,
    #[arg(long, default_value_t = 9000)]
    p2p_port: u16,
    #[arg(long, default_value_t = 7777)]
    rpc_port: u16,
    #[arg(long)]
    devnet: bool,
    #[arg(long)]
    bootnode: Option<String>,
}

fn setup_telemetry(data_dir: &std::path::Path) -> anyhow::Result<tracing_appender::non_blocking::WorkerGuard> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,noirnet=debug"));
    let console_layer = tracing_subscriber::fmt::layer().with_target(true).with_thread_ids(true).with_line_number(true).with_ansi(true).boxed();
    let log_dir = data_dir.join("logs");
    std::fs::create_dir_all(&log_dir)?;
    let file_appender = tracing_appender::rolling::daily(log_dir, "noirnet-node.log");
    let (non_blocking_appender, guard) = tracing_appender::non_blocking(file_appender);
    let file_layer = tracing_subscriber::fmt::layer().json().with_writer(non_blocking_appender).boxed();
    tracing_subscriber::registry().with(env_filter).with(console_layer).with(file_layer).init();
    Ok(guard)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let _guard = setup_telemetry(&args.data_dir)?;

    let db_path = args.data_dir.join("rocksdb");
    let db = Arc::new(open_db(&db_path)?);
    let state_store = Arc::new(StateStore::open(db)?);
    info!("Storage initialized at {:?}", db_path);

    let mempool = Arc::new(PrivateMempool::new(state_store.clone()));
    info!("Private Mempool initialized");

    let local_key = identity::Keypair::generate_ed25519();
    let (high_tx, high_rx) = mpsc::channel::<NetworkCommand>(100);
    let (low_tx, low_rx) = mpsc::channel::<NetworkCommand>(500);
    let network_tx = PriorityNetworkSender::new(high_tx, low_tx);
    
    let (mempool_tx, mut mempool_rx) = mpsc::channel::<noirnet_types::transaction::Transaction>(100);
    let (consensus_block_tx, consensus_block_rx) = mpsc::channel::<noirnet_types::block::Block>(100);
    let (vote_tx, vote_rx) = mpsc::channel::<noirnet_types::validator::Vote>(100);
    let (sync_req_tx, sync_req_rx) = mpsc::channel(100);
    let (sync_res_tx, sync_res_rx) = mpsc::channel(100);

    let network_service = NetworkService::new(
        local_key,
        high_rx,
        low_rx,
        mempool_tx,
        consensus_block_tx,
        vote_tx,
        sync_req_tx,
        sync_res_tx,
        args.p2p_port,
    )?;

    tokio::spawn(async move {
        network_service.run().await;
    });

    let mempool_p2p = mempool.clone();
    tokio::spawn(async move {
        while let Some(tx) = mempool_rx.recv().await {
            if let Err(e) = mempool_p2p.insert(tx) {
                tracing::debug!("P2P tx rejected by mempool: {:?}", e);
            }
        }
    });

    let rpc_addr: SocketAddr = format!("0.0.0.0:{}", args.rpc_port).parse()?;
    let rpc_state = state_store.clone();
    let rpc_mempool = mempool.clone();
    let rpc_network_tx = network_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = start_rpc_server(rpc_addr, rpc_mempool, rpc_state, rpc_network_tx).await {
            tracing::error!("RPC Server failed: {}", e);
        }
    });

    let validator_data = if args.devnet {
        let bls_sk = noirnet_crypto::BlsSecretKey::generate();
        let id = [1u8; 32];
        Some((id, bls_sk))
    } else {
        None
    };
    
    let mut consensus = ConsensusEngine::new(
        state_store.clone(),
        mempool.clone(),
        validator_data,
        consensus_block_rx,
        vote_rx,
        sync_req_rx,
        sync_res_rx,
        network_tx,
    );
    info!("Consensus engine started");

    // Background pruning task
    let prune_state = state_store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(600)); // 10 mins
        loop {
            interval.tick().await;
            if let Err(e) = prune_state.prune_history(1000) {
                tracing::error!("Pruning failed: {:?}", e);
            }
        }
    });

    consensus.run().await;

    Ok(())
}
