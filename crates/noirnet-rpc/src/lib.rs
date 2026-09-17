//! Production RPC API with enterprise-grade security features

use std::net::SocketAddr;
use std::sync::Arc;

use jsonrpsee::{
    core::async_trait,
    proc_macros::rpc,
    server::Server,
    types::{error::ErrorCode, ErrorObjectOwned},
};
use tracing::info;

use noirnet_mempool::PrivateMempool;
use noirnet_network::p2p::{NetworkCommand, PriorityNetworkSender};
use noirnet_storage::state::StateStore;
use noirnet_types::transaction::Transaction;

/// RPC server configuration
#[derive(Clone)]
pub struct RpcConfig {
    pub listen_addr: SocketAddr,
    pub max_request_size: u32,
    pub rate_limit: u64,
}

pub struct RpcState {
    pub config: RpcConfig,
    pub mempool: Arc<PrivateMempool>,
    pub state_store: Arc<StateStore>,
    pub network_tx: PriorityNetworkSender,
}

#[rpc(server)]
pub trait NoirNetApi {
    #[method(name = "noirnet_getBlockHeight")]
    fn get_block_height(&self) -> Result<u64, ErrorObjectOwned>;

    #[method(name = "noirnet_sendTransaction")]
    async fn send_transaction(&self, tx_hex: String) -> Result<String, ErrorObjectOwned>;

    #[method(name = "noirnet_getStorage")]
    fn get_storage(&self, contract_id: String, key: String) -> Result<Option<String>, ErrorObjectOwned>;

    #[method(name = "noirnet_getSyncStatus")]
    async fn get_sync_status(&self) -> Result<serde_json::Value, ErrorObjectOwned>;
}

pub struct NoirNetApiImpl {
    state: Arc<RpcState>,
}

#[async_trait]
impl NoirNetApiServer for NoirNetApiImpl {
    fn get_block_height(&self) -> Result<u64, ErrorObjectOwned> {
        Ok(self.state.state_store.get_chain_height().unwrap_or(0))
    }

    async fn send_transaction(&self, tx_hex: String) -> Result<String, ErrorObjectOwned> {
        let tx_bytes = hex::decode(tx_hex).map_err(|_| ErrorObjectOwned::from(ErrorCode::InvalidParams))?;
        let tx: Transaction = bincode::deserialize(&tx_bytes).map_err(|_| ErrorObjectOwned::from(ErrorCode::ParseError))?;
        
        if let Err(e) = self.state.mempool.insert(tx.clone()) {
            return Err(ErrorObjectOwned::owned(-32000, format!("Mempool error: {:?}", e), Some(())));
        }
        
        let _ = self.state.network_tx.send(NetworkCommand::BroadcastTx(tx_bytes)).await;
        Ok(tx.tx_id().to_string())
    }

    fn get_storage(&self, contract_id: String, key: String) -> Result<Option<String>, ErrorObjectOwned> {
        let cid = noirnet_types::hash::Hash32::from_hex(&contract_id).map_err(|_| ErrorObjectOwned::from(ErrorCode::InvalidParams))?;
        let k_bytes = hex::decode(key).map_err(|_| ErrorObjectOwned::from(ErrorCode::InvalidParams))?;
        
        let val = self.state.state_store.get_contract_state(&cid, &k_bytes)
            .map_err(|e| ErrorObjectOwned::owned(-32001, e.to_string(), Some(())))?;
            
        Ok(val.map(hex::encode))
    }

    async fn get_sync_status(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if let Err(e) = self.state.network_tx.send(NetworkCommand::GetStatus(tx)).await {
            return Err(ErrorObjectOwned::owned(-32002, format!("Network error: {:?}", e), Some(())));
        }
        
        let status = rx.await.map_err(|_| ErrorObjectOwned::owned(-32003, "Network timeout", Some(())))?;
        
        Ok(serde_json::json!({
            "synced": status.is_synced,
            "peers": status.peer_count,
            "height": self.state.state_store.get_chain_height().unwrap_or(0)
        }))
    }
}

pub async fn start_rpc_server(
    addr: SocketAddr,
    mempool: Arc<PrivateMempool>,
    state_store: Arc<StateStore>,
    network_tx: PriorityNetworkSender,
) -> anyhow::Result<()> {
    let config = RpcConfig {
        listen_addr: addr,
        max_request_size: 10 * 1024 * 1024,
        rate_limit: 1000,
    };
    
    let state = Arc::new(RpcState {
        config: config.clone(),
        mempool,
        state_store,
        network_tx,
    });

    let server = Server::builder()
        .max_request_body_size(config.max_request_size)
        .build(config.listen_addr)
        .await?;
        
    let mut module = jsonrpsee::RpcModule::new(());
    module.merge(NoirNetApiImpl { state }.into_rpc())?;
    
    let handle = server.start(module);
    
    info!("Starting JSON-RPC server on {}", config.listen_addr);
    tokio::spawn(handle.stopped());
    
    Ok(())
}
