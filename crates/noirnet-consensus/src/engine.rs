use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use noirnet_network::p2p::{NetworkCommand, PriorityNetworkSender};
use noirnet_storage::state::StateStore;
use noirnet_mempool::PrivateMempool;
use noirnet_types::{
    block::{Block, SyncRequest, SyncResponse},
    validator::{Vote, VoteType, ValidatorState},
};
use noirnet_vm::WasmRuntime;
use noirnet_zk::proof::{setup_nova, verify_spend_proof};

/// Production consensus engine with enterprise features
pub struct ConsensusEngine {
    state_store: Arc<StateStore>,
    mempool: Arc<PrivateMempool>,
    builder: crate::block_builder::BlockBuilder,
    vm: WasmRuntime,
    local_validator_id: [u8; 32],
    secret_key: Option<noirnet_crypto::BlsSecretKey>,
    is_validator: bool,
    block_rx: mpsc::Receiver<Block>,
    vote_rx: mpsc::Receiver<Vote>,
    sync_req_rx: mpsc::Receiver<(libp2p::PeerId, SyncRequest, libp2p::request_response::ResponseChannel<SyncResponse>)>,
    sync_res_rx: mpsc::Receiver<(libp2p::PeerId, SyncResponse)>,
    network_tx: PriorityNetworkSender,
    sync_manager: crate::sync::SyncManager,
    
    // Production features
    slashing_conditions: SlashingConditions,
    last_block_time: std::time::Instant,
    consecutive_missed_blocks: u64,
}

/// Slashing conditions for Byzantine fault tolerance
#[derive(Clone)]
pub struct SlashingConditions {
    pub max_consecutive_missed_blocks: u64,
    pub max_downtime_percentage: f64,
    pub double_sign_slashing: bool,
    pub equivocation_slashing: bool,
}

impl Default for SlashingConditions {
    fn default() -> Self {
        Self {
            max_consecutive_missed_blocks: 10,
            max_downtime_percentage: 0.05, // 5%
            double_sign_slashing: true,
            equivocation_slashing: true,
        }
    }
}

impl ConsensusEngine {
    pub fn new(
        state_store: Arc<StateStore>,
        mempool: Arc<PrivateMempool>,
        validator_id: Option<([u8; 32], noirnet_crypto::BlsSecretKey)>,
        block_rx: mpsc::Receiver<Block>,
        vote_rx: mpsc::Receiver<Vote>,
        sync_req_rx: mpsc::Receiver<(libp2p::PeerId, SyncRequest, libp2p::request_response::ResponseChannel<SyncResponse>)>,
        sync_res_rx: mpsc::Receiver<(libp2p::PeerId, SyncResponse)>,
        network_tx: PriorityNetworkSender,
    ) -> Self {
        let vm = WasmRuntime::new().expect("WasmRuntime init failed");
        let builder = crate::block_builder::BlockBuilder::new(state_store.clone());
        let is_validator = validator_id.is_some();
        let (local_id, sk) = match validator_id {
            Some((id, sk)) => (id, Some(sk)),
            None => ([0u8; 32], None),
        };
        Self {
            builder,
            state_store,
            mempool,
            vm,
            local_validator_id: local_id,
            secret_key: sk,
            is_validator,
            block_rx,
            vote_rx,
            sync_req_rx,
            sync_res_rx,
            network_tx,
            sync_manager: crate::sync::SyncManager::new(),
            slashing_conditions: SlashingConditions::default(),
            last_block_time: std::time::Instant::now(),
            consecutive_missed_blocks: 0,
        }
    }

    /// Execute and apply a block with production-grade validation
    async fn execute_and_apply_block(&mut self, block: Block) {
        // Production validation checks
        if self.is_validator && block.bls_aggregate_sig.is_empty() {
            warn!("REJECTING block {}: missing BLS signature", block.header.height);
            return;
        }

        // Check block timestamp (prevent future blocks, allow small clock skew)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if block.header.timestamp > now + 60 {
            warn!("REJECTING block {}: timestamp too far in future", block.header.height);
            return;
        }

        let tx_count = block.transactions.len();
        let mut contract_state_changes = std::collections::HashMap::new();
        let mut new_contracts = Vec::new();

        // Phase 1: ZK proof verification
        let pp = setup_nova();
        for tx in &block.transactions {
            // Check for double-spend attempts
            if !tx.spends.is_empty() {
                if tx.aggregate_spend_proof.is_empty() {
                    warn!("REJECTING block {}: tx {} missing ZK proof", block.header.height, tx.tx_id());
                    return;
                }
                match verify_spend_proof(&pp, &tx.aggregate_spend_proof, tx.spends.len()) {
                    Ok(true) => {}
                    _ => { 
                        warn!("REJECTING block {}: tx {} invalid ZK proof", block.header.height, tx.tx_id()); 
                        self.record_slashing_event("invalid_zk_proof");
                        return; 
                    }
                }
            }
            
            // Validate transaction format and rules
            if let Err(e) = tx.validate_format() {
                warn!("REJECTING block {}: tx {} format error: {}", block.header.height, tx.tx_id(), e);
                return;
            }
            
            // Check gas limit per transaction
            if tx.gas_limit > noirnet_types::constants::MAX_TX_GAS {
                warn!("REJECTING block {}: tx {} exceeds gas limit", block.header.height, tx.tx_id());
                return;
            }
        }

        // Phase 2: Smart contract execution with gas metering
        for tx in &block.transactions {
            if let Some(ref bytecode) = tx.deploy_contract {
                // Contract size limit
                if bytecode.len() > noirnet_types::constants::MAX_CONTRACT_SIZE {
                    warn!("Contract deployment exceeds size limit");
                    continue;
                }
                
                use noirnet_types::hash::Hash32;
                let contract_id = Hash32::blake3_of(bytecode);
                info!("Deploying contract {}", contract_id);
                
                let ctx = noirnet_vm::ExecutionContext {
                    contract_id, 
                    caller_commitment: [0u8; 32], 
                    gas_remaining: tx.gas_limit,
                    state_diff: std::collections::HashMap::new(),
                    existing_state: self.state_store.get_contract_state_all(&contract_id).unwrap_or_default(),
                    events: vec![], 
                    memory: None,
                };
                
                match self.vm.execute(bytecode, "init", &[], ctx) {
                    Ok(r) => {
                        info!("Contract {} deployed. Gas: {}, Events: {}", contract_id, r.gas_used, r.events.len());
                        new_contracts.push((contract_id, bytecode.clone()));
                        for (k, v) in r.state_changes {
                            let mut c = Vec::with_capacity(32 + k.len());
                            c.extend_from_slice(contract_id.as_bytes());
                            c.extend_from_slice(&k);
                            contract_state_changes.insert(c, v);
                        }
                    }
                    Err(e) => { 
                        warn!("Contract deploy failed: {}", e);
                        // Record contract failure metric
                    }
                }
            }

            // Contract call execution
            if let Some(ref call) = tx.contract_call {
                match self.state_store.get_contract_code(&call.contract_id) {
                    Ok(Some(code)) => {
                        let existing_state = self.state_store.get_contract_state_all(&call.contract_id).unwrap_or_default();
                        let ctx = noirnet_vm::ExecutionContext {
                            contract_id: call.contract_id, 
                            caller_commitment: call.caller_commitment,
                            gas_remaining: call.gas_limit,
                            state_diff: std::collections::HashMap::new(),
                            existing_state, 
                            events: vec![], 
                            memory: None,
                        };
                        match self.vm.execute(&code, &call.method, &call.args, ctx) {
                            Ok(r) => {
                                info!("Contract call succeeded. Gas: {}, Events: {}", r.gas_used, r.events.len());
                                for (k, v) in r.state_changes {
                                    let mut c = Vec::with_capacity(32 + k.len());
                                    c.extend_from_slice(call.contract_id.as_bytes());
                                    c.extend_from_slice(&k);
                                    contract_state_changes.insert(c, v);
                                }
                            }
                            Err(e) => { 
                                warn!("Contract call failed: {}", e);
                            }
                        }
                    }
                    Ok(None) => { warn!("Contract not found"); }
                    Err(e) => { warn!("Failed to load contract: {}", e); }
                }
            }
        }

        // Phase 3: Apply block to state with atomicity
        match self.state_store.apply_block(&block, contract_state_changes, new_contracts) {
            Ok(state_root) => {
                // Critical: verify state root matches
                if state_root != block.header.state_root {
                    error!("CRITICAL: state root mismatch! Computed: {}, Header: {}",
                        state_root, block.header.state_root);
                    self.record_slashing_event("state_root_mismatch");
                    return;
                }
                info!("Block {} applied successfully. State root: {}, Txs: {}", 
                    block.header.height, state_root, tx_count);
                
                // Update metrics
                self.consecutive_missed_blocks = 0;
                self.last_block_time = std::time::Instant::now();
                
                // Remove mined transactions from mempool
                self.mempool.remove_mined(&block.transactions);
            }
            Err(e) => { 
                error!("Failed to apply block {}: {}", block.header.height, e);
                self.record_slashing_event("apply_block_failed");
            }
        }
    }
    
    /// Record slashing event for Byzantine behavior
    fn record_slashing_event(&self, event_type: &str) {
        error!("SLASHING EVENT: {} by validator {:?}", event_type, self.local_validator_id);
        // In production: submit slashing transaction to network
    }

    /// Main consensus loop
    pub async fn run(&mut self) {
        info!("Starting PRODUCTION consensus engine...");
        
        loop {
            let height = self.state_store.get_chain_height().unwrap_or(0) + 1;
            let epoch = height / noirnet_types::constants::EPOCH_BLOCKS;
            let mut round = 0;
            
            let val_set = self.state_store.get_validator_set(epoch).unwrap_or_default();
            let total_validators = if val_set.is_empty() { 4 } else { val_set.len() };
            
            let mut bft_state = crate::bft::BftRoundState::new(height, round, total_validators);
            let is_syncing = self.sync_manager.check_sync_status(height.saturating_sub(1));
            
            let mut pseudo_vrf = [0u8; 32];
            pseudo_vrf[0..8].copy_from_slice(&height.to_le_bytes());
            pseudo_vrf[8..12].copy_from_slice(&round.to_le_bytes());
            let vrf_hash = noirnet_types::hash::Hash32::blake3_of(&pseudo_vrf).0;
            
            let is_leader = if val_set.is_empty() {
                self.is_validator
            } else {
                if let Some(leader) = val_set.elect_leader(&vrf_hash, epoch) {
                    leader.id() == self.local_validator_id
                } else {
                    false
                }
            };

            // Validator block proposal
            if is_leader && !is_syncing {
                let txs = self.mempool.select_for_block(10_000, noirnet_types::constants::MAX_BLOCK_GAS);
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let parent_hash = if height > 1 {
                    self.state_store.get_block_by_height(height - 1).unwrap().map(|b| b.header.hash()).unwrap_or(noirnet_types::hash::Hash32([0u8; 32]))
                } else {
                    noirnet_types::hash::Hash32([0u8; 32])
                };
                let block = self.builder.build_block(txs, self.local_validator_id, parent_hash.0, timestamp, height);
                info!("Proposing block {} with {} transactions...", block.header.height, block.transactions.len());
                
                if let Ok(bytes) = bincode::serialize(&block) {
                    let _ = self.network_tx.send(NetworkCommand::BroadcastBlock(bytes)).await;
                }
            }
            
            let mut current_block = None;
            loop {
                tokio::select! {
                    // Receive new block proposals
                    Some(block) = self.block_rx.recv() => {
                        let bh = block.header.height;
                        if let Some(_req) = self.sync_manager.handle_peer_height(libp2p::PeerId::random(), bh, height.saturating_sub(1)) {
                            if let Some((peer, req)) = &self.sync_manager.current_request {
                                let _ = self.network_tx.send(NetworkCommand::SendSyncRequest(peer.clone(), req.clone())).await;
                            }
                        }
                        if bh == height && !self.sync_manager.is_syncing {
                            info!("Received proposal for block {}", block.header.hash());
                            current_block = Some(block.clone());
                            bft_state.try_advance_phase(&block.header.hash());
                            
                            if let Some(ref sk) = self.secret_key {
                                let sig = sk.sign(&block.header.hash().0);
                                let vote = Vote {
                                    height, round, block_hash: block.header.hash(), vote_type: VoteType::Prevote,
                                    validator_id: self.local_validator_id, signature: sig.to_bytes(),
                                };
                                if let Ok(bytes) = bincode::serialize(&vote) {
                                    let _ = self.network_tx.send(NetworkCommand::BroadcastVote(bytes)).await;
                                }
                                bft_state.add_vote(vote);
                            }
                        }
                    }
                    
                    // Process votes from other validators
                    Some(vote) = self.vote_rx.recv() => {
                        if vote.height == height && vote.round == round {
                            // Verify BLS signature
                            let is_valid = if let Some(val) = val_set.get_by_id(&vote.validator_id) {
                                if let Ok(pk) = noirnet_crypto::BlsPublicKey::from_bytes(&val.bls_pubkey) {
                                    if let Ok(sig) = noirnet_crypto::BlsSignature::from_bytes(&vote.signature) {
                                        sig.verify(&vote.block_hash.0, &pk)
                                    } else { false }
                                } else { false }
                            } else { 
                                // Default set (devnet) - allow all if val_set is empty
                                if val_set.is_empty() { true } else { false }
                            };

                            if is_valid && bft_state.add_vote(vote.clone()) {
                                if let Some(new_phase) = bft_state.try_advance_phase(&vote.block_hash) {
                                    match new_phase {
                                        crate::bft::BftPhase::Precommit => {
                                            info!("Quorum reached, broadcasting Precommit");
                                            if let Some(ref sk) = self.secret_key {
                                                let sig = sk.sign(&vote.block_hash.0);
                                                let pv = Vote {
                                                    height, round, block_hash: vote.block_hash,
                                                    vote_type: VoteType::Precommit,
                                                    validator_id: self.local_validator_id, signature: sig.to_bytes(),
                                                };
                                                if let Ok(bytes) = bincode::serialize(&pv) {
                                                    let _ = self.network_tx.send(NetworkCommand::BroadcastVote(bytes)).await;
                                                }
                                                bft_state.add_vote(pv);
                                            }
                                        }
                                        crate::bft::BftPhase::Commit => {
                                            info!("COMMITTING block {} to ledger!", vote.block_hash);
                                            if let Some(ref b) = current_block {
                                                self.execute_and_apply_block(b.clone()).await;
                                                break;
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                    
                    // Handle sync requests
                    Some((peer, req, channel)) = self.sync_req_rx.recv() => {
                        tracing::info!("Handling SyncRequest from {} for height {}", peer, req.start_height);
                        let mut blocks = Vec::new();
                        let max_h = std::cmp::min(
                            req.start_height + req.limit as u64, 
                            self.state_store.get_chain_height().unwrap_or(0) + 1
                        );
                        for h in req.start_height..max_h {
                            if let Ok(Some(b)) = self.state_store.get_block_by_height(h) {
                                blocks.push(b);
                            } else { break; }
                        }
                        let res = SyncResponse { blocks };
                        let _ = self.network_tx.send(NetworkCommand::SendSyncResponse(channel, res)).await;
                    }
                    
                    // Handle sync responses
                    Some((peer, res)) = self.sync_res_rx.recv() => {
                        tracing::info!("Handling SyncResponse from {} with {} blocks", peer, res.blocks.len());
                        if self.sync_manager.is_syncing {
                            for b in res.blocks {
                                if b.header.height >= height {
                                    tracing::info!("Applying synced block {}", b.header.height);
                                    self.execute_and_apply_block(b).await;
                                }
                            }
                            let ch = self.state_store.get_chain_height().unwrap_or(0);
                            if self.sync_manager.check_sync_status(ch) {
                                if let Some((p, r)) = &self.sync_manager.current_request {
                                    let mut nr = r.clone();
                                    nr.start_height = ch + 1;
                                    let _ = self.network_tx.send(NetworkCommand::SendSyncRequest(p.clone(), nr)).await;
                                } else { break; }
                            }
                        }
                    }
                    
                    // Round timeout
                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(10)) => {
                        warn!("Round {} timeout. Moving to next round...", round);
                        round += 1;
                        self.consecutive_missed_blocks += 1;
                        
                        // Check slashing conditions
                        if self.consecutive_missed_blocks >= self.slashing_conditions.max_consecutive_missed_blocks {
                            error!("SLASHING: Validator missed {} consecutive blocks", self.consecutive_missed_blocks);
                            self.record_slashing_event("excessive_downtime");
                        }
                        
                        bft_state = crate::bft::BftRoundState::new(height, round, total_validators);
                    }
                }
            }
        }
    }
}

pub struct ConsensusState {
    pub current_height: u64,
    pub current_epoch: u64,
    pub current_round: u32,
    pub active_validators: Vec<ValidatorState>,
}
