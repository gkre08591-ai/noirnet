use libp2p::{
    gossipsub, identify, identity, kad, ping,
    swarm::{Swarm, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, SwarmBuilder,
};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, warn};

use libp2p::futures::StreamExt;

use super::{NetworkError, NetworkResult};
use crate::behaviour::{NoirNetBehaviour, NoirNetBehaviourEvent};
use noirnet_types::{block::Block, transaction::Transaction};

pub struct NetworkService {
    swarm: Swarm<NoirNetBehaviour>,
    high_priority_command_rx: mpsc::Receiver<NetworkCommand>,
    low_priority_command_rx: mpsc::Receiver<NetworkCommand>,
    mempool_tx: mpsc::Sender<Transaction>,
    consensus_tx: mpsc::Sender<Block>,
    vote_tx: mpsc::Sender<noirnet_types::validator::Vote>,
    sync_req_tx: mpsc::Sender<(PeerId, noirnet_types::block::SyncRequest, libp2p::request_response::ResponseChannel<noirnet_types::block::SyncResponse>)>,
    sync_res_tx: mpsc::Sender<(PeerId, noirnet_types::block::SyncResponse)>,
}

pub enum NetworkCommand {
    Dial(Multiaddr),
    BroadcastTx(Vec<u8>),
    BroadcastBlock(Vec<u8>),
    BroadcastVote(Vec<u8>),
    SendSyncRequest(PeerId, noirnet_types::block::SyncRequest),
    SendSyncResponse(libp2p::request_response::ResponseChannel<noirnet_types::block::SyncResponse>, noirnet_types::block::SyncResponse),
    GetStatus(tokio::sync::oneshot::Sender<NetworkStatus>),
}

#[derive(Debug, Clone)]
pub struct PriorityNetworkSender {
    high: mpsc::Sender<NetworkCommand>,
    low: mpsc::Sender<NetworkCommand>,
}

impl PriorityNetworkSender {
    pub fn new(high: mpsc::Sender<NetworkCommand>, low: mpsc::Sender<NetworkCommand>) -> Self {
        Self { high, low }
    }

    pub async fn send(&self, cmd: NetworkCommand) -> Result<(), mpsc::error::SendError<NetworkCommand>> {
        match cmd {
            NetworkCommand::BroadcastVote(_) | 
            NetworkCommand::SendSyncResponse(_, _) | 
            NetworkCommand::GetStatus(_) |
            NetworkCommand::Dial(_) => {
                self.high.send(cmd).await
            }
            _ => {
                self.low.send(cmd).await
            }
        }
    }
}

#[derive(Debug)]
pub struct NetworkStatus {
    pub peer_count: usize,
    pub is_synced: bool,
}

impl NetworkService {
    pub fn new(
        local_key: identity::Keypair,
        high_priority_command_rx: mpsc::Receiver<NetworkCommand>,
        low_priority_command_rx: mpsc::Receiver<NetworkCommand>,
        mempool_tx: mpsc::Sender<Transaction>,
        consensus_tx: mpsc::Sender<Block>,
        vote_tx: mpsc::Sender<noirnet_types::validator::Vote>,
        sync_req_tx: mpsc::Sender<(PeerId, noirnet_types::block::SyncRequest, libp2p::request_response::ResponseChannel<noirnet_types::block::SyncResponse>)>,
        sync_res_tx: mpsc::Sender<(PeerId, noirnet_types::block::SyncResponse)>,
        listen_port: u16,
    ) -> NetworkResult<Self> {
        // ... (same implementation for behaviour and swarm)
        let local_peer_id = PeerId::from(local_key.public());
        info!("Local peer id: {:?}", local_peer_id);

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(3))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .build().expect("Valid config");

        let mut gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        ).expect("Valid gossipsub");

        gossipsub.subscribe(&gossipsub::IdentTopic::new("noirnet-txs")).unwrap();
        gossipsub.subscribe(&gossipsub::IdentTopic::new("noirnet-blocks")).unwrap();
        gossipsub.subscribe(&gossipsub::IdentTopic::new("noirnet-votes")).unwrap();

        let store = kad::store::MemoryStore::new(local_peer_id);
        let mut kademlia = kad::Behaviour::new(local_peer_id, store);
        kademlia.set_mode(Some(kad::Mode::Server));

        let identify = identify::Behaviour::new(identify::Config::new("/noirnet/1.0.0".into(), local_key.public()));
        let ping = ping::Behaviour::new(ping::Config::default().with_interval(Duration::from_secs(30)));

        let request_response = libp2p::request_response::cbor::Behaviour::<noirnet_types::block::SyncRequest, noirnet_types::block::SyncResponse>::new(
            [(libp2p::StreamProtocol::new("/noirnet/sync/1.0.0"), libp2p::request_response::ProtocolSupport::Full)],
            libp2p::request_response::Config::default(),
        );

        let behaviour = NoirNetBehaviour { gossipsub, kademlia, identify, ping, request_response };

        let mut swarm = SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                libp2p::tls::Config::new,
                yamux::Config::default
            ).expect("TCP/TLS/Yamux")
            .with_behaviour(|_| behaviour).expect("Behaviour")
            .with_swarm_config(|c| c.with_max_negotiating_inbound_streams(10).with_idle_connection_timeout(Duration::from_secs(30)))
            .build();

        let tcp_addr = format!("/ip4/0.0.0.0/tcp/{listen_port}").parse().map_err(|e| NetworkError::P2p(format!("invalid TCP: {e}")))?;
        swarm.listen_on(tcp_addr).map_err(|e| NetworkError::P2p(format!("TCP listen: {e}")))?;

        Ok(Self { 
            swarm, 
            high_priority_command_rx, 
            low_priority_command_rx, 
            mempool_tx, 
            consensus_tx, 
            vote_tx, 
            sync_req_tx, 
            sync_res_tx 
        })
    }

    pub async fn run(mut self) {
        loop {
            tokio::select! {
                biased;

                Some(cmd) = self.high_priority_command_rx.recv() => {
                    self.handle_command(cmd).await;
                }
                event = self.swarm.select_next_some() => { 
                    self.handle_swarm_event(event).await; 
                }
                Some(cmd) = self.low_priority_command_rx.recv() => {
                    self.handle_command(cmd).await;
                }
            }
        }
    }

    async fn handle_swarm_event(&mut self, event: SwarmEvent<NoirNetBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => { info!("Listening on {:?}", address); }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => { info!("Connected to {:?}", peer_id); }
            SwarmEvent::ConnectionClosed { peer_id, .. } => { info!("Disconnected from {:?}", peer_id); }
            SwarmEvent::Behaviour(NoirNetBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                use bincode::Options;
                let bincode_opts = bincode::DefaultOptions::new().with_limit(noirnet_types::constants::MAX_P2P_MESSAGE_SIZE);
                let topic_str = message.topic.as_str();
                if message.data.len() > noirnet_types::constants::MAX_P2P_MESSAGE_SIZE as usize {
                    tracing::warn!("Dropping oversized P2P message: {} bytes", message.data.len());
                    return;
                }
                if topic_str == "noirnet-txs" {
                    if let Ok(tx) = bincode_opts.deserialize::<Transaction>(&message.data) {
                        let jitter_ms = rand::random::<u64>() % 400 + 100;
                        tokio::time::sleep(tokio::time::Duration::from_millis(jitter_ms)).await;
                        info!("Received tx {} from P2P (jitter: {}ms)", tx.tx_id(), jitter_ms);
                        let _ = self.mempool_tx.send(tx).await;
                    } else { tracing::warn!("Failed to deserialize P2P tx (OOM attack)"); }
                } else if topic_str == "noirnet-blocks" {
                    if let Ok(block) = bincode_opts.deserialize::<Block>(&message.data) {
                        info!("Received block {} from P2P", block.header.height);
                        let _ = self.consensus_tx.send(block).await;
                    } else { tracing::warn!("Failed to deserialize P2P block (OOM attack)"); }
                } else if topic_str == "noirnet-votes" {
                    if let Ok(vote) = bincode_opts.deserialize::<noirnet_types::validator::Vote>(&message.data) {
                        tracing::debug!("Received vote from P2P for block {}", vote.block_hash);
                        let _ = self.vote_tx.send(vote).await;
                    } else { tracing::warn!("Failed to deserialize P2P vote"); }
                }
            }
            SwarmEvent::Behaviour(NoirNetBehaviourEvent::RequestResponse(libp2p::request_response::Event::Message { peer, message })) => {
                match message {
                    libp2p::request_response::Message::Request { request_id: _, request, channel } => {
                        let _ = self.sync_req_tx.send((peer, request, channel)).await;
                    }
                    libp2p::request_response::Message::Response { request_id: _, response } => {
                        let _ = self.sync_res_tx.send((peer, response)).await;
                    }
                }
            }
            _ => {}
        }
    }

    async fn handle_command(&mut self, cmd: NetworkCommand) {
        match cmd {
            NetworkCommand::Dial(addr) => { self.swarm.dial(addr).unwrap_or_else(|e| warn!("Dial failed: {e}")); }
            NetworkCommand::BroadcastTx(data) => { let topic = self.swarm.behaviour().gossipsub.topics().next().unwrap().clone(); let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, data); }
            NetworkCommand::BroadcastBlock(data) => { let topic = self.swarm.behaviour().gossipsub.topics().nth(1).unwrap().clone(); let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, data); }
            NetworkCommand::BroadcastVote(data) => { let topic = self.swarm.behaviour().gossipsub.topics().nth(2).unwrap().clone(); let _ = self.swarm.behaviour_mut().gossipsub.publish(topic, data); }
            NetworkCommand::SendSyncRequest(peer, req) => { let _ = self.swarm.behaviour_mut().request_response.send_request(&peer, req); }
            NetworkCommand::SendSyncResponse(channel, res) => { let _ = self.swarm.behaviour_mut().request_response.send_response(channel, res); }
            NetworkCommand::GetStatus(reply) => {
                let status = NetworkStatus {
                    peer_count: self.swarm.connected_peers().count(),
                    is_synced: true, // TODO: Implement real sync status
                };
                let _ = reply.send(status);
            }
        }
    }
}
