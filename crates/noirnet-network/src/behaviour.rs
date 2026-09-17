// behaviour.rs — libp2p behaviour

use libp2p::{gossipsub, identify, kad, ping, request_response, swarm::NetworkBehaviour};

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "NoirNetBehaviourEvent")]
pub struct NoirNetBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub request_response: request_response::cbor::Behaviour<
        noirnet_types::block::SyncRequest,
        noirnet_types::block::SyncResponse,
    >,
}

pub enum NoirNetBehaviourEvent {
    Gossipsub(gossipsub::Event),
    Kademlia(kad::Event),
    Identify(identify::Event),
    Ping(ping::Event),
    RequestResponse(request_response::Event<noirnet_types::block::SyncRequest, noirnet_types::block::SyncResponse>),
}

impl From<gossipsub::Event> for NoirNetBehaviourEvent {
    fn from(event: gossipsub::Event) -> Self {
        Self::Gossipsub(event)
    }
}

impl From<kad::Event> for NoirNetBehaviourEvent {
    fn from(event: kad::Event) -> Self {
        Self::Kademlia(event)
    }
}

impl From<identify::Event> for NoirNetBehaviourEvent {
    fn from(event: identify::Event) -> Self {
        Self::Identify(event)
    }
}

impl From<ping::Event> for NoirNetBehaviourEvent {
    fn from(event: ping::Event) -> Self {
        Self::Ping(event)
    }
}

impl From<request_response::Event<noirnet_types::block::SyncRequest, noirnet_types::block::SyncResponse>> for NoirNetBehaviourEvent {
    fn from(event: request_response::Event<noirnet_types::block::SyncRequest, noirnet_types::block::SyncResponse>) -> Self {
        Self::RequestResponse(event)
    }
}
