// sync.rs — Initial Block Download (IBD) Manager

use std::collections::{HashMap, HashSet};
use libp2p::PeerId;
use noirnet_types::block::{Block, SyncRequest};

pub struct SyncManager {
    pub is_syncing: bool,
    pub target_height: u64,
    pub current_request: Option<(PeerId, SyncRequest)>,
    // Buffer for blocks received during syncing
    pub buffered_blocks: HashMap<u64, Block>,
    // Peers we know about
    pub active_peers: HashSet<PeerId>,
}

impl SyncManager {
    pub fn new() -> Self {
        Self {
            is_syncing: false,
            target_height: 0,
            current_request: None,
            buffered_blocks: HashMap::new(),
            active_peers: HashSet::new(),
        }
    }

    pub fn start_sync(&mut self, target_height: u64, peer: PeerId, start_height: u64) -> SyncRequest {
        self.is_syncing = true;
        self.target_height = std::cmp::max(self.target_height, target_height);
        
        let request = SyncRequest {
            start_height,
            limit: 50, // request up to 50 blocks at a time
        };

        self.current_request = Some((peer, request.clone()));
        request
    }

    pub fn check_sync_status(&mut self, current_height: u64) -> bool {
        if self.is_syncing && current_height >= self.target_height {
            tracing::info!("Sync complete! Reached target height {}", self.target_height);
            self.is_syncing = false;
            self.current_request = None;
            self.buffered_blocks.clear();
        }
        self.is_syncing
    }

    pub fn handle_peer_height(&mut self, peer: PeerId, peer_height: u64, current_height: u64) -> Option<SyncRequest> {
        self.active_peers.insert(peer);
        
        if peer_height > current_height + 5 && !self.is_syncing {
            tracing::info!("Peer {} is ahead ({} > {}). Initiating IBD...", peer, peer_height, current_height);
            Some(self.start_sync(peer_height, peer, current_height + 1))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_manager_logic() {
        let mut manager = SyncManager::new();
        let peer = PeerId::random();

        // Node is at height 10, peer is at height 12 -> No sync (not > 5 difference)
        let req = manager.handle_peer_height(peer, 12, 10);
        assert!(req.is_none());
        assert!(!manager.is_syncing);

        // Node is at height 10, peer is at height 20 -> Start sync
        let req = manager.handle_peer_height(peer, 20, 10);
        assert!(req.is_some());
        assert!(manager.is_syncing);
        assert_eq!(manager.target_height, 20);

        let req = req.unwrap();
        assert_eq!(req.start_height, 11);
        assert_eq!(req.limit, 50);

        // Still syncing at height 15
        assert!(manager.check_sync_status(15));

        // Reached target height
        assert!(!manager.check_sync_status(20));
        assert!(!manager.is_syncing);
        assert!(manager.current_request.is_none());
    }
}
