// dandelion.rs — Dandelion++ протокол для транзакцій
// CVE-002 FIX: Time-based stem expiry замість фіксованого hop count

use libp2p::PeerId;
use noirnet_types::hash::TxId;
use rand::Rng;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub enum DandelionPhase {
    Stem,
    Fluff,
}

#[derive(Debug)]
pub struct TxState {
    pub phase: DandelionPhase,
    pub received_from: PeerId,
    pub created_at: Instant,
    /// CVE-002 FIX: Час, коли ця транзакція має перейти в fluff
    pub stem_deadline: Instant,
}

pub struct DandelionRouter {
    pub phase: DandelionPhase,
    pub stem_successor: Option<PeerId>,
    pub tx_states: HashMap<TxId, TxState>,
    pub fluff_probability: f64,
    /// CVE-002 FIX: Середній час stem-фази (експоненційний розподіл)
    pub mean_stem_duration_secs: f64,
}

pub enum RoutingDecision {
    Broadcast,
    ForwardTo(PeerId),
    Drop,
}

impl DandelionRouter {
    pub fn new(fluff_probability: f64) -> Self {
        Self {
            phase: DandelionPhase::Stem,
            stem_successor: None,
            tx_states: HashMap::new(),
            fluff_probability,
            mean_stem_duration_secs: 8.0, // CVE-002: середній час 8 секунд
        }
    }

    /// CVE-002 FIX: Генерувати випадковий час stem-фази (експоненційний розподіл)
    /// Це робить timing-аналіз значно складнішим, бо час непередбачуваний
    fn sample_stem_duration(&self) -> Duration {
        let mut rng = rand::thread_rng();
        // Exponential distribution: -mean * ln(U), де U ~ Uniform(0,1)
        let u: f64 = rng.gen_range(0.001..1.0); // уникаємо ln(0)
        let seconds = -self.mean_stem_duration_secs * u.ln();
        // Обмежуємо діапазон: від 2 до 30 секунд
        let clamped = seconds.clamp(2.0, 30.0);
        Duration::from_secs_f64(clamped)
    }

    pub fn rotate_successor(&mut self, connected_peers: &[PeerId]) {
        if connected_peers.is_empty() {
            self.stem_successor = None;
            return;
        }
        let mut rng = rand::thread_rng();
        let idx = rng.gen_range(0..connected_peers.len());
        self.stem_successor = Some(connected_peers[idx]);
    }

    /// CVE-002 FIX: Очистити прострочені stem-транзакції (викликати періодично)
    pub fn flush_expired_stems(&mut self) -> Vec<TxId> {
        let now = Instant::now();
        let mut expired = Vec::new();
        for (txid, state) in &mut self.tx_states {
            if state.phase == DandelionPhase::Stem && now > state.stem_deadline {
                state.phase = DandelionPhase::Fluff;
                expired.push(*txid);
            }
        }
        expired
    }

    pub fn route_tx(&mut self, txid: TxId, from: PeerId) -> RoutingDecision {
        if self.tx_states.contains_key(&txid) {
            return RoutingDecision::Drop; // Loop detection
        }

        let mut rng = rand::thread_rng();
        let stem_duration = self.sample_stem_duration();

        // Node in fluff phase always broadcasts
        if self.phase == DandelionPhase::Fluff {
            self.tx_states.insert(
                txid,
                TxState {
                    phase: DandelionPhase::Fluff,
                    received_from: from,
                    created_at: Instant::now(),
                    stem_deadline: Instant::now(), // не використовується у fluff
                },
            );
            return RoutingDecision::Broadcast;
        }

        // CVE-002 FIX: Замість фіксованої ймовірності, використовуємо комбінацію
        // ймовірності + time-based expiry
        if rng.gen::<f64>() < self.fluff_probability {
            // Flip to fluff
            self.tx_states.insert(
                txid,
                TxState {
                    phase: DandelionPhase::Fluff,
                    received_from: from,
                    created_at: Instant::now(),
                    stem_deadline: Instant::now(),
                },
            );
            return RoutingDecision::Broadcast;
        }

        // Forward to successor with time-limited stem
        if let Some(successor) = self.stem_successor {
            if successor != from {
                self.tx_states.insert(
                    txid,
                    TxState {
                        phase: DandelionPhase::Stem,
                        received_from: from,
                        created_at: Instant::now(),
                        stem_deadline: Instant::now() + stem_duration,
                    },
                );
                return RoutingDecision::ForwardTo(successor);
            }
        }

        // Fallback
        RoutingDecision::Broadcast
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noirnet_types::hash::Hash32;

    fn make_peer() -> PeerId {
        let kp = libp2p::identity::Keypair::generate_ed25519();
        PeerId::from(kp.public())
    }

    #[test]
    fn test_route_tx_drop_duplicate() {
        let mut router = DandelionRouter::new(1.0); // 100% fluff to guarantee state is saved
        let txid = Hash32([1u8; 32]);
        let peer = make_peer();
        let _ = router.route_tx(txid, peer);
        let d2 = router.route_tx(txid, peer);
        assert!(matches!(d2, RoutingDecision::Drop));
    }

    #[test]
    fn test_fluff_phase_broadcasts() {
        let mut router = DandelionRouter::new(0.5);
        router.phase = DandelionPhase::Fluff;
        let txid = Hash32([2u8; 32]);
        let d = router.route_tx(txid, make_peer());
        assert!(matches!(d, RoutingDecision::Broadcast));
    }

    #[test]
    fn test_rotate_successor_empty() {
        let mut router = DandelionRouter::new(0.5);
        router.rotate_successor(&[]);
        assert!(router.stem_successor.is_none());
    }

    #[test]
    fn test_rotate_successor_with_peers() {
        let mut router = DandelionRouter::new(0.5);
        let peers = vec![make_peer(), make_peer()];
        router.rotate_successor(&peers);
        assert!(router.stem_successor.is_some());
    }

    #[test]
    fn test_stem_duration_within_bounds() {
        let router = DandelionRouter::new(0.1);
        for _ in 0..100 {
            let dur = router.sample_stem_duration();
            assert!(dur >= Duration::from_secs(2));
            assert!(dur <= Duration::from_secs(30));
        }
    }

    #[test]
    fn test_flush_expired_stems() {
        let mut router = DandelionRouter::new(0.0); // 0% fluff — force stem
        let peers = vec![make_peer(), make_peer()];
        router.rotate_successor(&peers);

        let txid = Hash32([3u8; 32]);
        let peer = make_peer();
        let _ = router.route_tx(txid, peer);

        // Manually expire the stem deadline
        if let Some(state) = router.tx_states.get_mut(&txid) {
            state.stem_deadline = Instant::now() - Duration::from_secs(1);
        }

        let expired = router.flush_expired_stems();
        assert!(expired.contains(&txid));

        // Verify it transitioned to Fluff
        assert_eq!(router.tx_states[&txid].phase, DandelionPhase::Fluff);
    }
}
