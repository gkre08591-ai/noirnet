// sync.rs — сканування блокчейну

use noirnet_crypto::stealth::try_decrypt_output;
use noirnet_types::{address::IncomingViewKey, block::CompactBlock, hash::Hash32, note::Note};
use std::collections::HashSet;

#[derive(Clone, Debug)]
pub struct WalletNote {
    pub note: Note,
    pub commitment: Hash32,
    pub leaf_index: u64,
    pub nullifier: Hash32,
    pub is_spent: bool,
}

pub struct WalletSync {
    pub ivk: IncomingViewKey,
    pub notes: Vec<WalletNote>,
    pub last_scanned_height: u64,
}

impl WalletSync {
    pub fn new(ivk: IncomingViewKey) -> Self {
        Self {
            ivk,
            notes: Vec::new(),
            last_scanned_height: 0,
        }
    }

    pub fn scan_block(&mut self, block: &CompactBlock) {
        let mut new_notes = Vec::new();

        // 1. Scan for new notes
        for output in &block.compact_outputs {
            // Reconstruct full ciphertext for trial decrypt (in reality, we'd need the whole thing, but trial uses prefix)
            let mut fake_full_cipher = vec![0u8; 580];
            fake_full_cipher[..52].copy_from_slice(&output.enc_ciphertext_prefix);

            if let Some(note) = try_decrypt_output(
                &fake_full_cipher,
                &output.ephemeral_key,
                &output.note_commitment,
                &self.ivk,
            ) {
                // We found a note!
                // compute its nullifier (needs nk, but we only have ivk here.
                // In full implementation, we need FullViewingKey to compute nullifiers)
                // For POC, we'll use a dummy nullifier based on commitment
                let mut h = blake3::Hasher::new();
                h.update(output.note_commitment.as_bytes());
                let dummy_nf = Hash32(*h.finalize().as_bytes());

                new_notes.push(WalletNote {
                    note,
                    commitment: output.note_commitment,
                    leaf_index: output.leaf_index,
                    nullifier: dummy_nf,
                    is_spent: false,
                });
            }
        }

        self.notes.extend(new_notes);

        // 2. Scan for spent notes
        let block_nullifiers: HashSet<_> = block.nullifiers.iter().collect();
        for note in &mut self.notes {
            if block_nullifiers.contains(&note.nullifier) {
                note.is_spent = true;
            }
        }

        self.last_scanned_height = block.height;
    }

    pub fn balance(&self) -> u64 {
        self.notes
            .iter()
            .filter(|n| !n.is_spent)
            .map(|n| n.note.value)
            .sum()
    }
}
