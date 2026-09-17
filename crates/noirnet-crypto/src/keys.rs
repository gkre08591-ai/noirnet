// keys.rs — генерація та похідні ключі

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use noirnet_types::address::SpendingKey;
use rand_core::OsRng;
use zeroize::Zeroize;

/// Генерація нового Spending Key (з entropy)
pub fn generate_spending_key() -> SpendingKey {
    let mut entropy = [0u8; 32];
    use rand_core::RngCore;
    OsRng.fill_bytes(&mut entropy);
    let sk = SpendingKey::from_seed(&entropy);
    entropy.zeroize();
    sk
}

/// Ed25519 підпис
pub struct Ed25519Keypair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl Ed25519Keypair {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        use rand_core::RngCore;
        OsRng.fill_bytes(&mut bytes);
        let signing_key = SigningKey::from_bytes(&bytes);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing_key.sign(msg).to_bytes()
    }

    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> bool {
        let sig = Signature::from_bytes(sig);
        self.verifying_key.verify(msg, &sig).is_ok()
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}

/// Binding signature для транзакції (запобігає підробці балансу)
/// Спрощена реалізація: Ed25519 підпис від суми value commitments
pub fn create_binding_sig(
    spend_cvs: &[[u8; 32]],
    output_cvs: &[[u8; 32]],
    signing_key: &[u8; 32],
    tx_bytes: &[u8],
) -> [u8; 64] {
    let kp = Ed25519Keypair::from_seed(signing_key);
    // Message = hash(all CVs || tx_bytes)
    let mut h = blake3::Hasher::new();
    h.update(b"NoirNet_binding_sig_v1");
    for cv in spend_cvs {
        h.update(cv);
    }
    for cv in output_cvs {
        h.update(cv);
    }
    h.update(tx_bytes);
    let msg = h.finalize();
    kp.sign(msg.as_bytes())
}

/// Верифікація binding signature
pub fn verify_binding_sig(
    spend_cvs: &[[u8; 32]],
    output_cvs: &[[u8; 32]],
    sig: &[u8; 64],
    verifying_key: &[u8; 32],
    tx_bytes: &[u8],
) -> bool {
    let mut h = blake3::Hasher::new();
    h.update(b"NoirNet_binding_sig_v1");
    for cv in spend_cvs {
        h.update(cv);
    }
    for cv in output_cvs {
        h.update(cv);
    }
    h.update(tx_bytes);
    let msg = h.finalize();

    let vk = match VerifyingKey::from_bytes(verifying_key) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(sig);
    vk.verify(msg.as_bytes(), &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use noirnet_types::address::IncomingViewKey;

    #[test]
    fn test_ed25519_sign_verify() {
        let kp = Ed25519Keypair::generate();
        let msg = b"test message for signing";
        let sig = kp.sign(msg);
        assert!(kp.verify(msg, &sig));
        assert!(!kp.verify(b"wrong message", &sig));
    }

    #[test]
    fn test_spending_key_derivation() {
        let sk = generate_spending_key();
        let fvk = sk.to_fvk();
        let ivk = IncomingViewKey::from_fvk(&fvk);
        // IVK повинен бути ненульовим
        assert_ne!(ivk.ivk, [0u8; 32]);
    }

    #[test]
    fn test_binding_sig_roundtrip() {
        let sk = [77u8; 32];
        let spend_cvs = vec![[1u8; 32]];
        let output_cvs = vec![[2u8; 32]];
        let tx_bytes = b"test tx data";

        let sig = create_binding_sig(&spend_cvs, &output_cvs, &sk, tx_bytes);
        let vk = Ed25519Keypair::from_seed(&sk).public_key_bytes();
        assert!(verify_binding_sig(&spend_cvs, &output_cvs, &sig, &vk, tx_bytes));
    }

    #[test]
    fn test_binding_sig_wrong_key_fails() {
        let sk = [77u8; 32];
        let spend_cvs = vec![[1u8; 32]];
        let output_cvs = vec![[2u8; 32]];
        let tx_bytes = b"test tx data";

        let sig = create_binding_sig(&spend_cvs, &output_cvs, &sk, tx_bytes);
        let wrong_vk = Ed25519Keypair::from_seed(&[88u8; 32]).public_key_bytes();
        assert!(!verify_binding_sig(&spend_cvs, &output_cvs, &sig, &wrong_vk, tx_bytes));
    }
}
