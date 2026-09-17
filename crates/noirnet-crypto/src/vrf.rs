// vrf.rs — VRF (Verifiable Random Function) для вибору лідера

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// VRF output + proof
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VrfOutput {
    pub output: [u8; 32],
    pub proof: Vec<u8>, // Ed25519 sig over input
}

/// Генерація VRF output
pub fn vrf_prove(signing_key: &[u8; 32], input: &[u8]) -> VrfOutput {
    let sk = SigningKey::from_bytes(signing_key);
    // VRF input = "NoirNet_VRF_v1" || input
    let mut msg = b"NoirNet_VRF_v1".to_vec();
    msg.extend_from_slice(input);

    let sig: Signature = sk.sign(&msg);
    // VRF output = BLAKE3(sig)
    let output = *blake3::hash(sig.to_bytes().as_ref()).as_bytes();

    VrfOutput {
        output,
        proof: sig.to_bytes().to_vec(),
    }
}

/// Верифікація VRF output
pub fn vrf_verify(verifying_key: &[u8; 32], input: &[u8], vrf_output: &VrfOutput) -> bool {
    let vk = match VerifyingKey::from_bytes(verifying_key) {
        Ok(k) => k,
        Err(_) => return false,
    };

    if vrf_output.proof.len() != 64 {
        return false;
    }
    let sig_bytes: [u8; 64] = match vrf_output.proof.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&sig_bytes);

    let mut msg = b"NoirNet_VRF_v1".to_vec();
    msg.extend_from_slice(input);

    if vk.verify(&msg, &sig).is_err() {
        return false;
    }

    // Verify output = BLAKE3(sig)
    let expected = *blake3::hash(&sig_bytes).as_bytes();
    vrf_output.output == expected
}

/// Epoch beacon: VRF output з останнього блоку попередньої епохи
pub fn compute_epoch_beacon(prev_beacon: &[u8; 32], height: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"NoirNet_epoch_beacon_v1");
    h.update(prev_beacon);
    h.update(&height.to_le_bytes());
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vrf_prove_verify() {
        let sk = [42u8; 32];
        let sk_parsed = SigningKey::from_bytes(&sk);
        let vk = sk_parsed.verifying_key().to_bytes();
        let input = b"block_height_12345";
        let out = vrf_prove(&sk, input);
        assert!(vrf_verify(&vk, input, &out));
        assert!(!vrf_verify(&vk, b"wrong_input", &out));
    }
}
