// stealth.rs — stealth address protocol

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use noirnet_types::{
    address::IncomingViewKey,
    hash::Hash32,
    note::Note,
};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

/// Результат шифрування нотатки для output
pub struct EncryptedOutput {
    pub ephemeral_key: [u8; 32],
    pub enc_ciphertext: Vec<u8>, // encrypted for recipient
    pub out_ciphertext: Vec<u8>, // encrypted for sender
}

/// Зашифрувати нотатку для отримувача
pub fn encrypt_note(
    note: &Note,
    recipient_pk_d: &[u8; 32],
    sender_ovk: &[u8; 32],
) -> EncryptedOutput {
    let rng = OsRng;

    // Ephemeral key pair
    let esk = EphemeralSecret::random_from_rng(rng);
    let epk = PublicKey::from(&esk);

    // ECDH shared secret з otrimuvachem
    let recipient_pub = PublicKey::from(*recipient_pk_d);
    let shared = esk.diffie_hellman(&recipient_pub);

    // KDF: derive encryption key
    let enc_key = kdf_note(shared.as_bytes(), epk.as_bytes());

    // Encrypt note plaintext for recipient
    let plaintext = note.to_plaintext();
    let enc_ciphertext = chacha20_encrypt(&enc_key, 1, &plaintext);

    // Encrypt for sender (using ovk)
    let out_key = kdf_outgoing(sender_ovk, epk.as_bytes());
    let out_plaintext = {
        let mut p = Vec::new();
        p.extend_from_slice(recipient_pk_d);
        p.extend_from_slice(&note.rcm);
        p
    };
    let out_ciphertext = chacha20_encrypt(&out_key, 2, &out_plaintext);

    EncryptedOutput {
        ephemeral_key: *epk.as_bytes(),
        enc_ciphertext,
        out_ciphertext,
    }
}

/// Спробувати розшифрувати output за допомогою IVK
/// Повертає None якщо output не для цього IVK
pub fn try_decrypt_output(
    enc_ciphertext: &[u8],
    ephemeral_key: &[u8; 32],
    note_commitment: &Hash32,
    ivk: &IncomingViewKey,
) -> Option<Note> {
    // Derive pk_d from ivk (recipient public key)
    // In full impl: pk_d = diversified_base * ivk
    // Simplified: derive from ivk hash
    let pk_d = derive_pkd_from_ivk(&ivk.ivk);

    // ECDH: shared = ivk * epk
    let ivk_static = StaticSecret::from(ivk.ivk);
    let epk = PublicKey::from(*ephemeral_key);
    let shared = ivk_static.diffie_hellman(&epk);

    // KDF
    let enc_key = kdf_note(shared.as_bytes(), ephemeral_key);

    // Try decrypt
    let plaintext = chacha20_decrypt(&enc_key, 1, enc_ciphertext)?;

    // Parse note
    let note = Note::from_plaintext(&plaintext, pk_d)?;

    // Verify commitment
    if note.commitment() != *note_commitment {
        return None;
    }

    Some(note)
}

fn kdf_note(shared_secret: &[u8], epk: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"NoirNet_KDF_note_v1");
    h.update(shared_secret);
    h.update(epk);
    *h.finalize().as_bytes()
}

fn kdf_outgoing(ovk: &[u8], epk: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"NoirNet_KDF_out_v1");
    h.update(ovk);
    h.update(epk);
    *h.finalize().as_bytes()
}

fn chacha20_encrypt(key: &[u8; 32], nonce_byte: u8, plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 12];
    nonce[0] = nonce_byte;
    cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .expect("encryption failed")
}

fn chacha20_decrypt(key: &[u8; 32], nonce_byte: u8, ciphertext: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 12];
    nonce[0] = nonce_byte;
    cipher.decrypt(Nonce::from_slice(&nonce), ciphertext).ok()
}

fn derive_pkd_from_ivk(ivk: &[u8; 32]) -> [u8; 32] {
    // Derive the x25519 public key from ivk treated as a static secret.
    // This ensures ECDH consistency: esk.dh(pk_d) == ivk_static.dh(epk)
    let secret = StaticSecret::from(*ivk);
    let public = PublicKey::from(&secret);
    *public.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let ivk = IncomingViewKey { ivk: [0xAB; 32] };
        let pk_d = derive_pkd_from_ivk(&ivk.ivk);
        let ovk = [0xCD; 32];

        let note = Note::new(
            1_000_000_000, // 1 NOIR
            [11u8; 32],
            [22u8; 32],
            pk_d, // Must match the pk_d that try_decrypt_output will derive
            [44u8; 11],
        );

        let encrypted = encrypt_note(&note, &pk_d, &ovk);
        let cm = note.commitment();

        let decrypted = try_decrypt_output(
            &encrypted.enc_ciphertext,
            &encrypted.ephemeral_key,
            &cm,
            &ivk,
        );

        assert!(decrypted.is_some());
        let d = decrypted.unwrap();
        assert_eq!(d.value, note.value);
    }
}
