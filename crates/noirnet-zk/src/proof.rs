// proof.rs — генерація та верифікація доказів за допомогою Nova-SNARK

use crate::spend::SpendCircuit;
use nova_snark::{
    provider::{PallasEngine, VestaEngine},
    traits::{
        snark::default_ck_hint,
        Engine,
    },
    nova::{PublicParams, RecursiveSNARK},
};
use thiserror::Error;

pub type E1 = PallasEngine;
pub type E2 = VestaEngine;
pub type C1 = SpendCircuit<<E1 as Engine>::Scalar>;

#[derive(Debug, Error)]
pub enum ZkError {
    #[error("Proving failed: {0}")]
    ProvingFailed(String),
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("Setup failed: {0}")]
    SetupFailed(String),
}

/// Універсальні публічні параметри для Nova (без Trusted Setup)
pub fn setup_nova() -> PublicParams<E1, E2, C1> {
    let circuit_primary = SpendCircuit {
        note_value: None,
        secret_key: None,
        public_nullifier: None,
    };

    PublicParams::setup(
        &circuit_primary,
        &*default_ck_hint(),
        &*default_ck_hint(),
    ).expect("Failed to setup Nova parameters")
}

/// Згенерувати Spend Proof для кількох витрат (Nova RecursiveSNARK)
pub fn generate_multi_spend_proof(
    pp: &PublicParams<E1, E2, C1>,
    values: &[u64],
    sks: &[u64],
    nullifiers: &[u64],
) -> Result<Vec<u8>, ZkError> {
    if values.is_empty() || values.len() != sks.len() || values.len() != nullifiers.len() {
        return Err(ZkError::ProvingFailed("Invalid input lengths".to_string()));
    }

    // Початковий стан згортання
    let z0_primary = vec![<E1 as Engine>::Scalar::from(0u64)];

    // Ініціалізуємо RecursiveSNARK з першим кроком
    let mut circuit_primary = SpendCircuit {
        note_value: Some(<E1 as Engine>::Scalar::from(values[0])),
        secret_key: Some(<E1 as Engine>::Scalar::from(sks[0])),
        public_nullifier: Some(<E1 as Engine>::Scalar::from(nullifiers[0])),
    };

    let mut recursive_snark = RecursiveSNARK::<E1, E2, C1>::new(
        pp,
        &circuit_primary,
        &z0_primary,
    )
    .map_err(|e| ZkError::ProvingFailed(e.to_string()))?;

    // Робимо 1 крок згортання для першої витрати
    recursive_snark
        .prove_step(pp, &circuit_primary)
        .map_err(|e| ZkError::ProvingFailed(e.to_string()))?;

    // Згортаємо решту витрат
    for i in 1..values.len() {
        circuit_primary.note_value = Some(<E1 as Engine>::Scalar::from(values[i]));
        circuit_primary.secret_key = Some(<E1 as Engine>::Scalar::from(sks[i]));
        circuit_primary.public_nullifier = Some(<E1 as Engine>::Scalar::from(nullifiers[i]));

        recursive_snark
            .prove_step(pp, &circuit_primary)
            .map_err(|e| ZkError::ProvingFailed(e.to_string()))?;
    }

    // Серіалізуємо отриманий RecursiveSNARK
    let bytes = bincode::serialize(&recursive_snark)
        .map_err(|e| ZkError::ProvingFailed(e.to_string()))?;
    
    Ok(bytes)
}

/// Верифікувати Spend Proof
pub fn verify_spend_proof(
    pp: &PublicParams<E1, E2, C1>,
    proof_bytes: &[u8],
    num_steps: usize, // Для одиничного spend = 1
) -> Result<bool, ZkError> {
    let recursive_snark: RecursiveSNARK<E1, E2, C1> =
        bincode::deserialize(proof_bytes).map_err(|e| ZkError::VerificationFailed(e.to_string()))?;

    let z0_primary = vec![<E1 as Engine>::Scalar::from(0u64)];

    let res = recursive_snark.verify(pp, num_steps, &z0_primary);

    Ok(res.is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spend_proof_nova_roundtrip() {
        let pp = setup_nova();

        let values = [100u64, 200u64];
        let sks = [5u64, 6u64];
        let nullifiers = [500u64, 1200u64];

        // Генеруємо доказ (для 2 витрат)
        let proof = generate_multi_spend_proof(&pp, &values, &sks, &nullifiers).unwrap();

        // Верифікуємо (2 кроки)
        let is_valid = verify_spend_proof(&pp, &proof, 2).unwrap();
        assert!(is_valid);
    }
}
