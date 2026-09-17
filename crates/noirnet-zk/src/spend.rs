// spend.rs — ZK схема для Spend за допомогою Nova/bellpepper

use ff::PrimeField;
use nova_snark::traits::circuit::StepCircuit;
use nova_snark::frontend::{ConstraintSystem, num::AllocatedNum, SynthesisError};

/// ZK-схема для витрачання нотатки (Spend Circuit)
/// Реалізує Nova StepCircuit для можливості рекурсивного згортання (folding).
#[derive(Clone, Debug)]
pub struct SpendCircuit<F: PrimeField> {
    pub note_value: Option<F>,
    pub secret_key: Option<F>,
    pub public_nullifier: Option<F>,
}

impl<F: PrimeField> StepCircuit<F> for SpendCircuit<F> {
    fn arity(&self) -> usize {
        // Ми використовуємо arity 1 для передачі стану згортання.
        1
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let z_i = &z[0];

        // 1. Private variables (Witness)
        let val_var = AllocatedNum::alloc(cs.namespace(|| "note_value"), || {
            self.note_value.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let sk_var = AllocatedNum::alloc(cs.namespace(|| "secret_key"), || {
            self.secret_key.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // 2. Public variables (Instance)
        let nullifier_var = AllocatedNum::alloc(cs.namespace(|| "public_nullifier"), || {
            self.public_nullifier.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // 3. Constraints
        cs.enforce(
            || "nullifier = sk * value",
            |lc| lc + sk_var.get_variable(),
            |lc| lc + val_var.get_variable(),
            |lc| lc + nullifier_var.get_variable(),
        );

        // 4. Оновлення стану згортання (наприклад, +1)
        Ok(vec![z_i.clone()])
    }
}
