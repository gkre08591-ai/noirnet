// output.rs — ZK схема для Output

use nova_snark::traits::circuit::StepCircuit;
use nova_snark::frontend::{ConstraintSystem, num::AllocatedNum, SynthesisError};

use ff::PrimeField;

/// ZK-схема для створення нотатки (Output Circuit)
#[derive(Clone, Debug)]
pub struct OutputCircuit<F: PrimeField> {
    pub note_value: Option<F>,
    pub rcm: Option<F>,
    // Public
    pub public_commitment: Option<F>,
}

impl<F: PrimeField> StepCircuit<F> for OutputCircuit<F> {
    fn arity(&self) -> usize {
        1
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let z_i = &z[0];

        let val_var = AllocatedNum::alloc(cs.namespace(|| "note_value"), || {
            self.note_value.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        let rcm_var = AllocatedNum::alloc(cs.namespace(|| "rcm"), || {
            self.rcm.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        let cm_var = AllocatedNum::alloc(cs.namespace(|| "public_commitment"), || {
            self.public_commitment.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Спрощений constraint: cm = value + rcm (в реальності Pedersen hash)
        // (val + rcm) * 1 = cm
        cs.enforce(
            || "cm = value + rcm",
            |lc| lc + val_var.get_variable() + rcm_var.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + cm_var.get_variable(),
        );

        Ok(vec![z_i.clone()])
    }
}

#[cfg(test)]
mod tests {
    // Test constraint logic simply by checking if it synthesizes with correct vs incorrect values
    // In actual tests, you'd test the full RecursiveSNARK like in proof.rs
}
