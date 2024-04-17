use halo2_proofs::{
    circuit::AssignedCell,
    halo2curves::bn256::Fr as Fp,
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector},
};

use crate::key_schedule::Aes128KeyScheduleConfig;

#[derive(Clone, Debug)]
pub struct Aes128Config {}

impl Aes128Config {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        Aes128KeyScheduleConfig::configure(meta);

        todo!()
    }
}

#[cfg(test)]
mod tests {
    struct TestCircuit {}

    impl TestCircuit {}

    #[test]
    #[ignore]
    fn test_fixed_key_aes() {
        // what is the input to aes function?
        // plaintext (128 bit)
        // key (128 bit)

        // Expand key

        // Add key

        // Iterate the following operations for 10 rounds
        // but in the last round, we don't execute MixColumn.
        // 1. SubBytes
        // 2. ShiftRows
        // 3. MixColumns
        // 4. AddRoundKey
    }
}
