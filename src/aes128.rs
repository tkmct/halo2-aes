use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    halo2curves::bn256::Fr as Fp,
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

use crate::{
    key_schedule::Aes128KeyScheduleConfig, table::u8_xor::U8XorTableConfig, utils::xor_bytes,
};

#[derive(Clone, Debug)]
pub struct FixedAes128Config {
    key: Option<[u8; 16]>,
    key_schedule_config: Aes128KeyScheduleConfig,
    u8_xor_table_config: U8XorTableConfig,

    words_column: Column<Advice>,
    q_xor_bytes: Selector,
}

impl FixedAes128Config {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let key_schedule_config = Aes128KeyScheduleConfig::configure(meta);
        let u8_xor_table_config = U8XorTableConfig::configure(meta);
        let words_column = meta.advice_column();
        let q_xor_bytes = meta.complex_selector();

        meta.enable_equality(words_column);

        // TODO: setup constraints
        meta.lookup("XOR Bytes", |meta| {
            let q = meta.query_selector(q_xor_bytes);

            let x = meta.query_advice(words_column, Rotation::cur());
            let y = meta.query_advice(words_column, Rotation(4));
            let z = meta.query_advice(words_column, Rotation(8));

            vec![
                (q.clone() * x, u8_xor_table_config.x),
                (q.clone() * y, u8_xor_table_config.y),
                (q.clone() * z, u8_xor_table_config.z),
            ]
        });

        Self {
            key: None,
            key_schedule_config,
            u8_xor_table_config,
            words_column,
            q_xor_bytes,
        }
    }

    pub fn encrypt(
        &self,
        mut layouter: impl Layouter<Fp>,
        plaintext: [u8; 16],
    ) -> Result<(), Error> {
        let round_keys = self
            .key_schedule_config
            .schedule_keys(&mut layouter, self.key.expect("Key should be set"))?;
        let mut round_out = vec![];

        // 1. Initial round: Add RoundKey_0
        for i in 0..4 {
            let offset = i * 12;
            let tmp = layouter.assign_region(
                || "Assign Initial AddRoundKey",
                |mut region| {
                    let mut out = vec![];
                    // Assign plain text and key
                    for j in 0..4 {
                        let p = Value::known(Fp::from(plaintext[i * 4 + j] as u64));
                        let k = round_keys[0][i * 4 + j].value_field().evaluate();

                        self.q_xor_bytes.enable(&mut region, offset + j)?;
                        region.assign_advice(
                            || "Assign plaintext",
                            self.words_column,
                            offset + j,
                            || p,
                        )?;
                        round_keys[0][i * 4 + j].copy_advice(
                            || "Copy round key from scheduled keys",
                            &mut region,
                            self.words_column,
                            offset + 4 + j,
                        )?;
                        let xor = xor_bytes(&p, &k)?;
                        out.push(region.assign_advice(
                            || "Assign xor value",
                            self.words_column,
                            offset + 8 + j,
                            || xor,
                        )?);
                    }

                    Ok(out)
                },
            )?;
            round_out.push(tmp);
        }
        // we have 4 words in round_out vec.

        // this is just a xor of first round key
        Ok(())
    }

    pub fn decrypt(&self, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        todo!()
    }

    pub(crate) fn set_key(&mut self, key: [u8; 16]) {
        self.key = Some(key);
    }

    fn sub_bytes() {
        todo!()
    }

    fn shift_rows() {
        todo!()
    }

    fn mix_columns() {
        todo!()
    }

    fn add_round_key(&mut self, key: Vec<AssignedCell<Fp, Fp>>, val: Vec<u8>) {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        halo2curves::bn256::Fr as Fp,
        plonk::{Circuit, ConstraintSystem, Error},
    };

    #[derive(Clone)]
    struct TestAesCircuit {
        key: [u8; 16],
        plaintext: [u8; 16],
    }

    impl Circuit<Fp> for TestAesCircuit {
        type Config = FixedAes128Config;
        type FloorPlanner = SimpleFloorPlanner;

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            FixedAes128Config::configure(meta)
        }

        fn synthesize(
            &self,
            mut config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            config.u8_xor_table_config.load(&mut layouter)?;
            config.key_schedule_config.load(&mut layouter);

            config.set_key(self.key);
            config.encrypt(layouter, self.plaintext)?;

            Ok(())
        }

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }
    }

    #[test]
    fn test_correct_encryption() {
        let k = 18;
        let circuit = TestAesCircuit {
            key: [0u8; 16],
            plaintext: [0u8; 16],
        };

        let mock = MockProver::run(k, &circuit, vec![]).unwrap();
        mock.assert_satisfied();

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
