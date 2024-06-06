use crate::{
    chips::{
        sbox_chip::{SboxChip, SboxConfig},
        u8_range_check_chip::{U8RangeCheckChip, U8RangeCheckConfig},
        u8_xor_chip::{U8XorChip, U8XorConfig},
    },
    halo2_proofs::{
        circuit::{AssignedCell, Layouter, Value},
        halo2curves::bn256::Fr as Fp,
        plonk::{Advice, Column, ConstraintSystem, Error, Selector},
        poly::Rotation,
    },
    key_schedule::Aes128KeyScheduleConfig,
    table::{
        gf_mul::{PolyMulBy2TableConfig, PolyMulBy3TableConfig, MUL_BY_2, MUL_BY_3},
        s_box::SboxTableConfig,
        u8_range_check::U8RangeCheckTableConfig,
        u8_xor::U8XorTableConfig,
    },
};

#[derive(Clone, Debug)]
pub struct FixedAes128Config {
    key: Option<[u8; 16]>,
    pub key_schedule_config: Aes128KeyScheduleConfig,
    pub u8_xor_table_config: U8XorTableConfig,
    pub u8_range_check_table_config: U8RangeCheckTableConfig,
    pub sbox_table_config: SboxTableConfig,
    pub mul2_table_config: PolyMulBy2TableConfig,
    pub mul3_table_config: PolyMulBy3TableConfig,

    u8_range_check_config: U8RangeCheckConfig,
    u8_xor_config: U8XorConfig,
    sbox_config: SboxConfig,

    advices: [Column<Advice>; 3],

    words_column: Column<Advice>,
    q_mul_by_2: Selector,
    q_mul_by_3: Selector,
}

impl FixedAes128Config {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let u8_xor_table_config = U8XorTableConfig::configure(meta);
        let sbox_table_config = SboxTableConfig::configure(meta);
        let u8_range_check_table_config = U8RangeCheckTableConfig::configure(meta);
        let mul2_table_config = PolyMulBy2TableConfig::configure(meta);
        let mul3_table_config = PolyMulBy3TableConfig::configure(meta);

        let advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let q_u8_range_check = meta.complex_selector();
        let q_u8_xor = meta.complex_selector();
        let q_sbox = meta.complex_selector();

        let u8_range_check_config = U8RangeCheckChip::configure(
            meta,
            advices[0],
            q_u8_range_check,
            u8_range_check_table_config,
        );
        let u8_xor_config = U8XorChip::configure(
            meta,
            advices[0],
            advices[1],
            advices[2],
            q_u8_xor,
            u8_xor_table_config,
        );
        let sbox_config =
            SboxChip::configure(meta, advices[0], advices[1], q_sbox, sbox_table_config);

        let key_schedule_config = Aes128KeyScheduleConfig::configure(
            meta,
            advices,
            u8_xor_config,
            sbox_config,
            u8_range_check_config,
        );

        let words_column = meta.advice_column();
        let q_mul_by_2 = meta.complex_selector();
        let q_mul_by_3 = meta.complex_selector();

        meta.enable_equality(words_column);
        advices.iter().for_each(|advice| {
            meta.enable_equality(*advice);
        });

        // Constraints MUL by 2
        meta.lookup("Mul by 2", |meta| {
            let q = meta.query_selector(q_mul_by_2);
            let prev = meta.query_advice(words_column, Rotation::cur());
            let new = meta.query_advice(words_column, Rotation::next());

            vec![
                (q.clone() * prev, mul2_table_config.x),
                (q.clone() * new, mul2_table_config.y),
            ]
        });

        // Constraints MUL by 3
        meta.lookup("Mul by 3", |meta| {
            let q = meta.query_selector(q_mul_by_3);
            let prev = meta.query_advice(words_column, Rotation::cur());
            let new = meta.query_advice(words_column, Rotation::next());

            vec![
                (q.clone() * prev, mul3_table_config.x),
                (q.clone() * new, mul3_table_config.y),
            ]
        });

        Self {
            key: None,
            key_schedule_config,
            u8_xor_table_config,
            u8_range_check_table_config,
            sbox_table_config,
            mul2_table_config,
            mul3_table_config,

            advices,
            u8_range_check_config,
            u8_xor_config,
            sbox_config,

            words_column,

            q_mul_by_2,
            q_mul_by_3,
        }
    }

    pub fn encrypt(
        &mut self,
        mut layouter: impl Layouter<Fp>,
        plaintext: [u8; 16],
    ) -> Result<Vec<AssignedCell<Fp, Fp>>, Error> {
        // Prepare chips
        let xor_chip = U8XorChip::construct(self.u8_xor_config);
        let sbox_chip = SboxChip::construct(self.sbox_config);
        let range_chip = U8RangeCheckChip::construct(self.u8_range_check_config);

        let round_keys = self
            .key_schedule_config
            .schedule_keys(&mut layouter, self.key.expect("Key should be set"))?;

        // TODO: decide if open the plaintext as instance
        // Assign 16 bytes in cells
        let assigned_plaintext = layouter.assign_region(
            || "Assign plaintext",
            |mut region| {
                plaintext
                    .iter()
                    .enumerate()
                    .map(|(i, &p)| {
                        region.assign_advice(
                            || "Assign plaintext",
                            self.words_column,
                            i,
                            || Value::known(Fp::from(p as u64)),
                        )
                    })
                    .collect::<Result<Vec<_>, Error>>()
            },
        )?;

        let mut prev_round = assigned_plaintext
            .iter()
            .zip(round_keys[0].clone())
            .map(|(p, k)| xor_chip.xor(&mut layouter, p, &k))
            .collect::<Result<Vec<_>, Error>>()?;

        // we have 4 words in round_out vec.
        for no_round in 1..11 {
            // Sub round_out
            let subbed = prev_round
                .iter()
                .map(|byte| sbox_chip.substitute(&mut layouter, byte))
                .collect::<Result<Vec<_>, Error>>()?
                .chunks(4)
                .map(|word| word.to_vec())
                .collect::<Vec<_>>();

            // Shift rows is just copy constraints.
            // 1st word (0,0) (1,1) (2,2) (3,3)
            // 2nd word (0,1) (1,2) (2,3) (3,0)
            // 3rd word (0,2) (1,3) (2,0) (3,1)
            // 4th word (0,3) (1,0) (2,1) (3,2)
            let mut shifted = vec![];
            for i in 0..4 {
                let mut inner = vec![];
                for j in 0..4 {
                    inner.push(subbed[(i + j) % 4][j].clone());
                }
                shifted.push(inner);
            }

            // Mixcolumns
            // do linear transformation to the columns.
            // for each column(word) multiply by matrix
            let matrix = vec![
                vec![2, 3, 1, 1],
                vec![1, 2, 3, 1],
                vec![1, 1, 2, 3],
                vec![3, 1, 1, 2],
            ];

            // Now e have 4*4 = 16 bytes in the mixed
            let mixed = if no_round == 10 {
                shifted.clone()
            } else {
                shifted
                    .iter()
                    .map(|word| {
                        matrix
                            .iter()
                            .map(|col| self.lcon(&mut layouter, word, col))
                            .collect::<Result<Vec<_>, Error>>()
                    })
                    .collect::<Result<Vec<Vec<_>>, Error>>()?
            };

            prev_round = mixed
                .iter()
                .enumerate()
                .map(|(i, word)| {
                    (0..4)
                        .map(|j| {
                            xor_chip.xor(&mut layouter, &word[j], &round_keys[no_round][i * 4 + j])
                        })
                        .collect::<Result<Vec<_>, Error>>()
                })
                .collect::<Result<Vec<Vec<_>>, Error>>()?
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
        }

        Ok(prev_round)
    }

    pub fn decrypt(&self, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        todo!()
    }

    pub fn set_key(&mut self, key: [u8; 16]) {
        self.key = Some(key);
    }

    // Compute linear combination of word and given coefficients
    fn lcon(
        &mut self,
        layouter: &mut impl Layouter<Fp>,
        word: &Vec<AssignedCell<Fp, Fp>>,
        coeffs: &Vec<u32>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let xor_chip = U8XorChip::construct(self.u8_xor_config);

        let tmp = layouter.assign_region(
            || "Mul with coeffs",
            |mut region| {
                let mut offset = 0;

                word.iter()
                    .zip(coeffs)
                    .map(|(byte, col)| match col {
                        1 => {
                            // just copy advice from word
                            let res = byte.copy_advice(
                                || "Copy mul by 1",
                                &mut region,
                                self.words_column,
                                offset,
                            );
                            offset += 1;
                            res
                        }
                        2 => {
                            // TODO: extract method to map values using table
                            let new_byte = byte.value().map(|v| {
                                Fp::from(MUL_BY_2[*v.to_bytes().first().unwrap() as usize] as u64)
                            });
                            self.q_mul_by_2.enable(&mut region, offset)?;
                            byte.copy_advice(
                                || "Copy prev_byte",
                                &mut region,
                                self.words_column,
                                offset,
                            )?;
                            offset += 1;

                            let res = region.assign_advice(
                                || "Assign mul by 2",
                                self.words_column,
                                offset,
                                || new_byte,
                            );
                            offset += 1;
                            res
                        }
                        3 => {
                            // TODO: extract method to map values using table

                            let new_byte = byte.value().map(|v| {
                                Fp::from(MUL_BY_3[*v.to_bytes().first().unwrap() as usize] as u64)
                            });
                            self.q_mul_by_3.enable(&mut region, offset)?;
                            byte.copy_advice(
                                || "Copy prev_byte",
                                &mut region,
                                self.words_column,
                                offset,
                            )?;
                            offset += 1;

                            let res = region.assign_advice(
                                || "Assign mul by 3",
                                self.words_column,
                                offset,
                                || new_byte,
                            );
                            offset += 1;
                            res
                        }
                        _ => panic!("col should be 1, 2, or 3."),
                    })
                    .collect::<Result<Vec<_>, Error>>()
            },
        )?;

        let inter_1 = xor_chip.xor(layouter, &tmp[0], &tmp[1])?;
        let inter_2 = xor_chip.xor(layouter, &tmp[2], &tmp[3])?;
        xor_chip.xor(layouter, &inter_1, &inter_2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::halo2_proofs::{
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
            config.sbox_table_config.load(&mut layouter)?;
            config.u8_range_check_table_config.load(&mut layouter)?;
            config.mul2_table_config.load(&mut layouter)?;
            config.mul3_table_config.load(&mut layouter)?;

            config.set_key(self.key);

            let val = config.encrypt(layouter, self.plaintext)?;
            val.iter().for_each(|cell| {
                println!(" {:?}", cell.value());
            });

            Ok(())
        }

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }
    }

    #[test]
    #[cfg(feature = "halo2-pse")]
    fn test_correct_encryption() {
        let k = 18;
        let circuit = TestAesCircuit {
            key: [0u8; 16],
            plaintext: [0u8; 16],
        };

        let mock = MockProver::run(k, &circuit, vec![]).unwrap();
        mock.assert_satisfied();

        // Expected ciphertext
        {
            use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
            use aes::Aes128;

            let key = GenericArray::from([0u8; 16]);
            let mut block = GenericArray::from([0u8; 16]);

            // Initialize cipher
            let cipher = Aes128::new(&key);
            cipher.encrypt_block(&mut block);
            block.iter().for_each(|v| {
                println!("{:02X?}", v);
            });
        }
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_aes_encrypt() {
        use plotters::prelude::*;

        let k = 18;
        let circuit = TestAesCircuit {
            key: [0u8; 16],
            plaintext: [0u8; 16],
        };

        let root =
            BitMapBackend::new("prints/aes128-layout.png", (2048, 32768)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("AES128 Key schedule circuit", ("sans-serif", 60))
            .unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            .render(k, &circuit, &root)
            .unwrap();
    }

    #[cfg(feature = "cost-estimator")]
    #[test]
    fn cost_estimate_aes_encrypt() {
        use halo2_proofs::dev::cost_model::{from_circuit_to_model_circuit, CommitmentScheme};

        let k = 18;
        let circuit = TestAesCircuit {
            key: [0u8; 16],
            plaintext: [0u8; 16],
        };

        let model = from_circuit_to_model_circuit::<_, _, 56, 56>(
            k,
            &circuit,
            vec![],
            CommitmentScheme::KZGGWC,
        );
        println!(
            "Cost of AES128 Encryption: \n{}",
            serde_json::to_string_pretty(&model).unwrap()
        );
    }
}
