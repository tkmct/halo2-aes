use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    halo2curves::bn256::Fr as Fp,
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

use crate::{
    key_schedule::Aes128KeyScheduleConfig,
    table::{
        gf_mul::{PolyMulBy2TableConfig, PolyMulBy3TableConfig, MUL_BY_2, MUL_BY_3},
        s_box::SboxTableConfig,
        u8_xor::U8XorTableConfig,
    },
    utils::{sub_word, xor_bytes},
};

#[derive(Clone, Debug)]
pub struct FixedAes128Config {
    key: Option<[u8; 16]>,
    pub key_schedule_config: Aes128KeyScheduleConfig,
    pub u8_xor_table_config: U8XorTableConfig,
    pub sbox_table_config: SboxTableConfig,
    pub mul2_table_config: PolyMulBy2TableConfig,
    pub mul3_table_config: PolyMulBy3TableConfig,

    words_column: Column<Advice>,
    q_xor_bytes: Selector,
    q_xor_adj: Selector,
    q_sub_bytes: Selector,
    q_mul_by_2: Selector,
    q_mul_by_3: Selector,
}

impl FixedAes128Config {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let key_schedule_config = Aes128KeyScheduleConfig::configure(meta);
        let u8_xor_table_config = U8XorTableConfig::configure(meta);
        let sbox_table_config = SboxTableConfig::configure(meta);
        let mul2_table_config = PolyMulBy2TableConfig::configure(meta);
        let mul3_table_config = PolyMulBy3TableConfig::configure(meta);

        let words_column = meta.advice_column();
        let q_xor_bytes = meta.complex_selector();
        let q_xor_adj = meta.complex_selector();
        let q_sub_bytes = meta.complex_selector();
        let q_mul_by_2 = meta.complex_selector();
        let q_mul_by_3 = meta.complex_selector();

        meta.enable_equality(words_column);

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

        meta.lookup("XOR Adjacent Bytes", |meta| {
            let q = meta.query_selector(q_xor_adj);

            let x = meta.query_advice(words_column, Rotation::cur());
            let y = meta.query_advice(words_column, Rotation(1));
            let z = meta.query_advice(words_column, Rotation(2));

            vec![
                (q.clone() * x, u8_xor_table_config.x),
                (q.clone() * y, u8_xor_table_config.y),
                (q.clone() * z, u8_xor_table_config.z),
            ]
        });

        // Constraints sub bytes
        meta.lookup("Sub Bytes", |meta| {
            let q = meta.query_selector(q_sub_bytes);
            let rot_byte = meta.query_advice(words_column, Rotation::cur());
            let subbed_byte = meta.query_advice(words_column, Rotation(4));

            vec![
                (q.clone() * rot_byte, sbox_table_config.x),
                (q.clone() * subbed_byte, sbox_table_config.y),
            ]
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
            sbox_table_config,
            mul2_table_config,
            mul3_table_config,
            words_column,
            q_xor_bytes,
            q_xor_adj,
            q_sub_bytes,
            q_mul_by_2,
            q_mul_by_3,
        }
    }

    pub fn encrypt(
        &mut self,
        mut layouter: impl Layouter<Fp>,
        plaintext: [u8; 16],
    ) -> Result<Vec<AssignedCell<Fp, Fp>>, Error> {
        let round_keys = self
            .key_schedule_config
            .schedule_keys(&mut layouter, self.key.expect("Key should be set"))?;
        let mut round_out = vec![];

        // 1. Initial round: Add RoundKey_0
        for i in 0..4 {
            let offset = i * 12;
            let mut tmp = layouter.assign_region(
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
                        let xor = xor_bytes(&p, &k);
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
            round_out.append(&mut tmp);
        }
        println!("Round0");
        round_out.iter().for_each(|cell| {
            println!(" {:?}", cell.value());
        });

        // we have 4 words in round_out vec.
        for no_round in 1..11 {
            round_out = layouter.assign_region(
                || "Assign rounds",
                |mut region| {
                    // SubBytes subbed is 4*4 vector
                    let subbed = round_out // 16 bytes
                        .chunks(4)
                        .enumerate()
                        .map(|(no_word, word)| {
                            // iterate by 4 bytes * 4 times
                            word.iter().enumerate().for_each(|(no_byte, byte)| {
                                // iterate 1 byte * 4 times
                                // turn on sbox selector
                                self.q_sub_bytes
                                    .enable(&mut region, no_word * 8 + no_byte)
                                    .expect("Enabling selectors should not fail");
                                byte.copy_advice(
                                    || "Copy prev word",
                                    &mut region,
                                    self.words_column,
                                    no_word * 8 + no_byte,
                                )
                                .expect("copy advice should not fail");
                            });
                            sub_word(
                                &word
                                    .iter()
                                    .map(|a| a.value().map(|&v| v))
                                    .collect::<Vec<_>>(),
                            )
                            .iter()
                            .enumerate()
                            .map(|(j, v)| {
                                region.assign_advice(
                                    || "Assign sub_bytes word",
                                    self.words_column,
                                    no_word * 8 + 4 + j,
                                    || *v,
                                )
                            })
                            .collect::<Result<Vec<_>, Error>>()
                        })
                        .collect::<Result<Vec<Vec<_>>, Error>>()?;
                    println!("S_BOX ");
                    subbed
                        .iter()
                        .for_each(|cell| cell.iter().for_each(|v| println!("  {:?}", v.value())));

                    let mut offset = 32;

                    // ShiftRows
                    // Shift rows for subbed bytes.
                    let mut shifted = vec![];

                    // Shift rows is just copy constraints.
                    // 1st word (0,0) (1,1) (2,2) (3,3)
                    // 2nd word (0,1) (1,2) (2,3) (3,0)
                    // 3rd word (0,2) (1,3) (2,0) (3,1)
                    // 4th word (0,3) (1,0) (2,1) (3,2)
                    for i in 0..4 {
                        let mut v = vec![];
                        for j in 0..4 {
                            v.push(subbed[(i + j) % 4][j].copy_advice(
                                || "Copy subbed word",
                                &mut region,
                                self.words_column,
                                offset + j,
                            )?);
                        }
                        shifted.push(v);
                        offset += 4;
                    }
                    // println!("After shift");
                    // shifted
                    //     .iter()
                    //     .for_each(|cell| cell.iter().for_each(|v| println!("  {:?}", v.value())));

                    // Mixcolumns
                    // do linear transformation to the columns.
                    // for each column(word) multiply by matrix
                    //   2 3 1 1
                    //   1 2 3 1
                    //   1 1 2 3
                    //   3 1 1 2
                    //
                    let matrix = vec![
                        vec![2, 3, 1, 1],
                        vec![1, 2, 3, 1],
                        vec![1, 1, 2, 3],
                        vec![3, 1, 1, 2],
                    ];

                    // Now e have 4*4 = 16 bytes in the mixed
                    let mixed = if no_round == 10 {
                        shifted
                    } else {
                        shifted
                            .iter()
                            .map(|word| {
                                matrix
                                    .iter()
                                    .map(|col| {
                                        let (res, off) =
                                            self.lcon(&mut region, word, col, offset)?;
                                        offset += off;
                                        Ok(res)
                                    })
                                    .collect::<Result<Vec<_>, Error>>()
                            })
                            .collect::<Result<Vec<Vec<_>>, Error>>()?
                    };
                    // println!("After mixed");
                    // mixed
                    //     .iter()
                    //     .for_each(|cell| cell.iter().for_each(|v| println!("  {:?}", v.value())));

                    // AddRoundKey
                    // Assign mixed and key, then take xor
                    Ok(mixed
                        .iter()
                        .enumerate()
                        .map(|(i, word)| {
                            let mut out = vec![];

                            for j in 0..4 {
                                let p = word[j].value().map(|v| *v);
                                let k = round_keys[no_round][i * 4 + j].value_field().evaluate();

                                self.q_xor_bytes.enable(&mut region, offset + j)?;
                                region.assign_advice(
                                    || "Assign plaintext",
                                    self.words_column,
                                    offset + j,
                                    || p,
                                )?;
                                round_keys[no_round][i * 4 + j].copy_advice(
                                    || "Copy round key from scheduled keys",
                                    &mut region,
                                    self.words_column,
                                    offset + 4 + j,
                                )?;
                                let xor = xor_bytes(&p, &k);
                                out.push(region.assign_advice(
                                    || "Assign xor value",
                                    self.words_column,
                                    offset + 8 + j,
                                    || xor,
                                )?);
                            }
                            offset += 12;
                            Ok(out)
                        })
                        .collect::<Result<Vec<Vec<_>>, Error>>()?
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>())
                },
            )?;

            // println!("Round {}", no_round);
            // round_out.iter().for_each(|cell| {
            //     println!(" {:?}", cell.value());
            // });
        }

        Ok(round_out)
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
        region: &mut Region<Fp>,
        word: &Vec<AssignedCell<Fp, Fp>>,
        coeffs: &Vec<u32>,
        offset: usize,
    ) -> Result<(AssignedCell<Fp, Fp>, usize), Error> {
        let mut internal_offset = 0;

        let tmp = word
            .iter()
            .zip(coeffs)
            .map(|(byte, col)| match col {
                1 => {
                    // just copy advice from word
                    let res = byte.copy_advice(
                        || "Copy mul by 1",
                        region,
                        self.words_column,
                        offset + internal_offset,
                    );
                    internal_offset += 1;
                    res
                }
                2 => {
                    // TODO: extract method to map values using table
                    let new_byte = byte.value().map(|v| {
                        Fp::from(MUL_BY_2[*v.to_bytes().first().unwrap() as usize] as u64)
                    });
                    self.q_mul_by_2.enable(region, offset + internal_offset)?;
                    byte.copy_advice(
                        || "Copy prev_byte",
                        region,
                        self.words_column,
                        offset + internal_offset,
                    )?;
                    internal_offset += 1;

                    let res = region.assign_advice(
                        || "Assign mul by 2",
                        self.words_column,
                        offset + internal_offset,
                        || new_byte,
                    );
                    internal_offset += 1;
                    res
                }
                3 => {
                    // TODO: extract method to map values using table

                    let new_byte = byte.value().map(|v| {
                        Fp::from(MUL_BY_3[*v.to_bytes().first().unwrap() as usize] as u64)
                    });
                    self.q_mul_by_3.enable(region, offset + internal_offset)?;
                    byte.copy_advice(
                        || "Copy prev_byte",
                        region,
                        self.words_column,
                        offset + internal_offset,
                    )?;
                    internal_offset += 1;

                    let res = region.assign_advice(
                        || "Assign mul by 3",
                        self.words_column,
                        offset + internal_offset,
                        || new_byte,
                    );
                    internal_offset += 1;
                    res
                }
                _ => panic!("col should be 1, 2, or 3."),
            })
            .collect::<Result<Vec<_>, Error>>()?;

        // we have 4 bytes in tmp now
        // xor first two
        self.q_xor_adj.enable(region, offset + internal_offset)?;
        tmp[0].copy_advice(
            || "Copy mul[0]",
            region,
            self.words_column,
            offset + internal_offset,
        )?;
        internal_offset += 1;
        tmp[1].copy_advice(
            || "Copy mul[1]",
            region,
            self.words_column,
            offset + internal_offset,
        )?;
        internal_offset += 1;

        let intermediate_0 = region.assign_advice(
            || "Assign MixColumns intermediate value",
            self.words_column,
            offset + internal_offset,
            || xor_bytes(&tmp[0].value().map(|v| *v), &tmp[1].value().map(|v| *v)),
        )?;
        internal_offset += 1;

        self.q_xor_adj.enable(region, offset + internal_offset)?;
        tmp[2].copy_advice(
            || "Copy mul[2]",
            region,
            self.words_column,
            offset + internal_offset,
        )?;
        internal_offset += 1;
        tmp[3].copy_advice(
            || "Copy mul[3]",
            region,
            self.words_column,
            offset + internal_offset,
        )?;
        internal_offset += 1;

        // enable xor_adj for the last.
        self.q_xor_adj.enable(region, offset + internal_offset)?;
        let intermediate_1 = region.assign_advice(
            || "Assign MixColumns intermediate value",
            self.words_column,
            offset + internal_offset,
            || xor_bytes(&tmp[2].value().map(|v| *v), &tmp[3].value().map(|v| *v)),
        )?;
        internal_offset += 1;

        intermediate_0.copy_advice(
            || "Copy intermediate_0",
            region,
            self.words_column,
            offset + internal_offset,
        )?;
        internal_offset += 1;

        let res = region.assign_advice(
            || "Assign MixColumns new value",
            self.words_column,
            offset + internal_offset,
            || {
                xor_bytes(
                    &intermediate_0.value().map(|v| *v),
                    &intermediate_1.value().map(|v| *v),
                )
            },
        )?;
        Ok((res, internal_offset + 1))
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
            config.sbox_table_config.load(&mut layouter)?;
            config.key_schedule_config.load(&mut layouter);

            config.mul2_table_config.load(&mut layouter)?;
            config.mul3_table_config.load(&mut layouter)?;

            config.set_key(self.key);

            let val = config.encrypt(layouter, self.plaintext)?;
            // val.iter().for_each(|cell| {
            //     println!(" {:?}", cell.value());
            // });

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

        // Expected ciphertext
        // {
        //     use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
        //     use aes::Aes128;

        //     let key = GenericArray::from([0u8; 16]);
        //     let mut block = GenericArray::from([0u8; 16]);

        //     // Initialize cipher
        //     let cipher = Aes128::new(&key);
        //     cipher.encrypt_block(&mut block);
        //     block.iter().for_each(|v| {
        //         println!("{:02X?}", v);
        //     });
        // }
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
