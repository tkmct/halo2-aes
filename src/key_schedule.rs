//! Key expansion chip for AES key scheduling
//! NOTE: currently implemented only for 128 bit key.
//!
//! What key expansion does?
//! Take 4 words (=16 bytes) as input and output 44 words.
//! This suffices for the initial AddRoundKey phase and 10 rounds.
//!
//! Key expansion

use crate::{
    halo2_proofs::{
        circuit::{AssignedCell, Layouter, Value},
        halo2curves::bn256::Fr as Fp,
        plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector},
        poly::Rotation,
    },
    table::{s_box::SboxTableConfig, u8_range_check::U8RangeCheckConfig, u8_xor::U8XorTableConfig},
    utils::{get_round_constant, sub_word, xor_bytes, xor_words},
};

#[derive(Clone, Debug)]
pub struct Aes128KeyScheduleConfig {
    pub sbox_table_config: SboxTableConfig,
    pub u8_xor_table_config: U8XorTableConfig,
    pub range_config: U8RangeCheckConfig,

    // Store words as u8 value
    words_column: Column<Advice>,
    // Round constant to XOR for the
    round_constants: Column<Fixed>,

    q_sub_bytes: Selector,
    q_xor_bytes: Selector,
    q_eq_rcon: Selector,
}

impl Aes128KeyScheduleConfig {
    /// Configure key expansion chip
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        // constraint the each byte is in the u8 range -> range chip
        let words_column = meta.advice_column();

        let round_constants = meta.fixed_column();

        let q_xor_bytes = meta.complex_selector();
        let q_sub_bytes = meta.complex_selector();
        let q_eq_rcon = meta.selector();

        let u8_xor_table_config = U8XorTableConfig::configure(meta);
        let sbox_table_config = SboxTableConfig::configure(meta);
        let range_config = U8RangeCheckConfig::configure(meta, words_column);

        meta.enable_equality(words_column);
        meta.enable_constant(round_constants);

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

        meta.create_gate("Equality RC", |meta| {
            let q = meta.query_selector(q_eq_rcon);
            let x = meta.query_advice(words_column, Rotation::cur());
            let c = meta.query_fixed(round_constants, Rotation::cur());
            vec![q * (x - c)]
        });

        Self {
            words_column,
            round_constants,
            q_sub_bytes,
            q_xor_bytes,
            q_eq_rcon,
            u8_xor_table_config,
            sbox_table_config,
            range_config,
        }
    }

    pub fn load(&self, layouter: &mut impl Layouter<Fp>) {
        self.u8_xor_table_config
            .load(layouter)
            .expect("Load table should not fail");
        self.sbox_table_config
            .load(layouter)
            .expect("Load table should not fail");
        self.range_config
            .table
            .load(layouter)
            .expect("Load table should not fail");
    }

    /// Expand given 4 words key to 44 words key where each AssignedCell<Fp,Fp> represent a byte.
    pub fn schedule_keys(
        &self,
        layouter: &mut impl Layouter<Fp>,
        key: [u8; 16],
    ) -> Result<Vec<Vec<AssignedCell<Fp, Fp>>>, Error> {
        let mut words = vec![];

        // each round contain 16 byte = 4 words.
        let mut round = self.assign_first_round(layouter, key)?;
        words.push(round.clone());

        for i in 1..=10 {
            // assign each round
            round = self.assign_round(layouter, i, round)?;
            words.push(round.clone())
        }

        Ok(words)
    }

    fn assign_first_round(
        &self,
        layouter: &mut impl Layouter<Fp>,
        key: [u8; 16],
    ) -> Result<Vec<AssignedCell<Fp, Fp>>, Error> {
        layouter.assign_region(
            || "Assign first four words",
            |mut region| {
                let mut words: Vec<AssignedCell<Fp, Fp>> = vec![];
                for (i, &byte) in key.iter().enumerate() {
                    words.push(region.assign_advice(
                        || format!("Assign {}-th word, {}-th byte", i / 4, i % 4),
                        self.words_column,
                        i,
                        || Value::known(Fp::from(byte as u64)),
                    )?);
                }
                Ok(words)
            },
        )
    }

    fn assign_round(
        &self,
        layouter: &mut impl Layouter<Fp>,
        round: u32,
        prev_round_bytes: Vec<AssignedCell<Fp, Fp>>,
    ) -> Result<Vec<AssignedCell<Fp, Fp>>, Error> {
        layouter.assign_region(
            || "Assign words",
            |mut region| {
                // current position in the words_column
                let mut pos = 0;

                // resulting words == 44 words = 176 byte
                let mut words: Vec<AssignedCell<Fp, Fp>> = vec![];

                // copy prev word = last 4 byte of prev_round
                // prev_word is rotated one byte left-shift
                let prev_word = vec![13usize, 14, 15, 12]
                    .iter()
                    .map(|&i| {
                        // enable sub bytes selector
                        self.q_sub_bytes.enable(&mut region, pos)?;
                        let byte = prev_round_bytes[i].copy_advice(
                            || "Copy word from prev_round",
                            &mut region,
                            self.words_column,
                            pos,
                        );
                        pos += 1;
                        byte
                    })
                    .collect::<Result<Vec<_>, Error>>()?;

                // sub each byte of rotated word
                // enable xor_bytes flag for the first byte
                self.q_xor_bytes.enable(&mut region, pos)?;
                let subbed = sub_word(
                    &prev_word
                        .iter()
                        .map(|a| a.value().map(|&v| v))
                        .collect::<Vec<_>>(),
                )
                .iter()
                .map(|v| {
                    let byte = region.assign_advice(
                        || "Assign sub_bytes word",
                        self.words_column,
                        pos,
                        || *v,
                    );
                    pos += 1;
                    byte
                })
                .collect::<Result<Vec<_>, Error>>()?;

                // Assign round constant column for first byte of the word
                // and copy to the advice cell for constraints
                self.q_eq_rcon.enable(&mut region, pos)?;
                let rc = get_round_constant(round - 1);
                region.assign_fixed(
                    || "Assign round constants",
                    self.round_constants,
                    pos,
                    || rc,
                )?;

                region.assign_advice(
                    || "Copy fixed value to words_column",
                    self.words_column,
                    pos,
                    || rc,
                )?;
                // Enable xor for first byte of the Rconed sub ^ Rc
                pos += 1;

                // pad 0 for three byte
                for _ in 0..3 {
                    region.assign_advice(
                        || "Pad 0",
                        self.words_column,
                        pos,
                        || Value::known(Fp::from(0)),
                    )?;
                    pos += 1;
                }

                // xor round-constants with subbed word
                // enable xor flag
                let mut rconned = vec![];
                let rc_byte = xor_bytes(
                    &rc,
                    &subbed
                        .get(0)
                        .expect("First value should not be empty")
                        .value()
                        .map(|v| *v),
                );
                region.assign_advice(
                    || "Assign xor Rc and Sub",
                    self.words_column,
                    pos,
                    || rc_byte,
                )?;
                self.q_xor_bytes.enable(&mut region, pos)?;
                rconned.push(rc_byte);
                pos += 1;

                // copy other 3 bytes and enable xor flag
                for i in 1..4 {
                    let byte = subbed[i].copy_advice(
                        || "Copy word from subbed",
                        &mut region,
                        self.words_column,
                        pos,
                    )?;
                    self.q_xor_bytes.enable(&mut region, pos)?;
                    rconned.push(byte.value().map(|v| *v));
                    pos += 1;
                }

                // copy word from previous round first 4 bytes of prev_round.
                let word_prev_round = (0..4)
                    .map(|i| {
                        prev_round_bytes[i].copy_advice(
                            || "Copy word at prev_round",
                            &mut region,
                            self.words_column,
                            pos + i,
                        )
                    })
                    .collect::<Result<Vec<_>, Error>>()?;

                // added 4 bytes to words_column
                pos += 4;

                // xor prev_round and rconned word
                let mut word = xor_words(
                    &rconned,
                    &word_prev_round
                        .iter()
                        .map(|v| v.value().map(|&v| v))
                        .collect::<Vec<_>>(),
                )
                .iter()
                .map(|v| {
                    let cell =
                        region.assign_advice(|| "Assign new word", self.words_column, pos, || *v);
                    self.q_xor_bytes.enable(&mut region, pos)?;
                    pos += 1;
                    cell
                })
                .collect::<Result<Vec<_>, Error>>()?;

                words.append(&mut word.clone());

                // ====
                // consecutive 3 words
                for i in 1..4 {
                    let word_prev_round = vec![i * 4, i * 4 + 1, i * 4 + 2, i * 4 + 3]
                        .iter()
                        .map(|&j| {
                            let byte = prev_round_bytes[j].copy_advice(
                                || "Copy word from prev_round",
                                &mut region,
                                self.words_column,
                                pos,
                            );
                            pos += 1;
                            byte
                        })
                        .collect::<Result<Vec<_>, Error>>()?;

                    word = xor_words(
                        &word
                            .iter()
                            .map(|v| v.value().map(|&v| v))
                            .collect::<Vec<_>>(),
                        &word_prev_round
                            .iter()
                            .map(|v| v.value().map(|&v| v))
                            .collect::<Vec<_>>(),
                    )
                    .iter()
                    .map(|v| {
                        // Enable xor bytes except for the last word
                        if i != 3 {
                            self.q_xor_bytes.enable(&mut region, pos)?;
                        }
                        let cell = region.assign_advice(
                            || "Assign new word",
                            self.words_column,
                            pos,
                            || *v,
                        );
                        pos += 1;
                        cell
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                    words.append(&mut word.clone());
                }

                Ok(words)
            },
        )
    }
}

#[cfg(test)]
#[cfg(feature = "halo2-pse")]
mod tests {
    use super::*;

    use crate::halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::{CellValue, MockProver},
        halo2curves::bn256::Fr as Fp,
        plonk::{Circuit, ConstraintSystem, Error},
    };

    #[derive(Clone)]
    struct TestCircuit {
        key: [u8; 16],
    }

    impl Circuit<Fp> for TestCircuit {
        type Config = Aes128KeyScheduleConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            Aes128KeyScheduleConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            config.load(&mut layouter);

            let words = config
                .schedule_keys(&mut layouter.namespace(|| "AES128 schedule key"), self.key)?;
            // constraint range_check for every byte in the words
            let mut i = 0;
            for word in words {
                for byte in word {
                    // range chip
                    config.range_config.assign(
                        layouter.namespace(|| format!("range_check for word {}", i)),
                        &byte,
                    )?;

                    i += 1;
                }
            }

            Ok(())
        }

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }
    }

    fn get_key_positions() -> Vec<usize> {
        let mut indicies = (0..16).collect::<Vec<_>>();
        let offset = 16;
        let interval = 48;
        let word_starts = [20, 28, 36, 44];

        for i in 0..10 {
            for start in word_starts {
                (0..4).for_each(|j| indicies.push(offset + i * interval + start + j));
            }
        }

        indicies
    }

    const EXPANDED: [&str; 44] = [
        "00000000", "00000000", "00000000", "00000000", "62636363", "62636363", "62636363",
        "62636363", "9b9898c9", "f9fbfbaa", "9b9898c9", "f9fbfbaa", "90973450", "696ccffa",
        "f2f45733", "0b0fac99", "ee06da7b", "876a1581", "759e42b2", "7e91ee2b", "7f2e2b88",
        "f8443e09", "8dda7cbb", "f34b9290", "ec614b85", "1425758c", "99ff0937", "6ab49ba7",
        "21751787", "3550620b", "acaf6b3c", "c61bf09b", "0ef90333", "3ba96138", "97060a04",
        "511dfa9f", "b1d4d8e2", "8a7db9da", "1d7bb3de", "4c664941", "b4ef5bcb", "3e92e211",
        "23e951cf", "6f8f188e",
    ];

    #[test]
    fn test_correct_key_scheduling() {
        let k = 17;
        let circuit = TestCircuit { key: [0u8; 16] };

        let mock = MockProver::run(k, &circuit, vec![]).unwrap();

        // Check if the cells in the first column(words column) are properly set after the synthesize
        let word_cells = mock.advice().get(0).unwrap();
        let indicies = get_key_positions();

        let cells = indicies
            .iter()
            .map(|&i| {
                if let CellValue::Assigned(v) = word_cells[i] {
                    return v;
                } else {
                    panic!("never happens")
                }
            })
            .collect::<Vec<_>>();

        cells
            .chunks(4)
            .zip(EXPANDED)
            .for_each(|(actual, expected)| {
                // check if the assigned values are correct
                let hex = actual
                    .iter()
                    .map(|&c| format!("{:02x?}", c.to_bytes()[0]))
                    .collect::<Vec<_>>()
                    .join("");
                assert_eq!(hex, expected);
            });
    }

    #[test]
    fn test_constraints() {
        let k = 17;
        let circuit = TestCircuit { key: [0u8; 16] };

        let mock = MockProver::run(k, &circuit, vec![]).unwrap();
        mock.assert_satisfied();
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_key_schedule() {
        use plotters::prelude::*;

        let k = 17;
        let circuit = TestCircuit { key: [0u8; 16] };

        let root =
            BitMapBackend::new("prints/key-schedule-layout.png", (2048, 32768)).into_drawing_area();
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
    fn cost_estimate_key_schedule() {
        use halo2_proofs::dev::cost_model::{from_circuit_to_model_circuit, CommitmentScheme};

        let k = 17;
        let circuit = TestCircuit { key: [0u8; 16] };

        let model = from_circuit_to_model_circuit::<_, _, 56, 56>(
            k,
            &circuit,
            vec![],
            CommitmentScheme::KZGGWC,
        );
        println!(
            "Cost of AES128 key schedule: \n{}",
            serde_json::to_string_pretty(&model).unwrap()
        );
    }
}
