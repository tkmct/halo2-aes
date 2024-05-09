//! Key expansion chip for AES key scheduling
//! NOTE: currently implemented only for 128 bit key.
//!
//! What key expansion does?
//! Take 4 words (=16 bytes) as input and output 44 words.
//! This suffices for the initial AddRoundKey phase and 10 rounds.
//!
//! Key expansion

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    halo2curves::bn256::Fr as Fp,
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector},
    poly::Rotation,
};

use crate::{
    s_box_table::SboxTableConfig,
    u8_range_check::U8RangeCheckConfig,
    u8_xor_table::U8XorTableConfig,
    utils::{get_round_constant, rotate_word, sub_word, xor_bytes, xor_words},
};

#[derive(Clone, Debug)]
pub(crate) struct Aes128KeyScheduleConfig {
    // range_config: RangeConfig,
    sbox_table_config: SboxTableConfig,
    u8_xor_table_config: U8XorTableConfig,
    range_config: U8RangeCheckConfig,

    // Store words as u8 value
    words_column: Column<Advice>,
    // Column to store words substituted with s-box
    sub_bytes_column: Column<Advice>,
    // Column to store words rotated
    rot_column: Column<Advice>,
    // Column to store words after xor with round constant
    rcon_column: Column<Advice>,

    // Round constant to XOR for the
    round_constants: Column<Fixed>,

    q_range_u8: Selector,
    q_sub_bytes: Selector,
    q_rot: Selector,
    q_round_first: Selector,
    q_round_mid: Selector,
}

impl Aes128KeyScheduleConfig {
    /// Configure key expansion chip
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        // constraint the each byte is in the u8 range -> range chip
        let words_column = meta.advice_column();
        let sub_bytes_column = meta.advice_column();
        let rot_column = meta.advice_column();
        let rcon_column = meta.advice_column();

        let round_constants = meta.fixed_column();

        let q_range_u8 = meta.complex_selector();
        let q_sub_bytes = meta.complex_selector();
        let q_rot = meta.selector();
        let q_round_first = meta.complex_selector();
        let q_round_mid = meta.complex_selector();

        let u8_xor_table_config = U8XorTableConfig::configure(meta);
        let sbox_table_config = SboxTableConfig::configure(meta);
        let range_config = U8RangeCheckConfig::configure(meta, words_column);

        meta.enable_equality(words_column);
        meta.enable_constant(round_constants);

        for i in 0..4 {
            meta.lookup("Lookup first words of each round", |meta| {
                // Check XOR of Rconned word and prev_round
                let q = meta.query_selector(q_round_first);
                let new_word = meta.query_advice(words_column, Rotation(i));
                let rconned = meta.query_advice(rcon_column, Rotation(i));
                let prev_round = meta.query_advice(words_column, Rotation(i - 16));

                vec![
                    (q.clone() * prev_round, u8_xor_table_config.x),
                    (q.clone() * rconned, u8_xor_table_config.y),
                    (q * new_word, u8_xor_table_config.z),
                ]
            });

            meta.lookup("Mid words of each round", |meta| {
                let q = meta.query_selector(q_round_mid);
                let new_word = meta.query_advice(words_column, Rotation(i));
                let prev_word = meta.query_advice(words_column, Rotation(i - 4));
                let prev_round_word = meta.query_advice(words_column, Rotation(i - 16));

                vec![
                    (q.clone() * prev_word, u8_xor_table_config.x),
                    (q.clone() * prev_round_word, u8_xor_table_config.y),
                    (q * new_word, u8_xor_table_config.z),
                ]
            });
        }

        // FIXME: we can constraints this by copy constraints
        // Which is faster?
        meta.create_gate("Rotate word", |meta| {
            // do something
            let q = meta.query_selector(q_rot);
            // circuilar left shift by one byte
            let first_byte = meta.query_advice(words_column, Rotation::cur());
            let second_byte = meta.query_advice(words_column, Rotation(1));
            let third_byte = meta.query_advice(words_column, Rotation(2));
            let fourth_byte = meta.query_advice(words_column, Rotation(3));

            let first_rot_byte = meta.query_advice(rot_column, Rotation::cur());
            let second_rot_byte = meta.query_advice(rot_column, Rotation(1));
            let third_rot_byte = meta.query_advice(rot_column, Rotation(2));
            let fourth_rot_byte = meta.query_advice(rot_column, Rotation(3));

            // Check if first_byte == fourt_rot_byte
            //          second_byte == first_rot_byte
            //          third_byte == second_rot_byte
            //          fourth_byte == third_rot_byte
            vec![
                q.clone() * (first_byte - fourth_rot_byte),
                q.clone() * (second_byte - first_rot_byte),
                q.clone() * (third_byte - second_rot_byte),
                q.clone() * (fourth_byte - third_rot_byte),
            ]
        });

        // Constraints sub bytes
        meta.lookup("Sub word", |meta| {
            let q = meta.query_selector(q_sub_bytes);
            let rot_byte = meta.query_advice(rot_column, Rotation::cur());
            let subbed_byte = meta.query_advice(sub_bytes_column, Rotation::cur());

            vec![
                (q.clone() * rot_byte, sbox_table_config.x),
                (q.clone() * subbed_byte, sbox_table_config.y),
            ]
        });

        // TODO: Constraints Rcon
        // define Rcon as fixed cell
        // use the fixed cell and constraints xor lookup with them.
        meta.lookup("Rcon word", |meta| {
            let q = meta.query_selector(q_round_first);
            let r_const = meta.query_fixed(round_constants, Rotation::cur());
            let subbed = meta.query_advice(sub_bytes_column, Rotation::cur());
            let rcon = meta.query_advice(rcon_column, Rotation::cur());

            vec![
                (q.clone() * r_const, u8_xor_table_config.x),
                (q.clone() * subbed, u8_xor_table_config.y),
                (q.clone() * rcon, u8_xor_table_config.z),
            ]
        });

        Self {
            words_column,
            sub_bytes_column,
            rot_column,
            rcon_column,
            round_constants,
            q_range_u8,
            q_sub_bytes,
            q_rot,
            q_round_first,
            q_round_mid,
            u8_xor_table_config,
            sbox_table_config,
            range_config,
        }
    }

    /// Expand given 4 words key to 44 words key where each AssignedCell<Fp,Fp> represent a byte.
    pub(crate) fn schedule_keys(
        &self,
        mut layouter: impl Layouter<Fp>,
        key: [u8; 16],
    ) -> Result<Vec<Vec<AssignedCell<Fp, Fp>>>, Error> {
        layouter.assign_region(
            || "Assign words",
            |mut region| {
                // resulting words == 44 words = 176 byte
                let mut words: Vec<Vec<AssignedCell<Fp, Fp>>> = vec![];

                // Copy key into first 4 words
                for i in 0..4 {
                    let mut word = vec![];
                    for j in 0..4 {
                        let v = region.assign_advice(
                            || format!("Assign word{}_{}", i, j),
                            self.words_column,
                            i * 4 + j,
                            || Value::known(Fp::from(key[i * 4 + 1] as u64)),
                        )?;
                        word.push(v);
                    }
                    words.push(word);
                }

                // iterate over 4 to 44 words
                // TODO: for each index i, should define as single region?
                for i in 4..44 {
                    let pos = i * 4;
                    // get cells at position (i - 4) * 4 +(0..4) -> (i-4)-th word
                    let word_prev_round = words.get(i - 4).expect("Word should be set");
                    let word_prev = words.get(i - 1).expect("Word should be set");

                    if i % 4 == 0 {
                        // turn on selector
                        self.q_round_first.enable(&mut region, i * 4)?;

                        // Enable sub bytes selector for each byte in word
                        for l in 0..4 {
                            self.q_sub_bytes.enable(&mut region, i * 4 + l)?;
                        }

                        // get rotated bytes and assign to rot_column
                        let rotated = rotate_word(
                            &word_prev
                                .iter()
                                .map(|v| v.value().map(|&v| v))
                                .collect::<Vec<_>>(),
                        )
                        .iter()
                        .enumerate()
                        .map(|(j, v)| {
                            region.assign_advice(
                                || "Assign rotated word",
                                self.rot_column,
                                pos + j,
                                || *v,
                            )
                        })
                        .collect::<Result<Vec<_>, Error>>()?;

                        // sub_bytes each byte and assign to sub_bytes_column
                        let subbed = sub_word(
                            &rotated
                                .iter()
                                .map(|v| v.value().map(|&v| v))
                                .collect::<Vec<_>>(),
                        )
                        .iter()
                        .enumerate()
                        .map(|(j, v)| {
                            region.assign_advice(
                                || "Assign sub_bytes word",
                                self.sub_bytes_column,
                                pos + j,
                                || *v,
                            )
                        })
                        .collect::<Result<Vec<_>, Error>>()?;

                        // Assign round constant column for first byte of the word
                        let rc = get_round_constant(i as u32 / 4 - 1);
                        region.assign_fixed(
                            || "Assign round constants",
                            self.round_constants,
                            pos,
                            || rc,
                        )?;

                        let rc_byte = xor_bytes(
                            &rc,
                            &subbed
                                .get(0)
                                .expect("First value should not be empty")
                                .value()
                                .map(|v| *v),
                        )?;

                        // copy rconned
                        let rconned = vec![rc_byte]
                            .iter()
                            .chain(
                                &subbed
                                    .iter()
                                    .skip(1)
                                    .map(|assigned| assigned.value().map(|v| *v))
                                    .collect::<Vec<_>>(),
                            )
                            .enumerate()
                            .map(|(j, v)| {
                                region.assign_advice(
                                    || "Assign word after rcon",
                                    self.rcon_column,
                                    pos + j,
                                    || *v,
                                )
                            })
                            .collect::<Result<Vec<_>, Error>>()?;

                        let word = xor_words(
                            &rconned
                                .iter()
                                .map(|v| v.value().map(|&v| v))
                                .collect::<Vec<_>>(),
                            &word_prev_round
                                .iter()
                                .map(|v| v.value().map(|&v| v))
                                .collect::<Vec<_>>(),
                        )?
                        .iter()
                        .enumerate()
                        .map(|(j, v)| {
                            region.assign_advice(
                                || "Assign new word",
                                self.words_column,
                                pos + j,
                                || *v,
                            )
                        })
                        .collect::<Result<Vec<_>, Error>>()?;
                        words.push(word);
                    } else {
                        // turn on selector for taking xor of word_pre and word right before current one
                        self.q_round_mid.enable(&mut region, i * 4)?;
                        let word = xor_words(
                            &word_prev
                                .iter()
                                .map(|v| v.value().map(|&v| v))
                                .collect::<Vec<_>>(),
                            &word_prev_round
                                .iter()
                                .map(|v| v.value().map(|&v| v))
                                .collect::<Vec<_>>(),
                        )?
                        .iter()
                        .enumerate()
                        .map(|(j, v)| {
                            println!("Assign word, {i} {j} at pos {} = {:?}", pos + j, v);
                            region.assign_advice(
                                || "Assign new word",
                                self.words_column,
                                pos + j,
                                || *v,
                            )
                        })
                        .collect::<Result<Vec<_>, Error>>()?;
                        words.push(word);
                    }
                }

                Ok(words)
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::{CellValue, MockProver},
        halo2curves::bn256::Fr as Fp,
        plonk::{Circuit, ConstraintSystem, Error},
    };

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
            config.u8_xor_table_config.load(&mut layouter)?;
            config.sbox_table_config.load(&mut layouter)?;
            config.range_config.table.load(&mut layouter)?;

            let words =
                config.schedule_keys(layouter.namespace(|| "AES128 schedule key"), self.key)?;
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

        assert!(
            word_cells
                .iter()
                .take(176)
                .all(|cell| matches!(cell, CellValue::Assigned(_))),
            "Assert 44 words=176 bytes are filled."
        );
        let cells = word_cells
            .iter()
            .take(176)
            .map(|cell| match cell {
                CellValue::Assigned(v) => v,
                _ => panic!("never happens"),
            })
            .collect::<Vec<_>>();
        // check if each chunk are the correct key expansion of 0x00000000000000000000000000000000
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
        let k = 18;
        let circuit = TestCircuit { key: [0u8; 16] };

        let mock = MockProver::run(k, &circuit, vec![]).unwrap();
        mock.assert_satisfied();
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_key_schedule() {
        use plotters::prelude::*;

        let k = 18;
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
}
