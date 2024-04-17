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
};

use crate::utils::{get_round_constant, rotate_word, sub_word, xor_bytes, xor_words};

#[derive(Clone, Debug)]
pub(crate) struct Aes128KeyScheduleConfig {
    // range_config: RangeConfig,
    // sub_bytes_config: SubBytesConfig,
    // u8_xor_config: U8XorConfig,

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
        let q_sub_bytes = meta.selector();
        let q_rot = meta.selector();
        let q_round_first = meta.selector();
        let q_round_mid = meta.selector();

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
        }
    }

    /// Expand given 4 words key to 44 words key where each AssignedCell<Fp,Fp> represent a byte.
    pub(crate) fn schedule_keys(
        &self,
        mut layouter: impl Layouter<Fp>,
        key: [u8; 16],
    ) -> Result<Vec<Vec<AssignedCell<Fp, Fp>>>, Error> {
        layouter.assign_region(
            || "Assign first four words",
            |mut region| {
                // resulting words == 44 words = 176 byte
                let mut words: Vec<Vec<AssignedCell<Fp, Fp>>> = vec![];

                // Copy key into first 4 words
                for i in 0..4 {
                    let mut inner = vec![];
                    for j in 0..4 {
                        inner.push(region.assign_advice(
                            || format!("Assign word{}_{}", i, j),
                            self.words_column,
                            i * 4 + j,
                            || Value::known(Fp::from(key[i * 4 + 1] as u64)),
                        )?);
                    }
                    words.push(inner);
                }

                // println!("Words: {:?}", words);

                let mut pos = 16;

                // iterate over 4 to 44 words
                for i in 4..44 {
                    // get cells at position (i - 4) * 4 +(0..4) -> (i-4)-th word
                    let word_prev_round = words.get(i - 4).expect("Word should be set");
                    let word_prev = words.get(i - 1).expect("Word should be set");

                    if i % 4 == 0 {
                        // turn on selector
                        self.q_round_first.enable(&mut region, i * 4)?;

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

                        let rc = get_round_constant(i as u32 / 4 - 1);
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
                    pos += 4;
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
            layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            config.schedule_keys(layouter, self.key)?;
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
        let k = 10;
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
}
