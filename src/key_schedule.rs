//! Key expansion chip for AES key scheduling
//! NOTE: currently implemented only for 128 bit key.
//!
//! What key expansion does?
//! Take 4 words (=16 bytes) as input and output 44 words.
//! This suffices for the initial AddRoundKey phase and 10 rounds.
//!
//! Key expansion

use crate::{
    chips::{
        sbox_chip::{SboxChip, SboxConfig},
        u8_range_check_chip::{U8RangeCheckChip, U8RangeCheckConfig},
        u8_xor_chip::{U8XorChip, U8XorConfig},
    },
    halo2_proofs::{
        circuit::{AssignedCell, Layouter, Value},
        halo2curves::bn256::Fr as Fp,
        plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector},
        poly::Rotation,
    },
    utils::get_round_constant,
};

#[derive(Clone, Debug)]
pub struct Aes128KeyScheduleConfig {
    words_column: Column<Advice>,
    round_constants: Column<Fixed>,

    q_eq_rcon: Selector,
    _advices: [Column<Advice>; 3],

    u8_range_check_config: U8RangeCheckConfig,
    u8_xor_config: U8XorConfig,
    sbox_config: SboxConfig,
}

impl Aes128KeyScheduleConfig {
    /// Configure key expansion chip
    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        advices: [Column<Advice>; 3],
        u8_xor_config: U8XorConfig,
        sbox_config: SboxConfig,
        u8_range_check_config: U8RangeCheckConfig,
    ) -> Self {
        // constraint the each byte is in the u8 range -> range chip
        let words_column = meta.advice_column();
        let round_constants = meta.fixed_column();
        let q_eq_rcon = meta.selector();

        advices.iter().for_each(|advice| {
            meta.enable_equality(*advice);
        });

        meta.enable_equality(words_column);
        meta.enable_constant(round_constants);

        meta.create_gate("Equality RC", |meta| {
            let q = meta.query_selector(q_eq_rcon);
            let x = meta.query_advice(words_column, Rotation::cur());
            let c = meta.query_fixed(round_constants, Rotation::cur());
            vec![q * (x - c)]
        });

        Self {
            words_column,
            round_constants,

            q_eq_rcon,

            _advices: advices,
            u8_range_check_config,
            u8_xor_config,
            sbox_config,
        }
    }

    /// Expand given 4 words key to 44 words key where each AssignedCell<Fp,Fp> represent a byte.
    pub fn schedule_keys(
        &self,
        layouter: &mut impl Layouter<Fp>,
        key: [u8; 16],
    ) -> Result<Vec<Vec<AssignedCell<Fp, Fp>>>, Error> {
        let mut words = vec![];

        let mut round = self.assign_first_round(layouter, key)?;
        words.push(round.clone());

        for i in 1..=10 {
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

    /// Assign intermediate bytes for each round.
    /// prev_round_bytes has 16 bytes
    fn assign_round(
        &self,
        layouter: &mut impl Layouter<Fp>,
        round: u32,
        prev_round_bytes: Vec<AssignedCell<Fp, Fp>>,
    ) -> Result<Vec<AssignedCell<Fp, Fp>>, Error> {
        let xor_chip = U8XorChip::construct(self.u8_xor_config);
        let sbox_chip = SboxChip::construct(self.sbox_config);
        let range_chip = U8RangeCheckChip::construct(self.u8_range_check_config);

        // resulting words == 44 words = 176 byte
        let mut words: Vec<AssignedCell<Fp, Fp>> = vec![];

        // Derive the first word of the round.
        // copy prev word to words_column. (last 4 bytes of prev_round_bytes)
        // prev_word is rotated one byte left-shifted
        let shifted = layouter.assign_region(
            || "shift previous round",
            |mut region| {
                vec![13usize, 14, 15, 12]
                    .iter()
                    .enumerate()
                    .map(|(i, &v)| {
                        prev_round_bytes[v].copy_advice(
                            || "Copy word from prev_round",
                            &mut region,
                            self.words_column,
                            i,
                        )
                    })
                    .collect::<Result<Vec<_>, Error>>()
            },
        )?;

        let subbed = shifted
            .iter()
            .map(|byte| sbox_chip.substitute(layouter, byte))
            .collect::<Result<Vec<_>, Error>>()?;

        let rc = get_round_constant(round - 1);
        let rc_assigned = layouter.assign_region(
            || "Assign rc",
            |mut region| {
                let mut res = vec![];
                // copy fixed to advice
                // check equality of fixed and advice
                self.q_eq_rcon.enable(&mut region, 0)?;
                region.assign_fixed(|| "Assign round constants", self.round_constants, 0, || rc)?;
                res.push(region.assign_advice(
                    || "Copy fixed value to words_column",
                    self.words_column,
                    0,
                    || rc,
                )?);

                for i in 0..3 {
                    res.push(region.assign_advice(
                        || "Pad 0",
                        self.words_column,
                        i + 1,
                        || Value::known(Fp::from(0)),
                    )?);
                }

                Ok(res)
            },
        )?;

        let rconned = subbed
            .iter()
            .zip(rc_assigned)
            .map(|(s, r)| xor_chip.xor(layouter, &s, &r))
            .collect::<Result<Vec<_>, Error>>()?;

        // xor prev_round_word and rconned_word
        let mut next_word = prev_round_bytes
            .iter()
            .take(4)
            .zip(rconned)
            .map(|(p, r)| xor_chip.xor(layouter, &p, &r))
            .collect::<Result<Vec<_>, Error>>()?;

        words.append(&mut next_word.clone());

        // consecutive 3 words
        for i in 1..4 {
            next_word = prev_round_bytes
                .iter()
                .skip(i * 4)
                .take(4)
                .zip(next_word)
                .map(|(p, n)| xor_chip.xor(layouter, &p, &n))
                .collect::<Result<Vec<_>, Error>>()?;
            words.append(&mut next_word.clone());
        }

        words
            .iter()
            .map(|byte| range_chip.range_check(layouter, &byte))
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(words)
    }
}

#[cfg(test)]
#[cfg(feature = "halo2-pse")]
mod tests {
    use super::*;

    use crate::{
        halo2_proofs::{
            circuit::{Layouter, SimpleFloorPlanner},
            dev::{CellValue, MockProver},
            halo2curves::bn256::Fr as Fp,
            plonk::{Circuit, ConstraintSystem, Error, TableColumn},
        },
        table::load_enc_full_table,
    };

    #[derive(Clone)]
    struct TestCircuit {
        key: [u8; 16],
    }

    impl Circuit<Fp> for TestCircuit {
        type Config = (Aes128KeyScheduleConfig, [TableColumn; 4]);
        type FloorPlanner = SimpleFloorPlanner;

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            // We have table columns in  this config
            let advices = [
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
            ];
            let tables = [
                meta.lookup_table_column(),
                meta.lookup_table_column(),
                meta.lookup_table_column(),
                meta.lookup_table_column(),
            ];

            let q_u8_range_check = meta.complex_selector();
            let q_u8_xor = meta.complex_selector();
            let q_sbox = meta.complex_selector();

            let u8_range_check_config = U8RangeCheckChip::configure(
                meta,
                advices[0],
                q_u8_range_check,
                tables[0],
                tables[1],
            );
            let u8_xor_config = U8XorChip::configure(
                meta, advices[0], advices[1], advices[2], q_u8_xor, tables[0], tables[1],
                tables[2], tables[3],
            );
            let sbox_config = SboxChip::configure(
                meta, advices[0], advices[1], q_sbox, tables[0], tables[1], tables[2],
            );

            (
                Aes128KeyScheduleConfig::configure(
                    meta,
                    advices,
                    u8_xor_config,
                    sbox_config,
                    u8_range_check_config,
                ),
                tables,
            )
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            load_enc_full_table(&mut layouter, config.1)?;
            // let words =
            config
                .0
                .schedule_keys(&mut layouter.namespace(|| "AES128 schedule key"), self.key)?;

            // words.iter().enumerate().for_each(|(i, word)| {
            //     println!("{}-th word", i);
            //     word.iter().for_each(|byte| {
            //         println!("{:?}", byte.value_field().evaluate());
            //     });
            // });

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

    // TODO: ask how to test this kind of unit test
    #[test]
    #[ignore]
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
