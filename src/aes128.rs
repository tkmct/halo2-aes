use crate::{
    chips::{
        gf_mul_chip::{MulBy2Chip, MulBy2Config, MulBy3Chip, MulBy3Config},
        sbox_chip::{SboxChip, SboxConfig},
        u8_range_check_chip::{U8RangeCheckChip, U8RangeCheckConfig},
        u8_xor_chip::{U8XorChip, U8XorConfig},
    },
    constant::{AES_ROWS, KEY_SCHEDULE_ROWS},
    halo2_proofs::{
        circuit::{AssignedCell, Layouter, Value},
        halo2curves::bn256::Fr as Fp,
        plonk::{Advice, Column, ConstraintSystem, Error, TableColumn},
    },
    key_schedule::Aes128KeyScheduleConfig,
};

#[derive(Clone, Debug)]
struct Configs(
    Vec<U8RangeCheckConfig>,
    Vec<U8XorConfig>,
    Vec<SboxConfig>,
    Vec<MulBy2Config>,
    Vec<MulBy3Config>,
);

#[derive(Clone, Debug)]
pub struct FixedAes128Config<const K: u32, const N: usize> {
    keys: Option<Vec<Vec<AssignedCell<Fp, Fp>>>>,

    pub key_schedule_config: Aes128KeyScheduleConfig,

    configs: Configs,
    pub advices: [[Column<Advice>; 3]; N],
    pub tables: [TableColumn; 4],

    // Indicate which columns are currently used.
    // increment this by one once the available cells of advices[i][0]
    // is less than 1360
    current: usize,

    // Count number of AES calls
    count: u64,
}

impl<const K: u32, const N: usize> FixedAes128Config<K, N> {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        // First table_column is used as a tag column
        let tables = [
            meta.lookup_table_column(),
            meta.lookup_table_column(),
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        ];
        let advices = std::array::from_fn(|_| {
            [
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
            ]
        });
        let mut configs = Configs(vec![], vec![], vec![], vec![], vec![]);

        for i in 0..N {
            let q_u8_range_check = meta.complex_selector();
            let q_u8_xor = meta.complex_selector();
            let q_sbox = meta.complex_selector();
            let q_mul_by_2 = meta.complex_selector();
            let q_mul_by_3 = meta.complex_selector();

            configs.0.push(U8RangeCheckChip::configure(
                meta,
                advices[i][0],
                q_u8_range_check,
                tables[0],
                tables[1],
            ));
            configs.1.push(U8XorChip::configure(
                meta,
                advices[i][0],
                advices[i][1],
                advices[i][2],
                q_u8_xor,
                tables[0],
                tables[1],
                tables[2],
                tables[3],
            ));
            configs.2.push(SboxChip::configure(
                meta,
                advices[i][0],
                advices[i][1],
                q_sbox,
                tables[0],
                tables[1],
                tables[2],
            ));
            configs.3.push(MulBy2Chip::configure(
                meta,
                advices[i][0],
                advices[i][1],
                q_mul_by_2,
                tables[0],
                tables[1],
                tables[2],
            ));
            configs.4.push(MulBy3Chip::configure(
                meta,
                advices[i][0],
                advices[i][1],
                q_mul_by_3,
                tables[0],
                tables[1],
                tables[2],
            ));
        }

        // Setup key scheduling config with initial configs
        let key_schedule_config = Aes128KeyScheduleConfig::configure(
            meta,
            advices[0],
            configs.1[0],
            configs.2[0],
            configs.0[0],
        );

        advices.iter().for_each(|v| {
            v.iter().for_each(|v| {
                meta.enable_equality(*v);
            })
        });

        Self {
            keys: None,
            key_schedule_config,
            advices,
            tables,
            configs,
            current: 0,
            count: 0,
        }
    }

    pub fn schedule_key(
        &mut self,
        layouter: &mut impl Layouter<Fp>,
        key: [u8; 16],
    ) -> Result<(), Error> {
        let round_keys = self.key_schedule_config.schedule_keys(layouter, key)?;
        self.keys = Some(round_keys);

        Ok(())
    }

    pub fn encrypt(
        &mut self,
        layouter: &mut impl Layouter<Fp>,
        plaintext: [u8; 16],
    ) -> Result<Vec<AssignedCell<Fp, Fp>>, Error> {
        // Check if available rows of advice[0] is more than 1360
        if !self.aes_callable() {
            panic!("AES calls too many. doesn't fit in the rows")
        }
        self.count += 1;

        // Prepare chips
        let xor_chip = U8XorChip::construct(self.xor_config());
        let sbox_chip = SboxChip::construct(self.sbox_config());
        let _range_chip = U8RangeCheckChip::construct(self.range_config());

        let round_keys = self.keys.clone().expect("Keys should be scheduled");

        let advices = self.get_advices();

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
                            advices[0],
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
            .map(|(p, k)| xor_chip.xor(layouter, p, &k))
            .collect::<Result<Vec<_>, Error>>()?;

        // we have 4 words in round_out vec.
        for no_round in 1..11 {
            // Sub round_out
            let subbed = prev_round
                .iter()
                .map(|byte| sbox_chip.substitute(layouter, byte))
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
                            .map(|col| self.lcon(layouter, word, col))
                            .collect::<Result<Vec<_>, Error>>()
                    })
                    .collect::<Result<Vec<Vec<_>>, Error>>()?
            };

            prev_round = mixed
                .iter()
                .enumerate()
                .map(|(i, word)| {
                    (0..4)
                        .map(|j| xor_chip.xor(layouter, &word[j], &round_keys[no_round][i * 4 + j]))
                        .collect::<Result<Vec<_>, Error>>()
                })
                .collect::<Result<Vec<Vec<_>>, Error>>()?
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
        }

        Ok(prev_round)
    }

    // Compute linear combination of word and given coefficients
    fn lcon(
        &mut self,
        layouter: &mut impl Layouter<Fp>,
        word: &Vec<AssignedCell<Fp, Fp>>,
        coeffs: &Vec<u32>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let xor_chip = U8XorChip::construct(self.xor_config());
        let mul2_chip = MulBy2Chip::construct(self.mul2_config());
        let mul3_chip = MulBy3Chip::construct(self.mul3_config());
        let advices = self.get_advices();

        let tmp = word
            .iter()
            .zip(coeffs)
            .map(|(byte, col)| match col {
                1 => {
                    layouter.assign_region(
                        || "",
                        |mut region| {
                            // just copy advice from word
                            byte.copy_advice(|| "Copy mul by 1", &mut region, advices[0], 0)
                        },
                    )
                }
                2 => mul2_chip.mul(layouter, byte),
                3 => mul3_chip.mul(layouter, byte),
                _ => panic!("col should be 1, 2, or 3."),
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let inter_1 = xor_chip.xor(layouter, &tmp[0], &tmp[1])?;
        let inter_2 = xor_chip.xor(layouter, &tmp[2], &tmp[3])?;
        xor_chip.xor(layouter, &inter_1, &inter_2)
    }

    fn aes_callable(&mut self) -> bool {
        let mut max_row = u64::pow(2, K);
        if self.current == 0 {
            // Subtract key scheduling
            max_row -= KEY_SCHEDULE_ROWS;
        }
        // println!(
        //     "Call: {}, Max_row: {}, self.count*AES_ROWS: {}",
        //     self.count,
        //     max_row,
        //     self.count * AES_ROWS
        // );

        if max_row >= self.count * AES_ROWS + AES_ROWS {
            return true;
        } else if self.current < N - 1 {
            self.current += 1;
            self.count = 0;
            return true;
        } else {
            return false;
        }
    }

    // Config getters
    fn range_config(&self) -> U8RangeCheckConfig {
        assert!(self.current < N);
        self.configs.0[self.current]
    }

    fn xor_config(&self) -> U8XorConfig {
        assert!(self.current < N);
        self.configs.1[self.current]
    }

    fn sbox_config(&self) -> SboxConfig {
        assert!(self.current < N);
        self.configs.2[self.current]
    }

    fn mul2_config(&self) -> MulBy2Config {
        assert!(self.current < N);
        self.configs.3[self.current]
    }

    fn mul3_config(&self) -> MulBy3Config {
        assert!(self.current < N);
        self.configs.4[self.current]
    }

    fn get_advices(&self) -> &[Column<Advice>] {
        assert!(self.current < N);
        &self.advices[self.current]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        halo2_proofs::{
            circuit::{Layouter, SimpleFloorPlanner},
            dev::MockProver,
            halo2curves::bn256::Fr as Fp,
            plonk::{Circuit, ConstraintSystem, Error},
        },
        table::load_enc_full_table,
    };

    const K: u32 = 20;

    #[derive(Clone)]
    struct TestAesCircuit {
        key: [u8; 16],
        plaintext: [u8; 16],
    }

    impl Circuit<Fp> for TestAesCircuit {
        type Config = FixedAes128Config<K, 3>;
        type FloorPlanner = SimpleFloorPlanner;

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            FixedAes128Config::configure(meta)
        }

        fn synthesize(
            &self,
            mut config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            load_enc_full_table(&mut layouter, config.tables)?;
            config.schedule_key(&mut layouter, self.key)?;

            for _ in 0..1000 {
                config.encrypt(&mut layouter, self.plaintext)?;
            }

            Ok(())
        }

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }
    }

    #[test]
    #[cfg(feature = "halo2-pse")]
    fn test_correct_encryption() {
        let circuit = TestAesCircuit {
            key: [0u8; 16],
            plaintext: [0u8; 16],
        };

        let mock = MockProver::run(K, &circuit, vec![]).unwrap();
        mock.assert_satisfied();

        // Print expected ciphertext
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
            .render(K, &circuit, &root)
            .unwrap();
    }

    #[cfg(feature = "cost-estimator")]
    #[test]
    fn cost_estimate_aes_encrypt() {
        use halo2_proofs::dev::cost_model::{from_circuit_to_model_circuit, CommitmentScheme};
        let circuit = TestAesCircuit {
            key: [0u8; 16],
            plaintext: [0u8; 16],
        };

        let model = from_circuit_to_model_circuit::<_, _, 56, 56>(
            K,
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
