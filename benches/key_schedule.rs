use criterion::{criterion_group, criterion_main, Criterion};

use ark_std::{end_timer, start_timer};
use halo2_aes::{
    chips::{sbox_chip::SboxChip, u8_range_check_chip::U8RangeCheckChip, u8_xor_chip::U8XorChip},
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        halo2curves::bn256::{Bn256, Fr as Fp, G1Affine},
        plonk::{
            create_proof, keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error, ProvingKey,
            VerifyingKey,
        },
        poly::kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::ProverSHPLONK,
        },
        transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
    },
    key_schedule::Aes128KeyScheduleConfig,
    table::{
        s_box::SboxTableConfig, u8_range_check::U8RangeCheckTableConfig, u8_xor::U8XorTableConfig,
    },
};
use rand::rngs::OsRng;

const SAMPLE_SIZE: usize = 10;

#[derive(Clone, Copy)]
struct Aes128KeyScheduleBenchCircuit {
    key: [u8; 16],
}

#[derive(Clone)]
struct Tables {
    pub u8_xor: U8XorTableConfig,
    pub sbox: SboxTableConfig,
    pub u8_range_check: U8RangeCheckTableConfig,
}

impl Circuit<Fp> for Aes128KeyScheduleBenchCircuit {
    type Config = (Aes128KeyScheduleConfig, Tables);
    type FloorPlanner = SimpleFloorPlanner;

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        // We have table columns in  this config
        let u8_xor_table_config = U8XorTableConfig::configure(meta);
        let sbox_table_config = SboxTableConfig::configure(meta);
        let u8_range_check_table_config = U8RangeCheckTableConfig::configure(meta);

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

        (
            Aes128KeyScheduleConfig::configure(
                meta,
                advices,
                u8_xor_config,
                sbox_config,
                u8_range_check_config,
            ),
            Tables {
                u8_range_check: u8_range_check_table_config,
                u8_xor: u8_xor_table_config,
                sbox: sbox_table_config,
            },
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        config.1.u8_range_check.load(&mut layouter)?;
        config.1.u8_xor.load(&mut layouter)?;
        config.1.sbox.load(&mut layouter)?;

        config
            .0
            .schedule_keys(&mut layouter.namespace(|| "AES128 schedule key"), self.key)?;

        Ok(())
    }

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }
}

fn setup_params<C: Circuit<Fp>>(
    k: u32,
    circuit: C,
) -> (
    ParamsKZG<Bn256>,
    ProvingKey<G1Affine>,
    VerifyingKey<G1Affine>,
) {
    let params = ParamsKZG::<Bn256>::setup(k, OsRng);
    let vk = keygen_vk(&params, &circuit).expect("vk generation should not fail");
    let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk generation should not fail");
    (params, pk, vk)
}

fn prove_aes128_key_schedule_circuit(_c: &mut Criterion) {
    let mut criterion = Criterion::default().sample_size(SAMPLE_SIZE);
    let circuit = Aes128KeyScheduleBenchCircuit { key: [0u8; 16] };
    let (params, pk, _) = setup_params(17, circuit.clone());
    let bench_name = format!("prove key scheduling for AES128");

    criterion.bench_function(&bench_name, |b| {
        b.iter(|| {
            let tm = start_timer!(|| "Generating proof");
            let mut transcript =
                Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(vec![]);

            let result = create_proof::<
                KZGCommitmentScheme<Bn256>,
                ProverSHPLONK<'_, Bn256>,
                Challenge255<G1Affine>,
                _,
                _,
                _,
            >(&params, &pk, &[circuit], &[&[]], OsRng, &mut transcript);
            println!("Error: {:?}", result);
            if result.is_err() {
                panic!("Create proof fail");
            }

            // .expect("prover should not fail");
            end_timer!(tm);
        })
    });
}

criterion_group!(benches, prove_aes128_key_schedule_circuit,);
criterion_main!(benches);
