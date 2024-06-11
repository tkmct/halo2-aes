use criterion::{criterion_group, criterion_main, Criterion};

use ark_std::{end_timer, start_timer};
use halo2_aes::{
    chips::{sbox_chip::SboxChip, u8_range_check_chip::U8RangeCheckChip, u8_xor_chip::U8XorChip},
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        halo2curves::bn256::{Bn256, Fr as Fp, G1Affine},
        plonk::{
            create_proof, keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error, ProvingKey,
            TableColumn, VerifyingKey,
        },
        poly::kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::ProverSHPLONK,
        },
        transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
    },
    key_schedule::Aes128KeyScheduleConfig,
    table::load_enc_full_table,
};
use rand::rngs::OsRng;

const SAMPLE_SIZE: usize = 10;

#[derive(Clone, Copy)]
struct Aes128KeyScheduleBenchCircuit {
    key: [u8; 16],
}

impl Circuit<Fp> for Aes128KeyScheduleBenchCircuit {
    type Config = (Aes128KeyScheduleConfig, [TableColumn; 4]);
    type FloorPlanner = SimpleFloorPlanner;

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
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
        let u8_range_check_config =
            U8RangeCheckChip::configure(meta, advices[0], q_u8_range_check, tables[0], tables[1]);
        let u8_xor_config = U8XorChip::configure(
            meta, advices[0], advices[1], advices[2], q_u8_xor, tables[0], tables[1], tables[2],
            tables[3],
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
