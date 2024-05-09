use criterion::{criterion_group, criterion_main, Criterion};
use halo2_aes::key_schedule::Aes128KeyScheduleConfig;

use ark_std::{end_timer, start_timer};
use halo2_proofs::{
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
};
use rand::rngs::OsRng;

const SAMPLE_SIZE: usize = 10;

#[derive(Clone, Copy)]
struct Aes128KeyScheduleBenchCircuit {
    key: [u8; 16],
}

impl Circuit<Fp> for Aes128KeyScheduleBenchCircuit {
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

        let words = config.schedule_keys(layouter.namespace(|| "AES128 schedule key"), self.key)?;
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

            create_proof::<
                KZGCommitmentScheme<Bn256>,
                ProverSHPLONK<'_, Bn256>,
                Challenge255<G1Affine>,
                _,
                _,
                _,
            >(&params, &pk, &[circuit], &[&[]], OsRng, &mut transcript)
            .expect("prover should not fail");
            end_timer!(tm);
        })
    });
}

criterion_group!(benches, prove_aes128_key_schedule_circuit,);
criterion_main!(benches);
