use ark_std::{end_timer, start_timer};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use halo2_aes::{
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        halo2curves::bn256::{Bn256, Fr as Fp, G1Affine},
        plonk::{
            create_proof, keygen_pk, keygen_vk, Circuit, ConstraintSystem, Error, ProvingKey,
            VerifyingKey,
        },
        poly::{
            commitment::Params,
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                multiopen::ProverSHPLONK,
            },
        },
        transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
    },
    FixedAes128Config,
};
use rand::rngs::OsRng;
use std::fs::File;

const SAMPLE_SIZE: usize = 10;

#[derive(Clone, Copy)]
struct Aes128BenchCircuit {
    key: [u8; 16],
    plaintext: [u8; 16],
    pub encrypt_num: usize,
}

impl Circuit<Fp> for Aes128BenchCircuit {
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

        config.schedule_key(&mut layouter, self.key)?;
        for i in 0..self.encrypt_num {
            config.encrypt(&mut layouter, self.plaintext)?;
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
    // TODO: load kzg params if available

    let path = format!("ptau/kzg_bn254_{}.srs", k);
    let params = if let Ok(mut fs) = File::open(path) {
        ParamsKZG::<Bn256>::read(&mut fs).expect("Failed to read params")
    } else {
        // panic!("Not loaded");
        ParamsKZG::<Bn256>::setup(k, OsRng)
    };
    println!("Parameter files loaded");

    let vk = keygen_vk(&params, &circuit).expect("vk generation should not fail");
    let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk generation should not fail");
    (params, pk, vk)
}

fn prove_aes128_circuit(c: &mut Criterion) {
    // let mut criterion = Criterion::default().sample_size(SAMPLE_SIZE);
    let mut circuit = Aes128BenchCircuit {
        key: [0u8; 16],
        plaintext: [0u8; 16],
        encrypt_num: 1,
    };
    let (params, pk, _) = setup_params(19, circuit.clone());
    let mut group = c.benchmark_group("prove AES128 encryption");
    group.sample_size(SAMPLE_SIZE);

    for size in [1] {
        group.throughput(criterion::Throughput::Elements(size));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, s| {
            b.iter(|| {
                let tm = start_timer!(|| "Generating proof");
                let mut transcript =
                    Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(vec![]);
                circuit.encrypt_num = *s as usize;

                let result =
                    create_proof::<
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
            });
        });
    }
    group.finish();
}

criterion_group!(benches, prove_aes128_circuit);
criterion_main!(benches);
