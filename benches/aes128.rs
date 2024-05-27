use criterion::{criterion_group, criterion_main, Criterion};
use halo2_aes::FixedAes128Config;

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
struct Aes128BenchCircuit {
    key: [u8; 16],
    plaintext: [u8; 16],
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
        config.key_schedule_config.load(&mut layouter);

        config.mul2_table_config.load(&mut layouter)?;
        config.mul3_table_config.load(&mut layouter)?;

        config.set_key(self.key);

        let val = config.encrypt(layouter, self.plaintext)?;

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

fn prove_aes128_circuit(_c: &mut Criterion) {
    let mut criterion = Criterion::default().sample_size(SAMPLE_SIZE);
    let circuit = Aes128BenchCircuit {
        key: [0u8; 16],
        plaintext: [0u8; 16],
    };
    let (params, pk, _) = setup_params(17, circuit.clone());
    let bench_name = format!("prove AES128 encryption");

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

criterion_group!(benches, prove_aes128_circuit,);
criterion_main!(benches);
