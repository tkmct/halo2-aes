use ark_std::{end_timer, start_timer};
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
    table::load_enc_full_table,
    FixedAes128Config,
};
use rand::rngs::OsRng;
use std::fs::File;

const K: u32 = 20;

#[derive(Clone, Copy)]
struct Aes128BenchCircuit {
    key: [u8; 16],
    plaintext: [u8; 16],
    pub encrypt_num: usize,
}

impl Circuit<Fp> for Aes128BenchCircuit {
    type Config = FixedAes128Config<K, 4>;
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
        for _ in 0..self.encrypt_num {
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
    // load kzg params if available
    let path = format!("ptau/kzg_bn254_{}.srs", k);
    let params = if let Ok(mut fs) = File::open(path) {
        ParamsKZG::<Bn256>::read(&mut fs).expect("Failed to read params")
    } else {
        ParamsKZG::<Bn256>::setup(k, OsRng)
    };
    println!("Parameter files loaded");

    let vk = keygen_vk(&params, &circuit).expect("vk generation should not fail");
    let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk generation should not fail");
    (params, pk, vk)
}

fn main() {
    let circuit = Aes128BenchCircuit {
        key: [0u8; 16],
        plaintext: [0u8; 16],
        encrypt_num: 3000,
    };
    let (params, pk, _) = setup_params(K, circuit.clone());

    let tm = start_timer!(|| "Prove: AES encrypt start");
    let mut transcript = Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(vec![]);

    let result = create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        _,
        _,
    >(&params, &pk, &[circuit], &[&[]], OsRng, &mut transcript);
    end_timer!(tm);

    println!("Error: {:?}", result);
    if result.is_err() {
        panic!("Create proof fail");
    }
}
