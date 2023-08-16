use ff::Field;
use halo2_proofs::{
    circuit::{Value},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof,
    },
    poly::{
        commitment::ParamsProver,
        ipa::{
            commitment::{IPACommitmentScheme, ParamsIPA},
            multiopen::ProverIPA,
            strategy::SingleStrategy,
        },
        VerificationStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use halo2curves::pasta::{pallas, vesta, EqAffine, Fp};

use halo2_gadgets::poseidon::{
    primitives::{self as poseidon, ConstantLength},
};
use halo2_mt::utils::p128pow5t3::P128Pow5T3 as OrchardNullifier;
use std::convert::TryInto;
use std::marker::PhantomData;

use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;


use halo2_mt::circuits::poseidon::PoseidonCircuit;

const K: u32 = 7;

fn bench_poseidon<const L: usize>(name: &str, c: &mut Criterion) {
    // Initialize the polynomial commitment parameters
    let params: ParamsIPA<vesta::Affine> = ParamsIPA::new(K);

    // We'll use the PoseidonCircuit for OrchardNullifier directly now
    let empty_circuit = PoseidonCircuit::<OrchardNullifier, 3, 2, L> {
        message: (0..L)
            .map(|_| Value::unknown())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        output: Value::unknown(),
        _spec: PhantomData,
    };

    // Initialize the proving key
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

    let prover_name = name.to_string() + "-prover";
    let verifier_name = name.to_string() + "-verifier";

    let mut rng = OsRng;
    let message: [Fp; L] = (0..L)
        .map(|_| pallas::Base::random(&mut rng))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let output =
        poseidon::Hash::<_, OrchardNullifier, ConstantLength<L>, 3, 2>::init().hash(message);

    let circuit = PoseidonCircuit::<OrchardNullifier, 3, 2, L> {
        message: message.map(|x| Value::known(x)),
        output: Value::known(output),
        _spec: PhantomData,
    };

    c.bench_function(&prover_name, |b| {
        let circuit_cloned = circuit.clone();
        // Create a proof
        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
        b.iter(|| {
            create_proof::<IPACommitmentScheme<_>, ProverIPA<_>, _, _, _, _>(
                &params,
                &pk,
                &[circuit_cloned],
                &[&[&[output]]],
                &mut rng,
                &mut transcript,
            )
            .expect("proof generation should not fail")
        });
    });

    let circuit = PoseidonCircuit::<OrchardNullifier, 3, 2, L> {
        message: message.map(|x| Value::known(x)),
        output: Value::known(output),
        _spec: PhantomData,
    };

    // Create a proof for the verifier
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    create_proof::<IPACommitmentScheme<_>, ProverIPA<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[&[output]]],
        &mut rng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof = transcript.finalize();

    c.bench_function(&verifier_name, |b| {
        b.iter(|| {
            let strategy = SingleStrategy::new(&params);
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            assert!(verify_proof(
                &params,
                pk.get_vk(),
                strategy,
                &[&[&[output]]],
                &mut transcript
            )
            .is_ok());
        });
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    bench_poseidon::<2>("L = 2", c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
