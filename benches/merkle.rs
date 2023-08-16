#[allow(unused_imports)]
use ff::Field;
use halo2_proofs::dev::MockProver;
use halo2_proofs::{
    circuit::{Value},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof
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
use halo2curves::pasta::{vesta, EqAffine, Fp};

use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;

use halo2_mt::circuits::merkle::{compute_merkle_root, MerkleTreeCircuit};

/// Benchmark merkle proof creation and verification using a merkle tree of `depth`.
///
/// `degree` is the max polynomial degree our polynomial commitment scheme (IPA) can support. The degree should be
/// larger than the number of rows of our circuit.
fn bench_merkle(depth: usize, degree: u32, c: &mut Criterion) {
    // Initialize the polynomial commitment parameters
    let params: ParamsIPA<vesta::Affine> = ParamsIPA::new(degree);

    // Preprocess the SNARK and generate the proving/verifying keys
    // We will need an empty circuit to preprocess it
    let empty_circuit = MerkleTreeCircuit {
        leaf: Value::unknown(),
        elements: vec![Value::unknown(); depth],
        indices: vec![Value::unknown(); depth],
    };
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

    // Do a bunch of additional legwork
    let prover_name = format!("MT-{}-prover", depth);
    let verifier_name = format!("MT-{}-verifier", depth);
    let mut rng = OsRng;

    // Generate a random leaf, a bunch of siblings and a route to the root
    let leaf_f = Fp::random(&mut rng);
    let elements_f = (0..depth).map(|_| Fp::random(&mut rng)).collect::<Vec<_>>();
    let indices = vec![0u64; depth];
    // Compute the merkle root
    let digest = compute_merkle_root(&leaf_f, &elements_f, &indices);

    // Convert everything to circuit values
    let leaf_fp = Value::known(leaf_f);
    let elements_fp: Vec<Value<Fp>> = elements_f.iter().map(|x| Value::known(x.to_owned())).collect();
    let indices_fp: Vec<Value<Fp>> = indices.iter().map(|x| Value::known(Fp::from(x.to_owned()))).collect();

    // Populate an actual circuit with the trace
    let circuit = MerkleTreeCircuit {
        leaf: leaf_fp,
        elements: elements_fp.clone(),
        indices: indices_fp.clone(),
    };

    // Our instance is the leaf and the merkle root
    let public_input = vec![leaf_f, digest];
    // Check proof creation using a MockProver: a sanity check to make sure that things make sense
    // XXX why do we have to pass public_input twice?
    let prover = MockProver::run(
        degree,
        &circuit,
        vec![public_input.clone(), public_input.clone()],
    ).unwrap();
    prover.assert_satisfied();

    // Benchmark proof creation
    c.bench_function(&prover_name, |b| {
        b.iter(|| {
            let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
            create_proof::<IPACommitmentScheme<_>, ProverIPA<_>, _, _, _, _>(
                &params,
                &pk,
                &[circuit.clone()],
                &[&[&public_input, &public_input]],
                &mut rng,
                &mut transcript,
            )
            .expect("proof generation should not fail");
        });
    });

    // Now let's move towards benchmarking verifier

    // Create the proof that will be verified
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    create_proof::<IPACommitmentScheme<_>, ProverIPA<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[&public_input, &public_input]],
        &mut rng,
        &mut transcript,
    ).expect("proof generation should not fail");
    let proof = transcript.finalize();
    println!("proof length: {}", proof.len());

    // Benchmark the verifier
    c.bench_function(&verifier_name, |b| {
        b.iter(|| {
            let strategy = SingleStrategy::new(&params);
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            assert!(verify_proof(
                &params,
                pk.get_vk(),
                strategy,
                &[&[&public_input, &public_input]],
                &mut transcript
            )
            .is_ok());
        });
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    // Depth 22
    bench_merkle(22 as usize, 10, c);
    // Depth 24
    bench_merkle(24 as usize, 10, c);
    // Depth 26 needs higher degree polynomials because of the number of rows
    bench_merkle(26 as usize, 11, c);
}

criterion_group!(name = benches;
                 config = Criterion::default().sample_size(10);
                 targets = criterion_benchmark);
criterion_main!(benches);
