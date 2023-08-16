use halo2_gadgets::poseidon::{
    primitives::{self as poseidon, ConstantLength},
};
use halo2_proofs::{circuit::*, plonk::*};
use halo2curves::pasta::{Fp};

use crate::utils::p128pow5t3::P128Pow5T3 as OrchardNullifier;

use crate::chips::merkle::MerkleTreeChip;
use crate::chips::merkle::MerkleTreeConfig;

#[derive(Clone, Default)]
pub struct MerkleTreeCircuit {
    pub leaf: Value<Fp>,
    pub elements: Vec<Value<Fp>>,
    pub indices: Vec<Value<Fp>>,
}

impl Circuit<Fp> for MerkleTreeCircuit {
    type Config = MerkleTreeConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let instance = meta.instance_column();
        MerkleTreeChip::configure(meta, [col_a, col_b, col_c], instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = MerkleTreeChip::construct(config);
        let leaf_cell = chip.load_private(layouter.namespace(|| "load leaf"), self.leaf)?;
        // Constraint leaf to be placed in row 0 of the instance column
        chip.expose_public(layouter.namespace(|| "public leaf"), &leaf_cell, 0)?;
        let digest = chip.merkle_prove(
            layouter.namespace(|| "merkle_prove"),
            &leaf_cell,
            &self.elements,
            &self.indices,
        )?;
        // Constraint digest to be placed in row 1 of the instance column
        chip.expose_public(layouter.namespace(|| "public root"), &digest, 1)?;
        Ok(())
    }
}

// Helper function for computing a merkle root given a leaf, directions and the siblings
// elements correspond to siblings
pub fn compute_merkle_root(leaf: &Fp, elements: &Vec<Fp>, indices: &Vec<u64>) -> Fp {
    let k = elements.len();
    let mut digest = leaf.clone();
    let mut message: [Fp; 2];
    for i in 0..k {
        if indices[i] == 0 {
            message = [digest, elements[i]];
        } else {
            message = [elements[i], digest];
        }

        digest =
            poseidon::Hash::<_, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash(message);
    }
    return digest;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use halo2_proofs::dev::MockProver;
    use rand_core::OsRng;
    use halo2curves::pasta::{vesta, EqAffine};

    use halo2_proofs::{
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

    #[test]
    fn test() {
        let leaf = 99u64;
        let elements = vec![1u64, 5u64, 6u64, 9u64, 9u64];
        let indices = vec![0u64, 0u64, 0u64, 0u64, 0u64];

        let leaf_f = Fp::from(leaf);
        let elements_f: Vec<Fp> = elements.iter().map(|x| Fp::from(x.to_owned())).collect();

        let digest = compute_merkle_root(&leaf_f, &elements_f, &indices);

        let leaf_fp = Value::known(Fp::from(leaf));
        let elements_fp: Vec<Value<Fp>> = elements
            .iter()
            .map(|x| Value::known(Fp::from(x.to_owned())))
            .collect();
        let indices_fp: Vec<Value<Fp>> = indices
            .iter()
            .map(|x| Value::known(Fp::from(x.to_owned())))
            .collect();

        let circuit = MerkleTreeCircuit {
            leaf: leaf_fp,
            elements: elements_fp,
            indices: indices_fp,
        };

        let correct_public_input = vec![Fp::from(leaf), Fp::from(digest)];
        let correct_prover = MockProver::run(
            10,
            &circuit,
            vec![correct_public_input.clone(), correct_public_input.clone()],
        )
        .unwrap();
        correct_prover.assert_satisfied();

        let wrong_public_input = vec![Fp::from(leaf), Fp::from(432058235)];
        let wrong_prover = MockProver::run(
            10,
            &circuit,
            vec![wrong_public_input.clone(), wrong_public_input.clone()],
        )
        .unwrap();

        let result = wrong_prover.verify();
        match result {
            Ok(_res) => panic!("shouldve not proved correctly but did"),
            Err(_error) => true,
        };
    }

    // Same as `test()` but for a tree of depth 24
    #[test]
    fn test_big() {
        let mut rng = OsRng;
        let leaf_f = Fp::random(&mut rng);
        let elements_f = (0..24).map(|_| Fp::random(&mut rng)).collect::<Vec<_>>();
        let indices = vec![0u64; 24];

        let digest = compute_merkle_root(&leaf_f, &elements_f, &indices);

        let leaf_fp = Value::known(leaf_f);
        let elements_fp: Vec<Value<Fp>> = elements_f
            .iter()
            .map(|x| Value::known(x.to_owned()))
            .collect();
        let indices_fp: Vec<Value<Fp>> = indices
            .iter()
            .map(|x| Value::known(Fp::from(x.to_owned())))
            .collect();

        let circuit = MerkleTreeCircuit {
            leaf: leaf_fp,
            elements: elements_fp,
            indices: indices_fp,
        };

        let correct_public_input = vec![leaf_f, Fp::from(digest)];
        let correct_prover = MockProver::run(
            10,
            &circuit,
            vec![correct_public_input.clone(), correct_public_input.clone()],
        )
        .unwrap();
        correct_prover.assert_satisfied();

        let wrong_public_input = vec![leaf_f, Fp::from(432058235)];
        let wrong_prover = MockProver::run(
            10,
            &circuit,
            vec![wrong_public_input.clone(), wrong_public_input.clone()],
        )
        .unwrap();

        let result = wrong_prover.verify();
        assert!(
            result.is_err(),
            "Verification succeded when it should have failed"
        );
    }

    // Use the create_proof API instead of MockProver
    #[test]
    fn test_merkle_proving_and_verifying() {
        const DEPTH: usize = 24;
        const K: u32 = 10;

        // Initialization
        let params: ParamsIPA<vesta::Affine> = ParamsIPA::new(K);
        let empty_circuit = MerkleTreeCircuit {
            leaf: Value::unknown(),
            elements: vec![Value::unknown(); DEPTH],
            indices: vec![Value::unknown(); DEPTH],
        };
        let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

        let mut rng = OsRng;
        let leaf = 99u64;
        let elements_f = (0..DEPTH).map(|_| Fp::random(&mut rng)).collect::<Vec<_>>();
        let indices = vec![0u64; DEPTH];

        let leaf_f = Fp::from(leaf);
        let digest = compute_merkle_root(&leaf_f, &elements_f, &indices);

        let leaf_fp = Value::known(leaf_f);
        let elements_fp: Vec<Value<Fp>> = elements_f
            .iter()
            .map(|x| Value::known(x.to_owned()))
            .collect();
        let indices_fp: Vec<Value<Fp>> = indices
            .iter()
            .map(|x| Value::known(Fp::from(x.to_owned())))
            .collect();

        let circuit = MerkleTreeCircuit {
            leaf: leaf_fp,
            elements: elements_fp,
            indices: indices_fp,
        };

        let public_input = vec![leaf_f, digest];

        let prover = MockProver::run(
            K,
            &circuit,
            vec![public_input.clone(), public_input.clone()],
        )
        .unwrap();
        prover.assert_satisfied();

        // Proving
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
        let proof = transcript.finalize();

        // Verifying
        let strategy = SingleStrategy::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let verification_result = verify_proof(
            &params,
            pk.get_vk(),
            strategy,
            &[&[&public_input, &public_input]],
            &mut transcript,
        );

        assert!(verification_result.is_ok(), "Verification failed");

        // Try with a bad instance
        let wrong_public_input = vec![leaf_f, Fp::from(432058235)];
        let strategy = SingleStrategy::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let verification_result = verify_proof(
            &params,
            pk.get_vk(),
            strategy,
            &[&[&wrong_public_input, &wrong_public_input]],
            &mut transcript,
        );

        assert!(
            verification_result.is_err(),
            "Verification succeded when it should have failed"
        );
    }
}
