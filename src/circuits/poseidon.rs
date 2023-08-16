/*
An easy-to-use implementation of the Poseidon Hash in the form of a Halo2 Chip. While the Poseidon Hash function
is already implemented in halo2_gadgets, there is no wrapper chip that makes it easy to use in other circuits.
*/

use super::super::chips::poseidon::{PoseidonChip, PoseidonConfig};
use halo2_gadgets::poseidon::{
    primitives::{Spec},
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Circuit,
        ConstraintSystem, Error,
    },
};
use halo2curves::pasta::{Fp};
use std::marker::PhantomData;

#[derive(Debug, Clone, Copy)]
pub struct PoseidonCircuit<
    S: Spec<Fp, WIDTH, RATE>,
    const WIDTH: usize,
    const RATE: usize,
    const L: usize,
> {
    pub message: [Value<Fp>; L],
    pub output: Value<Fp>,
    pub _spec: PhantomData<S>,
}

impl<S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize> Circuit<Fp>
    for PoseidonCircuit<S, WIDTH, RATE, L>
{
    type Config = PoseidonConfig<WIDTH, RATE, L>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            message: (0..L)
                .map(|_i| Value::unknown())
                .collect::<Vec<Value<Fp>>>()
                .try_into()
                .unwrap(),
            output: Value::unknown(),
            _spec: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> PoseidonConfig<WIDTH, RATE, L> {
        PoseidonChip::<S, WIDTH, RATE, L>::configure(meta)
    }

    fn synthesize(
        &self,
        config: PoseidonConfig<WIDTH, RATE, L>,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let poseidon_chip = PoseidonChip::<S, WIDTH, RATE, L>::construct(config);
        let message_cells = poseidon_chip
            .load_private_inputs(layouter.namespace(|| "load private inputs"), self.message)?;
        let result = poseidon_chip.hash(layouter.namespace(|| "poseidon chip"), &message_cells)?;
        poseidon_chip.expose_public(layouter.namespace(|| "expose result"), &result, 0)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::p128pow5t3::P128Pow5T3 as OrchardNullifier;
    use halo2_gadgets::poseidon::{
        primitives::{self as poseidon, ConstantLength},
    };
    use halo2_proofs::arithmetic::Field;
    use halo2_proofs::dev::MockProver;
    use rand_core::OsRng;
    use std::marker::PhantomData;

    #[test]
    fn test() {
        let mut rng = OsRng;
        let message = [Fp::random(&mut rng), Fp::random(&mut rng)];
        let output =
            poseidon::Hash::<_, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash(message);

        let circuit = PoseidonCircuit::<OrchardNullifier, 3, 2, 2> {
            message: message.map(|x| Value::known(x)),
            output: Value::known(output),
            _spec: PhantomData,
        };
        let public_input = vec![output];
        let prover = MockProver::run(10, &circuit, vec![public_input.clone()]).unwrap();
        prover.assert_satisfied();
    }
}
