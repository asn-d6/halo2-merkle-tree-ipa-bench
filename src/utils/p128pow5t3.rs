// Had to move this here to make it cloneable...
use halo2_proofs::arithmetic::Field;
use halo2curves::pasta::{pallas::Base as Fp, vesta::Base as Fq};

use halo2_gadgets::poseidon::primitives::{Mds, Spec};

use super::fp as SuperFp;
use super::fq as SuperFq;

/// Poseidon-128 using the $x^5$ S-box, with a width of 3 field elements, and the
/// standard number of rounds for 128-bit security "with margin".
///
/// The standard specification for this set of parameters (on either of the Pasta
/// fields) uses $R_F = 8, R_P = 56$. This is conveniently an even number of
/// partial rounds, making it easier to construct a Halo 2 circuit.
#[derive(Debug, Clone, Copy)]
pub struct P128Pow5T3;

impl Spec<Fp, 3, 2> for P128Pow5T3 {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: Fp) -> Fp {
        val.pow_vartime(&[5])
    }

    fn secure_mds() -> usize {
        unimplemented!()
    }

    fn constants() -> (Vec<[Fp; 3]>, Mds<Fp, 3>, Mds<Fp, 3>) {
        (
            SuperFp::ROUND_CONSTANTS[..].to_vec(),
            SuperFp::MDS,
            SuperFp::MDS_INV,
        )
    }
}

impl Spec<Fq, 3, 2> for P128Pow5T3 {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: Fq) -> Fq {
        val.pow_vartime(&[5])
    }

    fn secure_mds() -> usize {
        unimplemented!()
    }

    fn constants() -> (Vec<[Fq; 3]>, Mds<Fq, 3>, Mds<Fq, 3>) {
        (
            SuperFq::ROUND_CONSTANTS[..].to_vec(),
            SuperFq::MDS,
            SuperFq::MDS_INV,
        )
    }
}
