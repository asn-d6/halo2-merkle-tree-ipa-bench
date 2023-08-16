# halo2-merkle-tree-ipa-bench

Benchmarking membership proofs (merkle proof creation and verification) using Halo2 and IPAs.

Such membership proofs can be used in anonymous credential schemes (like the ones required by the proof of validator).

The circuit logic is directly taken from the [halo2-merkle-tree](https://github.com/jtguibas/halo2-merkle-tree/)
project. All props go to @jtguibas and @enricobottazzi.

The following modifications were done to the original repository:
- Simplifies some circuits and deletes unused ones
- Massages circuit creation code to use the `create_proof()` API
- Writes benchmarks for the prover and verifier
- Address all compiler warnings

This code just exists to collect some rough benchmarks. Don't even think about using this in production.

## Usage

Just do `cargo bench`

