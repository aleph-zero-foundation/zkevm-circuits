// #![deny(unused_crate_dependencies)]

//! # zk_evm

// We should try not to use incomplete_features unless it is really really needed and cannot be
// avoided like `adt_const_params` used by DummyGadget
#![allow(incomplete_features)]
// Needed by DummyGadget in evm circuit
#![feature(adt_const_params)]
// Required for adding reasons in allow(dead_code)
#![feature(lint_reasons)]
// Needed by some builder patterns in testing modules.
#![cfg_attr(docsrs, feature(doc_cfg))]
// We want to have UPPERCASE idents sometimes.
#![allow(clippy::upper_case_acronyms)]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::debug_assert_with_mut_call)]

#[allow(dead_code, reason = "under active development")]
pub(crate) mod circuit_tools;
pub(crate) mod copy_circuit;
pub(crate) mod evm_circuit;
pub(crate) mod exp_circuit;
pub(crate) mod keccak_circuit;
pub(crate) mod table;

pub(crate) mod util;
pub(crate) mod witness;

use std::time::Instant;
use halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk};
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_proofs::poly::kzg::multiopen::ProverGWC;
use halo2_proofs::transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
pub(crate) use gadgets::impl_expr;
use crate::keccak_circuit::keccak_packed_multi::get_num_rows_per_round;
use crate::keccak_circuit::KeccakCircuit;

#[allow(missing_docs)]
pub fn run_keccak_prover() {
    println!("Using {} rows per round", get_num_rows_per_round());

    let k = 15;
    let inputs = vec![
        vec![],
        (0u8..1).collect::<Vec<_>>(),
        (0u8..135).collect::<Vec<_>>(),
        (0u8..136).collect::<Vec<_>>(),
        (0u8..200).collect::<Vec<_>>(),
    ];

    let circuit = KeccakCircuit::new(2usize.pow(k), inputs);

    let mut rng = ChaCha20Rng::seed_from_u64(0);
    let params = ParamsKZG::<Bn256>::setup(k, &mut rng);

    let now = Instant::now();

    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

    let mut transcript = Blake2bWrite::<_, _, Challenge255<G1Affine>>::init(vec![]);

    let elapsed = now.elapsed();
    println!("Key and transcript generation took: {}ms", elapsed.as_millis());

    create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<'_, Bn256>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[]],
        rng,
        &mut transcript,
        &now,
    )
        .expect("proof generation should not fail");

    transcript.finalize();

    let elapsed = now.elapsed();
    println!("The whole procedure took: {}ms", elapsed.as_millis());
}
