use super::*;
use eth_types::Field;
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use log::error;
use std::iter::zip;
use halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk};
use halo2_proofs::poly::commitment::Prover;
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_proofs::poly::kzg::multiopen::ProverGWC;
use halo2_proofs::transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use super::util::{target_part_sizes, target_part_sizes_rot, WordParts};

#[allow(unused)]
fn verify<F: Field>(k: u32, inputs: Vec<Vec<u8>>) {
    let circuit = KeccakCircuit::new(2usize.pow(k), inputs);

    let mut rng = ChaCha20Rng::seed_from_u64(0);
    let params = ParamsKZG::<Bn256>::setup(k, &mut rng);

    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

    let mut transcript = Blake2bWrite::<_, _, Challenge255<G1Affine>>::init(vec![]);
    create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<'_, Bn256>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[]],
        rng,
        &mut transcript,
    )
        .expect("proof generation should not fail");
    transcript.finalize();
}

fn keygen_check<F: Field>(k: u32, inputs: Vec<Vec<u8>>) {
    let circuit = KeccakCircuit::new(2usize.pow(k), inputs);

    let mut rng = ChaCha20Rng::seed_from_u64(0);
    // todo: assert that degree === k
    let general_params = ParamsKZG::<Bn256>::setup(k, &mut rng);

    let vk = keygen_vk(&general_params, &circuit).expect("keygen_vk should not fail");

    println!("LOOKUPS: {}", vk.cs().lookups().len());
    println!("COLUMNS: {}", vk.cs().num_advice_columns() + vk.cs().num_instance_columns() + vk.cs().num_fixed_columns());
}

#[test]
fn packed_multi_keccak_simple() {
    let k = 15;
    let inputs = vec![
        vec![],
        (0u8..1).collect::<Vec<_>>(),
        (0u8..135).collect::<Vec<_>>(),
        (0u8..136).collect::<Vec<_>>(),
        (0u8..200).collect::<Vec<_>>(),
    ];
    verify::<Fr>(k, inputs.clone());
    // keygen_check::<Fr>(k, inputs);
}

#[test]
fn variadic_size_check() {
    let k = 14;
    let num_rows = 2usize.pow(k);
    // Empty
    let inputs = vec![];
    let circuit = KeccakCircuit::new(num_rows, inputs);
    let prover1 = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();

    // Non-empty
    let inputs = vec![
        vec![],
        (0u8..1).collect::<Vec<_>>(),
        (0u8..135).collect::<Vec<_>>(),
        (0u8..136).collect::<Vec<_>>(),
        (0u8..200).collect::<Vec<_>>(),
    ];
    let circuit = KeccakCircuit::new(num_rows, inputs);
    let prover2 = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();

    assert_eq!(prover1.fixed(), prover2.fixed());
    assert_eq!(prover1.permutation(), prover2.permutation());
}

#[test]
fn test_target_part_sizes() {
    // Uniform 8 parts of 8 bits each.
    assert_eq!(target_part_sizes_rot(8, 0), vec![8, 8, 8, 8, 8, 8, 8, 8]);
    // With rotations.
    assert_eq!(target_part_sizes_rot(8, 1), vec![1, 8, 8, 8, 8, 8, 8, 8, 7]);
    assert_eq!(target_part_sizes_rot(8, 2), vec![2, 8, 8, 8, 8, 8, 8, 8, 6]);
    assert_eq!(target_part_sizes_rot(8, 8), vec![8, 8, 8, 8, 8, 8, 8, 8]);
    assert_eq!(target_part_sizes_rot(8, 9), vec![8, 1, 8, 8, 8, 8, 8, 8, 7]);

    // Parts of 11 bits and the remaining 9 bits.
    assert_eq!(target_part_sizes_rot(11, 0), vec![11, 11, 11, 11, 11, 9]);
    // With rotations.
    assert_eq!(target_part_sizes_rot(11, 1), vec![1, 11, 11, 11, 11, 11, 8]);
    assert_eq!(target_part_sizes_rot(11, 2), vec![2, 11, 11, 11, 11, 11, 7]);
    assert_eq!(target_part_sizes_rot(11, 11), vec![11, 11, 11, 11, 11, 9]);
    assert_eq!(
        target_part_sizes_rot(11, 12),
        vec![11, 1, 11, 11, 11, 11, 8]
    );

    // "uniform" is the same as rot=0
    assert_eq!(target_part_sizes(8), target_part_sizes_rot(8, 0));
    assert_eq!(target_part_sizes(11), target_part_sizes_rot(11, 0));
}

#[test]
fn test_word_parts() {
    {
        let word = WordParts::new(11, 0, true);
        // Parts of bits.
        let expected: Vec<Vec<usize>> = vec![
            (0..11).collect(),  // Length 11
            (11..22).collect(), // …
            (22..33).collect(), // …
            (33..44).collect(), // …
            (44..55).collect(), // …
            (55..64).collect(), // Length 9
        ];
        assert_eq!(word.parts.len(), expected.len());
        for (part, xbits) in zip(word.parts, expected) {
            assert_eq!(part.bits, xbits);
        }
    }

    {
        let word = WordParts::new(11, 1, false);
        // Parts of bits.
        let expected: Vec<Vec<usize>> = vec![
            (0..11).collect(),  // Length 11
            (11..22).collect(), // …
            (22..33).collect(), // …
            (33..44).collect(), // …
            (44..55).collect(), // …
            (55..63).collect(), // Length 8
            (63..64).collect(), // Length 1
        ];
        assert_eq!(word.parts.len(), expected.len());
        for (part, xbits) in zip(word.parts, expected) {
            assert_eq!(part.bits, xbits);
        }
    }
}
