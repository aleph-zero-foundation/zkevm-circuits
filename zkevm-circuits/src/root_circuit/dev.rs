use super::{aggregate, AggregationConfig, Halo2Loader, KzgSvk, Snark, SnarkWitness, LIMBS};
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    halo2curves::{ff::Field as Halo2Field, serde::SerdeObject},
    plonk::{Circuit, ConstraintSystem, Error},
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use itertools::Itertools;
use maingate::MainGateInstructions;
use snark_verifier::{
    loader::native::NativeLoader,
    pcs::{
        kzg::*, AccumulationDecider, AccumulationScheme, AccumulationSchemeProver,
        PolynomialCommitmentScheme,
    },
};
use std::{iter, marker::PhantomData, rc::Rc};

use halo2_proofs::halo2curves::pairing::MultiMillerLoop as GeoMultiMillerLoop;
use halo2_proofs::halo2curves::pairing::Engine as GeoEngine;
use maingate::halo2::halo2curves::pairing::MultiMillerLoop as MaingateMultiMillerLoop;

pub trait MultiMillerLoop: GeoMultiMillerLoop + MaingateMultiMillerLoop + std::fmt::Debug {}
impl<M: GeoMultiMillerLoop + MaingateMultiMillerLoop + std::fmt::Debug> MultiMillerLoop for M {}

/// Aggregation circuit for testing purpose.
#[derive(Clone)]
pub struct TestAggregationCircuit<'a, M: MultiMillerLoop, As> {
    svk: KzgSvk<M>,
    snarks: Vec<SnarkWitness<'a, <M as GeoEngine>::G1Affine>>,
    instances: Vec<<M as GeoEngine>::Scalar>,
    _marker: PhantomData<As>,
}

impl<'a, M: MultiMillerLoop, As> TestAggregationCircuit<'a, M, As>
where
    <M as GeoEngine>::G1Affine: SerdeObject,
    <M as GeoEngine>::G2Affine: SerdeObject,
    <M as GeoEngine>::Scalar: Field,
    for<'b> As: PolynomialCommitmentScheme<
            <M as GeoEngine>::G1Affine,
            NativeLoader,
            VerifyingKey = KzgSvk<M>,
            Output = KzgAccumulator<<M as GeoEngine>::G1Affine, NativeLoader>,
        > + AccumulationSchemeProver<
            <M as GeoEngine>::G1Affine,
            Accumulator = KzgAccumulator<<M as GeoEngine>::G1Affine, NativeLoader>,
            ProvingKey = KzgAsProvingKey<<M as GeoEngine>::G1Affine>,
        > + AccumulationDecider<<M as GeoEngine>::G1Affine, NativeLoader, DecidingKey = KzgDecidingKey<M>>,
{
    /// Create an Aggregation circuit with aggregated accumulator computed.
    /// Returns `None` if any given snark is invalid.
    pub fn new(
        params: &ParamsKZG<M>,
        snarks: impl IntoIterator<Item = Snark<'a, <M as GeoEngine>::G1Affine>>,
    ) -> Result<Self, snark_verifier::Error> {
        let snarks = snarks.into_iter().collect_vec();

        let accumulator_limbs = aggregate::<M, As>(params, snarks.clone())?;
        let instances = iter::empty()
            // Propagate aggregated snarks' instances
            .chain(
                snarks
                    .iter()
                    .flat_map(|snark| snark.instances.clone())
                    .flatten(),
            )
            // Output aggregated accumulator
            .chain(accumulator_limbs)
            .collect_vec();

        Ok(Self {
            svk: KzgSvk::<M>::new(params.get_g()[0]),
            snarks: snarks.into_iter().map_into().collect(),
            instances,
            _marker: PhantomData,
        })
    }

    /// Returns accumulator indices in instance columns, which will be in
    /// the last 4 * LIMBS rows of MainGate's instance column.
    pub fn accumulator_indices(&self) -> Vec<(usize, usize)> {
        (self.instances.len() - 4 * LIMBS..)
            .map(|idx| (0, idx))
            .take(4 * LIMBS)
            .collect()
    }

    /// Returns number of instance
    pub fn num_instance(&self) -> Vec<usize> {
        vec![self.instances.len()]
    }

    /// Returns instances
    pub fn instances(&self) -> Vec<Vec<<M as GeoEngine>::Scalar>> {
        vec![self.instances.clone()]
    }
}

impl<'a, M: MultiMillerLoop, As> Circuit<<M as GeoEngine>::Scalar> for TestAggregationCircuit<'a, M, As>
where
    <M as GeoEngine>::Scalar: Field,
    for<'b> As: PolynomialCommitmentScheme<
            <M as GeoEngine>::G1Affine,
            Rc<Halo2Loader<'b, <M as GeoEngine>::G1Affine>>,
            VerifyingKey = KzgSvk<M>,
            Output = KzgAccumulator<<M as GeoEngine>::G1Affine, Rc<Halo2Loader<'b, <M as GeoEngine>::G1Affine>>>,
        > + AccumulationScheme<
            <M as GeoEngine>::G1Affine,
            Rc<Halo2Loader<'b, <M as GeoEngine>::G1Affine>>,
            Accumulator = KzgAccumulator<<M as GeoEngine>::G1Affine, Rc<Halo2Loader<'b, <M as GeoEngine>::G1Affine>>>,
            VerifyingKey = KzgAsVerifyingKey,
        >,
{
    type Config = AggregationConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            svk: self.svk,
            snarks: self
                .snarks
                .iter()
                .map(SnarkWitness::without_witnesses)
                .collect(),
            instances: vec![<M as GeoEngine>::Scalar::ZERO; self.instances.len()],
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<<M as GeoEngine>::Scalar>) -> Self::Config {
        AggregationConfig::configure::<<M as GeoEngine>::G1Affine>(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<<M as GeoEngine>::Scalar>,
    ) -> Result<(), Error> {
        config.load_table(&mut layouter)?;
        let (instances, accumulator_limbs) =
            config.aggregate::<M, As>(&mut layouter, &self.svk, self.snarks.clone())?;

        // Constrain equality to instance values
        let main_gate = config.main_gate();
        for (row, limb) in instances
            .into_iter()
            .flatten()
            .flatten()
            .chain(accumulator_limbs)
            .enumerate()
        {
            main_gate.expose_public(layouter.namespace(|| ""), limb, row)?;
        }

        Ok(())
    }
}
