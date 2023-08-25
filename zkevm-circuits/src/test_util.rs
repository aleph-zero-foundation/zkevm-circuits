//! Testing utilities

use crate::{
    witness::{Block, },
};
use bus_mapping::{circuit_input_builder::FixedCParams, };

use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use mock::TestContext;

#[cfg(test)]
#[ctor::ctor]
fn init_env_logger() {
    // Enable RUST_LOG during tests
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("error")).init();
}

#[allow(clippy::type_complexity)]
/// Struct used to easily generate tests for EVM &| State circuits being able to
/// customize all of the steps involved in the testing itself.
///
/// By default, the tests run through `prover.assert_satisfied_par()` but the
/// builder pattern provides functions that allow to pass different functions
/// that the prover should execute when verifying the CTB correctness.
///
/// The CTB also includes a mechanism to recieve calls that will modify the
/// block produced from the [`TestContext`] and apply them before starting to
/// compute the proof.
pub struct CircuitTestBuilder<const NACC: usize, const NTX: usize> {
    test_ctx: Option<TestContext<NACC, NTX>>,
    circuits_params: Option<FixedCParams>,
    block: Option<Block<Fr>>,
    evm_checks: Box<dyn Fn(MockProver<Fr>, &Vec<usize>, &Vec<usize>)>,
    state_checks: Box<dyn Fn(MockProver<Fr>, &Vec<usize>, &Vec<usize>)>,
    block_modifiers: Vec<Box<dyn Fn(&mut Block<Fr>)>>,
}

impl<const NACC: usize, const NTX: usize> CircuitTestBuilder<NACC, NTX> {
    /// Generates an empty/set to default `CircuitTestBuilder`.
    fn empty() -> Self {
        CircuitTestBuilder {
            test_ctx: None,
            circuits_params: None,
            block: None,
            evm_checks: Box::new(|prover, gate_rows, lookup_rows| {
                prover.assert_satisfied_at_rows_par(
                    gate_rows.iter().cloned(),
                    lookup_rows.iter().cloned(),
                )
            }),
            state_checks: Box::new(|prover, gate_rows, lookup_rows| {
                prover.assert_satisfied_at_rows_par(
                    gate_rows.iter().cloned(),
                    lookup_rows.iter().cloned(),
                )
            }),
            block_modifiers: vec![],
        }
    }

    /// Generates a CTBC from a [`TestContext`] passed with all the other fields
    /// set to [`Default`].
    pub fn new_from_test_ctx(ctx: TestContext<NACC, NTX>) -> Self {
        Self::empty().test_ctx(ctx)
    }

    /// Generates a CTBC from a [`Block`] passed with all the other fields
    /// set to [`Default`].
    pub fn new_from_block(block: Block<Fr>) -> Self {
        Self::empty().block(block)
    }

    /// Allows to produce a [`TestContext`] which will serve as the generator of
    /// the Block.
    pub fn test_ctx(mut self, ctx: TestContext<NACC, NTX>) -> Self {
        self.test_ctx = Some(ctx);
        self
    }

    /// Allows to pass a non-default [`FixedCParams`] to the builder.
    /// This means that we can increase for example, the `max_rws` or `max_txs`.
    pub fn params(mut self, params: FixedCParams) -> Self {
        assert!(
            self.block.is_none(),
            "circuit_params already provided in the block"
        );
        self.circuits_params = Some(params);
        self
    }

    /// Allows to pass a [`Block`] already built to the constructor.
    pub fn block(mut self, block: Block<Fr>) -> Self {
        self.block = Some(block);
        self
    }

    #[allow(clippy::type_complexity)]
    /// Allows to provide checks different than the default ones for the State
    /// Circuit verification.
    pub fn state_checks(
        mut self,
        state_checks: Box<dyn Fn(MockProver<Fr>, &Vec<usize>, &Vec<usize>)>,
    ) -> Self {
        self.state_checks = state_checks;
        self
    }

    #[allow(clippy::type_complexity)]
    /// Allows to provide checks different than the default ones for the EVM
    /// Circuit verification.
    pub fn evm_checks(
        mut self,
        evm_checks: Box<dyn Fn(MockProver<Fr>, &Vec<usize>, &Vec<usize>)>,
    ) -> Self {
        self.evm_checks = evm_checks;
        self
    }

    #[allow(clippy::type_complexity)]
    /// Allows to provide modifier functions for the [`Block`] that will be
    /// generated within this builder.
    ///
    /// That removes the need in a lot of tests to build the block outside of
    /// the builder because they need to modify something particular.
    pub fn block_modifier(mut self, modifier: Box<dyn Fn(&mut Block<Fr>)>) -> Self {
        self.block_modifiers.push(modifier);
        self
    }
}

impl<const NACC: usize, const NTX: usize> CircuitTestBuilder<NACC, NTX> {
    /// Triggers the `CircuitTestBuilder` to convert the [`TestContext`] if any,
    /// into a [`Block`] and apply the default or provided block_modifiers or
    /// circuit checks to the provers generated for the State and EVM circuits.
    pub fn run(self) {
    }
}
