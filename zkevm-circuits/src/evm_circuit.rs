//! The EVM circuit implementation.

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::*,
};

mod execution;
pub mod param;
pub mod step;
pub mod table;
pub(crate) mod util;

use self::step::HasExecutionState;

pub use crate::witness;
use crate::{
    evm_circuit::param::{MAX_STEP_HEIGHT, STEP_STATE_HEIGHT},
    table::{
        BlockTable, BytecodeTable, CopyTable, ExpTable, KeccakTable, LookupTable, RwTable, TxTable,
        UXTable,
    },
    util::{Challenges, SubCircuit, SubCircuitConfig},
};
use bus_mapping::evm::OpcodeId;
use eth_types::Field;
use execution::ExecutionConfig;
use itertools::Itertools;
use strum::IntoEnumIterator;
use table::FixedTableTag;
use witness::Block;

/// EvmCircuitConfig implements verification of execution trace of a block.
#[derive(Clone, Debug)]
pub struct EvmCircuitConfig<F> {
    fixed_table: [Column<Fixed>; 4],
    u8_table: UXTable<8>,
    u16_table: UXTable<16>,
    /// The execution config
    pub execution: Box<ExecutionConfig<F>>,
    // External tables
    tx_table: TxTable,
    rw_table: RwTable,
    bytecode_table: BytecodeTable,
    block_table: BlockTable,
    copy_table: CopyTable,
    keccak_table: KeccakTable,
    exp_table: ExpTable,
}

/// Circuit configuration arguments
pub struct EvmCircuitConfigArgs<F: Field> {
    /// Challenge
    pub challenges: Challenges<Expression<F>>,
    /// TxTable
    pub tx_table: TxTable,
    /// RwTable
    pub rw_table: RwTable,
    /// BytecodeTable
    pub bytecode_table: BytecodeTable,
    /// BlockTable
    pub block_table: BlockTable,
    /// CopyTable
    pub copy_table: CopyTable,
    /// KeccakTable
    pub keccak_table: KeccakTable,
    /// ExpTable
    pub exp_table: ExpTable,
    /// U8Table
    pub u8_table: UXTable<8>,
    /// U16Table
    pub u16_table: UXTable<16>,
}

impl<F: Field> SubCircuitConfig<F> for EvmCircuitConfig<F> {
    type ConfigArgs = EvmCircuitConfigArgs<F>;

    /// Configure EvmCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            challenges,
            tx_table,
            rw_table,
            bytecode_table,
            block_table,
            copy_table,
            keccak_table,
            exp_table,
            u8_table,
            u16_table,
        }: Self::ConfigArgs,
    ) -> Self {
        let fixed_table = [(); 4].map(|_| meta.fixed_column());
        let execution = Box::new(ExecutionConfig::configure(
            meta,
            challenges,
            &fixed_table,
            &u8_table,
            &u16_table,
            &tx_table,
            &rw_table,
            &bytecode_table,
            &block_table,
            &copy_table,
            &keccak_table,
            &exp_table,
        ));

        u8_table.annotate_columns(meta);
        u16_table.annotate_columns(meta);
        fixed_table.iter().enumerate().for_each(|(idx, &col)| {
            meta.annotate_lookup_any_column(col, || format!("fix_table_{}", idx))
        });
        tx_table.annotate_columns(meta);
        rw_table.annotate_columns(meta);
        bytecode_table.annotate_columns(meta);
        block_table.annotate_columns(meta);
        copy_table.annotate_columns(meta);
        keccak_table.annotate_columns(meta);
        exp_table.annotate_columns(meta);
        u8_table.annotate_columns(meta);
        u16_table.annotate_columns(meta);

        Self {
            fixed_table,
            u8_table,
            u16_table,
            execution,
            tx_table,
            rw_table,
            bytecode_table,
            block_table,
            copy_table,
            keccak_table,
            exp_table,
        }
    }
}

impl<F: Field> EvmCircuitConfig<F> {
    /// Load fixed table
    pub fn load_fixed_table(
        &self,
        layouter: &mut impl Layouter<F>,
        fixed_table_tags: Vec<FixedTableTag>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "fixed table",
            |mut region| {
                for (offset, row) in std::iter::once([F::ZERO; 4])
                    .chain(fixed_table_tags.iter().flat_map(|tag| tag.build()))
                    .enumerate()
                {
                    for (column, value) in self.fixed_table.iter().zip_eq(row) {
                        region.assign_fixed(|| "", *column, offset, || Value::known(value))?;
                    }
                }

                Ok(())
            },
        )
    }
}

/// Tx Circuit for verifying transaction signatures
#[derive(Clone, Default, Debug)]
pub struct EvmCircuit<F: Field> {
    /// Block
    pub block: Option<Block<F>>,
    fixed_table_tags: Vec<FixedTableTag>,
}

impl<F: Field> EvmCircuit<F> {
    /// Return a new EvmCircuit
    pub fn new(block: Block<F>) -> Self {
        Self {
            block: Some(block),
            fixed_table_tags: FixedTableTag::iter().collect(),
        }
    }
    /// Get the minimum number of rows required to process the block
    /// If unspecified, then compute it
    pub(crate) fn get_num_rows_required(block: &Block<F>) -> usize {
        let evm_rows = block.circuits_params.max_evm_rows;
        if evm_rows == 0 {
            Self::get_min_num_rows_required(block)
        } else {
            // It must have at least one unused row.
            block.circuits_params.max_evm_rows + 1
        }
    }
    /// Compute the minimum number of rows required to process the block
    fn get_min_num_rows_required(block: &Block<F>) -> usize {
        let mut num_rows = 0;
        for transaction in &block.txs {
            for step in transaction.steps() {
                num_rows += step.execution_state().get_step_height();
            }
        }

        // It must have one row for EndBlock and at least one unused one
        num_rows + 2
    }
}

impl<F: Field> SubCircuit<F> for EvmCircuit<F> {
    type Config = EvmCircuitConfig<F>;

    fn unusable_rows() -> usize {
        // Most columns are queried at MAX_STEP_HEIGHT + STEP_STATE_HEIGHT distinct rotations, so
        // returns (MAX_STEP_HEIGHT + STEP_STATE_HEIGHT + 3) unusable rows.
        MAX_STEP_HEIGHT + STEP_STATE_HEIGHT + 3
    }

    fn new_from_block(block: &witness::Block<F>) -> Self {
        Self::new(block.clone())
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        let num_rows_required_for_execution_steps: usize = Self::get_num_rows_required(block);
        let num_rows_required_for_fixed_table: usize = detect_fixed_table_tags(block)
            .iter()
            .map(|tag| tag.build::<F>().count())
            .sum();
        (
            std::cmp::max(
                num_rows_required_for_execution_steps,
                num_rows_required_for_fixed_table,
            ),
            block.circuits_params.max_evm_rows,
        )
    }

    /// Make the assignments to the EvmCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let block = self.block.as_ref().unwrap();

        config.load_fixed_table(layouter, self.fixed_table_tags.clone())?;
        config.execution.assign_block(layouter, block, challenges)
    }
}

/// create fixed_table_tags needed given witness block
pub(crate) fn detect_fixed_table_tags<F: Field>(block: &Block<F>) -> Vec<FixedTableTag> {
    let need_bitwise_lookup = block.txs.iter().any(|tx| {
        tx.steps().iter().any(|step| {
            matches!(
                step.opcode(),
                Some(OpcodeId::AND)
                    | Some(OpcodeId::OR)
                    | Some(OpcodeId::XOR)
                    | Some(OpcodeId::NOT)
            )
        })
    });
    FixedTableTag::iter()
        .filter(|t| {
            !matches!(
                t,
                FixedTableTag::BitwiseAnd | FixedTableTag::BitwiseOr | FixedTableTag::BitwiseXor
            ) || need_bitwise_lookup
        })
        .collect()
}

#[cfg(any(feature = "test-util", test))]
pub(crate) mod cached {
    use super::*;
    use halo2_proofs::halo2curves::bn256::Fr;
    use lazy_static::lazy_static;

    struct Cache {
        cs: ConstraintSystem<Fr>,
        config: (EvmCircuitConfig<Fr>, Challenges),
    }

    lazy_static! {
        /// Cached values of the ConstraintSystem after the EVM Circuit configuration and the EVM
        /// Circuit configuration.  These values are calculated just once.
        static ref CACHE: Cache = {
            let mut meta = ConstraintSystem::<Fr>::default();
            let config = EvmCircuit::<Fr>::configure(&mut meta);
            Cache { cs: meta, config }
        };
    }

    /// Wrapper over the EvmCircuit that behaves the same way and also
    /// implements the halo2 Circuit trait, but reuses the precalculated
    /// results of the configuration which are cached in the public variable
    /// `CACHE`.  This wrapper is useful for testing because it allows running
    /// many unit tests while reusing the configuration step of the circuit.
    pub struct EvmCircuitCached(EvmCircuit<Fr>);

    impl Circuit<Fr> for EvmCircuitCached {
        type Config = (EvmCircuitConfig<Fr>, Challenges);
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self(self.0.without_witnesses())
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            *meta = CACHE.cs.clone();
            CACHE.config.clone()
        }

        fn synthesize(
            &self,
            config: Self::Config,
            layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            self.0.synthesize(config, layouter)
        }
    }
}

// Always exported because of `EXECUTION_STATE_HEIGHT_MAP`
impl<F: Field> Circuit<F> for EvmCircuit<F> {
    type Config = (EvmCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let tx_table = TxTable::construct(meta);
        let rw_table = RwTable::construct(meta);
        let bytecode_table = BytecodeTable::construct(meta);
        let block_table = BlockTable::construct(meta);
        let q_copy_table = meta.fixed_column();
        let copy_table = CopyTable::construct(meta, q_copy_table);
        let keccak_table = KeccakTable::construct(meta);
        let exp_table = ExpTable::construct(meta);
        let u8_table = UXTable::construct(meta);
        let u16_table = UXTable::construct(meta);
        let challenges = Challenges::construct(meta);
        let challenges_expr = challenges.exprs(meta);

        (
            EvmCircuitConfig::new(
                meta,
                EvmCircuitConfigArgs {
                    challenges: challenges_expr,
                    tx_table,
                    rw_table,
                    bytecode_table,
                    block_table,
                    copy_table,
                    keccak_table,
                    exp_table,
                    u8_table,
                    u16_table,
                },
            ),
            challenges,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let block = self.block.as_ref().unwrap();

        let (config, challenges) = config;
        let challenges = challenges.values(&mut layouter);

        config.tx_table.load(
            &mut layouter,
            &block.txs,
            block.circuits_params.max_txs,
            block.circuits_params.max_calldata,
        )?;
        block.rws.check_rw_counter_sanity();
        config.rw_table.load(
            &mut layouter,
            &block.rws.table_assignments(),
            block.circuits_params.max_rws,
        )?;
        config
            .bytecode_table
            .load(&mut layouter, block.bytecodes.clone())?;
        config.block_table.load(&mut layouter, &block.context)?;
        config.copy_table.load(&mut layouter, block, &challenges)?;
        config
            .keccak_table
            .dev_load(&mut layouter, &block.sha3_inputs, &challenges)?;
        config.exp_table.load(&mut layouter, block)?;

        config.u8_table.load(&mut layouter)?;
        config.u16_table.load(&mut layouter)?;

        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}

