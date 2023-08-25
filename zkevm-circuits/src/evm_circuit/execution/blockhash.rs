use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_U64,
        step::ExecutionState,
        util::{
            and,
            common_gadget::{SameContextGadget, WordByteCapGadget},
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, StepStateTransition,
                Transition::Delta,
            },
            math_gadget::LtGadget,
            CachedRegion, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::BlockContextFieldTag,
    util::word::WordExpr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToScalar};
use gadgets::util::{not, Expr};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct BlockHashGadget<F> {
    same_context: SameContextGadget<F>,
    block_number: WordByteCapGadget<F, N_BYTES_U64>,
    current_block_number: Cell<F>,
    block_hash: Word<Cell<F>>,
    diff_lt: LtGadget<F, N_BYTES_U64>,
}

impl<F: Field> ExecutionGadget<F> for BlockHashGadget<F> {
    const NAME: &'static str = "BLOCKHASH";

    const EXECUTION_STATE: ExecutionState = ExecutionState::BLOCKHASH;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let current_block_number = cb.query_cell();
        cb.block_lookup(
            BlockContextFieldTag::Number.expr(),
            None,
            Word::from_lo_unchecked(current_block_number.expr()),
        );

        let block_number = WordByteCapGadget::construct(cb, current_block_number.expr());
        cb.stack_pop(block_number.original_word().to_word());

        let block_hash = cb.query_word_unchecked();

        let diff_lt = LtGadget::construct(
            cb,
            current_block_number.expr(),
            257.expr() + block_number.valid_value(),
        );

        let is_valid = and::expr([block_number.lt_cap(), diff_lt.expr()]);

        cb.condition(is_valid.expr(), |cb| {
            cb.block_lookup(
                BlockContextFieldTag::BlockHash.expr(),
                Some(block_number.valid_value()),
                block_hash.to_word(),
            );
        });

        cb.condition(not::expr(is_valid), |cb| {
            cb.require_zero_word(
                "Invalid block number for block hash lookup",
                block_hash.to_word(),
            );
        });

        cb.stack_push(block_hash.to_word());

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::BLOCKHASH.constant_gas_cost().expr()),
            ..Default::default()
        };

        let opcode = cb.query_cell();
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);
        Self {
            same_context,
            block_number,
            current_block_number,
            block_hash,
            diff_lt,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let current_block_number = block.context.number;
        let current_block_number = current_block_number
            .to_scalar()
            .expect("unexpected U256 -> Scalar conversion failure");

        let block_number = block.get_rws(step, 0).stack_value();
        self.block_number
            .assign(region, offset, block_number, current_block_number)?;

        self.current_block_number
            .assign(region, offset, Value::known(current_block_number))?;

        self.block_hash
            .assign_u256(region, offset, block.get_rws(step, 1).stack_value())?;

        self.diff_lt.assign(
            region,
            offset,
            current_block_number,
            F::from(u64::try_from(block_number).unwrap_or(u64::MAX)) + F::from(257),
        )?;

        Ok(())
    }
}

