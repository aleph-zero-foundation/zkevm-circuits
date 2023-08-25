use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_WORD,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, StepStateTransition,
                Transition::Delta,
            },
            CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::{word::Word, Expr},
};
use bus_mapping::evm::OpcodeId;
use eth_types::Field;
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct MsizeGadget<F> {
    same_context: SameContextGadget<F>,
    value: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for MsizeGadget<F> {
    const NAME: &'static str = "MSIZE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::MSIZE;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let value = cb.query_cell();

        // memory_size is limited to 64 bits
        // constrain equality with step state therefore only use single cell
        cb.require_equal(
            "Constrain memory_size equal to stack value",
            value.expr(),
            cb.curr.state.memory_word_size.expr() * N_BYTES_WORD.expr(),
        );

        // Push the value on the stack
        cb.stack_push(Word::from_lo_unchecked(value.expr()));

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(1.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            gas_left: Delta(-OpcodeId::MSIZE.constant_gas_cost().expr()),
            ..Default::default()
        };
        let opcode = cb.query_cell();
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            value,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        _: &Block<F>,
        _: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;
        self.value.assign(
            region,
            offset,
            Value::known(F::from(step.memory_size as u64)),
        )?;

        Ok(())
    }
}

