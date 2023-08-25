use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{EVMConstraintBuilder, StepStateTransition, Transition::Delta},
            CachedRegion,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::{
        word::{WordCell, WordExpr},
        Expr,
    },
};
use eth_types::{evm_types::OpcodeId, Field};
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct DupGadget<F> {
    same_context: SameContextGadget<F>,
    value: WordCell<F>,
}

impl<F: Field> ExecutionGadget<F> for DupGadget<F> {
    const NAME: &'static str = "DUP";

    const EXECUTION_STATE: ExecutionState = ExecutionState::DUP;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let value = cb.query_word_unchecked();

        // The stack index we have to peek, deduced from the 'x' value of 'dupx'
        // The offset starts at 0 for DUP1
        let dup_offset = opcode.expr() - OpcodeId::DUP1.expr();

        // Peek the value at `dup_offset` and push the value on the stack
        cb.stack_lookup(false.expr(), dup_offset, value.to_word());
        cb.stack_push(value.to_word());

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            gas_left: Delta(-OpcodeId::DUP1.constant_gas_cost().expr()),
            ..Default::default()
        };
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
        block: &Block<F>,
        _: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let value = block.get_rws(step, 0).stack_value();
        self.value.assign_u256(region, offset, value)?;

        Ok(())
    }
}

