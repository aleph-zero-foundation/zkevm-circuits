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
    table::CallContextFieldTag,
    util::{
        word::{WordCell, WordExpr},
        Expr,
    },
};
use bus_mapping::evm::OpcodeId;
use eth_types::Field;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct CallDataSizeGadget<F> {
    same_context: SameContextGadget<F>,
    call_data_size: WordCell<F>,
}

impl<F: Field> ExecutionGadget<F> for CallDataSizeGadget<F> {
    const NAME: &'static str = "CALLDATASIZE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CALLDATASIZE;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        // Add lookup constraint in the call context for the calldatasize field.
        let call_data_size = cb.query_word_unchecked();
        cb.call_context_lookup_read(
            None,
            CallContextFieldTag::CallDataLength,
            call_data_size.to_word(),
        );

        // The calldatasize should be pushed to the top of the stack.
        cb.stack_push(call_data_size.to_word());

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            gas_left: Delta(-OpcodeId::CALLDATASIZE.constant_gas_cost().expr()),
            ..Default::default()
        };

        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            call_data_size,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _tx: &Transaction,
        _call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let call_data_size = block.get_rws(step, 1).stack_value();

        self.call_data_size
            .assign_u64(region, offset, call_data_size.as_u64())?;

        Ok(())
    }
}

