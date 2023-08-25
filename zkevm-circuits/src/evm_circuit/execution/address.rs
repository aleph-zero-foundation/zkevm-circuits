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
use eth_types::{Field, ToAddress};
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct AddressGadget<F> {
    same_context: SameContextGadget<F>,
    address: WordCell<F>,
}

impl<F: Field> ExecutionGadget<F> for AddressGadget<F> {
    const NAME: &'static str = "ADDRESS";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ADDRESS;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let address = cb.query_word_unchecked();

        // Lookup callee address in call context.
        cb.call_context_lookup_read(None, CallContextFieldTag::CalleeAddress, address.to_word());

        cb.stack_push(address.to_word());

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            gas_left: Delta(-OpcodeId::ADDRESS.constant_gas_cost().expr()),
            ..Default::default()
        };

        let opcode = cb.query_cell();
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            address,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let address = block.get_rws(step, 1).stack_value();
        debug_assert_eq!(call.address, address.to_address());

        self.address
            .assign_h160(region, offset, address.to_address())?;

        Ok(())
    }
}

