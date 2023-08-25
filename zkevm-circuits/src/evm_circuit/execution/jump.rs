use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                EVMConstraintBuilder, StepStateTransition,
                Transition::{Delta, To},
            },
            CachedRegion, U64Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::{word::WordExpr, Expr},
};
use eth_types::{evm_types::OpcodeId, Field};
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct JumpGadget<F> {
    same_context: SameContextGadget<F>,
    destination: U64Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for JumpGadget<F> {
    const NAME: &'static str = "JUMP";

    const EXECUTION_STATE: ExecutionState = ExecutionState::JUMP;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let destination = cb.query_u64();

        // Pop the value from the stack
        cb.stack_pop(destination.to_word());

        // Lookup opcode at destination
        cb.opcode_lookup_at(destination.expr(), OpcodeId::JUMPDEST.expr(), 1.expr());

        // State transition
        let opcode = cb.query_cell();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(1.expr()),
            program_counter: To(destination.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::JUMP.constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            destination,
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

        let destination = block.get_rws(step, 0).stack_value();
        self.destination.assign_u256(region, offset, destination)?;

        Ok(())
    }
}

