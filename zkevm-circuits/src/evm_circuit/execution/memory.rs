use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_MEMORY_WORD_SIZE,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                EVMConstraintBuilder, StepStateTransition,
                Transition::{Delta, To},
            },
            math_gadget::IsEqualGadget,
            memory_gadget::MemoryExpansionGadget,
            not, CachedRegion, MemoryAddress,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::{
        word::{Word32Cell, WordExpr},
        Expr,
    },
};
use eth_types::{evm_types::OpcodeId, Field};
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct MemoryGadget<F> {
    same_context: SameContextGadget<F>,
    address: MemoryAddress<F>,
    value: Word32Cell<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    is_mload: IsEqualGadget<F>,
    is_mstore8: IsEqualGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for MemoryGadget<F> {
    const NAME: &'static str = "MEMORY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::MEMORY;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        // In successful case the address must be in 5 bytes
        let address = cb.query_memory_address();
        let value = cb.query_word32();

        // Check if this is an MLOAD
        let is_mload = IsEqualGadget::construct(cb, opcode.expr(), OpcodeId::MLOAD.expr());
        // Check if this is an MSTORE8
        let is_mstore8 = IsEqualGadget::construct(cb, opcode.expr(), OpcodeId::MSTORE8.expr());
        // This is an MSTORE/MSTORE8
        let is_store = not::expr(is_mload.expr());
        // This is an MSTORE/MLOAD
        let is_not_mstore8 = not::expr(is_mstore8.expr());

        // Calculate the next memory size and the gas cost for this memory
        // access
        let memory_expansion = MemoryExpansionGadget::construct(
            cb,
            [address.expr() + 1.expr() + (is_not_mstore8.clone() * 31.expr())],
        );

        // Stack operations
        // Pop the address from the stack
        cb.stack_pop(address.to_word());
        // For MLOAD push the value to the stack
        // FOR MSTORE pop the value from the stack
        cb.stack_lookup(
            is_mload.expr(),
            cb.stack_pointer_offset().expr() - is_mload.expr(),
            value.to_word(),
        );

        cb.condition(is_mstore8.expr(), |cb| {
            cb.memory_lookup(1.expr(), address.expr(), value.limbs[0].expr(), None);
        });

        cb.condition(is_not_mstore8, |cb| {
            for idx in 0..32 {
                cb.memory_lookup(
                    is_store.clone(),
                    address.expr() + idx.expr(),
                    value.limbs[31 - idx].expr(),
                    None,
                );
            }
        });

        // State transition
        // - `rw_counter` needs to be increased by 34 when is_not_mstore8, otherwise to be increased
        //   by 31
        // - `program_counter` needs to be increased by 1
        // - `stack_pointer` needs to be increased by 2 when is_store, otherwise to be same
        // - `memory_size` needs to be set to `next_memory_size`
        let gas_cost = OpcodeId::MLOAD.constant_gas_cost().expr() + memory_expansion.gas_cost();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(34.expr() - is_mstore8.expr() * 31.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(is_store * 2.expr()),
            gas_left: Delta(-gas_cost),
            memory_word_size: To(memory_expansion.next_memory_word_size()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            address,
            value,
            memory_expansion,
            is_mload,
            is_mstore8,
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

        let opcode = step.opcode().unwrap();

        // Inputs/Outputs
        let [address, value] = [0, 1].map(|index| block.get_rws(step, index).stack_value());
        self.address.assign_u256(region, offset, address)?;
        self.value.assign_u256(region, offset, value)?;

        // Check if this is an MLOAD
        self.is_mload.assign(
            region,
            offset,
            F::from(opcode.as_u64()),
            F::from(OpcodeId::MLOAD.as_u64()),
        )?;
        // Check if this is an MSTORE8
        let is_mstore8 = self.is_mstore8.assign(
            region,
            offset,
            F::from(opcode.as_u64()),
            F::from(OpcodeId::MSTORE8.as_u64()),
        )?;

        // Memory expansion
        self.memory_expansion.assign(
            region,
            offset,
            step.memory_word_size(),
            [address.as_u64() + if is_mstore8 == F::ONE { 1 } else { 32 }],
        )?;

        Ok(())
    }
}

