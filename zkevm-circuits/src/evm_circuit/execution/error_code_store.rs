use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_GAS, N_BYTES_U64},
        step::ExecutionState,
        util::{
            common_gadget::CommonErrorGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::LtGadget,
            memory_gadget::{CommonMemoryAddressGadget, MemoryAddressGadget},
            CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::{word::WordExpr, Expr},
};

use eth_types::{
    evm_types::{GasCost, OpcodeId},
    Field,
};

use halo2_proofs::{circuit::Value, plonk::Error};

const MAXCODESIZE: u64 = 0x6000u64;

/// Gadget for code store oog and max code size exceed
#[derive(Clone, Debug)]
pub(crate) struct ErrorCodeStoreGadget<F> {
    opcode: Cell<F>,
    memory_address: MemoryAddressGadget<F>,
    // check not static call
    is_static: Cell<F>,
    // check for CodeStoreOutOfGas error
    code_store_gas_insufficient: LtGadget<F, N_BYTES_GAS>,
    // check for MaxCodeSizeExceeded error
    max_code_size_exceed: LtGadget<F, N_BYTES_U64>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorCodeStoreGadget<F> {
    const NAME: &'static str = "ErrorCodeStore";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorCodeStore;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.require_equal(
            "ErrorCodeStore checking at RETURN in create context ",
            opcode.expr(),
            OpcodeId::RETURN.expr(),
        );

        let offset = cb.query_word_unchecked();
        let length = cb.query_memory_address();
        cb.stack_pop(offset.to_word());
        cb.stack_pop(length.to_word());
        let memory_address = MemoryAddressGadget::construct(cb, offset, length);
        // constrain not in static call
        let is_static = cb.call_context(None, CallContextFieldTag::IsStatic);
        cb.require_zero("is_static is false in ErrorCodeStore", is_static.expr());

        cb.require_true("is_create is true", cb.curr.state.is_create.expr());

        // constrain code store gas > gas left, that is GasCost::CODE_DEPOSIT_BYTE_COST
        // * length > gas left
        let code_store_gas_insufficient = LtGadget::construct(
            cb,
            cb.curr.state.gas_left.expr(),
            GasCost::CODE_DEPOSIT_BYTE_COST.expr() * memory_address.length(),
        );

        // constrain code size > MAXCODESIZE
        let max_code_size_exceed =
            LtGadget::construct(cb, MAXCODESIZE.expr(), memory_address.length());

        // check must be one of CodeStoreOutOfGas or MaxCodeSizeExceeded
        cb.require_in_set(
            "CodeStoreOutOfGas or MaxCodeSizeExceeded",
            code_store_gas_insufficient.expr() + max_code_size_exceed.expr(),
            vec![1.expr(), 2.expr()],
        );

        let common_error_gadget = CommonErrorGadget::construct_with_return_data(
            cb,
            opcode.expr(),
            5.expr(),
            memory_address.offset(),
            memory_address.length(),
        );

        Self {
            opcode,
            memory_address,
            is_static,
            code_store_gas_insufficient,
            max_code_size_exceed,
            common_error_gadget,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode().unwrap();
        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;
        let [memory_offset, length] = [0, 1].map(|i| block.get_rws(step, i).stack_value());
        self.memory_address
            .assign(region, offset, memory_offset, length)?;

        self.is_static
            .assign(region, offset, Value::known(F::from(call.is_static as u64)))?;
        self.code_store_gas_insufficient.assign(
            region,
            offset,
            F::from(step.gas_left),
            F::from(GasCost::CODE_DEPOSIT_BYTE_COST * length.as_u64()),
        )?;

        self.max_code_size_exceed.assign(
            region,
            offset,
            F::from(MAXCODESIZE),
            F::from(length.as_u64()),
        )?;

        self.common_error_gadget
            .assign(region, offset, block, call, step, 5)?;
        Ok(())
    }
}

