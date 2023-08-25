use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::CommonErrorGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::IsEqualGadget,
            memory_gadget::{CommonMemoryAddressGadget, MemoryAddressGadget},
            CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::{word::WordExpr, Expr},
};
use eth_types::{evm_types::INVALID_INIT_CODE_FIRST_BYTE, Field};
use halo2_proofs::{circuit::Value, plonk::Error};

/// Gadget for the invalid creation code error
#[derive(Clone, Debug)]
pub(crate) struct ErrorInvalidCreationCodeGadget<F> {
    opcode: Cell<F>,
    first_byte: Cell<F>,
    is_first_byte_invalid: IsEqualGadget<F>,
    memory_address: MemoryAddressGadget<F>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorInvalidCreationCodeGadget<F> {
    const NAME: &'static str = "ErrorInvalidCreationCode";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorInvalidCreationCode;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        let first_byte = cb.query_cell();

        let offset = cb.query_word_unchecked();
        let length = cb.query_memory_address();

        cb.stack_pop(offset.to_word());
        cb.stack_pop(length.to_word());
        cb.require_true("is_create is true", cb.curr.state.is_create.expr());

        let memory_address = MemoryAddressGadget::construct(cb, offset, length);
        cb.memory_lookup(0.expr(), memory_address.offset(), first_byte.expr(), None);

        let is_first_byte_invalid =
            IsEqualGadget::construct(cb, first_byte.expr(), INVALID_INIT_CODE_FIRST_BYTE.expr());
        cb.require_true(
            "is_first_byte_invalid is true",
            is_first_byte_invalid.expr(),
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
            first_byte,
            is_first_byte_invalid,
            memory_address,
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

        let [memory_offset, length] = [0, 1].map(|i| block.rws[step.rw_index(i)].stack_value());
        self.memory_address
            .assign(region, offset, memory_offset, length)?;

        let first_byte = block.rws[step.rw_index(2)].memory_value().into();
        self.first_byte
            .assign(region, offset, Value::known(F::from(first_byte)))?;
        self.is_first_byte_invalid.assign(
            region,
            offset,
            F::from(first_byte),
            F::from(INVALID_INIT_CODE_FIRST_BYTE.into()),
        )?;

        self.common_error_gadget
            .assign(region, offset, block, call, step, 5)?;

        Ok(())
    }
}

