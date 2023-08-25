use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_GAS, N_BYTES_MEMORY_WORD_SIZE},
        step::ExecutionState,
        util::{
            common_gadget::CommonErrorGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::LtGadget,
            memory_gadget::{
                CommonMemoryAddressGadget, MemoryCopierGasGadget, MemoryExpandedAddressGadget,
                MemoryExpansionGadget,
            },
            or, CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::{
    evm_types::{GasCost, OpcodeId},
    Field,
};
use halo2_proofs::{circuit::Value, plonk::Error};

/// Gadget to implement the corresponding out of gas error for
/// [`OpcodeId::SHA3`].
#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGSha3Gadget<F> {
    opcode: Cell<F>,
    memory_address: MemoryExpandedAddressGadget<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    memory_copier_gas: MemoryCopierGasGadget<F, { GasCost::COPY_SHA3 }>,
    insufficient_gas: LtGadget<F, N_BYTES_GAS>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGSha3Gadget<F> {
    const NAME: &'static str = "ErrorOutOfGasSHA3";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasSHA3;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.require_equal(
            "ErrorOutOfGasSHA3 opcode must be SHA3",
            opcode.expr(),
            OpcodeId::SHA3.expr(),
        );

        let memory_address = MemoryExpandedAddressGadget::construct_self(cb);
        cb.stack_pop(memory_address.offset_word());
        cb.stack_pop(memory_address.length_word());

        let memory_expansion = MemoryExpansionGadget::construct(cb, [memory_address.address()]);
        let memory_copier_gas = MemoryCopierGasGadget::construct(
            cb,
            memory_address.length(),
            memory_expansion.gas_cost(),
        );

        let insufficient_gas = LtGadget::construct(
            cb,
            cb.curr.state.gas_left.expr(),
            OpcodeId::SHA3.constant_gas_cost().expr() + memory_copier_gas.gas_cost(),
        );

        cb.require_equal(
            "Memory address is overflow or gas left is less than cost",
            or::expr([memory_address.overflow(), insufficient_gas.expr()]),
            1.expr(),
        );

        let common_error_gadget = CommonErrorGadget::construct(cb, opcode.expr(), 4.expr());

        Self {
            opcode,
            memory_address,
            memory_expansion,
            memory_copier_gas,
            insufficient_gas,
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
        log::debug!(
            "ErrorOutOfGasSHA3: gas_cost = {}, gas_left = {}",
            step.gas_cost,
            step.gas_left,
        );

        let opcode = step.opcode();
        self.opcode.assign(
            region,
            offset,
            Value::known(F::from(opcode.unwrap().as_u64())),
        )?;

        let [memory_offset, memory_length] =
            [0, 1].map(|idx| block.get_rws(step, idx).stack_value());

        let expanded_address =
            self.memory_address
                .assign(region, offset, memory_offset, memory_length)?;
        let (_, memory_expansion_cost) = self.memory_expansion.assign(
            region,
            offset,
            step.memory_word_size(),
            [expanded_address],
        )?;
        let memory_copier_gas = self.memory_copier_gas.assign(
            region,
            offset,
            MemoryExpandedAddressGadget::<F>::length_value(memory_offset, memory_length),
            memory_expansion_cost,
        )?;
        self.insufficient_gas.assign_value(
            region,
            offset,
            Value::known(F::from(step.gas_left)),
            Value::known(F::from(
                OpcodeId::SHA3.constant_gas_cost() + memory_copier_gas,
            )),
        )?;
        self.common_error_gadget
            .assign(region, offset, block, call, step, 4)?;

        Ok(())
    }
}

