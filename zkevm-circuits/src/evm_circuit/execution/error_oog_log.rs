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
                CommonMemoryAddressGadget, MemoryAddressGadget, MemoryExpansionGadget,
            },
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

#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGLogGadget<F> {
    opcode: Cell<F>,
    // memory address
    memory_address: MemoryAddressGadget<F>,
    is_static_call: Cell<F>,
    is_opcode_logn: LtGadget<F, 1>,
    // constrain gas left is less than gas cost
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    insufficient_gas: LtGadget<F, N_BYTES_GAS>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGLogGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasLOG";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasLOG;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        let mstart = cb.query_word_unchecked();
        let msize = cb.query_memory_address();

        // Pop mstart_address, msize from stack
        cb.stack_pop(mstart.to_word());
        cb.stack_pop(msize.to_word());

        // constrain not in static call
        let is_static_call = cb.call_context(None, CallContextFieldTag::IsStatic);
        cb.require_zero("is_static_call is false in LOGN", is_static_call.expr());

        let topic_count = opcode.expr() - OpcodeId::LOG0.as_u8().expr();
        let is_opcode_logn = LtGadget::construct(cb, topic_count.clone(), 5.expr());
        cb.require_equal(
            "topic count in [0..5) which means opcode is Log0...Log4 ",
            is_opcode_logn.expr(),
            1.expr(),
        );

        // check memory
        let memory_address = MemoryAddressGadget::construct(cb, mstart, msize);

        // Calculate the next memory size and the gas cost for this memory
        // access
        let memory_expansion = MemoryExpansionGadget::construct(cb, [memory_address.address()]);

        let gas_cost = GasCost::LOG.expr()
            + GasCost::LOG.expr() * topic_count
            + 8.expr() * memory_address.length()
            + memory_expansion.gas_cost();

        // Check if the amount of gas available is less than the amount of gas
        // required
        let insufficient_gas = LtGadget::construct(cb, cb.curr.state.gas_left.expr(), gas_cost);
        cb.require_equal(
            "gas left is less than gas required ",
            insufficient_gas.expr(),
            1.expr(),
        );

        let common_error_gadget = CommonErrorGadget::construct(cb, opcode.expr(), 5.expr());

        Self {
            opcode,
            is_static_call,
            is_opcode_logn,
            memory_address,
            memory_expansion,
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
        let opcode = step.opcode().unwrap();
        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;

        let [memory_start, msize] = [0, 1].map(|index| block.get_rws(step, index).stack_value());

        let memory_address = self
            .memory_address
            .assign(region, offset, memory_start, msize)?;

        // Memory expansion
        self.memory_expansion
            .assign(region, offset, step.memory_word_size(), [memory_address])?;

        let topic_count = opcode.postfix().expect("opcode with postfix") as u64;
        assert!(topic_count <= 4);
        self.is_static_call
            .assign(region, offset, Value::known(F::from(call.is_static as u64)))?;

        self.is_opcode_logn
            .assign(region, offset, F::from(topic_count), F::from(5u64))?;

        // Gas insufficient check
        self.insufficient_gas.assign(
            region,
            offset,
            F::from(step.gas_left),
            F::from(step.gas_cost),
        )?;
        self.common_error_gadget
            .assign(region, offset, block, call, step, 5)?;
        Ok(())
    }
}

