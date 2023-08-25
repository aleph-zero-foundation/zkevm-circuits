use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_GAS,
        step::ExecutionState,
        util::{
            common_gadget::{CommonCallGadget, CommonErrorGadget},
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::{IsZeroGadget, LtGadget},
            CachedRegion, Cell,
        },
    },
    table::CallContextFieldTag,
    util::Expr,
    witness::{Block, Call, ExecStep, Transaction},
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, U256};
use halo2_proofs::{circuit::Value, plonk::Error};

/// Gadget to implement the corresponding out of gas errors for
/// [`OpcodeId::CALL`], [`OpcodeId::CALLCODE`], [`OpcodeId::DELEGATECALL`] and
/// [`OpcodeId::STATICCALL`].
#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGCallGadget<F> {
    opcode: Cell<F>,
    is_call: IsZeroGadget<F>,
    is_callcode: IsZeroGadget<F>,
    is_delegatecall: IsZeroGadget<F>,
    is_staticcall: IsZeroGadget<F>,
    tx_id: Cell<F>,
    is_static: Cell<F>,
    call: CommonCallGadget<F, false>,
    is_warm: Cell<F>,
    insufficient_gas: LtGadget<F, N_BYTES_GAS>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGCallGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasCall";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasCall;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let is_call = IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::CALL.expr());
        let is_callcode = IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::CALLCODE.expr());
        let is_delegatecall =
            IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::DELEGATECALL.expr());
        let is_staticcall =
            IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::STATICCALL.expr());

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let is_static = cb.call_context(None, CallContextFieldTag::IsStatic);

        let call_gadget = CommonCallGadget::construct(
            cb,
            is_call.expr(),
            is_callcode.expr(),
            is_delegatecall.expr(),
            is_staticcall.expr(),
        );

        // Add callee to access list
        let is_warm = cb.query_bool();
        cb.account_access_list_read(tx_id.expr(), call_gadget.callee_address(), is_warm.expr());

        cb.condition(call_gadget.has_value.expr(), |cb| {
            cb.require_zero(
                "CALL with value must not be in static call stack",
                is_static.expr(),
            );
        });

        // Verify gas cost
        let gas_cost = call_gadget.gas_cost_expr(is_warm.expr(), is_call.expr());

        // Check if the amount of gas available is less than the amount of gas required
        let insufficient_gas = LtGadget::construct(cb, cb.curr.state.gas_left.expr(), gas_cost);
        cb.require_equal(
            "gas left is less than gas required",
            insufficient_gas.expr(),
            1.expr(),
        );

        // Both CALL and CALLCODE opcodes have an extra stack pop `value` relative to
        // DELEGATECALL and STATICCALL.
        let common_error_gadget = CommonErrorGadget::construct(
            cb,
            opcode.expr(),
            13.expr() + is_call.expr() + is_callcode.expr(),
        );

        Self {
            opcode,
            is_call,
            is_callcode,
            is_delegatecall,
            is_staticcall,
            tx_id,
            is_static,
            call: call_gadget,
            is_warm,
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
        let is_call_or_callcode =
            usize::from([OpcodeId::CALL, OpcodeId::CALLCODE].contains(&opcode));
        let [tx_id, is_static] =
            [0, 1].map(|index| block.get_rws(step, index).call_context_value());
        let [gas, callee_address] = [2, 3].map(|index| block.get_rws(step, index).stack_value());
        let value = if is_call_or_callcode == 1 {
            block.get_rws(step, 4).stack_value()
        } else {
            U256::zero()
        };
        let [cd_offset, cd_length, rd_offset, rd_length] =
            [4, 5, 6, 7].map(|i| block.get_rws(step, is_call_or_callcode + i).stack_value());

        let callee_code_hash = block
            .get_rws(step, 9 + is_call_or_callcode)
            .account_value_pair()
            .0;
        let callee_exists = !callee_code_hash.is_zero();

        let (is_warm, is_warm_prev) = block
            .get_rws(step, 10 + is_call_or_callcode)
            .tx_access_list_value_pair();

        let memory_expansion_gas_cost = self.call.assign(
            region,
            offset,
            gas,
            callee_address,
            value,
            U256::from(0),
            cd_offset,
            cd_length,
            rd_offset,
            rd_length,
            step.memory_word_size(),
            callee_code_hash,
        )?;

        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;

        self.is_call.assign(
            region,
            offset,
            F::from(opcode.as_u64()) - F::from(OpcodeId::CALL.as_u64()),
        )?;
        self.is_callcode.assign(
            region,
            offset,
            F::from(opcode.as_u64()) - F::from(OpcodeId::CALLCODE.as_u64()),
        )?;
        self.is_delegatecall.assign(
            region,
            offset,
            F::from(opcode.as_u64()) - F::from(OpcodeId::DELEGATECALL.as_u64()),
        )?;
        self.is_staticcall.assign(
            region,
            offset,
            F::from(opcode.as_u64()) - F::from(OpcodeId::STATICCALL.as_u64()),
        )?;

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx_id.low_u64())))?;

        self.is_static
            .assign(region, offset, Value::known(F::from(is_static.low_u64())))?;

        self.is_warm
            .assign(region, offset, Value::known(F::from(is_warm as u64)))?;

        let has_value = !value.is_zero();
        let gas_cost = self.call.cal_gas_cost_for_assignment(
            memory_expansion_gas_cost,
            is_warm_prev,
            true,
            has_value,
            !callee_exists,
        )?;

        self.insufficient_gas.assign_value(
            region,
            offset,
            Value::known(F::from(step.gas_left)),
            Value::known(F::from(gas_cost)),
        )?;

        // Both CALL and CALLCODE opcodes have an extra stack pop `value` relative to
        // DELEGATECALL and STATICCALL.
        self.common_error_gadget.assign(
            region,
            offset,
            block,
            call,
            step,
            13 + is_call_or_callcode,
        )?;
        Ok(())
    }
}

