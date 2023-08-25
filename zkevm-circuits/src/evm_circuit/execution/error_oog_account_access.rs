use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_GAS,
        step::ExecutionState,
        util::{
            common_gadget::CommonErrorGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::LtGadget,
            select, AccountAddress, CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::{word::WordExpr, Expr},
};
use eth_types::{
    evm_types::{GasCost, OpcodeId},
    Field, ToAddress,
};
use halo2_proofs::{circuit::Value, plonk::Error};

/// Gadget to implement the corresponding out of gas errors for
/// [`OpcodeId::BALANCE`,`OpcodeId::EXTCODESIZE`, `OpcodeId::EXTCODEHASH`].
#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGAccountAccessGadget<F> {
    opcode: Cell<F>,
    address: AccountAddress<F>,
    tx_id: Cell<F>,
    is_warm: Cell<F>,
    insufficient_gas_cost: LtGadget<F, N_BYTES_GAS>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGAccountAccessGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasAccountAccess";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasAccountAccess;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.require_in_set(
            "ErrorOutOfGasAccountAccess happens for BALANCE | EXTCODESIZE | EXTCODEHASH ",
            opcode.expr(),
            vec![
                OpcodeId::BALANCE.expr(),
                OpcodeId::EXTCODESIZE.expr(),
                OpcodeId::EXTCODEHASH.expr(),
            ],
        );
        let address = cb.query_account_address();
        cb.stack_pop(address.to_word());

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let is_warm = cb.query_bool();
        // read is_warm
        cb.account_access_list_read(tx_id.expr(), address.to_word(), is_warm.expr());

        let gas_cost = select::expr(
            is_warm.expr(),
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_ACCOUNT_ACCESS.expr(),
        );

        let insufficient_gas_cost =
            LtGadget::construct(cb, cb.curr.state.gas_left.expr(), gas_cost);

        cb.require_equal(
            "Gas left is less than gas cost",
            insufficient_gas_cost.expr(),
            1.expr(),
        );

        let common_error_gadget = CommonErrorGadget::construct(cb, opcode.expr(), 5.expr());
        Self {
            opcode,
            address,
            tx_id,
            is_warm,
            insufficient_gas_cost,
            common_error_gadget,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode().unwrap();
        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;

        let address = block.get_rws(step, 0).stack_value();
        self.address
            .assign_h160(region, offset, address.to_address())?;

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id)))?;

        let (_, is_warm) = block.get_rws(step, 2).tx_access_list_value_pair();
        self.is_warm
            .assign(region, offset, Value::known(F::from(is_warm as u64)))?;

        // BALANCE EXTCODESIZE EXTCODEHASH shares same gas cost model
        let gas_cost = if is_warm {
            GasCost::WARM_ACCESS
        } else {
            GasCost::COLD_ACCOUNT_ACCESS
        };

        self.insufficient_gas_cost.assign_value(
            region,
            offset,
            Value::known(F::from(step.gas_left)),
            Value::known(F::from(gas_cost)),
        )?;
        self.common_error_gadget
            .assign(region, offset, block, call, step, 5)?;

        Ok(())
    }
}

