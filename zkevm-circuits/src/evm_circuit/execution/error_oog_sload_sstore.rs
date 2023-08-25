use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_GAS,
        step::ExecutionState,
        util::{
            and,
            common_gadget::{
                cal_sload_gas_cost_for_assignment, cal_sstore_gas_cost_for_assignment,
                CommonErrorGadget, SloadGasGadget, SstoreGasGadget,
            },
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::{LtGadget, PairSelectGadget},
            or, select, CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::{
        word::{Word, WordCell, WordExpr},
        Expr,
    },
};
use eth_types::{
    evm_types::{GasCost, OpcodeId},
    Field, U256,
};
use halo2_proofs::{circuit::Value, plonk::Error};

/// Gadget to implement the corresponding out of gas errors for
/// [`OpcodeId::SLOAD`] and [`OpcodeId::SSTORE`].
#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGSloadSstoreGadget<F> {
    opcode: Cell<F>,
    tx_id: Cell<F>,
    is_static: Cell<F>,
    callee_address: WordCell<F>,
    key: WordCell<F>,
    value: WordCell<F>,
    value_prev: WordCell<F>,
    original_value: WordCell<F>,
    is_warm: Cell<F>,
    is_sstore: PairSelectGadget<F>,
    sstore_gas_cost: SstoreGasGadget<F, WordCell<F>>,
    insufficient_gas_cost: LtGadget<F, N_BYTES_GAS>,
    // Constrain for SSTORE reentrancy sentry.
    insufficient_gas_sentry: LtGadget<F, N_BYTES_GAS>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGSloadSstoreGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasSloadSstore";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasSloadSstore;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let is_sstore = PairSelectGadget::construct(
            cb,
            opcode.expr(),
            OpcodeId::SSTORE.expr(),
            OpcodeId::SLOAD.expr(),
        );

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let is_static = cb.call_context(None, CallContextFieldTag::IsStatic);
        let callee_address = cb.call_context_read_as_word(None, CallContextFieldTag::CalleeAddress);

        // Constrain `is_static` must be false for SSTORE.
        cb.require_zero("is_static == false", is_static.expr() * is_sstore.expr().0);

        let key = cb.query_word_unchecked();
        let value = cb.query_word_unchecked();
        let value_prev = cb.query_word_unchecked();
        let original_value = cb.query_word_unchecked();
        let is_warm = cb.query_bool();

        cb.stack_pop(key.to_word());
        cb.account_storage_access_list_read(
            tx_id.expr(),
            callee_address.to_word(),
            key.to_word(),
            Word::from_lo_unchecked(is_warm.expr()),
        );

        let sload_gas_cost = SloadGasGadget::construct(cb, is_warm.expr());
        let sstore_gas_cost = cb.condition(is_sstore.expr().0, |cb| {
            cb.stack_pop(value.to_word());

            cb.account_storage_read(
                callee_address.to_word(),
                key.to_word(),
                value_prev.to_word(),
                tx_id.expr(),
                original_value.to_word(),
            );

            SstoreGasGadget::construct(
                cb,
                is_warm.clone(),
                value.clone(),
                value_prev.clone(),
                original_value.clone(),
            )
        });

        let insufficient_gas_cost = LtGadget::construct(
            cb,
            cb.curr.state.gas_left.expr(),
            select::expr(
                is_sstore.expr().0,
                sstore_gas_cost.expr(),
                sload_gas_cost.expr(),
            ),
        );
        // Constrain for SSTORE reentrancy sentry.
        let insufficient_gas_sentry = LtGadget::construct(
            cb,
            cb.curr.state.gas_left.expr(),
            (GasCost::SSTORE_SENTRY + 1).expr(),
        );
        cb.require_equal(
            "Gas left is less than gas cost or gas sentry (only for SSTORE)",
            or::expr([
                insufficient_gas_cost.expr(),
                and::expr([is_sstore.expr().0, insufficient_gas_sentry.expr()]),
            ]),
            1.expr(),
        );

        let common_error_gadget = CommonErrorGadget::construct(
            cb,
            opcode.expr(),
            7.expr() + 2.expr() * is_sstore.expr().0,
        );

        Self {
            opcode,
            tx_id,
            is_static,
            callee_address,
            key,
            value,
            value_prev,
            original_value,
            is_warm,
            is_sstore,
            sstore_gas_cost,
            insufficient_gas_cost,
            insufficient_gas_sentry,
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
        let is_sstore = opcode == OpcodeId::SSTORE;
        let key = block.get_rws(step, 3).stack_value();
        let (is_warm, _) = block.get_rws(step, 4).tx_access_list_value_pair();

        let (value, value_prev, original_value, gas_cost) = if is_sstore {
            let value = block.get_rws(step, 5).stack_value();
            let (_, value_prev, _, original_value) = block.get_rws(step, 6).storage_value_aux();
            let gas_cost =
                cal_sstore_gas_cost_for_assignment(value, value_prev, original_value, is_warm);
            (value, value_prev, original_value, gas_cost)
        } else {
            let gas_cost = cal_sload_gas_cost_for_assignment(is_warm);
            (U256::zero(), U256::zero(), U256::zero(), gas_cost)
        };

        log::debug!(
            "ErrorOutOfGasSloadSstore: is_sstore = {}, gas_left = {}, gas_cost = {}, gas_sentry = {}",
            is_sstore,
            step.gas_left,
            gas_cost,
            if is_sstore { GasCost::SSTORE_SENTRY } else { 0 },
        );

        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;
        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id)))?;
        self.is_static
            .assign(region, offset, Value::known(F::from(call.is_static as u64)))?;
        self.callee_address
            .assign_h160(region, offset, call.address)?;
        self.key.assign_u256(region, offset, key)?;
        self.value.assign_u256(region, offset, value)?;
        self.value_prev.assign_u256(region, offset, value_prev)?;
        self.original_value
            .assign_u256(region, offset, original_value)?;
        self.is_warm
            .assign(region, offset, Value::known(F::from(is_warm as u64)))?;

        self.is_sstore.assign(
            region,
            offset,
            F::from(opcode.as_u64()),
            F::from(OpcodeId::SSTORE.as_u64()),
            F::from(OpcodeId::SLOAD.as_u64()),
        )?;
        self.sstore_gas_cost
            .assign(region, offset, value, value_prev, original_value, is_warm)?;
        self.insufficient_gas_cost.assign_value(
            region,
            offset,
            Value::known(F::from(step.gas_left)),
            Value::known(F::from(gas_cost)),
        )?;
        self.insufficient_gas_sentry.assign_value(
            region,
            offset,
            Value::known(F::from(step.gas_left)),
            Value::known(F::from(GasCost::SSTORE_SENTRY.checked_add(1).unwrap())),
        )?;

        // Additional one stack pop and one account storage read for SSTORE.
        self.common_error_gadget.assign(
            region,
            offset,
            block,
            call,
            step,
            7 + usize::from(is_sstore) * 2,
        )?;

        Ok(())
    }
}

