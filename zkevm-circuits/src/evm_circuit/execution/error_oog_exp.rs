use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_GAS,
        step::ExecutionState,
        util::{
            common_gadget::CommonErrorGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::{ByteSizeGadget, LtGadget},
            CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::{
        word::{Word32Cell, WordExpr},
        Expr,
    },
};
use eth_types::{
    evm_types::{GasCost, OpcodeId},
    Field,
};
use halo2_proofs::{circuit::Value, plonk::Error};

/// Gadget to implement the corresponding out of gas errors for
/// [`OpcodeId::EXP`].
#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGExpGadget<F> {
    opcode: Cell<F>,
    base: Word32Cell<F>,
    exponent: Word32Cell<F>,
    exponent_byte_size: ByteSizeGadget<F>,
    insufficient_gas_cost: LtGadget<F, N_BYTES_GAS>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGExpGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasEXP";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasEXP;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        cb.require_equal(
            "ErrorOutOfGasEXP opcode must be EXP",
            opcode.expr(),
            OpcodeId::EXP.expr(),
        );

        let base = cb.query_word32();
        let exponent = cb.query_word32();
        cb.stack_pop(base.to_word());
        cb.stack_pop(exponent.to_word());

        let exponent_byte_size = ByteSizeGadget::construct(
            cb,
            exponent
                .limbs
                .iter()
                .map(Expr::expr)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );

        let insufficient_gas_cost = LtGadget::construct(
            cb,
            cb.curr.state.gas_left.expr(),
            // static_gas = 10
            // dynamic_gas = exponent_byte_size * 50
            // gas_cost = dynamic_gas + static_gas
            exponent_byte_size.byte_size() * GasCost::EXP_BYTE_TIMES.expr()
                + OpcodeId::EXP.constant_gas_cost().expr(),
        );

        cb.require_equal(
            "Gas left is less than gas cost",
            insufficient_gas_cost.expr(),
            1.expr(),
        );

        let common_error_gadget = CommonErrorGadget::construct(cb, opcode.expr(), 4.expr());
        Self {
            opcode,
            base,
            exponent,
            exponent_byte_size,
            insufficient_gas_cost,
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
        let [base, exponent] = [0, 1].map(|index| block.get_rws(step, index).stack_value());

        log::debug!(
            "ErrorOutOfGasEXP: gas_left = {}, gas_cost = {}",
            step.gas_left,
            step.gas_cost,
        );

        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;
        self.base.assign_u256(region, offset, base)?;
        self.exponent.assign_u256(region, offset, exponent)?;
        self.exponent_byte_size.assign(region, offset, exponent)?;
        self.insufficient_gas_cost.assign_value(
            region,
            offset,
            Value::known(F::from(step.gas_left)),
            Value::known(F::from(step.gas_cost)),
        )?;
        self.common_error_gadget
            .assign(region, offset, block, call, step, 4)?;

        Ok(())
    }
}

