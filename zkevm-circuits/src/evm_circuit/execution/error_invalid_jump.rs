use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_PROGRAM_COUNTER,
        step::ExecutionState,
        util::{
            common_gadget::{CommonErrorGadget, WordByteCapGadget},
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::{IsEqualGadget, IsZeroWordGadget},
            CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::{
        word::{Word, WordCell, WordExpr},
        Expr,
    },
};
use eth_types::{evm_types::OpcodeId, Field, U256};

use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ErrorInvalidJumpGadget<F> {
    opcode: Cell<F>,
    dest: WordByteCapGadget<F, N_BYTES_PROGRAM_COUNTER>,
    code_len: Cell<F>,
    value: Cell<F>,
    is_code: Cell<F>,
    is_jump_dest: IsEqualGadget<F>,
    is_jumpi: IsEqualGadget<F>,
    condition: WordCell<F>,
    is_condition_zero: IsZeroWordGadget<F, WordCell<F>>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorInvalidJumpGadget<F> {
    const NAME: &'static str = "ErrorInvalidJump";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorInvalidJump;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let code_len = cb.query_cell();
        let dest = WordByteCapGadget::construct(cb, code_len.expr());

        let opcode = cb.query_cell();
        let value = cb.query_cell();
        let is_code = cb.query_cell();
        let condition = cb.query_word_unchecked();

        cb.require_in_set(
            "ErrorInvalidJump only happend in JUMP or JUMPI",
            opcode.expr(),
            vec![OpcodeId::JUMP.expr(), OpcodeId::JUMPI.expr()],
        );

        let is_jumpi = IsEqualGadget::construct(cb, opcode.expr(), OpcodeId::JUMPI.expr());

        // initialize is_jump_dest
        let is_jump_dest = IsEqualGadget::construct(cb, value.expr(), OpcodeId::JUMPDEST.expr());

        // first default this condition, if use will re-construct with real condition
        // value
        let is_condition_zero = IsZeroWordGadget::construct(cb, &condition);

        // Pop the value from the stack
        cb.stack_pop(dest.original_word().to_word());

        cb.condition(is_jumpi.expr(), |cb| {
            cb.stack_pop(condition.to_word());
            // if condition is zero, jump will not happen, so constrain condition not zero
            cb.require_zero("condition is not zero", is_condition_zero.expr());
        });

        // Look up bytecode length
        cb.bytecode_length(cb.curr.state.code_hash.to_word(), code_len.expr());

        // If destination is in valid range, lookup for the value.
        cb.condition(dest.lt_cap(), |cb| {
            cb.bytecode_lookup(
                cb.curr.state.code_hash.to_word(),
                dest.valid_value(),
                is_code.expr(),
                value.expr(),
            );
            cb.require_zero(
                "is_code is false or not JUMPDEST",
                is_code.expr() * is_jump_dest.expr(),
            );
        });

        let common_error_gadget =
            CommonErrorGadget::construct(cb, opcode.expr(), 3.expr() + is_jumpi.expr());

        Self {
            opcode,
            dest,
            code_len,
            value,
            is_code,
            is_jump_dest,
            is_jumpi,
            condition,
            is_condition_zero,
            common_error_gadget,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode().unwrap();
        let is_jumpi = opcode == OpcodeId::JUMPI;
        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;

        let condition = if is_jumpi {
            block.get_rws(step, 1).stack_value()
        } else {
            U256::zero()
        };

        let code = block
            .bytecodes
            .get_from_h256(&call.code_hash)
            .expect("could not find current environment's bytecode");
        let code_len = code.codesize() as u64;
        self.code_len
            .assign(region, offset, Value::known(F::from(code_len)))?;

        let dest = block.get_rws(step, 0).stack_value();
        self.dest.assign(region, offset, dest, F::from(code_len))?;

        // set default value in case can not find value, is_code from bytecode table
        let dest = usize::try_from(dest).unwrap_or(code.codesize());
        let (value, is_code) = code.get(dest).unwrap_or((0, false));

        self.value
            .assign(region, offset, Value::known(F::from(value.into())))?;
        self.is_code
            .assign(region, offset, Value::known(F::from(is_code.into())))?;
        self.is_jump_dest.assign(
            region,
            offset,
            F::from(value.into()),
            F::from(OpcodeId::JUMPDEST.as_u64()),
        )?;

        self.is_jumpi.assign(
            region,
            offset,
            F::from(opcode.as_u64()),
            F::from(OpcodeId::JUMPI.as_u64()),
        )?;

        self.condition.assign_u256(region, offset, condition)?;
        self.is_condition_zero
            .assign_value(region, offset, Value::known(Word::from(condition)))?;

        self.common_error_gadget.assign(
            region,
            offset,
            block,
            call,
            step,
            3 + is_jumpi as usize,
        )?;

        Ok(())
    }
}

