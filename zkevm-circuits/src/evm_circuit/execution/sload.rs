use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::{SameContextGadget, SloadGasGadget},
            constraint_builder::{
                EVMConstraintBuilder, ReversionInfo, StepStateTransition, Transition::Delta,
            },
            CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::{
        word::{Word, WordCell, WordExpr},
        Expr,
    },
};
use eth_types::Field;
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct SloadGadget<F> {
    same_context: SameContextGadget<F>,
    tx_id: Cell<F>,
    reversion_info: ReversionInfo<F>,
    callee_address: WordCell<F>,
    key: WordCell<F>,
    value: WordCell<F>,
    committed_value: WordCell<F>,
    is_warm: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for SloadGadget<F> {
    const NAME: &'static str = "SLOAD";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SLOAD;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let mut reversion_info = cb.reversion_info_read(None);
        let callee_address = cb.call_context_read_as_word(None, CallContextFieldTag::CalleeAddress);

        let key = cb.query_word_unchecked();
        // Pop the key from the stack
        cb.stack_pop(key.to_word());

        let value = cb.query_word_unchecked();
        let committed_value = cb.query_word_unchecked();
        cb.account_storage_read(
            callee_address.to_word(),
            key.to_word(),
            value.to_word(),
            tx_id.expr(),
            committed_value.to_word(),
        );

        cb.stack_push(value.to_word());

        let is_warm = cb.query_bool();
        cb.account_storage_access_list_write(
            tx_id.expr(),
            callee_address.to_word(),
            key.to_word(),
            Word::from_lo_unchecked(true.expr()),
            Word::from_lo_unchecked(is_warm.expr()),
            Some(&mut reversion_info),
        );

        let gas_cost = SloadGasGadget::construct(cb, is_warm.expr()).expr();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(8.expr()),
            program_counter: Delta(1.expr()),
            reversible_write_counter: Delta(1.expr()),
            gas_left: Delta(-gas_cost),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            tx_id,
            reversion_info,
            callee_address,
            key,
            value,
            committed_value,
            is_warm,
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
        self.same_context.assign_exec_step(region, offset, step)?;

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id)))?;
        self.reversion_info.assign(
            region,
            offset,
            call.rw_counter_end_of_reversion,
            call.is_persistent,
        )?;
        self.callee_address
            .assign_h160(region, offset, call.address)?;

        let key = block.get_rws(step, 4).stack_value();
        let value = block.get_rws(step, 6).stack_value();
        self.key.assign_u256(region, offset, key)?;
        self.value.assign_u256(region, offset, value)?;

        let (_, committed_value) = block.get_rws(step, 5).aux_pair();
        self.committed_value
            .assign_u256(region, offset, committed_value)?;

        let (_, is_warm) = block.get_rws(step, 7).tx_access_list_value_pair();
        self.is_warm
            .assign(region, offset, Value::known(F::from(is_warm as u64)))?;

        Ok(())
    }
}

