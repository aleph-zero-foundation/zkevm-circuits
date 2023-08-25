use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, ReversionInfo, StepStateTransition,
                Transition::Delta,
            },
            math_gadget::IsZeroWordGadget,
            not, select, AccountAddress, CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, CallContextFieldTag},
    util::{
        word::{Word, Word32Cell, WordCell, WordExpr},
        Expr,
    },
};
use eth_types::{evm_types::GasCost, Field, ToAddress, ToWord};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct BalanceGadget<F> {
    same_context: SameContextGadget<F>,
    address: AccountAddress<F>,
    reversion_info: ReversionInfo<F>,
    tx_id: Cell<F>,
    is_warm: Cell<F>,
    code_hash: WordCell<F>,
    not_exists: IsZeroWordGadget<F, WordCell<F>>,
    balance: Word32Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for BalanceGadget<F> {
    const NAME: &'static str = "BALANCE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::BALANCE;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let address = cb.query_account_address();
        cb.stack_pop(address.to_word());

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let mut reversion_info = cb.reversion_info_read(None);
        let is_warm = cb.query_bool();
        cb.account_access_list_write_unchecked(
            tx_id.expr(),
            address.to_word(),
            1.expr(),
            is_warm.expr(),
            Some(&mut reversion_info),
        );
        let code_hash = cb.query_word_unchecked();
        // For non-existing accounts the code_hash must be 0 in the rw_table.
        cb.account_read(
            address.to_word(),
            AccountFieldTag::CodeHash,
            code_hash.to_word(),
        );
        let not_exists = IsZeroWordGadget::construct(cb, &code_hash);
        let exists = not::expr(not_exists.expr());
        let balance = cb.query_word32();
        cb.condition(exists.expr(), |cb| {
            cb.account_read(
                address.to_word(),
                AccountFieldTag::Balance,
                balance.to_word(),
            );
        });
        cb.condition(not_exists.expr(), |cb| {
            cb.require_zero_word("balance is zero when non_exists", balance.to_word());
        });

        cb.stack_push(balance.to_word());

        let gas_cost = select::expr(
            is_warm.expr(),
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_ACCOUNT_ACCESS.expr(),
        );

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(7.expr() + exists.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(0.expr()),
            gas_left: Delta(-gas_cost),
            reversible_write_counter: Delta(1.expr()),
            ..Default::default()
        };

        let opcode = cb.query_cell();
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            address,
            reversion_info,
            tx_id,
            is_warm,
            code_hash,
            not_exists,
            balance,
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

        let address = block.get_rws(step, 0).stack_value();
        self.address
            .assign_h160(region, offset, address.to_address())?;

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id)))?;

        self.reversion_info.assign(
            region,
            offset,
            call.rw_counter_end_of_reversion,
            call.is_persistent,
        )?;

        let (_, is_warm) = block.get_rws(step, 4).tx_access_list_value_pair();
        self.is_warm
            .assign(region, offset, Value::known(F::from(is_warm as u64)))?;

        let code_hash = block.get_rws(step, 5).account_value_pair().0;
        self.code_hash
            .assign_u256(region, offset, code_hash.to_word())?;
        self.not_exists
            .assign_value(region, offset, Value::known(Word::from(code_hash)))?;
        let balance = if code_hash.is_zero() {
            eth_types::Word::zero()
        } else {
            block.get_rws(step, 6).account_value_pair().0
        };
        self.balance.assign_u256(region, offset, balance)?;

        Ok(())
    }
}

