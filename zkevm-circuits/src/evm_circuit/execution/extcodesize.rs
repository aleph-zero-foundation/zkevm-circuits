use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_ACCOUNT_ADDRESS,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, ReversionInfo, StepStateTransition,
                Transition::Delta,
            },
            math_gadget::IsZeroWordGadget,
            not, select, AccountAddress, CachedRegion, Cell, U64Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, CallContextFieldTag},
    util::{
        word::{Word, Word32Cell, WordCell, WordExpr},
        Expr,
    },
};
use eth_types::{evm_types::GasCost, Field};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ExtcodesizeGadget<F> {
    same_context: SameContextGadget<F>,
    address_word: Word32Cell<F>,
    reversion_info: ReversionInfo<F>,
    tx_id: Cell<F>,
    is_warm: Cell<F>,
    code_hash: WordCell<F>,
    not_exists: IsZeroWordGadget<F, WordCell<F>>,
    code_size: U64Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for ExtcodesizeGadget<F> {
    const NAME: &'static str = "EXTCODESIZE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::EXTCODESIZE;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let address_word = cb.query_word32();
        let address = AccountAddress::new(
            address_word.limbs[..N_BYTES_ACCOUNT_ADDRESS]
                .to_vec()
                .try_into()
                .unwrap(),
        );
        cb.stack_pop(address_word.to_word());

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

        // range check will be cover by account code_hash lookup
        let code_hash = cb.query_word_unchecked();
        // For non-existing accounts the code_hash must be 0 in the rw_table.
        cb.account_read(
            address.to_word(),
            AccountFieldTag::CodeHash,
            code_hash.to_word(),
        );
        let not_exists = IsZeroWordGadget::construct(cb, &code_hash);
        let exists = not::expr(not_exists.expr());

        let code_size = cb.query_u64();
        cb.condition(exists.expr(), |cb| {
            cb.bytecode_length(code_hash.to_word(), code_size.expr());
        });
        cb.condition(not_exists.expr(), |cb| {
            cb.require_zero("code_size is zero when non_exists", code_size.expr());
        });

        cb.stack_push(code_size.to_word());

        let gas_cost = select::expr(
            is_warm.expr(),
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_ACCOUNT_ACCESS.expr(),
        );

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(7.expr()),
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
            address_word,
            tx_id,
            reversion_info,
            is_warm,
            code_hash,
            not_exists,
            code_size,
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
        self.address_word.assign_u256(region, offset, address)?;

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
        self.code_hash.assign_u256(region, offset, code_hash)?;
        self.not_exists
            .assign(region, offset, Word::from(code_hash))?;

        let code_size = block.get_rws(step, 6).stack_value().as_u64();
        self.code_size
            .assign(region, offset, Some(code_size.to_le_bytes()))?;

        Ok(())
    }
}

