use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_MEMORY_WORD_SIZE,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, StepStateTransition,
                Transition::{Delta, To},
            },
            memory_gadget::{
                CommonMemoryAddressGadget, MemoryAddressGadget, MemoryExpansionGadget,
            },
            not, sum, CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{CallContextFieldTag, TxLogFieldTag},
    util::{
        build_tx_log_expression,
        word::{Word, Word32Cell, WordCell, WordExpr},
        Expr,
    },
};
use array_init::array_init;
use bus_mapping::circuit_input_builder::CopyDataType;
use eth_types::{
    evm_types::{GasCost, OpcodeId},
    Field, ToScalar, U256,
};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct LogGadget<F> {
    same_context: SameContextGadget<F>,
    // memory address
    memory_address: MemoryAddressGadget<F>,
    topics: [Word32Cell<F>; 4],
    topic_selectors: [Cell<F>; 4],

    contract_address: WordCell<F>,
    is_static_call: Cell<F>,
    is_persistent: Cell<F>,
    tx_id: Cell<F>,
    copy_rwc_inc: Cell<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
}

impl<F: Field> ExecutionGadget<F> for LogGadget<F> {
    const NAME: &'static str = "LOG";

    const EXECUTION_STATE: ExecutionState = ExecutionState::LOG;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let mstart = cb.query_word_unchecked();
        let msize = cb.query_memory_address();

        // Pop mstart_address, msize from stack
        cb.stack_pop(mstart.to_word());
        cb.stack_pop(msize.to_word());
        // read tx id
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        // constrain not in static call
        let is_static_call = cb.call_context(None, CallContextFieldTag::IsStatic);
        cb.require_zero("is_static_call is false", is_static_call.expr());

        // check contract_address in CallContext & TxLog
        // use call context's  callee address as contract address
        let contract_address =
            cb.call_context_read_as_word(None, CallContextFieldTag::CalleeAddress);
        let is_persistent = cb.call_context(None, CallContextFieldTag::IsPersistent);
        cb.require_boolean("is_persistent is bool", is_persistent.expr());

        cb.condition(is_persistent.expr(), |cb| {
            cb.tx_log_lookup(
                tx_id.expr(),
                cb.curr.state.log_id.expr() + 1.expr(),
                TxLogFieldTag::Address,
                0.expr(),
                contract_address.to_word(),
            );
        });

        // constrain topics in logs
        let topics = array_init(|_| cb.query_word32());
        let topic_selectors: [Cell<F>; 4] = array_init(|_| cb.query_cell());
        for (idx, topic) in topics.iter().enumerate() {
            cb.condition(topic_selectors[idx].expr(), |cb| {
                cb.stack_pop(topic.to_word());
            });
            cb.condition(topic_selectors[idx].expr() * is_persistent.expr(), |cb| {
                cb.tx_log_lookup(
                    tx_id.expr(),
                    cb.curr.state.log_id.expr() + 1.expr(),
                    TxLogFieldTag::Topic,
                    idx.expr(),
                    topic.to_word(),
                );
            });
        }

        let opcode = cb.query_cell();
        let topic_count = opcode.expr() - OpcodeId::LOG0.as_u8().expr();

        // TOPIC_COUNT == Non zero topic selector count
        cb.require_equal(
            " sum of topic selectors = topic_count ",
            topic_count.clone(),
            sum::expr(topic_selectors.clone()),
        );

        // `topic_selectors` order must be from 1 --> 0
        for idx in 0..4 {
            cb.require_boolean("topic selector is bool ", topic_selectors[idx].expr());
            if idx > 0 {
                let selector_prev = topic_selectors[idx - 1].expr();
                // selector can transit from 1 to 0 only once as [1, 1 ..., 0]
                cb.require_boolean(
                    "Constrain topic selectors can only transit from 1 to 0",
                    selector_prev - topic_selectors[idx].expr(),
                );
            }
        }

        // check memory copy
        let memory_address = MemoryAddressGadget::construct(cb, mstart, msize);

        // Calculate the next memory size and the gas cost for this memory
        // access
        let memory_expansion = MemoryExpansionGadget::construct(cb, [memory_address.address()]);

        let copy_rwc_inc = cb.query_cell();
        let dst_addr = build_tx_log_expression(
            0.expr(),
            TxLogFieldTag::Data.expr(),
            cb.curr.state.log_id.expr() + 1.expr(),
        );
        let cond = memory_address.has_length() * is_persistent.expr();
        cb.condition(cond.clone(), |cb| {
            cb.copy_table_lookup(
                Word::from_lo_unchecked(cb.curr.state.call_id.expr()),
                CopyDataType::Memory.expr(),
                Word::from_lo_unchecked(tx_id.expr()),
                CopyDataType::TxLog.expr(),
                memory_address.offset(),
                memory_address.address(),
                dst_addr,
                memory_address.length(),
                0.expr(), // for LOGN, rlc_acc is 0
                copy_rwc_inc.expr(),
            );
        });
        cb.condition(not::expr(cond), |cb| {
            cb.require_zero(
                "if length is 0 or tx is not persistent, copy table rwc inc == 0",
                copy_rwc_inc.expr(),
            );
        });

        let gas_cost = GasCost::LOG.expr()
            + GasCost::LOG.expr() * topic_count.clone()
            + 8.expr() * memory_address.length()
            + memory_expansion.gas_cost();
        // State transition

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(cb.rw_counter_offset()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(2.expr() + topic_count),
            memory_word_size: To(memory_expansion.next_memory_word_size()),
            log_id: Delta(is_persistent.expr()),
            gas_left: Delta(-gas_cost),
            ..Default::default()
        };

        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            memory_address,
            topics,
            topic_selectors,
            contract_address,
            is_static_call,
            is_persistent,
            tx_id,
            copy_rwc_inc,
            memory_expansion,
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

        let [memory_start, msize] = [0, 1].map(|index| block.get_rws(step, index).stack_value());
        let memory_address = self
            .memory_address
            .assign(region, offset, memory_start, msize)?;

        // Memory expansion
        self.memory_expansion
            .assign(region, offset, step.memory_word_size(), [memory_address])?;

        let opcode = step.opcode().unwrap();
        let topic_count = opcode.postfix().expect("opcode with postfix") as usize;
        assert!(topic_count <= 4);

        let is_persistent = call.is_persistent as usize;
        let mut topics = (0..topic_count).map(|topic| {
            // We compute the index of the correct read-write record from
            // bus-mapping/src/evm/opcodes/logs.rs::gen_log_step
            // It takes 6 + is_persistent reads or writes to reach the topic stack write section.
            // Each topic takes at least 1 stack read. They take an additional tx log write if the
            // call is persistent.
            block
                .get_rws(step, 6 + is_persistent + topic * (1 + is_persistent))
                .stack_value()
        });
        for i in 0..4 {
            let topic = topics.next();
            self.topic_selectors[i].assign(
                region,
                offset,
                Value::known(F::from(topic.is_some().into())),
            )?;
            self.topics[i].assign_u256(region, offset, topic.unwrap_or_default())?;
        }

        self.contract_address
            .assign_h160(region, offset, call.address)?;
        let is_persistent = call.is_persistent as u64;
        self.is_static_call
            .assign(region, offset, Value::known(F::from(call.is_static as u64)))?;
        self.is_persistent
            .assign(region, offset, Value::known(F::from(is_persistent)))?;
        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id)))?;
        // rw_counter increase from copy table lookup is `msize` memory reads + `msize`
        // log writes when `is_persistent` is true.
        self.copy_rwc_inc.assign(
            region,
            offset,
            Value::known(
                ((msize + msize) * U256::from(is_persistent))
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;

        Ok(())
    }
}

