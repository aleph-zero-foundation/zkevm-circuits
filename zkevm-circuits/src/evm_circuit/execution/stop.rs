use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_PROGRAM_COUNTER,
        step::ExecutionState,
        util::{
            common_gadget::RestoreContextGadget,
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, StepStateTransition,
                Transition::{Delta, Same},
            },
            math_gadget::ComparisonGadget,
            CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::{
        word::{Word, WordExpr},
        Expr,
    },
};
use bus_mapping::evm::OpcodeId;
use eth_types::Field;
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct StopGadget<F> {
    code_length: Cell<F>,
    out_of_range: ComparisonGadget<F, N_BYTES_PROGRAM_COUNTER>,
    opcode: Cell<F>,
    restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for StopGadget<F> {
    const NAME: &'static str = "STOP";

    const EXECUTION_STATE: ExecutionState = ExecutionState::STOP;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let code_length = cb.query_cell();
        cb.bytecode_length(cb.curr.state.code_hash.to_word(), code_length.expr());

        let out_of_range = ComparisonGadget::construct(
            cb,
            code_length.expr(),
            cb.curr.state.program_counter.expr(),
        );
        let (lt, eq) = out_of_range.expr();
        let is_out_of_range = lt + eq;

        let opcode = cb.query_cell();
        cb.condition(1.expr() - is_out_of_range, |cb| {
            cb.opcode_lookup(opcode.expr(), 1.expr());
        });

        // We do the responsible opcode check explicitly here because we're not using
        // the `SameContextGadget` for `STOP`.
        cb.require_equal(
            "Opcode should be STOP",
            opcode.expr(),
            OpcodeId::STOP.expr(),
        );

        // Call ends with STOP must be successful
        cb.call_context_lookup_read(None, CallContextFieldTag::IsSuccess, Word::one());

        let is_to_end_tx = cb.next.execution_state_selector([ExecutionState::EndTx]);
        cb.require_equal(
            "Go to EndTx only when is_root",
            cb.curr.state.is_root.expr(),
            is_to_end_tx,
        );

        // When it's a root call
        cb.condition(cb.curr.state.is_root.expr(), |cb| {
            // Do step state transition
            cb.require_step_state_transition(StepStateTransition {
                call_id: Same,
                rw_counter: Delta(1.expr()),
                ..StepStateTransition::any()
            });
        });

        // When it's an internal call
        let restore_context = cb.condition(1.expr() - cb.curr.state.is_root.expr(), |cb| {
            RestoreContextGadget::construct(
                cb,
                true.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
            )
        });

        Self {
            code_length,
            out_of_range,
            opcode,
            restore_context,
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
        let code = block
            .bytecodes
            .get_from_h256(&call.code_hash)
            .expect("could not find current environment's bytecode");

        let code_length = code.codesize() as u64;
        self.code_length
            .assign(region, offset, Value::known(F::from(code_length)))?;

        self.out_of_range
            .assign(region, offset, F::from(code_length), F::from(step.pc))?;

        let opcode = step.opcode().unwrap();
        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;

        if !call.is_root {
            self.restore_context
                .assign(region, offset, block, call, step, 1)?;
        }

        Ok(())
    }
}

