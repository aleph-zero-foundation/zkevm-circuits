use crate::evm_circuit::{
    execution::ExecutionGadget,
    step::ExecutionState,
    table::{FixedTableTag, Lookup},
    util::{
        common_gadget::CommonErrorGadget, constraint_builder::EVMConstraintBuilder, CachedRegion,
        Cell,
    },
    witness::{Block, Call, ExecStep, Transaction},
};
use eth_types::Field;
use gadgets::util::Expr;
use halo2_proofs::{circuit::Value, plonk::Error};

/// Gadget for invalid opcodes. It verifies by a fixed lookup for
/// ResponsibleOpcode.
#[derive(Clone, Debug)]
pub(crate) struct ErrorInvalidOpcodeGadget<F> {
    opcode: Cell<F>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorInvalidOpcodeGadget<F> {
    const NAME: &'static str = "ErrorInvalidOpcode";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorInvalidOpcode;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.add_lookup(
            "Responsible opcode lookup",
            Lookup::Fixed {
                tag: FixedTableTag::ResponsibleOpcode.expr(),
                values: [
                    Self::EXECUTION_STATE.as_u64().expr(),
                    opcode.expr(),
                    0.expr(),
                ],
            },
        );

        let common_error_gadget = CommonErrorGadget::construct(cb, opcode.expr(), 2.expr());

        Self {
            opcode,
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
        let opcode = F::from(step.opcode().unwrap().as_u64());
        self.opcode.assign(region, offset, Value::known(opcode))?;

        self.common_error_gadget
            .assign(region, offset, block, call, step, 2)?;
        Ok(())
    }
}

