use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, StepStateTransition,
                Transition::Delta,
            },
            math_gadget::{IsZeroWordGadget, LtWordGadget, MulAddWordsGadget},
            CachedRegion,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::{
        word::{Word, Word32Cell, WordExpr},
        Expr,
    },
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, U256};
use halo2_proofs::plonk::Error;

/// MulGadget verifies opcode MUL, DIV, and MOD.
/// For MUL, verify a * b = c (mod 2^256);
/// For DIV, verify a / b = c (mod 2^256);
/// For MOD, verify a % b = c (mod 2^256);
/// where a, b, c are 256-bit words.
#[derive(Clone, Debug)]
pub(crate) struct MulDivModGadget<F> {
    same_context: SameContextGadget<F>,
    /// Words a, b, c, d
    pub words: [Word32Cell<F>; 4],
    /// Gadget that verifies a * b + c = d
    mul_add_words: MulAddWordsGadget<F>,
    /// Check if divisor is zero for DIV and MOD
    divisor_is_zero: IsZeroWordGadget<F, Word32Cell<F>>,
    /// Check if residue < divisor when divisor != 0 for DIV and MOD
    lt_word: LtWordGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for MulDivModGadget<F> {
    const NAME: &'static str = "MUL_DIV_MOD";

    const EXECUTION_STATE: ExecutionState = ExecutionState::MUL_DIV_MOD;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let is_mul = (OpcodeId::DIV.expr() - opcode.expr())
            * (OpcodeId::MOD.expr() - opcode.expr())
            * F::from(8).invert().unwrap();
        let is_div = (opcode.expr() - OpcodeId::MUL.expr())
            * (OpcodeId::MOD.expr() - opcode.expr())
            * F::from(4).invert().unwrap();
        let is_mod = (opcode.expr() - OpcodeId::MUL.expr())
            * (opcode.expr() - OpcodeId::DIV.expr())
            * F::from(8).invert().unwrap();
        let a = cb.query_word32();
        let b = cb.query_word32();
        let c = cb.query_word32();
        let d = cb.query_word32();

        let mul_add_words = MulAddWordsGadget::construct(cb, [&a, &b, &c, &d]);
        let divisor_is_zero = IsZeroWordGadget::construct(cb, &b);
        let lt_word = LtWordGadget::construct(cb, &c.to_word(), &b.to_word());

        // Pop a and b from the stack, push result on the stack
        // The first pop is multiplier for MUL and dividend for DIV/MOD
        // The second pop is multiplicand for MUL and divisor for DIV/MOD
        // The push is product for MUL, quotient for DIV, and residue for MOD
        // Note that for DIV/MOD, when divisor == 0, the push value is also 0.
        cb.stack_pop(Word::select(is_mul.clone(), a.to_word(), d.to_word()));
        cb.stack_pop(b.to_word());
        cb.stack_push(
            d.to_word()
                .mul_selector(is_mul.clone())
                .add_unchecked(
                    a.to_word()
                        .mul_selector(is_div * (1.expr() - divisor_is_zero.expr())),
                )
                .add_unchecked(
                    c.to_word()
                        .mul_selector(is_mod * (1.expr() - divisor_is_zero.expr())),
                ),
        );

        // Constraint for MUL case
        cb.require_zero_word(
            "c == 0 for opcode MUL",
            c.to_word().mul_selector(is_mul.clone()),
        );

        // Constraints for DIV and MOD cases
        cb.condition(1.expr() - is_mul, |cb| {
            cb.add_constraint(
                "residue < divisor when divisor != 0 for opcode DIV/MOD",
                (1.expr() - lt_word.expr()) * (1.expr() - divisor_is_zero.expr()),
            );
            cb.require_zero("overflow == 0 for opcode DIV/MOD", mul_add_words.overflow());
        });

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::MUL.constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            words: [a, b, c, d],
            same_context,
            mul_add_words,
            divisor_is_zero,
            lt_word,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;
        let [pop1, pop2, push] = [0, 1, 2].map(|index| block.get_rws(step, index).stack_value());
        let (a, b, c, d) = match step.opcode().unwrap() {
            OpcodeId::MUL => (pop1, pop2, U256::from(0), push),
            OpcodeId::DIV => (push, pop2, pop1 - push * pop2, pop1),
            OpcodeId::MOD => (
                if pop2.is_zero() {
                    U256::from(0)
                } else {
                    pop1 / pop2
                },
                pop2,
                if pop2.is_zero() { pop1 } else { push },
                pop1,
            ),
            _ => unreachable!(),
        };
        self.words[0].assign_u256(region, offset, a)?;
        self.words[1].assign_u256(region, offset, b)?;
        self.words[2].assign_u256(region, offset, c)?;
        self.words[3].assign_u256(region, offset, d)?;
        self.mul_add_words.assign(region, offset, [a, b, c, d])?;
        self.lt_word.assign(region, offset, c, b)?;
        self.divisor_is_zero.assign(region, offset, Word::from(b))?;
        Ok(())
    }
}

