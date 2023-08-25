use crate::{
    evm_circuit::{
        param::N_BYTES_WORD,
        util::{
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::*,
            CachedRegion,
        },
    },
    util::{
        word::{Word32Cell, WordExpr},
        Expr,
    },
};
use eth_types::{Field, ToLittleEndian, Word};
use gadgets::util::sum;
use halo2_proofs::plonk::Error;

/// Construction of 256-bit word original and absolute values, which is useful
/// for opcodes operated on signed values.
/// For a special case, when `x = -2^255` then absolute value should be `2^255`.
/// But a signed word could only express value from `-2^255` to `2^255 - 1`.
/// So in this case both `x` and `x_abs` should be equal to `-2^255`
/// (expressed as an U256 of `2^255`).
#[derive(Clone, Debug)]
pub(crate) struct AbsWordGadget<F> {
    x: Word32Cell<F>,
    x_abs: Word32Cell<F>,
    sum: Word32Cell<F>,
    is_neg: LtGadget<F, 1>,
    add_words: AddWordsGadget<F, 2, false>,
}

impl<F: Field> AbsWordGadget<F> {
    pub(crate) fn construct(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let x = cb.query_word32();
        let x_abs = cb.query_word32();
        let sum = cb.query_word32();
        let (x_lo, x_hi) = x.to_word().to_lo_hi();
        let (x_abs_lo, x_abs_hi) = x_abs.to_word().to_lo_hi();
        let is_neg = LtGadget::construct(cb, 127.expr(), x.limbs[31].expr());

        cb.add_constraint(
            "x_abs_lo == x_lo when x >= 0",
            (1.expr() - is_neg.expr()) * (x_abs_lo.expr() - x_lo.expr()),
        );
        cb.add_constraint(
            "x_abs_hi == x_hi when x >= 0",
            (1.expr() - is_neg.expr()) * (x_abs_hi.expr() - x_hi.expr()),
        );

        // When `is_neg`, constrain `sum == 0` and `carry == 1`. Since the final
        // result is `1 << 256`.
        let add_words = AddWordsGadget::construct(cb, [x.clone(), x_abs.clone()], sum.clone());
        cb.add_constraint(
            "sum == 0 when x < 0",
            is_neg.expr() * sum::expr(add_words.sum().to_word_n::<N_BYTES_WORD>().limbs),
        );
        cb.add_constraint(
            "carry_hi == 1 when x < 0",
            is_neg.expr() * (1.expr() - add_words.carry().as_ref().unwrap().expr()),
        );

        Self {
            x,
            x_abs,
            sum,
            is_neg,
            add_words,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        x: Word,
        x_abs: Word,
    ) -> Result<(), Error> {
        self.x.assign_u256(region, offset, x)?;
        self.x_abs.assign_u256(region, offset, x_abs)?;
        self.is_neg.assign(
            region,
            offset,
            127.into(),
            u64::from(x.to_le_bytes()[31]).into(),
        )?;
        let sum = x.overflowing_add(x_abs).0;
        self.sum.assign_u256(region, offset, sum)?;
        self.add_words.assign(region, offset, [x, x_abs], sum)
    }

    pub(crate) fn is_neg(&self) -> &LtGadget<F, 1> {
        &self.is_neg
    }

    pub(crate) fn x(&self) -> &Word32Cell<F> {
        &self.x
    }
    pub(crate) fn x_abs(&self) -> &Word32Cell<F> {
        &self.x_abs
    }
}

