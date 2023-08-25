use crate::{
    evm_circuit::util::{
        self,
        constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
        pow_of_two_expr, split_u256, sum, CachedRegion, Cell,
    },
    util::{
        word::{Word32Cell, WordExpr},
        Expr,
    },
};
use eth_types::{Field, ToScalar, Word};
use halo2_proofs::{circuit::Value, plonk::Error};

/// Construction of 2 256-bit words addition and result, which is useful for
/// opcode ADD, SUB and balance operation
#[derive(Clone, Debug)]
pub(crate) struct AddWordsGadget<F, const N_ADDENDS: usize, const CHECK_OVERFLOW: bool> {
    addends: [Word32Cell<F>; N_ADDENDS],
    sum: Word32Cell<F>,
    carry_lo: Cell<F>,
    carry_hi: Option<Cell<F>>,
}

impl<F: Field, const N_ADDENDS: usize, const CHECK_OVERFLOW: bool>
    AddWordsGadget<F, N_ADDENDS, CHECK_OVERFLOW>
{
    pub(crate) fn construct(
        cb: &mut EVMConstraintBuilder<F>,
        addends: [Word32Cell<F>; N_ADDENDS],
        sum: Word32Cell<F>,
    ) -> Self {
        let carry_lo = cb.query_cell();
        let carry_hi = if CHECK_OVERFLOW {
            None
        } else {
            Some(cb.query_cell())
        };

        let addends_lo = &addends
            .iter()
            .map(|addend| addend.to_word().lo())
            .collect::<Vec<_>>();
        let addends_hi = addends
            .iter()
            .map(|addend| addend.to_word().hi())
            .collect::<Vec<_>>();
        let (sum_lo, sum_hi) = sum.to_word().to_lo_hi();

        cb.require_equal(
            "sum(addends_lo) == sum_lo + carry_lo ⋅ 2^128",
            sum::expr(addends_lo),
            sum_lo + carry_lo.expr() * pow_of_two_expr(128),
        );
        cb.require_equal(
            if CHECK_OVERFLOW {
                "sum(addends_hi) + carry_lo == sum_hi"
            } else {
                "sum(addends_hi) + carry_lo == sum_hi + carry_hi ⋅ 2^128"
            },
            sum::expr(addends_hi) + carry_lo.expr(),
            if CHECK_OVERFLOW {
                sum_hi
            } else {
                sum_hi + carry_hi.as_ref().unwrap().expr() * pow_of_two_expr(128)
            },
        );

        for carry in if CHECK_OVERFLOW {
            vec![&carry_lo]
        } else {
            vec![&carry_lo, carry_hi.as_ref().unwrap()]
        } {
            cb.require_in_set(
                "carry_lo in 0..N_ADDENDS",
                carry.expr(),
                (0..N_ADDENDS).map(|idx| idx.expr()).collect(),
            );
        }

        Self {
            addends,
            sum,
            carry_lo,
            carry_hi,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        addends: [Word; N_ADDENDS],
        sum: Word,
    ) -> Result<(), Error> {
        for (word, value) in self.addends.iter().zip(addends.iter()) {
            word.assign_u256(region, offset, *value)?;
        }
        self.sum.assign_u256(region, offset, sum)?;

        let (addends_lo, addends_hi): (Vec<_>, Vec<_>) = addends.iter().map(split_u256).unzip();
        let (sum_lo, sum_hi) = split_u256(&sum);

        let sum_of_addends_lo = addends_lo
            .into_iter()
            .fold(Word::zero(), |acc, addend_lo| acc + addend_lo);
        let sum_of_addends_hi = addends_hi
            .into_iter()
            .fold(Word::zero(), |acc, addend_hi| acc + addend_hi);

        let carry_lo = (sum_of_addends_lo - sum_lo) >> 128;
        self.carry_lo.assign(
            region,
            offset,
            Value::known(
                carry_lo
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;

        if !CHECK_OVERFLOW {
            let carry_hi = (sum_of_addends_hi + carry_lo - sum_hi) >> 128;
            self.carry_hi.as_ref().unwrap().assign(
                region,
                offset,
                Value::known(
                    carry_hi
                        .to_scalar()
                        .expect("unexpected U256 -> Scalar conversion failure"),
                ),
            )?;
        }

        Ok(())
    }

    #[allow(
        dead_code,
        reason = "this method is a legit API but is currently only used in the tests"
    )]
    pub(crate) fn addends(&self) -> &[Word32Cell<F>] {
        &self.addends
    }

    pub(crate) fn sum(&self) -> &Word32Cell<F> {
        &self.sum
    }

    pub(crate) fn carry(&self) -> &Option<util::Cell<F>> {
        &self.carry_hi
    }
}

