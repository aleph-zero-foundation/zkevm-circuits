use std::marker::PhantomData;

use crate::{
    evm_circuit::util::{
        constraint_builder::EVMConstraintBuilder, from_bytes, math_gadget::*, select, CachedRegion,
    },
    util::{word::WordExpr, Expr},
};
use eth_types::{Field, ToLittleEndian, Word};
use halo2_proofs::plonk::{Error, Expression};

#[derive(Clone, Debug)]
/// CmpWordsGadget compares two words, exposing `eq`  and `lt`
pub(crate) struct CmpWordsGadget<F, T1, T2> {
    comparison_lo: ComparisonGadget<F, 16>,
    comparison_hi: ComparisonGadget<F, 16>,
    pub eq: Expression<F>,
    pub lt: Expression<F>,
    _marker: PhantomData<(T1, T2)>,
}

impl<F: Field, T1: WordExpr<F>, T2: WordExpr<F>> CmpWordsGadget<F, T1, T2> {
    pub(crate) fn construct(cb: &mut EVMConstraintBuilder<F>, a: T1, b: T2) -> Self {
        let (a_lo, a_hi) = a.to_word().to_lo_hi();
        let (b_lo, b_hi) = b.to_word().to_lo_hi();
        // `a.lo <= b.lo`
        let comparison_lo = ComparisonGadget::construct(cb, a_lo, b_lo);

        let (lt_lo, eq_lo) = comparison_lo.expr();

        // `a.hi <= b.hi`
        let comparison_hi = ComparisonGadget::construct(cb, a_hi, b_hi);
        let (lt_hi, eq_hi) = comparison_hi.expr();

        // `a < b` when:
        // - `a.hi < b.hi` OR
        // - `a.hi == b.hi` AND `a.lo < b.lo`
        let lt = select::expr(lt_hi, 1.expr(), eq_hi.clone() * lt_lo);

        // `a == b` when both parts are equal
        let eq = eq_hi * eq_lo;

        Self {
            comparison_lo,
            comparison_hi,
            lt,
            eq,
            _marker: Default::default(),
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        a: Word,
        b: Word,
    ) -> Result<(), Error> {
        // `a[0..1] <= b[0..16]`
        self.comparison_lo.assign(
            region,
            offset,
            from_bytes::value(&a.to_le_bytes()[0..16]),
            from_bytes::value(&b.to_le_bytes()[0..16]),
        )?;

        // `a[16..32] <= b[16..32]`
        self.comparison_hi.assign(
            region,
            offset,
            from_bytes::value(&a.to_le_bytes()[16..32]),
            from_bytes::value(&b.to_le_bytes()[16..32]),
        )?;

        Ok(())
    }
}

