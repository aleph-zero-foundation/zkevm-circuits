use crate::{
    evm_circuit::util::{
        constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
        math_gadget::{LtWordGadget, *},
        CachedRegion,
    },
    util::{
        word::{self, Word32Cell, WordExpr},
        Expr,
    },
};
use eth_types::{Field, Word};
use halo2_proofs::{circuit::Value, plonk::Error};

/// Constraints for the words a, n, r:
/// a mod n = r, if n!=0
/// r = 0,       if n==0
///
/// We use the auxiliary a_or_zero word, whose value is constrained to be:
/// a_or_zero = a if n!=0, 0 if n==0.  This allows to use the equation
/// k * n + r = a_or_zero to verify the modulus, which holds with r=0 in the
/// case of n=0. Unlike the usual k * n + r = a, which forces r = a when n=0,
/// this equation assures that r<n or r=n=0.
#[derive(Clone, Debug)]
pub(crate) struct ModGadget<F> {
    k: Word32Cell<F>,
    a_or_zero: Word32Cell<F>,
    mul_add_words: MulAddWordsGadget<F>,
    n_is_zero: IsZeroWordGadget<F, Word32Cell<F>>,
    a_or_is_zero: IsZeroWordGadget<F, Word32Cell<F>>,
    eq: IsEqualWordGadget<F, Word32Cell<F>, Word32Cell<F>>,
    lt: LtWordGadget<F>,
}
impl<F: Field> ModGadget<F> {
    pub(crate) fn construct(cb: &mut EVMConstraintBuilder<F>, words: [&Word32Cell<F>; 3]) -> Self {
        let (a, n, r) = (words[0], words[1], words[2]);
        let k = cb.query_word32();
        let a_or_zero = cb.query_word32();
        let n_is_zero = IsZeroWordGadget::construct(cb, n);
        let a_or_is_zero = IsZeroWordGadget::construct(cb, &a_or_zero);
        let mul_add_words = MulAddWordsGadget::construct(cb, [&k, n, r, &a_or_zero]);
        let eq = IsEqualWordGadget::construct(cb, a, &a_or_zero);
        let lt = LtWordGadget::construct(cb, &r.to_word(), &n.to_word());
        // Constrain the aux variable a_or_zero to be =a or =0 if n==0:
        // (a == a_or_zero) ^ (n == 0 & a_or_zero == 0)
        cb.add_constraint(
            " (1 - (a == a_or_zero)) * ( 1 - (n == 0) * (a_or_zero == 0)",
            (1.expr() - eq.expr()) * (1.expr() - n_is_zero.expr() * a_or_is_zero.expr()),
        );

        // Constrain the result r to be valid: (r<n) ^ n==0
        cb.add_constraint(
            " (1 - (r<n) - (n==0) ",
            1.expr() - lt.expr() - n_is_zero.expr(),
        );

        // Constrain k * n + r no overflow
        cb.add_constraint("overflow == 0 for k * n + r", mul_add_words.overflow());

        Self {
            k,
            a_or_zero,
            mul_add_words,
            n_is_zero,
            a_or_is_zero,
            eq,
            lt,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        a: Word,
        n: Word,
        r: Word,
        k: Word,
    ) -> Result<(), Error> {
        let a_or_zero = if n.is_zero() { Word::zero() } else { a };

        self.k.assign_u256(region, offset, k)?;
        self.a_or_zero.assign_u256(region, offset, a_or_zero)?;
        self.n_is_zero.assign(region, offset, word::Word::from(n))?;
        self.a_or_is_zero
            .assign(region, offset, word::Word::from(a_or_zero))?;
        self.mul_add_words
            .assign(region, offset, [k, n, r, a_or_zero])?;
        self.lt.assign(region, offset, r, n)?;
        self.eq.assign_value(
            region,
            offset,
            Value::known(word::Word::from(a)),
            Value::known(word::Word::from(a_or_zero)),
        )?;

        Ok(())
    }
}

