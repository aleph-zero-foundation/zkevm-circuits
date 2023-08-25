use crate::{
    evm_circuit::util::{
        constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
        from_bytes, pow_of_two_expr, split_u256, split_u256_limb64, CachedRegion, Cell,
    },
    util::{
        word::{self, Word4, WordExpr},
        Expr,
    },
};
use eth_types::{Field, ToLittleEndian, Word};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

/// Construct the gadget that checks a * b + c == d * 2**256 + e
/// where a, b, c, d, e are 256-bit words.
///
/// We execute a multi-limb multiplication as follows:
/// a and b is divided into 4 64-bit limbs, denoted as a0~a3 and b0~b3
/// defined t0, t1, t2, t3, t4, t5, t6:
///   t0 = a0 * b0,
///   t1 = a0 * b1 + a1 * b0,
///   t2 = a0 * b2 + a2 * b0 + a1 * b1,
///   t3 = a0 * b3 + a3 * b0 + a2 * b1 + a1 * b2,
///   t4 = a1 * b3 + a2 * b2 + a3 * b1,
///   t5 = a2 * b3 + a3 * b2,
///   t6 = a3 * b3,
///
/// The addend c as well as the the words that form the result d, e are divided
/// in 2 128-bit limbs each: c_lo, c_hi, d_lo, d_hi, e_lo, e_hi.
///
/// so t0 ~ t1 include all contributions to the low 128-bit of product (e_lo),
/// with a maximum 65-bit carry (the part higher than 128-bit), denoted as
/// carry_0. Similarly, we define carry_1 as the carry of contributions to the
/// next 128-bit of the product (e_hi) with a maximum val of 66 bits. Finally,
/// we define carry_2 as the carry for the next 128 bits of the product (d_lo).
///
/// We can slightly relax the constraint of carry_0/carry_1, carry_2 to 72-bit
/// and allocate 9 bytes for them each
///
/// Finally we just prove:
///   t0 + t1 * 2^64 + c_lo = e_lo + carry_0 * 2^128
///   t2 + t3 * 2^64 + c_hi + carry_0 = e_hi + carry_1 * 2^128
///   t4 + t5 * 2^64 + carry_1 = d_lo + carry_2 * 2^128
///   t6 + carry_2 = d_hi
#[derive(Clone, Debug)]
pub(crate) struct MulAddWords512Gadget<F> {
    carry_0: [Cell<F>; 9],
    carry_1: [Cell<F>; 9],
    carry_2: [Cell<F>; 9],
}

impl<F: Field> MulAddWords512Gadget<F> {
    /// The words argument is: a, b, d, e
    /// Addend is the optional c.
    pub(crate) fn construct(
        cb: &mut EVMConstraintBuilder<F>,
        words: [&word::Word32Cell<F>; 4],
        addend: Option<&word::Word32Cell<F>>,
    ) -> Self {
        let carry_0 = cb.query_bytes();
        let carry_1 = cb.query_bytes();
        let carry_2 = cb.query_bytes();
        let carry_0_expr = from_bytes::expr(&carry_0);
        let carry_1_expr = from_bytes::expr(&carry_1);
        let carry_2_expr = from_bytes::expr(&carry_2);

        // Split input words in limbs
        let mut a_limbs = vec![];
        let mut b_limbs = vec![];
        let word4_a: Word4<Expression<F>> = words[0].to_word_n();
        let word4_b: Word4<Expression<F>> = words[1].to_word_n();
        for i in 0..4 {
            a_limbs.push(word4_a.limbs[i].expr());
            b_limbs.push(word4_b.limbs[i].expr());
        }

        let (d_lo, d_hi) = words[2].to_word().to_lo_hi();
        let (e_lo, e_hi) = words[3].to_word().to_lo_hi();

        // Limb multiplication
        let t0 = a_limbs[0].clone() * b_limbs[0].clone();
        let t1 = a_limbs[0].clone() * b_limbs[1].clone() + a_limbs[1].clone() * b_limbs[0].clone();
        let t2 = a_limbs[0].clone() * b_limbs[2].clone()
            + a_limbs[1].clone() * b_limbs[1].clone()
            + a_limbs[2].clone() * b_limbs[0].clone();
        let t3 = a_limbs[0].clone() * b_limbs[3].clone()
            + a_limbs[1].clone() * b_limbs[2].clone()
            + a_limbs[2].clone() * b_limbs[1].clone()
            + a_limbs[3].clone() * b_limbs[0].clone();
        let t4 = a_limbs[1].clone() * b_limbs[3].clone()
            + a_limbs[2].clone() * b_limbs[2].clone()
            + a_limbs[3].clone() * b_limbs[1].clone();
        let t5 = a_limbs[2].clone() * b_limbs[3].clone() + a_limbs[3].clone() * b_limbs[2].clone();
        let t6 = a_limbs[3].clone() * b_limbs[3].clone();

        if let Some(c) = addend {
            let c = c.to_word();
            let (c_lo, c_hi) = c.to_lo_hi();
            cb.require_equal(
                "(t0 + t1 ⋅ 2^64) + c_lo == e_lo + carry_0 ⋅ 2^128",
                t0.expr() + t1.expr() * pow_of_two_expr(64) + c_lo,
                e_lo + carry_0_expr.clone() * pow_of_two_expr(128),
            );

            cb.require_equal(
                "(t2 + t3 ⋅ 2^64) + c_hi + carry_0 == e_hi + carry_1 ⋅ 2^128",
                t2.expr() + t3.expr() * pow_of_two_expr(64) + c_hi + carry_0_expr,
                e_hi + carry_1_expr.clone() * pow_of_two_expr(128),
            );
        } else {
            cb.require_equal(
                "(t0 + t1 ⋅ 2^64) == e_lo + carry_0 ⋅ 2^128",
                t0.expr() + t1.expr() * pow_of_two_expr(64),
                e_lo + carry_0_expr.clone() * pow_of_two_expr(128),
            );

            cb.require_equal(
                "(t2 + t3 ⋅ 2^64) + carry_0 == e_hi + carry_1 ⋅ 2^128",
                t2.expr() + t3.expr() * pow_of_two_expr(64) + carry_0_expr,
                e_hi + carry_1_expr.clone() * pow_of_two_expr(128),
            );
        }

        cb.require_equal(
            "(t4 + t5 ⋅ 2^64) + carry_1 == d_lo + carry_2 ⋅ 2^128",
            t4.expr() + t5.expr() * pow_of_two_expr(64) + carry_1_expr,
            d_lo + carry_2_expr.clone() * pow_of_two_expr(128),
        );

        cb.require_equal("t6 + carry_2 == d_hi", t6.expr() + carry_2_expr, d_hi);

        Self {
            carry_0,
            carry_1,
            carry_2,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        words: [Word; 4],
        addend: Option<Word>,
    ) -> Result<(), Error> {
        let (a, b, d, e) = (words[0], words[1], words[2], words[3]);

        let a_limbs = split_u256_limb64(&a);
        let b_limbs = split_u256_limb64(&b);
        let (d_lo, _d_hi) = split_u256(&d);
        let (e_lo, e_hi) = split_u256(&e);

        let t0 = a_limbs[0] * b_limbs[0];
        let t1 = a_limbs[0] * b_limbs[1] + a_limbs[1] * b_limbs[0];
        let t2 = a_limbs[0] * b_limbs[2] + a_limbs[1] * b_limbs[1] + a_limbs[2] * b_limbs[0];
        let t3 = a_limbs[0] * b_limbs[3]
            + a_limbs[1] * b_limbs[2]
            + a_limbs[2] * b_limbs[1]
            + a_limbs[3] * b_limbs[0];

        let t4 = a_limbs[1] * b_limbs[3] + a_limbs[2] * b_limbs[2] + a_limbs[3] * b_limbs[1];
        let t5 = a_limbs[2] * b_limbs[3] + a_limbs[3] * b_limbs[2];

        let (carry_0, carry_1) = if let Some(c) = addend {
            let (c_lo, c_hi) = split_u256(&c);
            let carry_0 = ((t0 + (t1 << 64) + c_lo).saturating_sub(e_lo)) >> 128;
            let carry_1 = ((t2 + (t3 << 64) + c_hi + carry_0).saturating_sub(e_hi)) >> 128;
            (carry_0, carry_1)
        } else {
            let carry_0 = ((t0 + (t1 << 64)).saturating_sub(e_lo)) >> 128;
            let carry_1 = ((t2 + (t3 << 64) + carry_0).saturating_sub(e_hi)) >> 128;
            (carry_0, carry_1)
        };
        let carry_2 = ((t4 + (t5 << 64) + carry_1).saturating_sub(d_lo)) >> 128;

        self.carry_0
            .iter()
            .zip(carry_0.to_le_bytes().iter())
            .map(|(cell, byte)| cell.assign(region, offset, Value::known(F::from(*byte as u64))))
            .collect::<Result<Vec<_>, _>>()?;

        self.carry_1
            .iter()
            .zip(carry_1.to_le_bytes().iter())
            .map(|(cell, byte)| cell.assign(region, offset, Value::known(F::from(*byte as u64))))
            .collect::<Result<Vec<_>, _>>()?;

        self.carry_2
            .iter()
            .zip(carry_2.to_le_bytes().iter())
            .map(|(cell, byte)| cell.assign(region, offset, Value::known(F::from(*byte as u64))))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(())
    }
}

