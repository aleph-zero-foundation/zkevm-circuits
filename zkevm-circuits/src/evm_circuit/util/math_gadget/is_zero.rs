use crate::{
    evm_circuit::util::{
        constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
        CachedRegion, Cell, CellType,
    },
    util::Expr,
};
use eth_types::Field;
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

/// Returns `1` when `value == 0`, and returns `0` otherwise.
#[derive(Clone, Debug)]
pub struct IsZeroGadget<F> {
    inverse: Cell<F>,
    is_zero: Expression<F>,
}

impl<F: Field> IsZeroGadget<F> {
    pub(crate) fn construct(cb: &mut EVMConstraintBuilder<F>, value: Expression<F>) -> Self {
        let inverse = cb.query_cell_with_type(CellType::storage_for_expr(&value));

        let is_zero = 1.expr() - (value.clone() * inverse.expr());
        // when `value != 0` check `inverse = a.invert()`: value * (1 - value *
        // inverse)
        cb.add_constraint("value ⋅ (1 - value ⋅ value_inv)", value * is_zero.clone());
        // when `value == 0` check `inverse = 0`: `inverse ⋅ (1 - value *
        // inverse)`
        cb.add_constraint(
            "value_inv ⋅ (1 - value ⋅ value_inv)",
            inverse.expr() * is_zero.clone(),
        );

        Self { inverse, is_zero }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        self.is_zero.clone()
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: F,
    ) -> Result<F, Error> {
        let inverse = value.invert().unwrap_or(F::ZERO);
        self.inverse.assign(region, offset, Value::known(inverse))?;
        Ok(if value.is_zero().into() {
            F::ONE
        } else {
            F::ZERO
        })
    }
}

