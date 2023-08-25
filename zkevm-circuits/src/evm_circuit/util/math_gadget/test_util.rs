use itertools::Itertools;
use std::marker::PhantomData;
use strum::IntoEnumIterator;

use crate::{
    evm_circuit::{
        param::{MAX_STEP_HEIGHT, N_PHASE2_COLUMNS, STEP_WIDTH},
        step::{ExecutionState, Step},
        table::{FixedTableTag, Table},
        util::{
            constraint_builder::EVMConstraintBuilder, rlc, CachedRegion, StoredExpression,
            LOOKUP_CONFIG,
        },
        Advice, Column, Fixed,
    },
    table::LookupTable,
    util::{cell_manager::CellType, Challenges},
};
use eth_types::{Field, Word};
pub(crate) use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::{
    circuit::SimpleFloorPlanner,
    plonk::{Circuit, ConstraintSystem, Error, FirstPhase, SecondPhase, Selector, ThirdPhase},
};

// Maximum field value in bn256: bn256::MODULES - 1

// I256::MAX = 2^255 - 1, and I256::MIN = 2^255.

pub(crate) trait MathGadgetContainer<F: Field>: Clone {
    fn configure_gadget_container(cb: &mut EVMConstraintBuilder<F>) -> Self
    where
        Self: Sized;

    fn assign_gadget_container(
        &self,
        witnesses: &[Word],
        region: &mut CachedRegion<'_, '_, F>,
    ) -> Result<(), Error>;
}

#[derive(Debug, Clone)]
pub(crate) struct UnitTestMathGadgetBaseCircuitConfig<F: Field, G>
where
    G: MathGadgetContainer<F>,
{
    q_usable: Selector,
    fixed_table: [Column<Fixed>; 4],
    advices: [Column<Advice>; STEP_WIDTH],
    step: Step<F>,
    stored_expressions: Vec<StoredExpression<F>>,
    math_gadget_container: G,
    _marker: PhantomData<F>,
}

pub(crate) struct UnitTestMathGadgetBaseCircuit<G> {
    witnesses: Vec<Word>,
    _marker: PhantomData<G>,
}


impl<F: Field, G: MathGadgetContainer<F>> Circuit<F> for UnitTestMathGadgetBaseCircuit<G> {
    type Config = (UnitTestMathGadgetBaseCircuitConfig<F, G>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        UnitTestMathGadgetBaseCircuit {
            witnesses: vec![],
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let challenges = Challenges::construct(meta);
        let challenges_exprs = challenges.exprs(meta);

        let q_usable = meta.selector();
        let fixed_table = [(); 4].map(|_| meta.fixed_column());

        let lookup_column_count: usize = LOOKUP_CONFIG.iter().map(|(_, count)| *count).sum();
        let advices = [(); STEP_WIDTH]
            .iter()
            .enumerate()
            .map(|(n, _)| {
                if n < lookup_column_count {
                    meta.advice_column_in(ThirdPhase)
                } else if n < lookup_column_count + N_PHASE2_COLUMNS {
                    meta.advice_column_in(SecondPhase)
                } else {
                    meta.advice_column_in(FirstPhase)
                }
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let step_curr = Step::new(meta, advices, 0);
        let step_next = Step::new(meta, advices, MAX_STEP_HEIGHT);
        let mut cb = EVMConstraintBuilder::new(
            meta,
            step_curr.clone(),
            step_next,
            &challenges_exprs,
            ExecutionState::STOP,
        );
        let math_gadget_container = G::configure_gadget_container(&mut cb);
        let (constraints, stored_expressions, _, _) = cb.build();

        if !constraints.step.is_empty() {
            let step_constraints = constraints.step;
            meta.create_gate("MathGadgetTestContainer", |meta| {
                let q_usable = meta.query_selector(q_usable);
                step_constraints
                    .into_iter()
                    .map(move |(name, constraint)| (name, q_usable.clone() * constraint))
            });
        }

        let cell_manager = step_curr.cell_manager.clone();
        for column in cell_manager.columns().iter() {
            if let CellType::Lookup(table) = column.cell_type {
                let column_expr = column.expr(meta);
                if table == Table::Fixed {
                    let name = format!("{:?}", table);
                    meta.lookup_any(Box::leak(name.into_boxed_str()), |meta| {
                        let table_expressions = fixed_table.table_exprs(meta);
                        vec![(
                            column_expr,
                            rlc::expr(&table_expressions, challenges_exprs.lookup_input()),
                        )]
                    });
                }
            }
        }

        (
            UnitTestMathGadgetBaseCircuitConfig::<F, G> {
                q_usable,
                fixed_table,
                advices,
                step: step_curr,
                stored_expressions,
                math_gadget_container,
                _marker: PhantomData,
            },
            challenges,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let (config, challenges) = config;
        let challenge_values = challenges.values(&mut layouter);
        layouter.assign_region(
            || "assign test container",
            |mut region| {
                let offset = 0;
                config.q_usable.enable(&mut region, offset)?;
                let cached_region = &mut CachedRegion::<'_, '_, F>::new(
                    &mut region,
                    &challenge_values,
                    config.advices.to_vec(),
                    MAX_STEP_HEIGHT * 3,
                    offset,
                );
                config.step.state.execution_state.assign(
                    cached_region,
                    offset,
                    ExecutionState::STOP as usize,
                )?;
                config
                    .math_gadget_container
                    .assign_gadget_container(&self.witnesses, cached_region)?;
                for stored_expr in &config.stored_expressions {
                    stored_expr.assign(cached_region, offset)?;
                }
                Ok(())
            },
        )?;

        // assign fixed range tables only as they are the only tables referred by a
        // specfic math gadget -- ConstantDivisionGadget.
        layouter.assign_region(
            || "fixed table",
            |mut region| {
                for (offset, row) in std::iter::once([F::ZERO; 4])
                    .chain(
                        FixedTableTag::iter()
                            .filter(|t| {
                                matches!(
                                    t,
                                    FixedTableTag::Range5
                                        | FixedTableTag::Range16
                                        | FixedTableTag::Range32
                                        | FixedTableTag::Range64
                                        | FixedTableTag::Range128
                                        | FixedTableTag::Range256
                                        | FixedTableTag::Range512
                                        | FixedTableTag::Range1024
                                )
                            })
                            .flat_map(|tag| tag.build()),
                    )
                    .enumerate()
                {
                    for (column, value) in config.fixed_table.iter().zip_eq(row) {
                        region.assign_fixed(|| "", *column, offset, || Value::known(value))?;
                    }
                }

                Ok(())
            },
        )
    }
}


