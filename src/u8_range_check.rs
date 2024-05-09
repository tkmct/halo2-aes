use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    halo2curves::bn256::Fr as Fp,
    plonk::{Advice, Assigned, Column, ConstraintSystem, Error, Selector, TableColumn},
    poly::Rotation,
};

#[derive(Debug, Clone)]
/// A range-constrained value in the circuit produced by the RangeCheckConfig.
pub(crate) struct U8RangeConstrained(pub(crate) AssignedCell<Assigned<Fp>, Fp>);

#[derive(Clone, Debug)]
pub(crate) struct U8RangeCheckConfig {
    q_lookup: Selector,
    value: Column<Advice>,
    table: U8RangeTableConfig,
}

impl U8RangeCheckConfig {
    pub(crate) fn configure(meta: &mut ConstraintSystem<Fp>, value: Column<Advice>) -> Self {
        let q_lookup = meta.complex_selector();
        let table = U8RangeTableConfig::configure(meta);

        meta.lookup("U8 range_check", |meta| {
            let val = meta.query_advice(value, Rotation::cur());
            let q = meta.query_selector(q_lookup);

            vec![(q * val, table.value)]
        });

        U8RangeCheckConfig {
            q_lookup,
            value,
            table,
        }
    }

    pub(crate) fn assign(
        &self,
        mut layouter: impl Layouter<Fp>,
        value: &Value<Assigned<Fp>>,
    ) -> Result<U8RangeConstrained, Error> {
        layouter.assign_region(
            || "Assign u8 range_checked value",
            |mut region| {
                let offset = 0;

                self.q_lookup.enable(&mut region, offset)?;
                region
                    .assign_advice(
                        || "assign u8 range_check advice value",
                        self.value,
                        offset,
                        || value.clone(),
                    )
                    .map(U8RangeConstrained)
            },
        )
    }
}

#[derive(Clone, Debug)]
pub(crate) struct U8RangeTableConfig {
    pub(crate) value: TableColumn,
}

impl U8RangeTableConfig {
    pub(crate) fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        Self {
            value: meta.lookup_table_column(),
        }
    }

    pub(crate) fn load(&self, layouter: &mut impl Layouter<Fp>) -> Result<(), Error> {
        // create u8 table
        layouter.assign_table(
            || "load range table for u8",
            |mut table| {
                for i in 0..=u8::MAX {
                    table.assign_cell(
                        || "assign cell for u8 range_check",
                        self.value,
                        i as usize,
                        || Value::known(Fp::from(i as u64)),
                    )?;
                }

                Ok(())
            },
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::{FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::Fr as Fp,
        plonk::{Assigned, Circuit, ConstraintSystem, Error},
    };

    #[derive(Debug)]
    struct TestCircuit {
        value: Value<Assigned<Fp>>,
    }

    impl Circuit<Fp> for TestCircuit {
        type Config = U8RangeCheckConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let value = meta.advice_column();
            U8RangeCheckConfig::configure(meta, value)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            config.table.load(&mut layouter)?;
            config.assign(layouter, &self.value)?;

            Ok(())
        }

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }
    }

    #[test]
    fn test_range_check_success() {
        let k = 9;
        let circuit = TestCircuit {
            value: Value::known(Fp::from(255).into()),
        };

        let mock = MockProver::run(k, &circuit, vec![]).unwrap();
        mock.assert_satisfied();
    }

    #[test]
    fn test_range_check_fail() {
        let k = 9;
        let circuit = TestCircuit {
            value: Value::known(Fp::from(256).into()),
        };

        let mock = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(
            mock.verify(),
            Err(vec![VerifyFailure::Lookup {
                name: "U8 range_check".into(),
                lookup_index: 0,
                location: FailureLocation::InRegion {
                    region: (1, "Assign u8 range_checked value").into(),
                    offset: 0
                }
            }])
        );
    }
}
