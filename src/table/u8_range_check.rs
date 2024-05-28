use crate::halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    halo2curves::bn256::Fr as Fp,
    plonk::{Advice, Column, ConstraintSystem, Error, Selector, TableColumn},
    poly::Rotation,
};

#[derive(Clone, Debug)]
pub struct U8RangeCheckConfig {
    q_lookup: Selector,
    value: Column<Advice>,
    pub table: U8RangeTableConfig,
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

    pub fn assign(
        &self,
        mut layouter: impl Layouter<Fp>,
        value: &AssignedCell<Fp, Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        layouter.assign_region(
            || "Assign u8 range_checked value",
            |mut region| {
                let offset = 0;

                self.q_lookup.enable(&mut region, offset)?;
                value.copy_advice(|| "Assign value to range_check", &mut region, self.value, 0)
            },
        )
    }
}

#[derive(Clone, Debug)]
pub struct U8RangeTableConfig {
    pub(crate) value: TableColumn,
}

impl U8RangeTableConfig {
    pub(crate) fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        Self {
            value: meta.lookup_table_column(),
        }
    }

    pub fn load(&self, layouter: &mut impl Layouter<Fp>) -> Result<(), Error> {
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
#[cfg(feature = "halo2-pse")]
mod tests {
    use super::*;

    use crate::halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::{FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::Fr as Fp,
        plonk::{Circuit, ConstraintSystem, Error},
    };

    #[derive(Debug)]
    struct TestCircuit {
        value: Value<Fp>,
    }

    impl Circuit<Fp> for TestCircuit {
        type Config = U8RangeCheckConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let value = meta.advice_column();
            meta.enable_equality(value);
            U8RangeCheckConfig::configure(meta, value)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            config.table.load(&mut layouter)?;

            // assign cell to range check for testing
            let assigned_cell = layouter.assign_region(
                || "assign value",
                |mut region| {
                    region.assign_advice(|| "Value to be checked", config.value, 0, || self.value)
                },
            )?;
            config.assign(layouter, &assigned_cell)?;

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
                    region: (2, "Assign u8 range_checked value").into(),
                    offset: 0
                }
            }])
        );
    }
}
