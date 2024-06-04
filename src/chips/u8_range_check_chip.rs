use crate::{
    halo2_proofs::{
        circuit::{AssignedCell, Layouter},
        halo2curves::bn256::Fr as Fp,
        plonk::{Advice, Column, ConstraintSystem, Error, Selector},
        poly::Rotation,
    },
    table::u8_range_check::U8RangeCheckTableConfig,
};

#[derive(Clone, Copy, Debug)]
pub struct U8RangeCheckConfig {
    x: Column<Advice>,
    q: Selector,
}

#[derive(Clone, Copy, Debug)]
pub struct U8RangeCheckChip {
    config: U8RangeCheckConfig,
}

// TODO: implement Chip trait?
impl U8RangeCheckChip {
    pub fn construct(config: U8RangeCheckConfig) -> Self {
        Self { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        x_col: Column<Advice>,
        selector: Selector,
        table_config: U8RangeCheckTableConfig,
    ) -> U8RangeCheckConfig {
        meta.lookup("Range check u8 value", |meta| {
            let q = meta.query_selector(selector);
            let x = meta.query_advice(x_col, Rotation::cur());

            vec![(q.clone() * x, table_config.value)]
        });

        U8RangeCheckConfig {
            x: x_col,
            q: selector,
        }
    }

    pub fn range_check(
        &self,
        layouter: &mut impl Layouter<Fp>,
        x: &AssignedCell<Fp, Fp>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "Enable selector for checked value",
            |mut region| {
                // TODO: get offset from this region to x's region and calculate the relative offset from this region
                //    let offset = get_region_offset(
                //     layouter
                //     x.cell().region_index,
                //     x.cell().row_offset
                //     );
                //
                // self.config.q.enable()

                self.config.q.enable(&mut region, 0)?;
                x.copy_advice(
                    || "assign x value to check u8 xor",
                    &mut region,
                    self.config.x,
                    0,
                )?;

                Ok(())
            },
        )
    }
}
