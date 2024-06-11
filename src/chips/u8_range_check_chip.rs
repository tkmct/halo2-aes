use crate::{
    halo2_proofs::{
        circuit::{AssignedCell, Layouter},
        halo2curves::bn256::Fr as Fp,
        plonk::{Advice, Column, ConstraintSystem, Error, Selector, TableColumn},
        poly::Rotation,
    },
    table::Tag,
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
        tag_tab: TableColumn,
        value_tab: TableColumn,
    ) -> U8RangeCheckConfig {
        meta.lookup("Range check u8 value", |meta| {
            let q = meta.query_selector(selector);
            let x = meta.query_advice(x_col, Rotation::cur());

            vec![
                (q.clone() * Fp::from(Tag::U8 as u64), tag_tab),
                (q * x, value_tab),
            ]
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
            || "",
            |mut region| {
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
