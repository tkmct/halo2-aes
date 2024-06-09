use crate::{
    halo2_proofs::{
        circuit::{AssignedCell, Layouter},
        halo2curves::bn256::Fr as Fp,
        plonk::{Advice, Column, ConstraintSystem, Error, Selector},
        poly::Rotation,
    },
    table::s_box::SboxTableConfig,
    utils::sub_byte,
};

#[derive(Clone, Copy, Debug)]
pub struct SboxConfig {
    x: Column<Advice>,
    y: Column<Advice>,
    q: Selector,
}

#[derive(Clone, Copy, Debug)]
pub struct SboxChip {
    config: SboxConfig,
}

impl SboxChip {
    pub fn construct(config: SboxConfig) -> Self {
        Self { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        x_col: Column<Advice>,
        y_col: Column<Advice>,
        selector: Selector,
        table_config: SboxTableConfig,
    ) -> SboxConfig {
        meta.lookup("Check correct Sbox substitution", |meta| {
            let q = meta.query_selector(selector);
            let x = meta.query_advice(x_col, Rotation::cur());
            let y = meta.query_advice(y_col, Rotation::cur());

            vec![(q.clone() * x, table_config.x), (q * y, table_config.y)]
        });

        SboxConfig {
            x: x_col,
            y: y_col,
            q: selector,
        }
    }

    pub fn substitute(
        &self,
        layouter: &mut impl Layouter<Fp>,
        x: &AssignedCell<Fp, Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        layouter.assign_region(
            || "assign values for Sbox substitution",
            |mut region| {
                self.config.q.enable(&mut region, 0)?;
                let x_copied = x.copy_advice(
                    || "assign x value for sbox_sub",
                    &mut region,
                    self.config.x,
                    0,
                )?;

                let y = region.assign_advice(
                    || "assign y value for sbox_sub",
                    self.config.y,
                    0,
                    || sub_byte(&x_copied.value_field().evaluate()),
                );

                Ok(y)
            },
        )?
    }
}
