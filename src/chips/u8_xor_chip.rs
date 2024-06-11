use crate::{
    halo2_proofs::{
        circuit::{AssignedCell, Layouter},
        halo2curves::bn256::Fr as Fp,
        plonk::{Advice, Column, ConstraintSystem, Error, Selector, TableColumn},
        poly::Rotation,
    },
    table::Tag,
    utils::xor_bytes,
};

#[derive(Clone, Copy, Debug)]
pub struct U8XorConfig {
    x: Column<Advice>,
    y: Column<Advice>,
    z: Column<Advice>,
    q: Selector,
}

#[derive(Clone, Copy, Debug)]
pub struct U8XorChip {
    config: U8XorConfig,
}

impl U8XorChip {
    pub fn construct(config: U8XorConfig) -> Self {
        Self { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        x_col: Column<Advice>,
        y_col: Column<Advice>,
        z_col: Column<Advice>,
        selector: Selector,
        tag_tab: TableColumn,
        x_tab: TableColumn,
        y_tab: TableColumn,
        z_tab: TableColumn,
    ) -> U8XorConfig {
        meta.lookup("Check correct XOR of u8 values", |meta| {
            let q = meta.query_selector(selector);
            let x = meta.query_advice(x_col, Rotation::cur());
            let y = meta.query_advice(y_col, Rotation::cur());
            let z = meta.query_advice(z_col, Rotation::cur());

            vec![
                (q.clone() * Fp::from(Tag::Xor as u64), tag_tab),
                (q.clone() * x, x_tab),
                (q.clone() * y, y_tab),
                (q * z, z_tab),
            ]
        });

        U8XorConfig {
            x: x_col,
            y: y_col,
            z: z_col,
            q: selector,
        }
    }

    pub fn xor(
        &self,
        layouter: &mut impl Layouter<Fp>,
        x: &AssignedCell<Fp, Fp>,
        y: &AssignedCell<Fp, Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        layouter.assign_region(
            || "",
            |mut region| {
                self.config.q.enable(&mut region, 0)?;
                let x_copied = x.copy_advice(
                    || "assign x value to check u8 xor",
                    &mut region,
                    self.config.x,
                    0,
                )?;
                let y_copied = y.copy_advice(
                    || "assign y value to check u8 xor",
                    &mut region,
                    self.config.y,
                    0,
                )?;
                let z = region.assign_advice(
                    || "assign z value to check u8 xor",
                    self.config.z,
                    0,
                    || {
                        xor_bytes(
                            &x_copied.value_field().evaluate(),
                            &y_copied.value_field().evaluate(),
                        )
                    },
                );

                Ok(z)
            },
        )?
    }
}
