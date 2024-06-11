use crate::{
    constant::{MUL_BY_2, MUL_BY_3},
    halo2_proofs::{
        circuit::{AssignedCell, Layouter},
        halo2curves::bn256::Fr as Fp,
        plonk::{Advice, Column, ConstraintSystem, Error, Selector, TableColumn},
        poly::Rotation,
    },
    table::Tag,
};

macro_rules! define_mul_chip {
    ($chip_name:ident, $config_name:ident, $table:ty, $dict:expr, $n:expr, $tag:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $config_name {
            x: Column<Advice>,
            y: Column<Advice>,
            q: Selector,
        }

        #[derive(Clone, Copy, Debug)]
        pub struct $chip_name {
            config: $config_name,
        }

        impl $chip_name {
            pub fn construct(config: $config_name) -> Self {
                Self { config }
            }

            pub fn configure(
                meta: &mut ConstraintSystem<Fp>,
                x_col: Column<Advice>,
                y_col: Column<Advice>,
                selector: Selector,
                tag_tab: TableColumn,
                x_tab: TableColumn,
                y_tab: TableColumn,
            ) -> $config_name {
                meta.lookup("Check correct gf mul by $n", |meta| {
                    let q = meta.query_selector(selector);
                    let x = meta.query_advice(x_col, Rotation::cur());
                    let y = meta.query_advice(y_col, Rotation::cur());

                    vec![
                        (q.clone() * Fp::from($tag as u64), tag_tab),
                        (q.clone() * x, x_tab),
                        (q * y, y_tab),
                    ]
                });

                $config_name {
                    x: x_col,
                    y: y_col,
                    q: selector,
                }
            }

            pub fn mul(
                &self,
                layouter: &mut impl Layouter<Fp>,
                x: &AssignedCell<Fp, Fp>,
            ) -> Result<AssignedCell<Fp, Fp>, Error> {
                layouter.assign_region(
                    || "",
                    |mut region| {
                        self.config.q.enable(&mut region, 0)?;
                        x.copy_advice(
                            || "assign x value for gf mul by $n",
                            &mut region,
                            self.config.x,
                            0,
                        )?;

                        let y = region.assign_advice(
                            || "assign y value for gf mul by $n",
                            self.config.y,
                            0,
                            || {
                                x.value().map(|v| {
                                    Fp::from($dict[*v.to_bytes().first().unwrap() as usize] as u64)
                                })
                            },
                        );

                        Ok(y)
                    },
                )?
            }
        }
    };
}

define_mul_chip!(
    MulBy2Chip,
    MulBy2Config,
    PolyMulBy2TableConfig,
    MUL_BY_2,
    2,
    Tag::GfMul2
);
define_mul_chip!(
    MulBy3Chip,
    MulBy3Config,
    PolyMulBy3TableConfig,
    MUL_BY_3,
    3,
    Tag::GfMul3
);
