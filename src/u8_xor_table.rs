use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    halo2curves::bn256::Fr as Fp,
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector, TableColumn},
    poly::Rotation,
};

#[derive(Clone, Debug)]
pub(crate) struct U8XorTableConfig {
    pub(crate) x: TableColumn,
    pub(crate) y: TableColumn,
    pub(crate) z: TableColumn,
}

impl U8XorTableConfig {
    pub(crate) fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        Self {
            x: meta.lookup_table_column(),
            y: meta.lookup_table_column(),
            z: meta.lookup_table_column(),
        }
    }

    pub(crate) fn load(&self, layouter: &mut impl Layouter<Fp>) -> Result<(), Error> {
        // create u8 ^ u8 = u8 table
        layouter.assign_table(
            || "load xor table for u8",
            |mut table| {
                let mut l = 0;
                for i in 0..u8::MAX {
                    for j in 0..u8::MAX {
                        table.assign_cell(
                            || "assign cell for left input of XOR table",
                            self.x,
                            l,
                            || Value::known(Fp::from(i as u64)),
                        )?;
                        table.assign_cell(
                            || "assign cell for right input of XOR table",
                            self.y,
                            l,
                            || Value::known(Fp::from(j as u64)),
                        )?;
                        table.assign_cell(
                            || "assign cell for output of XOR table",
                            self.z,
                            l,
                            || Value::known(Fp::from((i ^ j) as u64)),
                        )?;
                        l += 1;
                    }
                }

                Ok(())
            },
        )?;
        Ok(())
    }
}
