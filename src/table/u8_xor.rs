use crate::halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::bn256::Fr as Fp,
    plonk::{ConstraintSystem, Error, TableColumn},
};

#[derive(Clone, Copy, Debug)]
pub struct U8XorTableConfig {
    pub x: TableColumn,
    pub y: TableColumn,
    pub z: TableColumn,
}

impl U8XorTableConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let x = meta.lookup_table_column();
        let y = meta.lookup_table_column();
        let z = meta.lookup_table_column();

        meta.annotate_lookup_column(x, || "LOOKUP_U8_XOR_X");
        meta.annotate_lookup_column(y, || "LOOKUP_U8_XOR_Y");
        meta.annotate_lookup_column(z, || "LOOKUP_U8_XOR_Z");

        Self { x, y, z }
    }

    pub fn load(&self, layouter: &mut impl Layouter<Fp>) -> Result<(), Error> {
        // create u8 ^ u8 = u8 table
        layouter.assign_table(
            || "load xor table for u8",
            |mut table| {
                let mut l = 0;
                for i in 0..=u8::MAX {
                    for j in 0..=u8::MAX {
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
