use crate::halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::bn256::Fr as Fp,
    plonk::{ConstraintSystem, Error, TableColumn},
};

#[derive(Clone, Copy, Debug)]
pub struct U8RangeCheckTableConfig {
    pub value: TableColumn,
}

impl U8RangeCheckTableConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
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
