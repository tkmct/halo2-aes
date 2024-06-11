use crate::{
    constant::{MUL_BY_2, MUL_BY_3, S_BOX},
    halo2_proofs::{
        circuit::{Layouter, Value},
        halo2curves::bn256::Fr as Fp,
        plonk::{Error, TableColumn},
    },
};

pub(crate) enum Tag {
    U8 = 1,
    Xor = 2,
    Sbox = 3,
    GfMul2 = 4,
    GfMul3 = 5,
}

pub fn load_enc_full_table(
    layouter: &mut impl Layouter<Fp>,
    tables: [TableColumn; 4],
) -> Result<(), Error> {
    layouter.assign_table(
        || "Assign full table",
        |mut table| {
            let mut offset = 0;
            // Assign for u8 range check
            for i in 0..=u8::MAX {
                let pos = (i as usize) + offset;
                table.assign_cell(
                    || "",
                    tables[0],
                    pos,
                    || Value::known(Fp::from(Tag::U8 as u64)),
                )?;
                table.assign_cell(
                    || "assign cell for u8 range_check",
                    tables[1],
                    pos,
                    || Value::known(Fp::from(i as u64)),
                )?;
                table.assign_cell(
                    || "assign empty",
                    tables[2],
                    pos,
                    || Value::known(Fp::from(0)),
                )?;
                table.assign_cell(
                    || "assign empty",
                    tables[3],
                    pos,
                    || Value::known(Fp::from(0)),
                )?;
            }
            offset += 256;

            // Assign sbox
            for i in 0..256 {
                let pos = offset + i;
                table.assign_cell(
                    || "assign tag for sbox",
                    tables[0],
                    pos,
                    || Value::known(Fp::from(Tag::Sbox as u64)),
                )?;
                table.assign_cell(
                    || "assign cell for sbox input",
                    tables[1],
                    pos,
                    || Value::known(Fp::from(i as u64)),
                )?;
                table.assign_cell(
                    || "assign cell for sbox output",
                    tables[2],
                    pos,
                    || Value::known(Fp::from(S_BOX[i] as u64)),
                )?;
                table.assign_cell(
                    || "assign empty",
                    tables[3],
                    pos,
                    || Value::known(Fp::from(0)),
                )?;
            }
            offset += 256;

            // Assign XOR
            let mut l = offset;
            for i in 0..=u8::MAX {
                for j in 0..=u8::MAX {
                    table.assign_cell(
                        || "assign tag for xor",
                        tables[0],
                        l,
                        || Value::known(Fp::from(Tag::Xor as u64)),
                    )?;
                    table.assign_cell(
                        || "assign cell for left input of XOR table",
                        tables[1],
                        l,
                        || Value::known(Fp::from(i as u64)),
                    )?;
                    table.assign_cell(
                        || "assign cell for right input of XOR table",
                        tables[2],
                        l,
                        || Value::known(Fp::from(j as u64)),
                    )?;
                    table.assign_cell(
                        || "assign cell for output of XOR table",
                        tables[3],
                        l,
                        || Value::known(Fp::from((i ^ j) as u64)),
                    )?;
                    l += 1;
                }
            }
            offset += 65536;

            // Assign mul2
            for i in 0..256 {
                table.assign_cell(
                    || "assign tag for mul",
                    tables[0],
                    offset + i,
                    || Value::known(Fp::from(Tag::GfMul2 as u64)),
                )?;
                table.assign_cell(
                    || "assign cell for mul input byte",
                    tables[1],
                    offset + i,
                    || Value::known(Fp::from(i as u64)),
                )?;
                table.assign_cell(
                    || "assign cell for mul output byte",
                    tables[2],
                    offset + i,
                    || Value::known(Fp::from(MUL_BY_2[i] as u64)),
                )?;
                table.assign_cell(
                    || "assign empty",
                    tables[3],
                    offset + i,
                    || Value::known(Fp::from(0)),
                )?;
            }
            offset += 256;

            // Assign mul3
            for i in 0..256 {
                table.assign_cell(
                    || "assign tag for mul",
                    tables[0],
                    offset + i,
                    || Value::known(Fp::from(Tag::GfMul3 as u64)),
                )?;
                table.assign_cell(
                    || "assign cell for mul input byte",
                    tables[1],
                    offset + i,
                    || Value::known(Fp::from(i as u64)),
                )?;
                table.assign_cell(
                    || "assign cell for mul output byte",
                    tables[2],
                    offset + i,
                    || Value::known(Fp::from(MUL_BY_3[i] as u64)),
                )?;
                table.assign_cell(
                    || "assign empty",
                    tables[3],
                    offset + i,
                    || Value::known(Fp::from(0)),
                )?;
            }
            offset += 256;

            // Add empty row
            tables.iter().for_each(|&col| {
                table
                    .assign_cell(
                        || "assign zero row",
                        col,
                        offset,
                        || Value::known(Fp::from(0)),
                    )
                    .expect("Should success to assign cell");
            });

            Ok(())
        },
    )
}
