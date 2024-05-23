use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr as Fp, plonk::Error};

use crate::table::s_box::S_BOX;

/// Calculate xor of given two bytes.
/// Returns the new value
pub(crate) fn xor_bytes(x: &Value<Fp>, y: &Value<Fp>) -> Result<Value<Fp>, Error> {
    // x and y should be u8.
    Ok(x.zip(*y)
        .map(|(x, y)| {
            x.to_bytes()
                .iter()
                .zip(y.to_bytes())
                .map(|(x_b, y_b)| x_b ^ y_b)
                .collect::<Vec<_>>()
        })
        .map(|bytes| Fp::from_bytes(&bytes.try_into().unwrap()).unwrap()))
}
/// Calculate XOR of given two words.
pub(crate) fn xor_words(x: &Vec<Value<Fp>>, y: &Vec<Value<Fp>>) -> Result<Vec<Value<Fp>>, Error> {
    x.iter()
        .zip(y)
        .map(|(x, y)| xor_bytes(x, y))
        .collect::<Result<Vec<_>, Error>>()
}

/// Substitute single byte using s-box
pub(crate) fn sub_byte(x: &Value<Fp>) -> Value<Fp> {
    x.map(|v| Fp::from(S_BOX[*v.to_bytes().first().unwrap() as usize] as u64))
}

/// Substitute each byte in a word using s-box
pub(crate) fn sub_word(x: &Vec<Value<Fp>>) -> Vec<Value<Fp>> {
    assert!(x.len() == 4);
    let word = x.iter().map(sub_byte).collect::<Vec<_>>();
    word
}

/// See here for the detailed explanation of the constant.
/// https://en.wikipedia.org/wiki/AES_key_schedule
const ROUND_CONSTANT: [u64; 10] = [1, 2, 4, 8, 16, 32, 64, 128, 27, 54];

/// Get round constant value from
pub(crate) fn get_round_constant(round: u32) -> Value<Fp> {
    Value::known(Fp::from(ROUND_CONSTANT[round as usize]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr as Fp};

    #[test]
    fn test_xor_bytes() {
        let x = Value::known(Fp::from(5));
        let y = Value::known(Fp::from(12));
        let z = xor_bytes(&x, &y).unwrap();

        z.assert_if_known(|v| v.eq(&Fp::from(9)));
    }
}
