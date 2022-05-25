use num_bigint::{BigUint, ToBigUint};

pub fn mod_pow(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    let mut result = 1u8.to_biguint().unwrap();
    let mut base = base & modulus;
    let mut exp = exponent.clone();

    while exp > 0u8.to_biguint().unwrap() {
        let s_bit = &exp % &2u8.to_biguint().unwrap() == 1u8.to_biguint().unwrap();
        result = ((&result * &base) % modulus) * u8::from(s_bit) + &result * (1 - u8::from(s_bit));

        exp >>= 1u8;
        base = (base.pow(2)) % modulus;
    }
    result
}
