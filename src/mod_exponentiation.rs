use num_bigint::BigUint;
use num_traits::{One, Zero};

pub fn mod_pow(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    let mut result = BigUint::from(1u8);
    let mut base = base & modulus;
    let mut exp = exponent.clone();

    while !exp.is_zero() {
        let s_bit = &exp % 2u8 == One::one();
        result = ((&result * &base) % modulus) * u8::from(s_bit) + &result * (1 - u8::from(s_bit));

        exp >>= 1u8;
        base = (base.pow(2)) % modulus;
    }
    result
}
