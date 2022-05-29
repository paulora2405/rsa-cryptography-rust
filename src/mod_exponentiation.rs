use num_bigint::BigUint;
use num_traits::{One, Zero};

#[must_use]
pub fn mod_pow(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    let mut result = BigUint::from(1u8);
    let mut base_ = base % modulus;
    let mut exp = exponent.clone();

    while !exp.is_zero() {
        let s_bit = &exp % 2u8 == One::one();
        result = ((&result * &base_) % modulus) * u8::from(s_bit) + &result * (1 - u8::from(s_bit));

        exp >>= 1u8;
        base_ = (base_.pow(2)) % modulus;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mod_exp() {
        let base = 4u64;
        let exponent = 13u64;
        let modulus = 497u64;
        let result = 445u64;
        assert_eq!(
            mod_pow(
                &BigUint::from(base),
                &BigUint::from(exponent),
                &BigUint::from(modulus)
            ),
            BigUint::from(result)
        );
        let base = 23u64;
        let exponent = 20u64;
        let modulus = 29u64;
        let result = 24u64;
        assert_eq!(
            mod_pow(
                &BigUint::from(base),
                &BigUint::from(exponent),
                &BigUint::from(modulus)
            ),
            BigUint::from(result)
        );
        let base = 31u64;
        let exponent = 397u64;
        let modulus = 55u64;
        let result = 26u64;
        assert_eq!(
            mod_pow(
                &BigUint::from(base),
                &BigUint::from(exponent),
                &BigUint::from(modulus)
            ),
            BigUint::from(result)
        );
    }
}
