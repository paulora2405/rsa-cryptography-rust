use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};

// pub fn gcd(a: &mut BigUint, b: &mut BigUint) -> BigUint {
//     if b > a {
//         swap(a, b);
//     }

//     let mut r: BigUint = a % b;
//     if r == 0u8.to_biguint().unwrap() {
//         return *b;
//     }

//     gcd(b, &mut r)
// }

// pub fn gcd_iter(a: &mut BigUint, b: &mut BigUint) -> BigUint {
//     while *b > 0u8.to_biguint().unwrap() {
//         *a %= *b;
//         swap(a, b)
//     }
//     *a
// }

pub fn euclides_extended(a: &BigUint, b: &BigUint) -> (BigInt, BigInt, BigInt) {
    let (mut old_r, mut rem) = (BigInt::from(a.clone()), BigInt::from(b.clone()));
    let (mut old_s, mut coeff_s) = (One::one(), Zero::zero());
    let (mut old_t, mut coeff_t) = (Zero::zero(), One::one());

    while !rem.is_zero() {
        let quotient = old_r.clone() / rem.clone();

        update_step(&mut rem, &mut old_r, &quotient);
        update_step(&mut coeff_s, &mut old_s, &quotient);
        update_step(&mut coeff_t, &mut old_t, &quotient);
    }

    (old_r, old_s, old_t)
}

fn update_step(a: &mut BigInt, old_a: &mut BigInt, quotient: &BigInt) {
    let tmp = a.clone();
    *a = &*old_a - quotient * &tmp;
    *old_a = tmp;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_signed_values() {
        assert_eq!(
            euclides_extended(&BigUint::from(101u8), &BigUint::from(13u8)),
            (BigInt::from(1u8), BigInt::from(4u8), BigInt::from(-31i8))
        );
        assert_eq!(
            euclides_extended(&BigUint::from(123u8), &BigUint::from(19u8)),
            (BigInt::from(1i8), BigInt::from(-2i8), BigInt::from(13i8))
        );
        assert_eq!(
            euclides_extended(&BigUint::from(25u8), &BigUint::from(36u8)),
            (BigInt::from(1i8), BigInt::from(13i8), BigInt::from(-9i8))
        );
        assert_eq!(
            euclides_extended(&BigUint::from(69u8), &BigUint::from(54u8)),
            (BigInt::from(3i8), BigInt::from(-7i8), BigInt::from(9i8))
        );
        assert_eq!(
            euclides_extended(&BigUint::from(55u8), &BigUint::from(79u8)),
            (BigInt::from(1i8), BigInt::from(23i8), BigInt::from(-16i8))
        );
        assert_eq!(
            euclides_extended(&BigUint::from(33u8), &BigUint::from(44u8)),
            (BigInt::from(11i8), BigInt::from(-1i8), BigInt::from(1i8))
        );
        assert_eq!(
            euclides_extended(&BigUint::from(50u8), &BigUint::from(70u8)),
            (BigInt::from(10i8), BigInt::from(3i8), BigInt::from(-2i8))
        );
    }
}
