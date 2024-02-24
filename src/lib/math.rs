use num_bigint::{BigInt, BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::prelude::ThreadRng;

pub struct PrimeGenerator {
    prime: BigUint,
    odd: BigUint,
    rng: ThreadRng,
}

impl Default for PrimeGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl PrimeGenerator {
    /// Returns new `PrimeGenerator` instance with `rng` member properly initialized.
    #[must_use]
    pub fn new() -> Self {
        let prime = Zero::zero();
        let odd = Zero::zero();
        let rng = rand::thread_rng();
        Self { prime, odd, rng }
    }

    #[allow(clippy::many_single_char_names)]
    fn is_composite(n: &BigUint, a: &BigUint, d: &BigUint, s: &BigUint) -> bool {
        let mut x: BigUint = mod_pow(a, d, n);

        if x.is_one() || x == n - 1u8 {
            return false;
        }

        let mut i: BigUint = One::one();
        while i < *s {
            x = &x * &x % n;
            if x == n - 1u8 {
                return false;
            }
            i += 1u8;
        }

        true
    }

    /// Miller-Rabin primality test.
    ///
    /// **Returns** true if `n` is likely to be prime.
    fn miller_rabin(n: &BigUint) -> bool {
        if *n < BigUint::from(2u8) {
            return false;
        }

        let mut r: BigUint = Zero::zero();
        let mut d: BigUint = n - 1u8;
        let first_primes: [u8; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];

        while !d.bit(0) {
            d >>= 1u8;
            r += 1u8;
        }
        for a in first_primes {
            if *n == a.into() {
                return true;
            }
            if PrimeGenerator::is_composite(n, &a.into(), &d, &r) {
                return false;
            }
        }
        true
    }

    pub fn random_prime(&mut self, max_bits: u16) -> BigUint {
        let low = BigUint::from(2u8);
        let max_num: BigUint = (BigUint::from(1u8) << max_bits) - 1u8;
        self.prime = self.rng.gen_biguint_range(&low, &max_num);
        // No even numbers are primes (except 2), saves rng.gen overhead
        self.prime.set_bit(0, true);

        while !PrimeGenerator::miller_rabin(&self.prime) {
            self.prime += 2u8;
            if self.prime > max_num {
                self.prime = self.rng.gen_biguint_range(&low, &max_num);
                self.prime.set_bit(0, true);
            }
        }
        self.prime.clone()
    }

    #[allow(dead_code)]
    fn random_odd(&mut self, max_bits: u16) -> BigUint {
        let low = BigUint::from(3u8);
        let max_num: BigUint = (BigUint::from(1u8) << max_bits) - 1u8;

        self.odd = self.rng.gen_biguint_range(&low, &max_num);
        self.odd.set_bit(0, true);
        self.odd.clone()
    }
}

/// Calculates Modular Exponent for given `base`, `exponent` and `modulus`.
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

/// Calculates extended euclides algorithm for give `a` and  `b`.
#[must_use]
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
    fn test_miller_rabbin() {
        let p = 13u8;
        let np = 27u8;
        let bp = BigUint::from(918_020_423_304_243_854_760_595_069_249_u128);
        assert!(PrimeGenerator::miller_rabin(&BigUint::from(p)));
        assert!(!PrimeGenerator::miller_rabin(&BigUint::from(np)));
        assert!(PrimeGenerator::miller_rabin(&bp));
    }

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
