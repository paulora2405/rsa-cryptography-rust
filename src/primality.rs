use crate::mod_exponentiation::mod_pow;
use num_bigint::{BigUint, RandBigInt};
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_miller_rabbin() {
        let p = 13u8;
        let np = 27u8;
        let bp = BigUint::from(918020423304243854760595069249u128);
        assert!(PrimeGenerator::miller_rabin(&BigUint::from(p)));
        assert!(!PrimeGenerator::miller_rabin(&BigUint::from(np)));
        assert!(PrimeGenerator::miller_rabin(&bp));
    }
}
