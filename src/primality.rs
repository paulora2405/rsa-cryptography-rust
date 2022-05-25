use crate::mod_exponentiation::mod_pow;
use num_bigint::{BigUint, RandBigInt, ToBigUint};
use rand::prelude::ThreadRng;
pub struct PrimeGenerator {
    prime: BigUint,
    odd: BigUint,
    rng: ThreadRng,
}

impl PrimeGenerator {
    /// Creates new PrimeGenerator and initializes rng member
    pub fn new() -> Self {
        let prime = 0u8.to_biguint().unwrap();
        let odd = 0u8.to_biguint().unwrap();
        let rng = rand::thread_rng();
        Self { prime, odd, rng }
    }

    pub fn is_composite(n: &BigUint, a: &BigUint, d: &BigUint, s: &BigUint) -> bool {
        let mut x: BigUint = mod_pow(&a, &d, &n);

        if x == 1u8.to_biguint().unwrap() || x == n - 1u8.to_biguint().unwrap() {
            return false;
        }

        let mut i = 1u8.to_biguint().unwrap();
        while i < *s {
            x = &x * &x % n;
            if x == n - 1u8.to_biguint().unwrap() {
                return false;
            }
            i += 1u8.to_biguint().unwrap();
        }

        true
    }

    pub fn miller_rabin(n: &BigUint) -> bool {
        if *n < 2u8.to_biguint().unwrap() {
            return false;
        }

        let mut r: BigUint = 0u8.to_biguint().unwrap();
        let mut d: BigUint = n - 1u8.to_biguint().unwrap();
        let first_primes: [u8; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];

        while (&d & 1u8.to_biguint().unwrap()) == 0u8.to_biguint().unwrap() {
            d >>= 1u8;
            r += 1u8;
        }
        for a in first_primes {
            if *n == a.into() {
                return true;
            }
            if PrimeGenerator::is_composite(&n, &a.into(), &d, &r) {
                return false;
            }
        }
        true
    }

    pub fn random_prime(&mut self, max_bits: u16) -> BigUint {
        let low = 2u8.to_biguint().unwrap();
        let max_num: BigUint = 1u8.to_biguint().unwrap() << max_bits;
        self.prime = self.rng.gen_biguint_range(&low, &max_num);
        // No even numbers are primes (except 2), saves rng.gen overhead
        // if self.prime % 2u8.to_biguint().unwrap() == 0u8.to_biguint().unwrap() {
        //     self.prime += 1u8.to_biguint().unwrap();
        // }
        self.prime.set_bit(0, true);

        while !PrimeGenerator::miller_rabin(&self.prime) {
            self.prime += 2u8.to_biguint().unwrap();
            if self.prime > max_num {
                self.prime = self.rng.gen_biguint_range(&low, &max_num);
                self.prime.set_bit(0, true);
            }
        }
        self.prime.clone()
    }

    pub fn random_odd(&mut self, max_bits: u16) -> BigUint {
        let low = 3u8.to_biguint().unwrap();
        let max_num: BigUint = 1u8.to_biguint().unwrap() << max_bits;

        self.odd = self.rng.gen_biguint_range(&low, &max_num);
        self.odd.set_bit(0, true);
        self.odd.clone()
    }
}
