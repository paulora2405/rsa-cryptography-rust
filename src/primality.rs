use crate::mod_exponentiation::mod_pow;
use rand::{prelude::ThreadRng, Rng};
pub struct PrimeGenerator {
    prime: u128,
    odd: u128,
    rng: ThreadRng,
}

impl PrimeGenerator {
    /// Creates new PrimeGenerator and initializes rng member
    pub fn new() -> Self {
        let prime = 0;
        let odd = 0;
        let rng = rand::thread_rng();
        Self { prime, odd, rng }
    }

    pub fn is_composite(n: u128, a: u128, d: u128, s: u128) -> bool {
        let mut x: u128 = mod_pow(a, d, n);

        if x == 1 || x == n - 1 {
            return false;
        }

        for _ in 1..s {
            x = x * x % n;
            if x == n - 1 {
                return false;
            }
        }

        true
    }

    pub fn miller_rabin(n: u128) -> bool {
        if n < 2 {
            return false;
        }

        let mut r: u128 = 0;
        let mut d: u128 = n - 1;
        let first_primes: [u8; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];

        while (d & 1) == 0 {
            d >>= 1;
            r += 1;
        }
        for a in first_primes {
            if n == a.into() {
                return true;
            }
            if PrimeGenerator::is_composite(n, a.into(), d, r) {
                return false;
            }
        }
        true
    }

    pub fn random_prime(&mut self, max_bits: u8) -> u128 {
        let max_num: u128 = 1 << max_bits;
        self.prime = self.rng.gen_range(2..max_num);
        self.prime += if self.prime % 2 == 0 { 1 } else { 0 };

        while !PrimeGenerator::miller_rabin(self.prime) {
            self.prime += 2;
            if self.prime > max_num {
                self.prime = self.rng.gen_range(2..max_num);
                self.prime += !(self.prime & 1);
            }
        }
        self.prime.clone()
    }

    pub fn random_odd(&mut self, max_bits: u8) -> u128 {
        let max_num: u128 = 1 << max_bits;

        self.odd = self.rng.gen_range(3..max_num);
        self.odd -= !(self.odd & 1);
        self.odd.clone()
    }
}
