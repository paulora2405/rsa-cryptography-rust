use super::{Key, KeyPair};
use crate::math::{euclides_extended, PrimeGenerator};
use num_bigint::BigUint;
use num_traits::{CheckedMul, One, Signed};
use std::{io::Write, ops::RangeInclusive};

impl Key {
    const DEFAULT_KEY_SIZE: u16 = 4096;
    const KEY_SIZE_RANGE: RangeInclusive<u16> = (32..=4096);
    pub(super) const DEFAULT_EXPONENT: u32 = 65_537u32;
}

impl KeyPair {
    /// Generates the values of P, Q, N Phi(N), E and D and
    /// returns a `KeyPair` with a Public and a Private Key.
    ///
    /// ## How it works
    /// 1. Select two big prime numbers `P` and `Q`
    /// 2. Calculate `N = P * Q`
    /// 3. Calculate `λ(N) = (P-1) * (Q-1)`
    /// 4. Find a `E` such that `gcd(e, λ(N)) = 1` and `1 < E < λ(N)`
    /// 5. Calculate `D` such that `E*D = 1 (mod λ(N))`
    ///
    /// # Panics
    /// Panics if `key_size` is not in (32, 4096) interval
    #[allow(clippy::many_single_char_names)]
    #[must_use]
    pub fn generate(
        maybe_key_size_bits: Option<u16>,
        use_default_exponent: bool,
        print_results: bool,
        print_progress: bool,
    ) -> KeyPair {
        let pp = print_progress;
        let key_size = maybe_key_size_bits.unwrap_or(Key::DEFAULT_KEY_SIZE);
        assert!(
            Key::KEY_SIZE_RANGE.contains(&key_size),
            "Key size not supported!"
        );
        printf!(pp, "Generating key with {key_size} bits\n");

        let max_bits = key_size / 2;
        let mut attempts = 0u32;
        let (mut p, mut q, mut n, mut totn, mut e, mut d);
        let mut gen = PrimeGenerator::new();

        loop {
            attempts += 1;
            printf!(pp, "\nAttempt number {attempts}\nGenerating P...");
            p = gen.random_prime(max_bits);
            printf!(pp, "DONE\nGenerating Q...");
            q = gen.random_prime(max_bits);
            while p == q {
                q = gen.random_prime(max_bits);
            }
            printf!(pp, "DONE\nCalculating Public/Private Key's Modulus (N)...");
            n = p
                .checked_mul(&q)
                .expect("Checked multiplication of Big Integers failed.");
            printf!(pp, "DONE\n");
            totn = (&p - 1u8) * (&q - 1u8);

            if use_default_exponent {
                printf!(pp, "Using default exponent...DONE\n");
                e = BigUint::from(Key::DEFAULT_EXPONENT);
                assert!(e < totn, "Tot(N) is smaller than the default exponent");
            } else {
                printf!(pp, "Calculating Public Key's Exponent (E)...");
                e = gen.random_prime(max_bits);
                while e >= totn {
                    e = gen.random_prime(max_bits);
                }
                printf!(pp, "DONE\n");
            }

            printf!(pp, "Calculating Private Key's Exponent (D)...");
            let (_, d_tmp, _) = euclides_extended(&e, &totn);
            d = d_tmp.abs().to_biguint().unwrap();
            d = (d % &totn + &totn) % &totn;

            if (&e * &d % &totn) == One::one() {
                printf!(pp, "DONE\n");
                break;
            }
            printf!(pp, "\nCould not find a valid Private Key...RETRYING\n");
        }
        printf!(pp, "\nKey Pair successfully generated\n");

        let key_pair = KeyPair {
            public_key: Key {
                exponent: e.clone(),
                modulus: n.clone(),
                variant: crate::key::KeyVariant::PublicKey,
            },
            private_key: Key {
                exponent: d.clone(),
                modulus: n.clone(),
                variant: crate::key::KeyVariant::PrivateKey,
            },
        };

        assert!(key_pair.is_valid());

        if print_results {
            println!("Max bits for N: {key_size}");
            println!("Max bits for P and Q: {max_bits}");
            println!("Attempts needed: {attempts}");
            println!("The values calculated were:");
            println!("P = {p}");
            println!("Q = {q}");
            println!("N = {n}");
            println!("Tot(N) = {totn}");
            if !use_default_exponent {
                println!("E (Non default) = {e}");
            }
            println!("D = {d}");
        }

        key_pair
    }
}

/// If first expression is `true`, does a `print!()` with arguments
/// and then flushes STDOUT.
macro_rules! printf {
    ($should_print:expr, $( $string:expr),+ ) => {
        if $should_print {
            print!($($string,)*);
            std::io::stdout().flush().expect("Could not flush stdout");
        }
    };
}
use printf;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KeyVariant;

    #[test]
    fn test_key_validation() {
        let key_pair = KeyPair {
            public_key: Key {
                exponent: BigUint::from(0x1_0001u32), // default exponent
                modulus: BigUint::from(0x9668_F701u64),
                variant: KeyVariant::PublicKey,
            },
            private_key: Key {
                exponent: BigUint::from(0x147B_7F71u32),
                modulus: BigUint::from(0x9668_F701u64),
                variant: KeyVariant::PrivateKey,
            },
        };
        assert!(key_pair.is_valid());
        let key_pair = KeyPair {
            public_key: Key {
                exponent: BigUint::from(0x5B97u64),
                modulus: BigUint::from(0x11C6_8C75u64),
                variant: KeyVariant::PublicKey,
            },
            private_key: Key {
                exponent: BigUint::from(0x37A_21E7u64),
                modulus: BigUint::from(0x11C6_8C75u64),
                variant: KeyVariant::PrivateKey,
            },
        };
        assert!(key_pair.is_valid());
    }
}
