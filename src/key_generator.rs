use crate::euclidean::euclides_extended;
use crate::primality::PrimeGenerator;
use num_bigint::BigUint;
use num_traits::{One, Signed};

pub struct Key {
    pub d_e: BigUint,
    pub n: BigUint,
}
pub struct KeyPair {
    pub pub_key: Key,
    pub priv_key: Key,
}

impl KeyPair {
    /// Generates the values of P, Q, N Phi(N), E and D
    ///
    /// **Returns:** a KeyPair with a Public and a Private Key
    pub fn generate_keys(max_bits: u16, verbose: bool) -> KeyPair {
        if max_bits > 64 {
            panic!("Key size not supported!");
        }
        let mut p: BigUint;
        let mut q: BigUint;
        let mut n: BigUint;
        let mut totn: BigUint;
        let mut e: BigUint;
        let mut d: BigUint;
        let mut gen: PrimeGenerator = PrimeGenerator::new();

        // Step 1: Select two big prime numbers `P` and `Q`
        // Step 2: Calculate `N = P * Q`
        // Step 3: Calculate `λ(N) = (P-1) * (Q-1)`
        // Step 4: Find a `E` such that `gcd(e, λ(N)) = 1` and `1 < E < λ(N)`
        // Step 5: Calculate `D` such that `E*D = 1 (mod λ(N))`

        loop {
            p = gen.random_prime(max_bits);
            q = gen.random_prime(max_bits);

            n = &p * &q;
            totn = (&p - 1u8) * (&q - 1u8);

            loop {
                e = gen.random_prime(max_bits);

                if e < totn {
                    break;
                }
            }

            let (_, d_tmp, _) = euclides_extended(&e, &totn);
            d = d_tmp.abs().to_biguint().unwrap();
            d = (d % &totn + &totn) % &totn;

            if (&e * &d % &totn) == One::one() {
                break;
            }
        }

        if verbose {
            println!("Max bits for N: {}", max_bits);
            println!("The values calculated were:");
            println!("P = {}", p);
            println!("Q = {}", q);
            println!("N = {}", n);
            println!("Tot(N) = {}", totn);
            println!("E = {}", e);
            println!("D = {}", d);
        }

        KeyPair {
            pub_key: Key {
                d_e: e,
                n: n.clone(),
            },
            priv_key: Key { d_e: d, n },
        }
    }
}
