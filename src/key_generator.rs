use crate::euclidean::euclides_extended;
use crate::primality::PrimeGenerator;
use num_bigint::{BigUint, ToBigUint};

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

        // Step 1: Select two big prime numbers P and Q
        // Step 2: Calculate N = P * Q
        // Step 3: Calculate λ(N) = (P-1) * (Q-1)
        // Step 4: Achar um e tal que gcd(e, ø(n)) = 1 ; 1 < e < ø(n)
        // Step 5: Calcular d tal que e*d = 1 (mod ø(n))

        loop {
            p = gen.random_prime(max_bits);
            q = gen.random_prime(max_bits);

            n = &p * &q;
            totn = (&p - 1u8.to_biguint().unwrap()) * (&q - 1u8.to_biguint().unwrap());

            loop {
                e = gen.random_prime(max_bits);

                if e < totn {
                    break;
                }
            }

            (_, d, _) = euclides_extended(&mut e, &mut totn);
            d = (d % &totn * 2u8.to_biguint().unwrap()) % &totn;

            if (&e * &d % &totn) == 1u8.to_biguint().unwrap() {
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
