use crate::euclidean::euclides_extended;
use crate::primality::PrimeGenerator;

struct Key {
    d_e: u128,
    n: u128,
}
pub struct KeyPair {
    pub_key: Key,
    priv_key: Key,
}

impl KeyPair {
    /// Generates the values of P, Q, N Phi(N), E and D

    pub fn generate_keys(max_bits: u8, verbose: bool) -> KeyPair {
        if max_bits > 64 {
            panic!("Key size not supported!");
        }
        let mut p: u128;
        let mut q: u128;
        let mut n: u128;
        let mut totn: u128;
        let mut e: u128;
        let mut d: u128;
        let mut gen: PrimeGenerator = PrimeGenerator::new();

        // Step 1: Select two big prime numbers P and Q
        // Step 2: Calculate N = P * Q
        // Step 3: Calculate λ(N) = (P-1) * (Q-1)
        // Step 4: Achar um e tal que gcd(e, ø(n)) = 1 ; 1 < e < ø(n)
        // Step 5: Calcular d tal que e*d = 1 (mod ø(n))

        loop {
            p = gen.random_prime(max_bits);
            q = gen.random_prime(max_bits);

            n = p * q;
            totn = (p - 1) * (q - 1);

            loop {
                e = gen.random_prime(max_bits);

                if e < totn {
                    break;
                }
            }

            (_, d, _) = euclides_extended(e, totn);
            d = (d % totn.wrapping_add(totn)) % totn;

            if (e.wrapping_mul(d) % totn) == 1 {
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
            pub_key: Key { d_e: e, n },
            priv_key: Key { d_e: d, n },
        }
    }
}
