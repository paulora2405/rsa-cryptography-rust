use crate::euclidean::euclides_extended;
use crate::primality::PrimeGenerator;
use num_bigint::BigUint;
use num_traits::{One, Signed};
use std::fs::File;
use std::io::Write;

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
    pub fn generate_keys(
        key_size: u16,
        key_out_path: &str,
        use_default_exponent: bool,
        print_results: bool,
        print_progress: bool,
    ) -> KeyPair {
        if key_size > 4096 || key_size < 32 {
            panic!("Key size not supported!");
        }
        let max_bits = key_size / 2;
        let mut attempts = 0u32;
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

        macro_rules! printprogress {
            ($a: expr, $b: expr) => {
                if print_progress {
                    print!($a, $b);
                    std::io::stdout().flush().expect("Could not flush stdout");
                }
            };
            ($a: expr) => {
                if print_progress {
                    print!($a);
                    std::io::stdout().flush().expect("Could not flush stdout");
                }
            };
        }

        loop {
            attempts += 1;
            printprogress!("Attempt number {}\n", attempts);
            printprogress!("Generating P...");
            p = gen.random_prime(max_bits);
            printprogress!("DONE\nGenerating Q...");
            q = gen.random_prime(max_bits);
            while p == q {
                q = gen.random_prime(max_bits);
            }
            printprogress!("DONE\n");

            printprogress!("Calculating Public Key (N)...");
            n = &p * &q;
            printprogress!("DONE\n");
            totn = (&p - 1u8) * (&q - 1u8);

            if !use_default_exponent {
                printprogress!("Calculating Public Key (E)...");
                loop {
                    e = gen.random_prime(max_bits);
                    if e < totn {
                        printprogress!("DONE\n");
                        break;
                    };
                }
            } else {
                e = BigUint::from(65_537u32);
                assert!(e < totn);
            }

            printprogress!("Calculating Private Key (D)...");
            let (_, d_tmp, _) = euclides_extended(&e, &totn);
            d = d_tmp.abs().to_biguint().unwrap();
            d = (d % &totn + &totn) % &totn;

            if (&e * &d % &totn) == One::one() {
                printprogress!("DONE\n");
                break;
            }
            printprogress!("\nCould not find a valid Private Key...RETRYING\n");
        }
        printprogress!("Key Pair successfully generated\n");

        let key_pair = KeyPair {
            pub_key: Key {
                d_e: e.clone(),
                n: n.clone(),
            },
            priv_key: Key {
                d_e: d.clone(),
                n: n.clone(),
            },
        };

        if print_results {
            println!("Max bits for N: {}", key_size);
            println!("Max bits for P and Q: {}", max_bits);
            println!("Attempts needed: {}", attempts);
            println!("The values calculated were:");
            println!("P = {}", p);
            println!("Q = {}", q);
            println!("N = {}", n);
            println!("Tot(N) = {}", totn);
            if !use_default_exponent {
                println!("E (Non default) = {}", e);
            }
            println!("D = {}", d);
        }
        let mut file = File::create(key_out_path).expect("Could not open output path");
        let content = String::from("-----BEGIN RSA-RUST PRIVATE KEY-----\n")
            + &key_pair.priv_key.d_e.to_str_radix(16)
            + "\n-----END RSA-RUST PRIVATE KEY-----\n";
        file.write_all(content.as_bytes())
            .expect("Error writing to file");

        let mut file =
            File::create(key_out_path.to_owned() + ".pub").expect("Could not open output path");
        if use_default_exponent {
            let content = String::from("rsa-rust ") + &key_pair.pub_key.n.to_str_radix(16) + "\n";
            file.write_all(content.as_bytes())
                .expect("Error writing to file");
        } else {
            let content = String::from("rsa-rust-ndex ")
                + &key_pair.pub_key.n.to_str_radix(16)
                + "\n"
                + &key_pair.pub_key.d_e.to_str_radix(16)
                + "\n";
            file.write_all(content.as_bytes()).expect("writing to file");
        }

        key_pair
    }
}
