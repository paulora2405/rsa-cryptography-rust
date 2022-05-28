use crate::euclidean::euclides_extended;
use crate::mod_exponentiation::mod_pow;
use crate::primality::PrimeGenerator;
use num_bigint::BigUint;
use num_traits::{Num, One, Signed};
use regex::Regex;
use std::fs::File;
use std::io::Write;
use std::process::exit;

#[derive(Debug, PartialEq)]
pub struct Key {
    pub d_e: BigUint,
    pub n: BigUint,
}

#[derive(Debug, PartialEq)]
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

        key_pair
    }

    /// Validates key pair
    ///
    /// **Returns** true if valid
    pub fn is_valid(&self) -> bool {
        if self.pub_key.n != self.priv_key.n || self.pub_key.d_e > self.pub_key.n {
            return false;
        }
        let plain_msg = BigUint::from(12345678u64);
        let encoded_msg = mod_pow(&plain_msg, &self.pub_key.d_e, &self.pub_key.n);
        let decoded_msg = mod_pow(&encoded_msg, &self.priv_key.d_e, &self.priv_key.n);
        if plain_msg != decoded_msg {
            return false;
        }
        true
    }

    /// Validates and writes Public and Private key files to `key_out_path`
    pub fn write_key_files(key_out_path: &str, key_pair: &KeyPair) {
        let use_default_exponent: bool = key_pair.pub_key.d_e == BigUint::from(65_537u32);

        // Validation process
        if !key_pair.is_valid() {
            eprint!("Key Pair not valid!");
            panic!("Key Pair not valid!");
        }

        // Write to key files
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
                + " "
                + &key_pair.pub_key.d_e.to_str_radix(16)
                + "\n";
            file.write_all(content.as_bytes()).expect("writing to file");
        }
    }

    pub fn is_valid_key_file(
        file_data: &Vec<&str>,
        key_path: &str,
        is_public_key_file: bool,
    ) -> bool {
        let reg = Regex::new(r"^[0-9a-f]+$").unwrap();

        if is_public_key_file
            && file_data.len() == 2
            && file_data[0].trim() == "rsa-rust"
            && reg.is_match(file_data[1].trim())
            || is_public_key_file
                && file_data.len() == 3
                && file_data[0].trim() == "rsa-rust-dex"
                && reg.is_match(file_data[1].trim())
                && reg.is_match(file_data[2].trim())
            || !is_public_key_file
                && file_data.len() == 4
                && file_data[0] == "-----BEGIN RSA-RUST PRIVATE KEY-----"
                && file_data[2] == "-----END RSA-RUST PRIVATE KEY-----"
                && reg.is_match(file_data[1].trim())
        {
            return true;
        }

        if is_public_key_file {
            eprintln!("Public key `{}.pub` is invalid!", key_path);
        } else {
            eprintln!("Private key `{}` is invalid!", key_path);
        }
        false
    }

    /// Reads and validades Public and Private key files from `key_in_path`
    ///
    /// **Returns** KeyPair instance parsed from keys files
    pub fn read_key_files(key_in_path: &str) -> KeyPair {
        let priv_key_buf = std::fs::read_to_string(key_in_path).expect("Could not read file");
        let priv_key_buf: Vec<&str> = priv_key_buf.split('\n').collect();
        if !KeyPair::is_valid_key_file(&priv_key_buf, &key_in_path, false) {
            exit(1);
        }

        let pub_key_buf =
            std::fs::read_to_string(key_in_path.to_owned() + ".pub").expect("Could not read file");
        let pub_key_buf: Vec<&str> = pub_key_buf.split(' ').collect();
        if !KeyPair::is_valid_key_file(&pub_key_buf, &key_in_path, true) {
            exit(1);
        }

        let n = pub_key_buf[1].trim();
        let n: BigUint = BigUint::from_str_radix(n, 16).unwrap();
        let d = priv_key_buf[1].trim();
        let d: BigUint = BigUint::from_str_radix(d, 16).unwrap();
        let e: BigUint = if pub_key_buf[0].trim() == "rsa-rust-ndex" {
            BigUint::from_str_radix(pub_key_buf[2].trim(), 16).unwrap()
        } else {
            BigUint::from(65_537u32)
        };

        let key_pair = KeyPair {
            pub_key: Key {
                d_e: e,
                n: n.clone(),
            },
            priv_key: Key { d_e: d, n },
        };

        // Validation process
        if !key_pair.is_valid() {
            eprint!("Key Pair not valid!");
            panic!("Key Pair not valid!");
        }

        key_pair
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_validation() {
        let key_pair = KeyPair {
            pub_key: Key {
                d_e: BigUint::from(65_537u32), // default value isn't present in key file
                n: BigUint::from(2523461377u64), // 0x9668f701
            },
            priv_key: Key {
                d_e: BigUint::from(343637873u32), // 0x147b7f71
                n: BigUint::from(2523461377u64),  // 0x9668f701
            },
        };
        assert!(key_pair.is_valid());
        let key_pair = KeyPair {
            pub_key: Key {
                d_e: BigUint::from(23447u64),   // 0x5b97
                n: BigUint::from(298224757u64), // 0x11c68c75
            },
            priv_key: Key {
                d_e: BigUint::from(58335719u64), // 0x37a21e7
                n: BigUint::from(298224757u64),  // 0x11c68c75
            },
        };
        assert!(key_pair.is_valid());
    }

    #[test]
    fn test_key_import_dex() {
        let key_pair = KeyPair {
            pub_key: Key {
                d_e: BigUint::from(65_537u32), // default value isn't present in key file
                n: BigUint::from(2523461377u64), // 0x9668f701
            },
            priv_key: Key {
                d_e: BigUint::from(343637873u32), // 0x147b7f71
                n: BigUint::from(2523461377u64),  // 0x9668f701
            },
        };
        KeyPair::write_key_files("keys/tests/dex_key", &key_pair);
        let read_key_pair = KeyPair::read_key_files("keys/tests/dex_key");
        assert_eq!(read_key_pair, key_pair);
    }

    #[test]
    fn test_valid_key() {
        let _ = KeyPair::read_key_files("keys/tests/dex_key");
    }

    #[test]
    fn test_key_import_ndex() {
        let key_pair = KeyPair {
            pub_key: Key {
                d_e: BigUint::from(23447u64),   // 0x5b97
                n: BigUint::from(298224757u64), // 0x11c68c75
            },
            priv_key: Key {
                d_e: BigUint::from(58335719u64), // 0x37a21e7
                n: BigUint::from(298224757u64),  // 0x11c68c75
            },
        };
        KeyPair::write_key_files("keys/tests/ndex_key", &key_pair);
        let read_key_pair = KeyPair::read_key_files("keys/tests/ndex_key");
        assert_eq!(read_key_pair, key_pair);
    }
}
