use crate::math::{euclides_extended, mod_pow, PrimeGenerator};
use clap::crate_name;
use directories::BaseDirs;
use num_bigint::BigUint;
use num_traits::{Num, One, Signed};
use regex::Regex;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
pub enum KeyVariant {
    PublicKey,
    PrivateKey,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Key {
    /// `D` or `E` part of the key.
    pub exponent: BigUint,
    /// `N` part of the key.
    pub modulus: BigUint,
    pub variant: KeyVariant,
}

#[derive(Debug, PartialEq, Eq)]
pub struct KeyPair {
    pub public_key: Key,
    pub private_key: Key,
}

impl KeyPair {
    /// Generates the values of P, Q, N Phi(N), E and D and
    /// returns a `KeyPair` with a Public and a Private Key.
    /// ## How it works
    /// Step 1: Select two big prime numbers `P` and `Q` <p>
    /// Step 2: Calculate `N = P * Q` <p>
    /// Step 3: Calculate `λ(N) = (P-1) * (Q-1)` <p>
    /// Step 4: Find a `E` such that `gcd(e, λ(N)) = 1` and `1 < E < λ(N)` <p>
    /// Step 5: Calculate `D` such that `E*D = 1 (mod λ(N))`
    /// # Panics
    /// Panics if `key_size` is not in (32, 4096) interval
    #[must_use]
    pub fn generate_keys(
        maybe_key_size: Option<u16>,
        use_default_exponent: bool,
        print_results: bool,
        print_progress: bool,
    ) -> KeyPair {
        let key_size = maybe_key_size.unwrap_or(Key::DEFAULT_KEY_SIZE);
        assert!((32..=4096).contains(&key_size), "Key size not supported!");

        let max_bits = key_size / 2;
        let mut attempts = 0u32;
        let (mut p, mut q, mut n, mut totn, mut e, mut d);
        let mut gen: PrimeGenerator = PrimeGenerator::new();

        loop {
            attempts += 1;
            print_flush(&format!("Attempt number {}\n", attempts), print_progress);
            print_flush("Generating P...", print_progress);
            p = gen.random_prime(max_bits);
            print_flush("DONE\nGenerating Q...", print_progress);
            q = gen.random_prime(max_bits);
            while p == q {
                q = gen.random_prime(max_bits);
            }
            print_flush("DONE\n", print_progress);
            print_flush("Calculating Public Key (N)...", print_progress);
            n = &p * &q;
            print_flush("DONE\n", print_progress);
            totn = (&p - 1u8) * (&q - 1u8);

            if use_default_exponent {
                print_flush("Using default exponent...\n", print_progress);
                e = BigUint::from(Key::DEFAULT_EXPONENT);
                assert!(
                    e < totn,
                    "Tot(N) is smaller than `{}`",
                    Key::DEFAULT_EXPONENT
                );
            } else {
                print_flush("Calculating Public Key (E)...", print_progress);
                loop {
                    e = gen.random_prime(max_bits);
                    if e < totn {
                        print_flush("DONE\n", print_progress);
                        break;
                    };
                }
            }

            print_flush("Calculating Private Key (D)...", print_progress);
            let (_, d_tmp, _) = euclides_extended(&e, &totn);
            d = d_tmp.abs().to_biguint().unwrap();
            d = (d % &totn + &totn) % &totn;

            if (&e * &d % &totn) == One::one() {
                print_flush("DONE\n", print_progress);
                break;
            }
            print_flush(
                "\nCould not find a valid Private Key...RETRYING\n",
                print_progress,
            );
        }
        print_flush("Key Pair successfully generated\n", print_progress);

        let key_pair = KeyPair {
            public_key: Key {
                exponent: e.clone(),
                modulus: n.clone(),
                variant: KeyVariant::PublicKey,
            },
            private_key: Key {
                exponent: d.clone(),
                modulus: n.clone(),
                variant: KeyVariant::PrivateKey,
            },
        };

        assert!(key_pair.is_valid());

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

    pub fn write_key_files(&self, maybe_file_path: Option<PathBuf>) -> Result<(), String> {
        // differentiate if path already contains '.pub' extension (it should not)
        if !self.is_valid() {
            return Err(String::from("Tried writting an Invalid Key pair"));
        }

        let KeyPair {
            public_key,
            private_key,
        } = self;

        match maybe_file_path {
            Some(path) => {
                // let pub_path = path.join(Key::PUBLIC_KEY_FILE_SUFFIX);
                public_key.write_key_file(Some(path.clone()));
                private_key.write_key_file(Some(path));
            }
            None => {
                public_key.write_key_file(None);
                private_key.write_key_file(None);
            }
        }

        Ok(())
    }

    /// Returns `true` if `KeyPair` is valid.
    #[must_use]
    fn is_valid(&self) -> bool {
        if self.public_key.modulus != self.private_key.modulus
            || self.public_key.exponent > self.public_key.modulus
        {
            return false;
        }
        let plain_msg = BigUint::from(12_345_678u64);
        let encoded_msg = mod_pow(
            &plain_msg,
            &self.public_key.exponent,
            &self.public_key.modulus,
        );
        let decoded_msg = mod_pow(
            &encoded_msg,
            &self.private_key.exponent,
            &self.private_key.modulus,
        );
        if plain_msg != decoded_msg {
            return false;
        }
        true
    }
}

impl Key {
    const DEFAULT_KEY_SIZE: u16 = 4096;
    const DEFAULT_EXPONENT: u32 = 65_537u32;
    const BIGUINT_STR_RADIX: u32 = 16;
    const APP_CONFIG_DIR: &str = crate_name!();
    const PUBLIC_KEY_FILE_SUFFIX: &str = ".pub";
    const DEFAULT_KEY_NAME: &str = "rrsa_key";
    const PUBLIC_KEY_NORMAL_HEADER: &str = "rrsa ";
    const PUBLIC_KEY_NDEX_HEADER: &str = "rrsa-ndex ";
    const PUBLIC_KEY_SPLIT_CHAR: char = ' ';
    const PRIVATE_KEY_HEADER: &str = "-----BEGIN RSA-RUST PRIVATE KEY-----\n";
    const PRIVATE_KEY_FOOTER: &str = "\n-----END RSA-RUST PRIVATE KEY-----\n";
    const PRIVATE_KEY_SPLIT_CHAR: char = '\n';
    const KEY_FILE_STR_RADIX_REGEX: &str = r"^[0-9a-f]+$";

    /// Writes Public or Private key file to output path.
    pub fn write_key_file(&self, maybe_path: Option<PathBuf>) {
        let final_path: PathBuf;

        if let Some(path) = maybe_path {
            if path.is_file() {
                final_path = path;
            } else if path.is_dir() {
                final_path = path.join(self.variant.get_filename());
            } else {
                create_dir_all(path.parent().unwrap_or(Path::new(".")))
                    .expect("Failed to create necessary parent directories!");
                final_path = path;
            }
        } else if let Some(dirs) = BaseDirs::new() {
            let parent_dir = dirs.config_dir().join(Key::APP_CONFIG_DIR);
            create_dir_all(&parent_dir).expect("Failed to create necessary parent directories!");
            final_path = parent_dir.join(self.variant.get_filename());
        } else {
            eprintln!("Failed to find user's config directory! Falling back to cwd...");
            final_path = PathBuf::from(".")
                .join(Key::APP_CONFIG_DIR)
                .join(self.variant.get_filename());
        }
        println!("Saving Key file to `{}`", final_path.to_string_lossy());

        let mut file = File::create(&final_path).unwrap_or_else(|_| {
            panic!(
                "Could not open output filepath of {}",
                final_path.to_string_lossy()
            )
        });

        let content = match self.variant {
            KeyVariant::PublicKey => {
                let use_default_exponent = self.exponent.is_default_exponent();
                if use_default_exponent {
                    String::from(Key::PUBLIC_KEY_NORMAL_HEADER)
                        + &self.modulus.to_str_radix(Key::BIGUINT_STR_RADIX)
                        + "\n"
                } else {
                    String::from(Key::PUBLIC_KEY_NDEX_HEADER)
                        + &self.modulus.to_str_radix(Key::BIGUINT_STR_RADIX)
                        + " "
                        + &self.exponent.to_str_radix(Key::BIGUINT_STR_RADIX)
                        + "\n"
                }
            }
            KeyVariant::PrivateKey => {
                String::from(Key::PRIVATE_KEY_HEADER)
                    + &self.modulus.to_str_radix(Key::BIGUINT_STR_RADIX)
                    + "\n"
                    + &self.exponent.to_str_radix(Key::BIGUINT_STR_RADIX)
                    + Key::PRIVATE_KEY_FOOTER
            }
        };

        file.write_all(content.as_bytes())
            .expect("Error writing to file");
    }

    /// Reads Public or Private key file from input path.
    pub fn read_key_file(maybe_path: Option<PathBuf>, variant: KeyVariant) -> Result<Key, String> {
        let final_path: PathBuf;

        if let Some(path) = maybe_path {
            if path.is_file() {
                final_path = path;
            } else if path.is_dir() {
                final_path = path.join(variant.get_filename());
            } else {
                return Err(String::from("Input path is invalid"));
            }
        } else if let Some(dirs) = BaseDirs::new() {
            final_path = dirs
                .config_dir()
                .join(Key::APP_CONFIG_DIR)
                .join(variant.get_filename());
        } else {
            eprintln!("Failed to find user's config directory! Falling back to cwd...");
            final_path = PathBuf::from(".")
                .join(Key::APP_CONFIG_DIR)
                .join(variant.get_filename());
        }
        println!("Reading Key file from `{}`", final_path.to_string_lossy());

        let file_buf = std::fs::read_to_string(final_path).map_err(|e| e.to_string())?;
        match variant {
            KeyVariant::PublicKey => {
                let file_buf: Vec<&str> = file_buf.split(Key::PUBLIC_KEY_SPLIT_CHAR).collect();
                if variant.is_valid_key_file(&file_buf) {
                    Ok(Key {
                        modulus: BigUint::from_str_radix(
                            file_buf[1].trim(),
                            Key::BIGUINT_STR_RADIX,
                        )
                        .map_err(|e| e.to_string())?,

                        exponent: if file_buf[0] == Key::PUBLIC_KEY_NDEX_HEADER {
                            BigUint::from_str_radix(file_buf[2].trim(), Key::BIGUINT_STR_RADIX)
                                .map_err(|e| e.to_string())?
                        } else {
                            BigUint::from(Key::DEFAULT_EXPONENT)
                        },

                        variant,
                    })
                } else {
                    Err(String::from("File is an invalid public key"))
                }
            }
            KeyVariant::PrivateKey => {
                let file_buf: Vec<&str> = file_buf.split(Key::PRIVATE_KEY_SPLIT_CHAR).collect();
                if variant.is_valid_key_file(&file_buf) {
                    Ok(Key {
                        modulus: BigUint::from_str_radix(
                            file_buf[1].trim(),
                            Key::BIGUINT_STR_RADIX,
                        )
                        .map_err(|e| e.to_string())?,

                        exponent: BigUint::from_str_radix(
                            file_buf[2].trim(),
                            Key::BIGUINT_STR_RADIX,
                        )
                        .map_err(|e| e.to_string())?,

                        variant,
                    })
                } else {
                    Err(String::from("File is an invalid private key"))
                }
            }
        }
    }
}

impl KeyVariant {
    /// Returns the default filename for both Public and Private Key variants.
    fn get_filename(&self) -> String {
        if *self == KeyVariant::PublicKey {
            Key::DEFAULT_KEY_NAME.to_string() + Key::PUBLIC_KEY_FILE_SUFFIX
        } else {
            Key::DEFAULT_KEY_NAME.to_string()
        }
    }

    /// Validates a if a Key file is formatted correctly, but does not validate the key itself.
    fn is_valid_key_file(&self, file_buf: &Vec<&str>) -> bool {
        let reg = Regex::new(Key::KEY_FILE_STR_RADIX_REGEX).unwrap();

        match self {
            KeyVariant::PublicKey => {
                file_buf.len() == 2
                    && file_buf[0].trim() == Key::PUBLIC_KEY_NORMAL_HEADER.trim()
                    && reg.is_match(file_buf[1].trim())
                    || file_buf.len() == 3
                        && file_buf[0].trim() == Key::PUBLIC_KEY_NDEX_HEADER.trim()
                        && reg.is_match(file_buf[1].trim())
                        && reg.is_match(file_buf[2].trim())
            }
            KeyVariant::PrivateKey => {
                file_buf.len() == 5
                    && file_buf[0].trim() == Key::PRIVATE_KEY_HEADER.trim()
                    && file_buf[3].trim() == Key::PRIVATE_KEY_FOOTER.trim()
                    && reg.is_match(file_buf[1].trim())
                    && reg.is_match(file_buf[2].trim())
            }
        }
    }
}

trait IsDefaultExponent {
    fn is_default_exponent(&self) -> bool;
}

impl IsDefaultExponent for BigUint {
    #[must_use]
    fn is_default_exponent(&self) -> bool {
        *self == BigUint::from(Key::DEFAULT_EXPONENT)
    }
}

fn print_flush(string: &str, print_progress: bool) {
    if print_progress {
        print!("{}", string);
        std::io::stdout().flush().expect("Could not flush stdout");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_validation() {
        let key_pair = KeyPair {
            public_key: Key {
                exponent: BigUint::from(65_537u32), // default value isn't present in key file
                modulus: BigUint::from(2523461377u64), // 0x9668f701
                variant: KeyVariant::PublicKey,
            },
            private_key: Key {
                exponent: BigUint::from(343637873u32), // 0x147b7f71
                modulus: BigUint::from(2523461377u64), // 0x9668f701
                variant: KeyVariant::PrivateKey,
            },
        };
        assert!(key_pair.is_valid());
        let key_pair = KeyPair {
            public_key: Key {
                exponent: BigUint::from(23447u64),    // 0x5b97
                modulus: BigUint::from(298224757u64), // 0x11c68c75
                variant: KeyVariant::PublicKey,
            },
            private_key: Key {
                exponent: BigUint::from(58335719u64), // 0x37a21e7
                modulus: BigUint::from(298224757u64), // 0x11c68c75
                variant: KeyVariant::PrivateKey,
            },
        };
        assert!(key_pair.is_valid());
    }

    #[test]
    fn test_key_import_dex() {
        let public_key = Key {
            exponent: BigUint::from(65_537u32), // default value isn't present in key file
            modulus: BigUint::from(2523461377u64), // 0x9668f701
            variant: KeyVariant::PublicKey,
        };
        let private_key = Key {
            exponent: BigUint::from(343637873u32), // 0x147b7f71
            modulus: BigUint::from(2523461377u64), // 0x9668f701
            variant: KeyVariant::PrivateKey,
        };

        let pub_path = Some(PathBuf::from("keys/tests/dex_key.pub"));
        public_key.write_key_file(pub_path.clone());
        let read_pub_key = Key::read_key_file(pub_path, KeyVariant::PublicKey).unwrap();
        assert_eq!(read_pub_key, public_key);
        let priv_path = Some(PathBuf::from("keys/tests/dex_key"));
        private_key.write_key_file(priv_path.clone());
        let read_priv_key = Key::read_key_file(priv_path, KeyVariant::PrivateKey).unwrap();
        assert_eq!(read_priv_key, private_key);
    }

    #[test]
    #[should_panic]
    fn test_invalid_key() {
        let res = Key::read_key_file(
            Some(PathBuf::from("keys/tests/invalid_key.pub")),
            KeyVariant::PublicKey,
        );
        assert!(res.is_err());
        let res = Key::read_key_file(
            Some(PathBuf::from("keys/tests/invalid_key")),
            KeyVariant::PrivateKey,
        );
        assert!(res.is_err());
    }

    #[test]
    fn test_key_import_ndex() {
        let public_key = Key {
            exponent: BigUint::from(23447u64),    // 0x5b97
            modulus: BigUint::from(298224757u64), // 0x11c68c75
            variant: KeyVariant::PublicKey,
        };
        let private_key = Key {
            exponent: BigUint::from(58335719u64), // 0x37a21e7
            modulus: BigUint::from(298224757u64), // 0x11c68c75
            variant: KeyVariant::PrivateKey,
        };

        let pub_path = Some(PathBuf::from("keys/tests/ndex_key.pub"));
        public_key.write_key_file(pub_path.clone());
        let read_pub_key = Key::read_key_file(pub_path, KeyVariant::PublicKey).unwrap();
        assert_eq!(read_pub_key, public_key);
        let priv_path = Some(PathBuf::from("keys/tests/ndex_key"));
        private_key.write_key_file(priv_path.clone());
        let read_priv_key = Key::read_key_file(priv_path, KeyVariant::PrivateKey).unwrap();
        assert_eq!(read_priv_key, private_key);
    }

    #[test]
    fn test_write_key_file() {
        // let mut key = Key {
        //     exponent: BigUint::from(1u32),
        //     modulus: BigUint::from(1u32),
        //     variant: KeyVariant::PublicKey,
        // };
        // let path = Some(Path::new("teste"));
        // key.write_key_file(path);
        // key.variant = KeyVariant::PrivateKey;
        // // key.write_key_file(path);
        // key.write_key_file(None);
    }
}
