use crate::math::{euclides_extended, mod_pow, PrimeGenerator};
use clap::crate_name;
use directories::{BaseDirs, ProjectDirs, UserDirs};
use num_bigint::BigUint;
use num_traits::{FromPrimitive, Num, One, Signed};
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
    /// # Panics
    /// Panics if `key_size` is not in (32, 4096) interval
    #[must_use]
    pub fn generate_keys(
        key_size: u16,
        use_default_exponent: bool,
        print_results: bool,
        print_progress: bool,
    ) -> KeyPair {
        todo!()
    }

    /// Validates and writes Public and Private key files to `key_out_path`.
    /// # Panics
    /// Panics if `key_pair` isn't valid.
    pub fn write_key_files(key_out_path: &str, key_pair: &KeyPair) {
        todo!()
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

trait IsDefaultExponent {
    fn is_default_exponent(&self) -> bool;
}

impl IsDefaultExponent for BigUint {
    fn is_default_exponent(&self) -> bool {
        *self == BigUint::from(Key::DEFAULT_EXPONENT)
    }
}

impl Key {
    const DEFAULT_EXPONENT: u32 = 65_537u32;
    const PUBLIC_KEY_SUFFIX: &str = ".pub";
    const APP_CONFIG_DIR: &str = crate_name!();
    const DEFAULT_KEY_NAME: &str = "rrsa_key";
    const BIGUINT_STR_RADIX: u32 = 16;
    const DEFAULT_KEY_SIZE: usize = 4096;

    /// Returns the default filename for both Public and Private Key variants.
    fn get_filename(&self) -> String {
        if self.variant == KeyVariant::PublicKey {
            Key::DEFAULT_KEY_NAME.to_string() + Key::PUBLIC_KEY_SUFFIX
        } else {
            Key::DEFAULT_KEY_NAME.to_string()
        }
    }

    /// Writes Public or Private key file to output path.
    pub fn write_key_file(&self, maybe_path: Option<&Path>) {
        let final_path: PathBuf;

        if let Some(path) = maybe_path {
            if path.is_file() {
                final_path = path.to_path_buf();
            } else if path.is_dir() {
                final_path = path.join(self.get_filename());
            } else {
                // THIS ASSUMES THE PATH IS FOR A DIRECTORY
                create_dir_all(path).expect("Failed to create necessary parent directories!");
                final_path = path.join(self.get_filename());
            }
        } else if let Some(dirs) = BaseDirs::new() {
            let parent_dir = dirs.config_dir().join(Key::APP_CONFIG_DIR);
            create_dir_all(&parent_dir).expect("Failed to create necessary parent directories!");
            final_path = parent_dir.join(self.get_filename());
        } else {
            eprintln!("Failed to find user's config directory! Falling back to cwd...");
            final_path = PathBuf::from(".")
                .join(Key::APP_CONFIG_DIR)
                .join(self.get_filename());
        }
        println!("Key file saved to `{}`", final_path.to_string_lossy());

        dbg!(&final_path);

        let mut file = File::create(&final_path).unwrap_or_else(|_| {
            panic!(
                "Could not open output filepath of {}",
                final_path.to_string_lossy()
            )
        });

        let content: String = match self.variant {
            KeyVariant::PublicKey => {
                let use_default_exponent = self.exponent.is_default_exponent();
                if use_default_exponent {
                    String::from("rsa-rust ")
                        + &self.modulus.to_str_radix(Key::BIGUINT_STR_RADIX)
                        + "\n"
                } else {
                    String::from("rsa-rust-ndex ")
                        + &self.modulus.to_str_radix(Key::BIGUINT_STR_RADIX)
                        + " "
                        + &self.exponent.to_str_radix(Key::BIGUINT_STR_RADIX)
                        + "\n"
                }
            }
            KeyVariant::PrivateKey => {
                String::from("-----BEGIN RSA-RUST PRIVATE KEY-----\n")
                    + &self.exponent.to_str_radix(Key::BIGUINT_STR_RADIX)
                    + "\n-----END RSA-RUST PRIVATE KEY-----\n"
            }
        };

        file.write_all(content.as_bytes())
            .expect("Error writing to file");
    }

    /// Reads Public or Private key file from input path.
    pub fn read_key_file(&self, maybe_path: Option<&Path>) {}
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
    fn test_write_key_file() {
        let mut key = Key {
            exponent: BigUint::from(1u32),
            modulus: BigUint::from(1u32),
            variant: KeyVariant::PublicKey,
        };
        let path = Some(Path::new("teste"));
        // key.write_key_file(path);
        key.variant = KeyVariant::PrivateKey;
        // key.write_key_file(path);
        key.write_key_file(None);
    }
}
