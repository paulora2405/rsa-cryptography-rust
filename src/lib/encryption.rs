use crate::key::Key;
use crate::math::mod_pow;
use num_bigint::BigUint;
use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use std::path::PathBuf;

/// Returns the number of bytes needed to store all the bits of N-1
fn size_in_bytes(n: &BigUint) -> usize {
    (n.bits() / 8)
        .try_into()
        .expect("Couldn't cast nb_bytes from u64 to usize")
}

impl Key {
    const ENCRYPTION_BYTE_OFFSET: usize = 1;
    const DEFAULT_ENCRYPTED_FILE_EXTENSION: &str = "cypher";
    const DEFAULT_ENCRYPTED_FILE_NAME: &str = "encrypted";
    const DEFAULT_DECRYPTED_FILE_EXTENSION: &str = "message";
    const DEFAULT_DECRYPTED_FILE_NAME: &str = "decrypted";

    fn open_input_output(&self, file_path: PathBuf, out_path: Option<PathBuf>) -> (File, File) {
        let file_path = {
            if file_path.is_file() {
                file_path
            } else {
                // TODO: handle this case better, maybe return a Result<>?
                panic!("File does not exist");
            }
        };
        let out_path = {
            if let Some(out_path) = out_path {
                if out_path.is_file() {
                    match self.variant {
                        crate::key::KeyVariant::PublicKey => {
                            out_path.join(Key::DEFAULT_ENCRYPTED_FILE_EXTENSION)
                        }
                        crate::key::KeyVariant::PrivateKey => {
                            out_path.join(Key::DEFAULT_DECRYPTED_FILE_EXTENSION)
                        }
                    }
                } else if out_path.is_dir() {
                    match self.variant {
                        crate::key::KeyVariant::PublicKey => out_path
                            .join(Key::DEFAULT_ENCRYPTED_FILE_NAME)
                            .join(Key::DEFAULT_ENCRYPTED_FILE_EXTENSION),
                        crate::key::KeyVariant::PrivateKey => out_path
                            .join(Key::DEFAULT_DECRYPTED_FILE_NAME)
                            .join(Key::DEFAULT_DECRYPTED_FILE_EXTENSION),
                    }
                } else {
                    create_dir_all(&out_path).expect("Failed to create parents directories");
                    match self.variant {
                        crate::key::KeyVariant::PublicKey => out_path
                            .join(Key::DEFAULT_ENCRYPTED_FILE_NAME)
                            .join(Key::DEFAULT_ENCRYPTED_FILE_EXTENSION),
                        crate::key::KeyVariant::PrivateKey => out_path
                            .join(Key::DEFAULT_DECRYPTED_FILE_NAME)
                            .join(Key::DEFAULT_DECRYPTED_FILE_EXTENSION),
                    }
                }
            } else {
                match self.variant {
                    crate::key::KeyVariant::PublicKey => PathBuf::from(".")
                        .join(Key::DEFAULT_ENCRYPTED_FILE_NAME)
                        .join(Key::DEFAULT_ENCRYPTED_FILE_EXTENSION),
                    crate::key::KeyVariant::PrivateKey => PathBuf::from(".")
                        .join(Key::DEFAULT_DECRYPTED_FILE_NAME)
                        .join(Key::DEFAULT_DECRYPTED_FILE_EXTENSION),
                }
            }
        };

        let file_in = File::open(file_path).expect("Error opening input file");
        let file_out = File::create(out_path).expect("Error opening output file");

        (file_in, file_out)
    }

    /// Encrypts a file chunk by chunk
    pub fn encrypt_file(&self, file_path: PathBuf, out_path: Option<PathBuf>) {
        let (mut file_in, mut file_out) = self.open_input_output(file_path, out_path);
        let (exponent, modulus) = (&self.exponent, &self.modulus);
        let max_bytes_read = size_in_bytes(modulus) - Key::ENCRYPTION_BYTE_OFFSET; // always > 0 because min key size is 32 bits == 4 bytes
        let max_bytes_write = size_in_bytes(modulus);
        let mut source_bytes = vec![0u8; max_bytes_read];
        let mut destiny_bytes = Vec::<u8>::with_capacity(max_bytes_read);
        let mut bytes_amount_read = max_bytes_read;

        while bytes_amount_read == max_bytes_read {
            source_bytes.fill(0u8);
            bytes_amount_read = file_in.read(&mut source_bytes).unwrap();
            if bytes_amount_read == 0 {
                break;
            }
            let message = BigUint::from_bytes_le(&source_bytes);
            let encrypted = mod_pow(&message, exponent, modulus);
            destiny_bytes.clear();
            let _ = destiny_bytes.write(&encrypted.to_bytes_le()).unwrap();
            let size_diff = (max_bytes_write) - destiny_bytes.len();
            destiny_bytes.append(&mut vec![0u8; size_diff]);
            let _bytes_amount_written = file_out.write(&destiny_bytes).unwrap();
        }
    }

    /// decrypts a file chunk by chunk
    pub fn decrypt_file(&self, file_path: PathBuf, out_path: Option<PathBuf>) {
        let (mut file_in, mut file_out) = self.open_input_output(file_path, out_path);
        let (exponent, modulus) = (&self.exponent, &self.modulus);
        let max_bytes = size_in_bytes(modulus);
        let mut source_bytes = vec![0u8; max_bytes];
        let mut destiny_bytes = Vec::<u8>::with_capacity(max_bytes);
        let mut bytes_amount_read = max_bytes;

        while bytes_amount_read == max_bytes {
            source_bytes.fill(0u8);
            bytes_amount_read = file_in.read(&mut source_bytes).unwrap();
            if bytes_amount_read == 0 {
                break;
            }
            let encrypted = BigUint::from_bytes_le(&source_bytes);
            let message = mod_pow(&encrypted, exponent, modulus);
            destiny_bytes.clear();
            let _ = destiny_bytes.write(&message.to_bytes_le()).unwrap();
            let _bytes_amount_written = file_out.write(&destiny_bytes).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        // TODO: generate used files inside unit test
        let plain_file = PathBuf::from("messages/lorem.txt");
        let encrypted = Some(PathBuf::from("messages/"));
        let decrypted = Some(PathBuf::from("messages/"));

        let pub_path = Some(PathBuf::from("keys/small_key.pub"));
        let priv_path = Some(PathBuf::from("keys/small_key"));
        let pub_key = Key::read_key_file(pub_path, crate::key::KeyVariant::PublicKey).unwrap();
        let priv_key = Key::read_key_file(priv_path, crate::key::KeyVariant::PrivateKey).unwrap();
        pub_key.encrypt_file(plain_file, encrypted.clone());
        priv_key.decrypt_file(encrypted.unwrap(), decrypted);
    }
}
