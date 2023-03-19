use crate::key_generator::Key;
use crate::math::mod_pow;
use num_bigint::BigUint;
use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use std::path::{Path, MAIN_SEPARATOR};

const ENCRYPTION_BYTE_OFFSET: usize = 1;

/// Returns the number of bytes needed to store all the bits of N-1
fn size_in_bytes(n: &BigUint) -> usize {
    (n.bits() / 8)
        .try_into()
        .expect("Couldn't cast nb_bytes from u64 to usize")
}

/// Factored the repetition to open file_path and out_path
fn open_input_output(file_path: &str, out_path: &str) -> (File, File) {
    if !Path::new(file_path).exists() {
        let file_name: Vec<&str> = file_path.rsplit(MAIN_SEPARATOR).collect();
        if file_name.len() > 1 {
            let file_name = file_name.first().expect("Error at parent dir separation");
            let parent_dir = file_path
                .strip_suffix(file_name)
                .expect("Error stripping suffix");
            create_dir_all(parent_dir).expect("Error creating parent directories");
        }
    }
    if !Path::new(out_path).exists() {
        let file_name: Vec<&str> = out_path.rsplit(MAIN_SEPARATOR).collect();
        if file_name.len() > 1 {
            let file_name = file_name.first().expect("Error at parent dir separation");
            let parent_dir = out_path
                .strip_suffix(file_name)
                .expect("Error stripping suffix");
            create_dir_all(parent_dir).expect("Error creating parent directories");
        }
    }
    let file_in = File::open(file_path).expect("Error opening input file");
    let file_out = File::create(out_path).expect("Error opening output file");

    (file_in, file_out)
}

/// Encrypts a file chunk by chunk
pub fn encrypt_file(file_path: &str, out_path: &str, key: &Key) {
    let (mut file_in, mut file_out) = open_input_output(file_path, out_path);
    let (exponent, modulus) = (&key.d_e, &key.n);
    let max_bytes_read = size_in_bytes(modulus) - ENCRYPTION_BYTE_OFFSET; // always > 0 because min key size is 32 bits == 4 bytes
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
pub fn decrypt_file(file_path: &str, out_path: &str, key: &Key) {
    let (mut file_in, mut file_out) = open_input_output(file_path, out_path);
    let (exponent, modulus) = (&key.d_e, &key.n);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_generator::KeyPair;

    #[test]
    fn test_encrypt_decrypt() {
        let plain_file = "messages/lorem.txt";
        let encrypted = "messages/encrypted.txt";
        let decrypted = "messages/decrypted.txt";
        let keypair = KeyPair::read_key_files("keys/small_key");
        encrypt_file(plain_file, encrypted, &keypair.pub_key);
        decrypt_file(encrypted, decrypted, &keypair.priv_key);
    }
}
