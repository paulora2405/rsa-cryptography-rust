use crate::key_generator::Key;
use crate::mod_exponentiation::mod_pow;
use num_bigint::BigUint;
use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use std::path::{Path, MAIN_SEPARATOR};

const ENCRYPTION_BYTE_OFFSET: usize = 1;

/// Returns the number of bytes needed to store all the bits of N-1
fn size_in_bytes(n: &BigUint) -> usize {
    let one = &BigUint::from(1u32);

    assert!(n > one);

    let nb_bits = n.bits();
    let nb_bytes = nb_bits / 8;

    nb_bytes
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
    // dbg!(&exponent, &modulus);

    let max_bytes_read: usize = size_in_bytes(modulus) - ENCRYPTION_BYTE_OFFSET;
    let max_bytes_write: usize = size_in_bytes(modulus);
    // dbg!(size_in_bytes(modulus), max_bytes_read, max_bytes_write);
    assert!(max_bytes_read > 0); // never will be > 0 because min key size is 32 bits == 4 bytes

    let mut source_bytes = vec![0u8; max_bytes_read];
    let mut destiny_bytes = Vec::<u8>::with_capacity(max_bytes_read);
    let mut bytes_amount_read = max_bytes_read;

    // let mut i = 1;
    while bytes_amount_read == max_bytes_read {
        source_bytes.fill(0u8);
        bytes_amount_read = file_in.read(&mut source_bytes).unwrap();
        if bytes_amount_read == 0 {
            break;
        }

        // println!("--------\nIter {i}");
        // i += 1;
        // dbg!(bytes_amount_read);
        // dbg!(String::from_utf8_lossy(&source_bytes));

        let message = BigUint::from_bytes_le(&source_bytes);
        let encrypted = mod_pow(&message, exponent, modulus);
        // dbg_hex::dbg_hex!(&message.to_bytes_le(), &encrypted.to_bytes_le());

        destiny_bytes.clear();
        let _ = destiny_bytes.write(&encrypted.to_bytes_le()).unwrap();

        if destiny_bytes.len() < max_bytes_write {
            let size_diff = (max_bytes_write) - destiny_bytes.len();
            destiny_bytes.append(&mut vec![0u8; size_diff]);
        }

        let _bytes_amount_written = file_out.write(&destiny_bytes).unwrap();
        // dbg!(_bytes_amount_written);
    }
}

/// decrypts a file chunk by chunk
pub fn decrypt_file(file_path: &str, out_path: &str, key: &Key) {
    let (mut file_in, mut file_out) = open_input_output(file_path, out_path);

    let (exponent, modulus) = (&key.d_e, &key.n);
    // dbg!(&exponent, &modulus);

    let max_bytes = size_in_bytes(modulus);
    // dbg!(size_in_bytes(modulus), max_bytes);

    let mut source_bytes = vec![0u8; max_bytes];
    let mut destiny_bytes = Vec::<u8>::with_capacity(max_bytes);
    let mut bytes_amount_read = max_bytes;

    // let mut i = 1;
    while bytes_amount_read == max_bytes {
        source_bytes.fill(0u8); // source
        bytes_amount_read = file_in.read(&mut source_bytes).unwrap();
        if bytes_amount_read == 0 {
            break;
        }

        // println!("--------\nIter {i}");
        // i += 1;
        // dbg!(bytes_amount_read);

        let encrypted = BigUint::from_bytes_le(&source_bytes);
        let message = mod_pow(&encrypted, exponent, modulus);
        // dbg_hex::dbg_hex!(&encrypted, &message);
        // dbg_hex::dbg_hex!(&encrypted.to_bytes_le(), &message.to_bytes_le());

        destiny_bytes.clear();
        let _ = destiny_bytes.write(&message.to_bytes_le()).unwrap();

        let _bytes_amount_written = file_out.write(&destiny_bytes).unwrap();
        // dbg!(_bytes_amount_written);
        // dbg!(String::from_utf8_lossy(&destiny_bytes));
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
