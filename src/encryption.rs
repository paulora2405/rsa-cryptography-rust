use crate::key_generator::Key;
use crate::mod_exponentiation::mod_pow;
use base64::{decode_config, encode_config};
use num_bigint::BigUint;
use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use std::path::{Path, MAIN_SEPARATOR};

pub fn encrypt_file(file_path: &str, out_path: &str, pub_key: &Key) {
    if !Path::new(file_path).exists() {
        let file_name: Vec<&str> = file_path.rsplit(MAIN_SEPARATOR).collect();
        if file_name.len() > 1 {
            let file_name = file_name.first().expect("Error at parent dir separation");
            let parent_dir = file_path
                .strip_suffix(file_name)
                .expect("Error strinping suffix");
            create_dir_all(parent_dir).expect("Error creating parent directories");
        }
    }
    let mut file_in = File::open(file_path).expect("Error opening input file");
    let mut file_out = File::create(out_path).expect("Error opening output file");
    let max_bytes: usize = {
        let nb_bits = pub_key.n.bits();
        (nb_bits / 8) + (nb_bits & 8 != 0) as u64
    }
    .try_into()
    .expect("Could not convert max bytes `u64` to `usize`");
    let mut buf: Vec<u8> = Vec::new();
    buf.resize(max_bytes, 0u8);
    loop {
        let ret = file_in.read(&mut buf).expect("Error reading file");
        if ret < max_bytes {
            if ret == 0 {
                break;
            }
            buf.truncate(ret);
            let encoded = text_to_base64_exponentiated(&buf, &pub_key.d_e, &pub_key.n);
            file_out.write_all(&encoded).expect("Error writing to file");
            break;
        }
        let encoded = text_to_base64_exponentiated(&buf, &pub_key.d_e, &pub_key.n);
        file_out.write_all(&encoded).expect("Error writing to file");
    }
}

pub fn decrypt_file(file_path: &str, out_path: &str, priv_key: &Key) {
    if !Path::new(file_path).exists() {
        let file_name: Vec<&str> = file_path.rsplit(MAIN_SEPARATOR).collect();
        if file_name.len() > 1 {
            let file_name = file_name.first().expect("Error at parent dir separation");
            let parent_dir = file_path
                .strip_suffix(file_name)
                .expect("Error strinping suffix");
            create_dir_all(parent_dir).expect("Error creating parent directories");
        }
    }
    let mut file_in = File::open(file_path).expect("Error opening input file");
    let mut file_out = File::create(out_path).expect("Error opening output file");
    let max_bytes: usize = {
        let nb_bits = priv_key.n.bits();
        (nb_bits / 8) + (nb_bits & 8 != 0) as u64
    }
    .try_into()
    .expect("Could not convert max bytes `u64` to `usize`");
    let mut buf: Vec<u8> = Vec::new();
    buf.resize(max_bytes, 0u8);
    loop {
        let ret = file_in.read(&mut buf).expect("Error reading file");
        if ret < max_bytes {
            if ret == 0 {
                break;
            }
            // buf.truncate(ret);
            let decoded = base64_to_text_exponentiated(&buf, &priv_key.d_e, &priv_key.n);
            file_out.write_all(&decoded).expect("Error writing to file");
            break;
        }
        let decoded = base64_to_text_exponentiated(&buf, &priv_key.d_e, &priv_key.n);
        file_out.write_all(&decoded).expect("Error writing to file");
    }
}

/// Receives a plain text buffer of bytes and a public key, and returns a base64 encrypted buffer of bytes.
#[must_use]
fn text_to_base64_exponentiated(
    text_bytes: &[u8],
    exponent: &BigUint,
    modulus: &BigUint,
) -> Vec<u8> {
    let numeric = BigUint::from_bytes_be(text_bytes);
    let numeric = mod_pow(&numeric, exponent, modulus);
    Vec::from(encode_config(numeric.to_bytes_be(), base64::CRYPT).as_bytes())
}

/// Receives a encoded text buffer of bytes and a private key, and returns a plain text buffer of bytes.
#[must_use]
fn base64_to_text_exponentiated(
    base64_bytes: &Vec<u8>,
    exponent: &BigUint,
    modulus: &BigUint,
) -> Vec<u8> {
    let decoded = decode_config(base64_bytes, base64::CRYPT).expect("Error decoding base64 string");
    let numeric = BigUint::from_bytes_be(&decoded);
    let numeric = mod_pow(&numeric, exponent, modulus);
    numeric.to_bytes_be()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_generator::KeyPair;

    #[test]
    fn test_parent_dir() {
        // let file_path = "messages/tests/seila.txt";
        let file_path = "seila.txt";
        if !Path::new(file_path).exists() {
            let file_name: Vec<&str> = file_path.rsplit(MAIN_SEPARATOR).collect();
            if file_name.len() > 1 {
                let file_name = file_name.first().unwrap();
                let parent_dir = file_path
                    .strip_suffix(file_name)
                    .expect("Error strinping suffix");
                create_dir_all(parent_dir).expect("Error creating parent directories");
            }
        }
    }

    #[test]
    fn test_encrypt_decrypt() {
        let plain_file = "messages/lorem.txt";
        let encrypted = "messages/encrypted.txt";
        let decrypted = "messages/decrypted.txt";
        let keypair = KeyPair::read_key_files("keys/key");
        encrypt_file(plain_file, encrypted, &keypair.pub_key);
        decrypt_file(encrypted, decrypted, &keypair.priv_key);
    }

    #[test]
    fn test_encrypt() {
        let file_in = "messages/simple.txt";
        let file_out = "messages/encrypted.txt";
        let key = KeyPair::read_key_files("keys/key").pub_key;
        encrypt_file(file_in, file_out, &key);
    }

    #[test]
    fn test_decrypt() {
        let file_in = "messages/encrypted.txt";
        let file_out = "messages/decrypted.txt";
        let key = KeyPair::read_key_files("keys/key").priv_key;
        decrypt_file(file_in, file_out, &key);
    }

    #[test]
    fn test_read_to_limit_bytes() {
        let mut file_in = File::open("messages/lorem.txt").expect("Error opening input file");
        let max_bytes = 65usize / 8usize;
        println!("max_bytes: {}", &max_bytes);
        let mut buf: Vec<u8> = Vec::new();
        buf.resize(max_bytes, 0u8);
        loop {
            let ret = file_in.read(&mut buf).unwrap();
            if ret < max_bytes {
                if ret == 0 {
                    break;
                }
                buf.truncate(max_bytes - ret);
                print!("{}", String::from_utf8(buf.clone()).unwrap());
                break;
            }
            print!("{}", String::from_utf8(buf.clone()).unwrap());
        }
        println!();
    }

    #[test]
    fn test_base64_encode_decode() {
        let text = "Test";
        let text_bytes: Vec<u8> = Vec::from(text.as_bytes());
        let encoded = text_to_base64_exponentiated(
            &text_bytes,
            &BigUint::from(65_537u32),
            &BigUint::from(2523461377u64),
        );
        let decoded = String::from_utf8(base64_to_text_exponentiated(
            &encoded,
            &BigUint::from(343637873u32),
            &BigUint::from(2523461377u64),
        ))
        .unwrap();
        assert_eq!(decoded, text);
    }
}
