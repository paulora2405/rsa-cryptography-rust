use crate::key_generator::Key;
use crate::mod_exponentiation::mod_pow;
use base64::{decode, encode};
use num_bigint::BigUint;
use std::fs::File;
use std::io::{Read, Write};

pub fn encrypt_file(file_path: &str, out_path: &str, pub_key: &Key) {
    let mut file_in = File::open(file_path).expect("Error opening input file");
    let mut file_out = File::create(out_path).expect("Error opening output file");
    let max_bytes = usize::try_from(pub_key.n.bits() / 8u64)
        .expect("Could not convert max bytes `u64` to `usize`");
    let mut buf: Vec<u8> = Vec::new();
    buf.resize(max_bytes, 0u8);
    loop {
        let ret = file_in.read(&mut buf).expect("Error reading file");
        if ret < max_bytes {
            if ret == 0 {
                break;
            }
            buf.truncate(max_bytes - ret);
            let encoded = text_to_base64_exponentiated(&buf, &pub_key.d_e, &pub_key.n);
            file_out.write(&encoded).expect("Error writing to file");
            break;
        } else {
            let encoded = text_to_base64_exponentiated(&buf, &pub_key.d_e, &pub_key.n);
            file_out.write(&encoded).expect("Error writing to file");
        }
    }
}

pub fn decrypt_file(file_path: &str, out_path: &str, priv_key: &Key) {
    let mut file_in = File::open(file_path).expect("Error opening input file");
    let mut file_out = File::create(out_path).expect("Error opening output file");
    let max_bytes = usize::try_from(priv_key.n.bits() / 8u64)
        .expect("Could not convert bytes `u64` to `usize`");
    let mut buf: Vec<u8> = Vec::new();
    buf.resize(max_bytes, 0u8);
    loop {
        let ret = file_in.read(&mut buf).expect("Error reading file");
        if ret < max_bytes {
            if ret == 0 {
                break;
            }
            buf.truncate(max_bytes - ret);
            let decoded = base64_to_text_exponentiated(&buf, &priv_key.d_e, &priv_key.n);
            file_out.write(&decoded).expect("Error writing to file");
            break;
        } else {
            let decoded = base64_to_text_exponentiated(&buf, &priv_key.d_e, &priv_key.n);
            file_out.write(&decoded).expect("Error writing to file");
        }
    }
}

/// Receives a plain text buffer of bytes and a public key, and returns a base64 encrypted buffer of bytes.
#[must_use]
fn text_to_base64_exponentiated(
    text_bytes: &Vec<u8>,
    exponent: &BigUint,
    modulus: &BigUint,
) -> Vec<u8> {
    let numeric = BigUint::from_bytes_be(text_bytes);
    let numeric = mod_pow(&numeric, exponent, modulus);
    Vec::from(encode(numeric.to_bytes_be()).as_bytes())
}

/// Receives a encoded text buffer of bytes and a private key, and returns a plain text buffer of bytes.
#[must_use]
fn base64_to_text_exponentiated(
    base64_bytes: &Vec<u8>,
    exponent: &BigUint,
    modulus: &BigUint,
) -> Vec<u8> {
    let decoded = decode(base64_bytes).expect("Error decoding base64 string");
    let numeric = BigUint::from_bytes_be(&decoded);
    let numeric = mod_pow(&numeric, exponent, modulus);
    numeric.to_bytes_be()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_generator::KeyPair;

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
