use crate::key_generator::Key;
use crate::mod_exponentiation::mod_pow;
use base64::{decode_config, encode_config};
use num_bigint::BigUint;
use std::fs::{create_dir_all, File};
use std::io::{Read, Write};
use std::io::{Seek, SeekFrom};
use std::path::{Path, MAIN_SEPARATOR};

const IDEAL_SIZE_CHUNKS_ENC: usize = 264;

/// Returns the number of bytes needed to store all the bits of N-1
fn size_in_bytes(n: &BigUint) -> usize {
    let one = &BigUint::from(1u32);

    assert!(n > one);

    let nb_bits = (n - one).bits();
    let nb_bytes = (nb_bits / 8) + (nb_bits & 7 != 0) as u64;

    nb_bytes
        .try_into()
        .expect("Couldn't cast nb_bytes from u64 to usize")
}

/// Generates a number that is both a multiple of 3 and <= max(size_in_bytes(n), lower_eq)
/// really a toy function, see the comments in the encrypt_file and decrypt_file functions
/// not used in the code
fn get_max_bytes(n: &BigUint, lower_eq: usize) -> usize {
    let mut nb_bytes = size_in_bytes(n);

    nb_bytes = std::cmp::max(nb_bytes, lower_eq);

    // now, we have to make sure nb_bytes is a multiple of 3
    nb_bytes -= nb_bytes % 3;

    // we read at least one byte, no matter what, 3 is the first multiple of 3 that is >= 1
    std::cmp::max(3, nb_bytes)
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

/// Use this to get the size of an already opened file, in bytes, without reading it
fn get_file_size(file_in: &mut File) -> usize {
    let file_in_len = file_in
        .seek(SeekFrom::End(0))
        .expect("couldn't seek the end of the file");
    file_in
        .rewind()
        .expect("Couldn't rewind the file after getting its size");

    file_in_len
        .try_into()
        .expect("couldn't convert u64 to usize")
}

/// pow(n, p, m) is almost never the same size as n
/// we use this to pad the encrypted data
fn pad_left(buf: &[u8], pad_size: usize) -> Vec<u8> {
    //println!("buf.len() = {}, pad_size = {}", buf.len(), pad_size);
    assert!(buf.len() <= pad_size);
    if buf.len() == pad_size {
        return buf.to_vec();
    }

    let ret = pad_size - buf.len();
    let mut r = vec![0u8; pad_size];
    r[ret..].copy_from_slice(buf);

    r
}

/// Encrypts a file chunk by chunk
pub fn encrypt_file(file_path: &str, out_path: &str, key: &Key) {
    let (mut file_in, mut file_out) = open_input_output(file_path, out_path);

    let (exponent, modulus) = (&key.d_e, &key.n);

    /*--------
        max_bytes is the number of bytes we want to read from the input at a time
        it doesn't matter if it's not a multiple of 3, thanks to the padding
        more on this down there

        you can replace this by any other function returning a usize
        why not get_max_bytes(&key.n, file_in_len) after modifying get_max_bytes ?
    ----------*/
    let max_bytes = IDEAL_SIZE_CHUNKS_ENC;
    let mut buf = vec![0u8; max_bytes];
    let mut ret = max_bytes;

    /*---------
        THIS, matters
        size_of_modulus_multiple_3 is the fixed size of every encrypted chunk after
        we pad_left() them.

        It MUST be a multiple of 3, so that its base64 has a multiple of 4 as length

        it can (will) be > size_of_modulus, but it doesn't matter since we're padding with zeroes on the left
        and as you know, leading zeroes don't change the value of the number
    -----------*/
    let size_of_modulus = size_in_bytes(modulus);
    let size_of_modulus_multiple_3 = size_of_modulus + (3 - size_of_modulus % 3) % 3;

    while ret == max_bytes {
        ret = file_in.read(&mut buf).expect("Error reading input file");
        if ret == 0 {
            break;
        } // nothing to read

        // println!("read {}", String::from_utf8_lossy(&buf[..ret]));

        let b = BigUint::from_bytes_be(&buf[..ret]); // this can be of any size <= size_of_modulus
        let d = mod_pow(&b, exponent, modulus); // this too

        // but this is always size_of_modulus_multiple_3 bytes long
        let padded_d = pad_left(&d.to_bytes_be(), size_of_modulus_multiple_3);

        // so this is 4*size_of_modulus_multiple_3/3 bytes long, a multiple of 4
        let process_result = encode_config(&padded_d, base64::CRYPT).into_bytes();

        // println!(
        //     "wrote {}\nlen: {}\n",
        //     String::from_utf8_lossy(&process_result),
        //     process_result.len()
        // );
        file_out
            .write_all(&process_result)
            .expect("Error writing to output file");
    }
}

/// decrypts a file chunk by chunk
pub fn decrypt_file(file_path: &str, out_path: &str, key: &Key) {
    let (mut file_in, mut file_out) = open_input_output(file_path, out_path);
    let file_in_len = get_file_size(&mut file_in);

    assert!(
        file_in_len & 3 == 0,
        "decrypt_file can only decrypt base64 strings of size a multiple of 4"
    );

    let (exponent, modulus) = (&key.d_e, &key.n);

    /*----------
        What is important to us, is to read the file by chunks having a length
        which is a multiple of 4, yielding a multiple of 3 once base64 decoded

        why not get_max_bytes(&key.n, (file_in_len/4) * 3) after modifying get_max_bytes ?
    ------------*/
    let size_of_modulus = size_in_bytes(modulus);
    let size_of_modulus_multiple_3 = size_of_modulus + (3 - size_of_modulus % 3) % 3;

    let max_bytes = size_of_modulus_multiple_3 / 3 * 4;

    let mut buf = vec![0u8; max_bytes];
    let mut ret = max_bytes;

    while ret == max_bytes {
        ret = file_in.read(&mut buf).expect("Error reading input file");
        if ret == 0 {
            break;
        } // nothing to read

        // println!("read {}", String::from_utf8_lossy(&buf[..ret]));

        debug_assert!(ret & 3 == 0); // read only by multiples of 4

        let dec = decode_config(&buf[..ret], base64::CRYPT).expect("Error decoding base64 string");
        debug_assert!(dec.len() % 3 == 0);

        // automatically left-unpadded, as leading zeroes don't contribute to the underlying polynomial
        let d = BigUint::from_bytes_be(&dec);
        let b = mod_pow(&d, exponent, modulus);

        let process_result = b.to_bytes_be();

        // println!(
        //     "wrote {}\nlen: {}\n",
        //     String::from_utf8_lossy(&process_result),
        //     process_result.len()
        // );
        file_out
            .write_all(&process_result)
            .expect("Error writing to output file");
    }
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
}
