pub mod encryption;
pub mod euclidean;
pub mod key_generator;
pub mod mod_exponentiation;
pub mod primality;
use crate::encryption::{decrypt_file, encrypt_file};
use crate::key_generator::KeyPair;
use clap::{arg, Command};
use std::str::FromStr;

fn main() {
    let matches = create_command().get_matches();

    match matches.subcommand() {
        Some(("keygen", sub_matches)) => {
            let key_pair = KeyPair::generate_keys(
                u16::from_str(
                    sub_matches
                        .value_of("key_size")
                        .expect("Key size arg required"),
                )
                .expect("Failed to parse key size argument!"),
                !sub_matches.is_present("use_ndex"),
                false,
                true,
            );
            KeyPair::write_key_files(
                sub_matches
                    .value_of("path_out")
                    .expect("Key out path arg required"),
                &key_pair,
            );
        }
        Some(("encrypt", sub_matches)) => {
            encrypt_file(
                sub_matches
                    .value_of("file_path")
                    .expect("Error parsing file path"),
                sub_matches
                    .value_of("out_path")
                    .expect("Error parsing output path"),
                &KeyPair::read_key_files(
                    sub_matches
                        .value_of("key_path")
                        .expect("Error parsing key path"),
                )
                .pub_key,
            );
        }
        Some(("decrypt", sub_matches)) => {
            decrypt_file(
                sub_matches
                    .value_of("file_path")
                    .expect("Error parsing file path"),
                sub_matches
                    .value_of("out_path")
                    .expect("Error parsing output path"),
                &KeyPair::read_key_files(
                    sub_matches
                        .value_of("key_path")
                        .expect("Error parsing key path"),
                )
                .priv_key,
            );
        }
        _ => unreachable!(),
    }
}

fn create_command() -> Command<'static> {
    Command::new("rsa-rust")
        .about("RSA keys generation, encryption and decryption implemented in rust, for learning purposes only.\nSource code can be viewed in:\nhttps://github.com/paulora2405/rsa-cryptography-rust")
        .author("Paulo Roberto Albuquerque")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("keygen")
            .about("Generates a Public and a Private key, and stores then in output file.")
            .arg(arg!(-s --key_size <KEY_SIZE> "Key size in bits (Min=32; Max=4096)."))
            .arg(arg!(-o --path_out <OUT_PATH> "Path to save key file (Ex: keys/key)."))
            .arg_required_else_help(true)
            .arg(arg!(--use_ndex "Generates a key with non default exponent value."))
        )
    .subcommand(
        Command::new("encrypt")
        .about("Encrypts a plain text file using a Public Key.")
        .arg(arg!(-f --file_path <FILE_PATH> "Input file path."))
        .arg(arg!(-o --out_path <OUTPUT_PATH> "Output file path."))
        .arg(arg!(-k --key_path <KEY_PATH> "Path to Public Key (ommit the `.pub`)."))
        .arg_required_else_help(true)
    )
    .subcommand(
        Command::new("decrypt")
        .about("Decrypts an encrypted file using a Private Key.")
        .arg(arg!(-f --file_path <FILE_PATH> "Input file path."))
        .arg(arg!(-o --out_path <OUTPUT_PATH> "Output file path."))
        .arg(arg!(-k --key_path <KEY_PATH> "Path to Private Key."))
        .arg_required_else_help(true)
    )
}
