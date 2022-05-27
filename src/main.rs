pub mod encryption;
pub mod euclidean;
pub mod key_generator;
pub mod mod_exponentiation;
pub mod primality;
use crate::key_generator::KeyPair;
use clap::{arg, Command};
use std::str::FromStr;

fn main() {
    let matches = create_command().get_matches();

    match matches.subcommand() {
        Some(("keygen", sub_matches)) => {
            let _ = KeyPair::generate_keys(
                u16::from_str(
                    sub_matches
                        .value_of("key_size")
                        .expect("Key size arg required"),
                )
                .expect("Failed to parse key size argument!"),
                sub_matches
                    .value_of("path_out")
                    .expect("Key out path arg required"),
                true,
                false,
            );
        }
        _ => unreachable!(),
    }
}

fn create_command() -> Command<'static> {
    Command::new("rsa-rust")
        .about("RSA keys generation, encryption and decryption implemented in rust, for learning purposes only.")
        .author("Paulo Roberto Albuquerque")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("keygen")
            .about("Generates a Public and a Private key, and stores then in output file.")
            .arg(arg!(-s --key_size <KEY_SIZE> "Key size in bits (Min=32; Max=4096)."))
            .arg(arg!(-o --path_out <OUT_PATH> "Path to save key file (Ex: keys/key)."))
            .arg_required_else_help(true),
        )
    // .subcommand(
    //     Command::new("encrypt")
    //     .about("Encrypts a file")
    //     .arg(arg!(--file <FILE_PATH> "Input file"))
    //     .arg(arg!(--out <OUTPUT_PATH> "Output file path"))
    //     .arg(arg!(--key <KEY_PATH> "Path to Public Key"))
    //     .arg_required_else_help(true)
    // )
}
