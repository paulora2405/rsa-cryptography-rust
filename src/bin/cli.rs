use std::path::PathBuf;

use clap::{Parser, Subcommand};
use rrsa_common::key::{Key, KeyPair, KeyVariant};

fn main() {
    match RsaCli::parse().sub_command {
        RsaCommands::Keygen {
            key_size: maybe_key_size,
            out_path,
            use_ndex,
            print_results,
            print_progress,
        } => {
            let key_pair =
                KeyPair::generate_keys(maybe_key_size, !use_ndex, print_results, print_progress);
            key_pair
                .write_key_files(out_path)
                .unwrap_or_else(|e| panic!("Failed to write key pair, error: '{e}'"));
        }
        RsaCommands::Encrypt {
            file_path,
            out_path: maybe_out_path,
            key_path: maybe_key_path,
        } => {
            let key = Key::read_key_file(maybe_key_path, KeyVariant::PublicKey).unwrap(); // TODO:
            key.encrypt_file(file_path, maybe_out_path);
        }
        RsaCommands::Decrypt {
            file_path,
            out_path: maybe_out_path,
            key_path: maybe_key_path,
        } => {
            let key = Key::read_key_file(maybe_key_path, KeyVariant::PrivateKey).unwrap(); // TODO:
            key.decrypt_file(file_path, maybe_out_path);
        }
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct RsaCli {
    #[command(subcommand)]
    sub_command: RsaCommands,
}

#[derive(Subcommand)]
enum RsaCommands {
    /// Generates a Public and a Private key, and stores then in output file
    Keygen {
        /// Key size in bits, defaults to 4096 (32..=4096)
        #[arg(short, long)]
        key_size: Option<u16>,
        /// Path to save key file (Ex: ./keys/key)
        #[arg(short, long)]
        out_path: Option<PathBuf>,
        /// Generates a key with non default exponent value (False by default)
        #[arg(short, long, action = clap::ArgAction::SetTrue)]
        use_ndex: bool,
        /// Prints the key generation internal results (False by default)
        #[arg(short = 'r', long, action = clap::ArgAction::SetTrue)]
        print_results: bool,
        /// Prints the progress of the key generation (False by default)
        #[arg(short, long, action = clap::ArgAction::SetTrue)]
        print_progress: bool,
    },
    /// Encrypts a plain text file using a Public Key
    Encrypt {
        /// Input file path.
        #[arg(short, long)]
        file_path: PathBuf,
        /// Output file path
        #[arg(short, long)]
        out_path: Option<PathBuf>,
        /// Path to Public Key
        #[arg(short, long)]
        key_path: Option<PathBuf>,
    },
    /// Decrypts an encrypted file using a Private Key
    Decrypt {
        /// Input file path.
        #[arg(short, long)]
        file_path: PathBuf,
        /// Output file path
        #[arg(short, long)]
        out_path: Option<PathBuf>,
        /// Path to Private Key
        #[arg(short, long)]
        key_path: Option<PathBuf>,
    },
}
