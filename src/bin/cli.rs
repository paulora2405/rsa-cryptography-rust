use std::path::PathBuf;

use clap::{Parser, Subcommand};
use rrsa_common::key::{Key, KeyPair, KeyVariant};

fn main() -> Result<(), String> {
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
            key_pair.write_keypair_files(out_path)?;
        }
        RsaCommands::Encrypt {
            file_path,
            out_path: maybe_out_path,
            key_path: maybe_key_path,
        } => {
            let key = Key::read_key_file(maybe_key_path, KeyVariant::PublicKey)?;
            key.encrypt_file(file_path, maybe_out_path);
        }
        RsaCommands::Decrypt {
            file_path,
            out_path: maybe_out_path,
            key_path: maybe_key_path,
        } => {
            let key = Key::read_key_file(maybe_key_path, KeyVariant::PrivateKey)?;
            key.decrypt_file(file_path, maybe_out_path);
        }
    };
    Ok(())
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
        /// [OPTIONAL] Key size in bits (defaults to 4096, must be in (32..=4096))
        #[arg(short, long)]
        key_size: Option<u16>,
        /// [OPTIONAL] Path to save key file (Ex: ./keys/key or ./keys/, defaults to `~/.config/rrsa/`)
        #[arg(short, long)]
        out_path: Option<PathBuf>,
        /// [OPTIONAL] Generates a key with non default exponent value (False if absent)
        #[arg(short, long, action = clap::ArgAction::SetTrue)]
        use_ndex: bool,
        /// [OPTIONAL] Prints the key generation internal results (False if absent)
        #[arg(short = 'r', long, action = clap::ArgAction::SetTrue)]
        print_results: bool,
        /// [OPTIONAL] Prints the progress of the key generation (False if absent)
        #[arg(short, long, action = clap::ArgAction::SetTrue)]
        print_progress: bool,
    },
    /// Encrypts a plain text file using a Public Key
    Encrypt {
        /// Input file path.
        #[arg(short, long)]
        file_path: PathBuf,
        /// [OPTIONAL] Output file path (Defaults to cwd)
        #[arg(short, long)]
        out_path: Option<PathBuf>,
        /// [OPTIONAL] Path to Public Key (Defaults to `~/.config/rrsa/`)
        #[arg(short, long)]
        key_path: Option<PathBuf>,
    },
    /// Decrypts an encrypted file using a Private Key
    Decrypt {
        /// Input file path.
        #[arg(short, long)]
        file_path: PathBuf,
        /// [OPTIONAL] Output file path (Defaults to cwd)
        #[arg(short, long)]
        out_path: Option<PathBuf>,
        /// [OPTIONAL] Path to Private Key (Defaults to `~/.config/rrsa/`)
        #[arg(short, long)]
        key_path: Option<PathBuf>,
    },
}
