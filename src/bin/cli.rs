use clap::{Parser, Subcommand};
use rrsa_lib::{
    error::{RsaError, RsaResult},
    key::KeyPair,
};
use std::path::PathBuf;

fn main() -> Result<(), String> {
    run_cli().map_err(|e| e.to_string())
}

fn run_cli() -> RsaResult<()> {
    match RsaCli::parse().sub_command {
        RsaCommands::Keygen {
            key_size,
            out_path,
            use_ndex,
            print_results,
            print_progress,
        } => {
            let key_pair = KeyPair::generate(key_size, !use_ndex, print_results, print_progress);

            match out_path {
                Some(path) => key_pair.write_to_path(&path)?,
                None => key_pair.write_to_default()?,
            };
        }
        RsaCommands::Validate {
            path_pub,
            path_priv,
        } => {
            if path_pub.is_none() && path_priv.is_none() {
                return Err(RsaError::UnknownError(
                    "neither Public nor Private Key were present, at least one is needed".into(),
                ));
            }
            todo!()
        }
        RsaCommands::Encrypt {
            file_path,
            out_path,
            key_path,
        } => {
            // let key = Key::read_key_file(maybe_key_path, KeyVariant::PublicKey)?;
            // key.encrypt_file(file_path, maybe_out_path);
        }
        RsaCommands::Decrypt {
            file_path,
            out_path,
            key_path,
        } => {
            // let key = Key::read_key_file(maybe_key_path, KeyVariant::PrivateKey)?;
            // key.decrypt_file(file_path, maybe_out_path);
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

#[deny(missing_docs)]
#[derive(Subcommand)]
enum RsaCommands {
    /// Generates a Public and a Private key, and stores then in output file
    Keygen {
        /// OPTIONAL Key size in bits (defaults to 4096, must be in (32..=4096))
        #[arg(short, long)]
        key_size: Option<u16>,
        /// OPTIONAL Path to save key file (Ex: ./keys/key or ./keys/, defaults to `~/.config/rrsa/`)
        #[arg(short, long)]
        out_path: Option<PathBuf>,
        /// OPTIONAL Generates a key with non default exponent value (False if absent)
        #[arg(short, long, action = clap::ArgAction::SetTrue)]
        use_ndex: bool,
        /// OPTIONAL Prints the key generation internal results (False if absent)
        #[arg(short = 'r', long, action = clap::ArgAction::SetTrue)]
        print_results: bool,
        /// OPTIONAL Prints the progress of the key generation (False if absent)
        #[arg(short, long, action = clap::ArgAction::SetTrue)]
        print_progress: bool,
    },
    /// Validates a Key format (at least one of the Keys must be present) and/or
    /// validates that two Keys are is mathematically
    /// related (both Public and Private key must be present)
    Validate {
        /// OPTIONAL Path to a Public Key.
        #[arg(short, long)]
        path_pub: Option<PathBuf>,
        /// OPTIONAL Path to a Private Key.
        #[arg(short, long)]
        path_priv: Option<PathBuf>,
    },
    /// Encrypts a plain text file using a Public Key
    Encrypt {
        /// Input file path.
        #[arg(short, long)]
        file_path: PathBuf,
        /// OPTIONAL Output file path (Defaults to cwd)
        #[arg(short, long)]
        out_path: Option<PathBuf>,
        /// OPTIONAL Path to Public Key (Defaults to `~/.config/rrsa/`)
        #[arg(short, long)]
        key_path: Option<PathBuf>,
    },
    /// Decrypts an encrypted file using a Private Key
    Decrypt {
        /// Input file path.
        #[arg(short, long)]
        file_path: PathBuf,
        /// OPTIONAL Output file path (Defaults to cwd)
        #[arg(short, long)]
        out_path: Option<PathBuf>,
        /// OPTIONAL Path to Private Key (Defaults to `~/.config/rrsa/`)
        #[arg(short, long)]
        key_path: Option<PathBuf>,
    },
}
