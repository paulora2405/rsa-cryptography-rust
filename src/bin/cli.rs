use clap::{Args, Parser, Subcommand};
use rrsa_lib::{
    error::{RsaError, RsaResult},
    key::{Key, KeyPair},
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
            ndex,
            results,
            progress,
        } => {
            let key_pair = KeyPair::generate(key_size, !ndex, results, progress);

            match out_path {
                Some(path) => key_pair.write_to_path(&path)?,
                None => key_pair.write_to_default()?,
            };
        }
        RsaCommands::Validate { args } => {
            let public_key_path = args.public_key_path;
            let private_key_path = args.private_key_path;
            match (public_key_path, private_key_path) {
                (None, Some(priv_path)) => {
                    if !Key::read_from_path(&priv_path)?.is_private() {
                        return Err(RsaError::UnknownError(
                            "Private Key is actually a Public Key".into(),
                        ));
                    }
                    println!("Private Key is valid!");
                }
                (Some(pub_path), None) => {
                    if !Key::read_from_path(&pub_path)?.is_public() {
                        return Err(RsaError::UnknownError(
                            "Public Key is actually a Private Key".into(),
                        ));
                    }
                    println!("Public Key is valid!");
                }
                (Some(pub_path), Some(priv_path)) => {
                    let pair = KeyPair {
                        public_key: Key::read_from_path(&pub_path)?,
                        private_key: Key::read_from_path(&priv_path)?,
                    };
                    if pair.is_valid() {
                        println!("Key Pair is valid!");
                    } else {
                        return Err(RsaError::UnknownError("Key Pair is not valid!".into()));
                    }
                }
                _ => {}
            };
        }
        RsaCommands::Encrypt {
            in_path,
            out_path,
            key_path,
        } => {
            dbg!(in_path, out_path, key_path);
        }
        RsaCommands::Decrypt {
            in_path,
            out_path,
            key_path,
        } => {
            dbg!(in_path, out_path, key_path);
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
        #[arg(short, long, value_parser = clap::value_parser!(u16).range(32..=4096))]
        key_size: Option<u16>,
        /// OPTIONAL Path to save key file (Ex: ./keys/key or ./keys/, defaults to `~/.config/rrsa/`),
        /// directories must be pre-existing.
        #[arg(short, long, value_name = "PATH")]
        out_path: Option<PathBuf>,
        /// OPTIONAL Generates a key with non default exponent value (False if absent)
        #[arg(short, long, action = clap::ArgAction::SetTrue)]
        ndex: bool,
        /// OPTIONAL Prints the key generation internal results (False if absent)
        #[arg(short, long, action = clap::ArgAction::SetTrue)]
        results: bool,
        /// OPTIONAL Prints the progress of the key generation (False if absent)
        #[arg(short, long, action = clap::ArgAction::SetTrue)]
        progress: bool,
    },
    /// Validates a Key format (at least one of the Keys must be present)
    /// and/or validates that two Keys are is mathematically
    /// related (both Public and Private key must be present)
    Validate {
        #[command(flatten)]
        args: ValidateArgs,
    },
    /// Encrypts a plain text file using a Public Key
    Encrypt {
        /// Input file path.
        #[arg(short, long, value_name = "PATH")]
        in_path: PathBuf,
        /// OPTIONAL Output file path (Defaults to cwd)
        #[arg(short, long, value_name = "PATH")]
        out_path: Option<PathBuf>,
        /// OPTIONAL Path to Public Key (Defaults to `~/.config/rrsa/`)
        #[arg(short, long, value_name = "PATH")]
        key_path: Option<PathBuf>,
    },
    /// Decrypts an encrypted file using a Private Key
    Decrypt {
        /// Input file path.
        #[arg(short, long, value_name = "PATH")]
        in_path: PathBuf,
        /// OPTIONAL Output file path (Defaults to cwd)
        #[arg(short, long, value_name = "PATH")]
        out_path: Option<PathBuf>,
        /// OPTIONAL Path to Private Key (Defaults to `~/.config/rrsa/`)
        #[arg(short, long, value_name = "PATH")]
        key_path: Option<PathBuf>,
    },
}

#[derive(Args)]
#[group(required = true, multiple = true)]
struct ValidateArgs {
    /// Path to a Public Key.
    #[arg(short, long, value_name = "PATH")]
    public_key_path: Option<PathBuf>,
    /// Path to a Private Key.
    #[arg(short = 'k', long, value_name = "PATH")]
    private_key_path: Option<PathBuf>,
}
