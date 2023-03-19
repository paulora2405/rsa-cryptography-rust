use clap::{Parser, Subcommand};
use rsa_rs::{
    encryption::{decrypt_file, encrypt_file},
    key_generator::KeyPair,
};

fn main() {
    match RsaCli::parse().sub_command {
        RsaCommands::Keygen {
            key_size,
            out_path,
            use_ndex,
            print_results,
            print_progress,
        } => {
            let key_pair =
                KeyPair::generate_keys(key_size, !use_ndex, print_results, print_progress);
            KeyPair::write_key_files(&out_path, &key_pair);
        }
        RsaCommands::Encrypt {
            file_path,
            out_path,
            key_path,
        } => {
            let key = KeyPair::read_key_files(&key_path);
            encrypt_file(&file_path, &out_path, &key.pub_key);
        }
        RsaCommands::Decrypt {
            file_path,
            out_path,
            key_path,
        } => {
            let key = KeyPair::read_key_files(&key_path);
            decrypt_file(&file_path, &out_path, &key.priv_key);
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
        /// Key size in bits (Min=32; Max=4096)
        #[arg(short, long)]
        key_size: u16,
        /// Path to save key file (Ex: ./keys/key)
        #[arg(short, long)]
        out_path: String,
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
        file_path: String,
        /// Output file path
        #[arg(short, long)]
        out_path: String,
        /// Path to Public Key (ommit the `.pub`)
        #[arg(short, long)]
        key_path: String,
    },
    /// Decrypts an encrypted file using a Private Key
    Decrypt {
        /// Input file path.
        #[arg(short, long)]
        file_path: String,
        /// Output file path
        #[arg(short, long)]
        out_path: String,
        /// Path to Private Key
        #[arg(short, long)]
        key_path: String,
    },
}
