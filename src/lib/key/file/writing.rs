use crate::error::RsaResult;
use crate::key::{Key, KeyPair, KeyVariant};
use clap::crate_name;
use directories::ProjectDirs;
use std::{
    fs::{create_dir_all, File},
    io::Write,
    path::{Path, PathBuf},
};

impl KeyPair {
    /// Writes this [`KeyPair`] to a file or dir path,
    /// if it is a directory, it must have already been created.
    /// The Public Key will have the extension added automatically.
    /// # Errors
    /// Propagates [`std::io::Error`].
    pub fn write_to_path(&self, path: &Path) -> RsaResult<()> {
        if path.is_dir() {
            self.public_key.write_to_path(path)?;
            self.private_key.write_to_path(path)?;
        } else {
            self.public_key
                .write_to_path(&path.with_extension(Key::DEFAULT_PUBLIC_KEY_EXTENSION))?;
            self.private_key.write_to_path(path)?;
        }

        Ok(())
    }

    /// Writes this [`KeyPair`] to the default keys directory,
    /// or `cwd` if default keys directory cannot be created or accessed.
    /// # Errors
    /// Propagates [`std::io::Error`].
    pub fn write_to_default(&self) -> RsaResult<()> {
        self.public_key.write_to_default()?;
        self.private_key.write_to_default()?;
        Ok(())
    }
}

impl Key {
    pub(super) const APP_CONFIG_DIR: &'static str = crate_name!();
    pub const DEFAULT_PUBLIC_KEY_EXTENSION: &'static str = "pub";
    pub const DEFAULT_PUBLIC_KEY_NAME: &'static str = "rrsa_key.pub";
    pub const DEFAULT_PRIVATE_KEY_NAME: &'static str = "rrsa_key";

    /// Writes this [`Key`] to a filepath of an existing/to-be-created file,
    /// or the path to a existing directory.
    /// # Returns
    /// The final filepath written to.
    /// # Errors
    /// Propagates [`std::io::Error`].
    pub fn write_to_path(&self, path: &Path) -> RsaResult<PathBuf> {
        let filepath = if path.is_dir() {
            if self.variant == KeyVariant::PublicKey {
                path.join(Key::DEFAULT_PUBLIC_KEY_NAME)
            } else {
                path.join(Key::DEFAULT_PRIVATE_KEY_NAME)
            }
        } else {
            let parent = path.parent().unwrap_or(Path::new(""));
            create_dir_all(parent)?;
            path.to_path_buf()
        };

        std::fs::write(&filepath, self.to_string())?;
        Ok(filepath)
    }

    /// Writes this [`Key`] to the default keys directory,
    /// or `cwd` if default keys directory cannot be created or accessed.
    /// # Returns
    /// The final filepath written to.
    /// # Errors
    /// Propagates [`std::io::Error`].
    pub fn write_to_default(&self) -> RsaResult<PathBuf> {
        self.write_to_path(
            &(if self.variant == KeyVariant::PublicKey {
                Key::default_dir().join(Key::DEFAULT_PUBLIC_KEY_NAME)
            } else {
                Key::default_dir().join(Key::DEFAULT_PRIVATE_KEY_NAME)
            }),
        )
    }

    /// Returns the default keys directory, or `cwd` if it cannot be retrived.
    fn default_dir() -> PathBuf {
        if let Some(project_dirs) = ProjectDirs::from("com", "github", Key::APP_CONFIG_DIR) {
            let default_dir = project_dirs.config_dir();
            if create_dir_all(default_dir).is_ok() {
                return default_dir.to_path_buf();
            }
        }
        PathBuf::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KeyVariant;
    use num_bigint::BigUint;
    use std::path::PathBuf;

    #[test]
    fn test_write_key_to_file() {
        let public_key = Key {
            exponent: BigUint::from(0x1_0001u32), // default exponent
            modulus: BigUint::from(0x9668_F701u64),
            variant: KeyVariant::PublicKey,
        };
        let private_key = Key {
            exponent: BigUint::from(0x147B_7F71u32),
            modulus: BigUint::from(0x9668_F701u64),
            variant: KeyVariant::PrivateKey,
        };

        let pub_path = PathBuf::from("./keys/tests/test_key.pub");
        let priv_path = PathBuf::from("./keys/tests/test_key");
        let dir_path = PathBuf::from("./keys/tests/key/");
        create_dir_all(&dir_path).unwrap();

        public_key.write_to_path(&pub_path).unwrap();
        assert!(pub_path.is_file());

        public_key.write_to_path(&dir_path).unwrap();
        assert!(dir_path.join(Key::DEFAULT_PUBLIC_KEY_NAME).is_file());

        private_key.write_to_path(&dir_path).unwrap();
        assert!(dir_path.join(Key::DEFAULT_PRIVATE_KEY_NAME).is_file());

        private_key.write_to_path(&priv_path).unwrap();
        assert!(priv_path.is_file());
    }

    #[test]
    fn test_write_key_pair_to_file() {
        let pair = KeyPair {
            public_key: Key {
                exponent: BigUint::from(0x1_0001u32), // default exponent
                modulus: BigUint::from(0x9668_F701u64),
                variant: KeyVariant::PublicKey,
            },
            private_key: Key {
                exponent: BigUint::from(0x147B_7F71u32),
                modulus: BigUint::from(0x9668_F701u64),
                variant: KeyVariant::PrivateKey,
            },
        };

        let file_path = PathBuf::from("./keys/tests/test_pair");
        let dir_path = PathBuf::from("./keys/tests/pair");
        create_dir_all(&dir_path).unwrap();

        pair.write_to_path(&dir_path).unwrap();
        assert!(dir_path.join(Key::DEFAULT_PUBLIC_KEY_NAME).is_file());
        assert!(dir_path.join(Key::DEFAULT_PRIVATE_KEY_NAME).is_file());

        pair.write_to_path(&file_path).unwrap();
        assert!(file_path.is_file());
        assert!(file_path
            .with_extension(Key::DEFAULT_PUBLIC_KEY_EXTENSION)
            .is_file());
    }
}
