use crate::error::RsaResult;
use crate::key::{Key, KeyPair, KeyVariant};
use std::{
    fs::create_dir_all,
    path::{Path, PathBuf},
};

impl KeyPair {
    /// Writes this [`KeyPair`] to a file or dir path.
    ///
    /// If it is a directory, it must have already been created.
    /// The Public Key will have the extension added automatically.
    ///
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
    ///
    /// # Errors
    /// Propagates [`std::io::Error`].
    pub fn write_to_default(&self) -> RsaResult<()> {
        self.public_key.write_to_default()?;
        self.private_key.write_to_default()?;
        Ok(())
    }
}

impl Key {
    /// Writes this [`Key`] to a filepath of an existing/to-be-created file,
    /// or the path to a existing directory.
    ///
    /// If it is a directory, the default key names
    /// [`Key::DEFAULT_PRIVATE_KEY_NAME`] or
    /// [`Key::DEFAULT_PUBLIC_KEY_NAME`] are used.
    ///
    /// # Returns
    /// The final filepath written to.
    ///
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
    ///
    /// # Returns
    /// The final filepath written to.
    ///
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
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::key::{
        file::tests::{KEY_DIR_PATH, PAIR_DIR_PATH, PAIR_KEY_PATH, PRIV_KEY_PATH, PUB_KEY_PATH},
        tests::test_pair,
    };
    use std::path::PathBuf;

    #[test]
    pub(crate) fn test_write_key_to_file() {
        let pub_path = PathBuf::from(PUB_KEY_PATH);
        let priv_path = PathBuf::from(PRIV_KEY_PATH);
        let dir_path = PathBuf::from(KEY_DIR_PATH);
        create_dir_all(&dir_path).unwrap();

        test_pair().public_key.write_to_path(&pub_path).unwrap();
        assert!(pub_path.is_file());

        test_pair().public_key.write_to_path(&dir_path).unwrap();
        assert!(dir_path.join(Key::DEFAULT_PUBLIC_KEY_NAME).is_file());

        test_pair().private_key.write_to_path(&dir_path).unwrap();
        assert!(dir_path.join(Key::DEFAULT_PRIVATE_KEY_NAME).is_file());

        test_pair().private_key.write_to_path(&priv_path).unwrap();
        assert!(priv_path.is_file());
    }

    #[test]
    pub(crate) fn test_write_key_pair_to_file() {
        let file_path = PathBuf::from(PAIR_KEY_PATH);
        let dir_path = PathBuf::from(PAIR_DIR_PATH);
        create_dir_all(&dir_path).unwrap();

        test_pair().write_to_path(&dir_path).unwrap();
        assert!(dir_path.join(Key::DEFAULT_PUBLIC_KEY_NAME).is_file());
        assert!(dir_path.join(Key::DEFAULT_PRIVATE_KEY_NAME).is_file());

        test_pair().write_to_path(&file_path).unwrap();
        assert!(file_path.is_file());
        assert!(file_path
            .with_extension(Key::DEFAULT_PUBLIC_KEY_EXTENSION)
            .is_file());
    }

    #[test]
    pub(crate) fn test_write_key_pair_to_default() {
        test_pair().write_to_default().unwrap();
        assert!(Key::default_dir().is_dir());
        assert!(Key::default_dir()
            .join(Key::DEFAULT_PUBLIC_KEY_NAME)
            .is_file());
        assert!(Key::default_dir()
            .join(Key::DEFAULT_PRIVATE_KEY_NAME)
            .is_file());
    }
}
