use crate::{
    error::{RsaError, RsaResult},
    key::{Key, KeyPair},
};
use std::{fs::read_to_string, path::Path, str::FromStr};

impl KeyPair {
    /// Reads a [`KeyPair`] from two files or a directory path.
    ///
    /// If it two files, they must have identical names,
    /// other than that the public key file must have
    /// the default extension [`Key::DEFAULT_PUBLIC_KEY_EXTENSION`].
    /// Example: To read `my_key` and `my_key.pub` files,
    /// one would pass `my_key` as a path parameter to this function.
    ///
    /// If it is a directory, the default key names
    /// [`Key::DEFAULT_PRIVATE_KEY_NAME`] and
    /// [`Key::DEFAULT_PUBLIC_KEY_NAME`] are used.
    ///
    /// # Errors
    /// Propagates [`std::io::Error`].
    pub fn read_from_path(path: &Path) -> RsaResult<Self> {
        let pub_path;
        let priv_path;

        if path.is_dir() {
            pub_path = path.join(Key::DEFAULT_PUBLIC_KEY_NAME);
            priv_path = path.join(Key::DEFAULT_PRIVATE_KEY_NAME);
        } else {
            pub_path = path.with_extension(Key::DEFAULT_PUBLIC_KEY_EXTENSION);
            priv_path = path.to_path_buf();
        }
        if !(pub_path.is_file() && priv_path.is_file()) {
            return Err(RsaError::MissingKeyFromDirError);
        }

        Ok(KeyPair {
            public_key: Key::read_from_path(&pub_path)?,
            private_key: Key::read_from_path(&priv_path)?,
        })
    }

    /// Reads a [`KeyPair`] from the default directory.
    ///
    /// The default key names
    /// [`Key::DEFAULT_PRIVATE_KEY_NAME`] and
    /// [`Key::DEFAULT_PUBLIC_KEY_NAME`] are used.
    ///
    /// # Errors
    /// Propagates [`std::io::Error`].
    pub fn read_from_default() -> RsaResult<Self> {
        KeyPair::read_from_path(&Key::default_dir())
    }
}

impl Key {
    /// Reads a [`Key`] from a file or dir path.
    ///
    /// If it is a directory, the default key names
    /// [`Key::DEFAULT_PRIVATE_KEY_NAME`] or
    /// [`Key::DEFAULT_PUBLIC_KEY_NAME`] are used,
    /// in this order of priority.
    ///
    /// # Errors
    /// Propagates [`std::io::Error`].
    pub fn read_from_path(path: &Path) -> RsaResult<Self> {
        if path.is_dir() {
            if path.join(Key::DEFAULT_PRIVATE_KEY_NAME).is_file() {
                Key::from_str(&read_to_string(path.join(Key::DEFAULT_PRIVATE_KEY_NAME))?)
            } else if path.join(Key::DEFAULT_PUBLIC_KEY_NAME).is_file() {
                Key::from_str(&read_to_string(path.join(Key::DEFAULT_PUBLIC_KEY_NAME))?)
            } else {
                Err(RsaError::MissingKeyFromDirError)
            }
        } else {
            Key::from_str(&read_to_string(path)?)
        }
    }

    /// Reads a [`Key`] from default directory.
    ///
    /// The default key names
    /// [`Key::DEFAULT_PRIVATE_KEY_NAME`] or
    /// [`Key::DEFAULT_PUBLIC_KEY_NAME`] are used,
    /// in this order of priority.
    ///
    /// # Errors
    /// Propagates [`std::io::Error`].
    pub fn read_from_default() -> RsaResult<Self> {
        Key::read_from_path(&Key::default_dir())
    }
}

#[cfg(test)]
mod tests {
    use super::{super::writing::tests::test_write_key_to_file, *};
    use crate::key::{
        file::{
            tests::{KEY_DIR_PATH, PAIR_DIR_PATH, PAIR_KEY_PATH, PRIV_KEY_PATH, PUB_KEY_PATH},
            writing::tests::{test_write_key_pair_to_default, test_write_key_pair_to_file},
        },
        tests::test_pair,
    };
    use std::path::PathBuf;

    #[test]
    fn test_read_key_from_file() {
        let pub_path = PathBuf::from(PUB_KEY_PATH);
        let priv_path = PathBuf::from(PRIV_KEY_PATH);
        let dir_path = PathBuf::from(KEY_DIR_PATH);
        test_write_key_to_file();

        let key = Key::read_from_path(&pub_path).unwrap();
        assert_eq!(key, test_pair().public_key);

        let key = Key::read_from_path(&priv_path).unwrap();
        assert_eq!(key, test_pair().private_key);

        // reads the private key
        let key = Key::read_from_path(&dir_path).unwrap();
        assert_eq!(key, test_pair().private_key);
    }

    #[test]
    fn test_read_key_pair_to_file() {
        let file_path = PathBuf::from(PAIR_KEY_PATH);
        let dir_path = PathBuf::from(PAIR_DIR_PATH);
        test_write_key_pair_to_file();

        let pair = KeyPair::read_from_path(&file_path).unwrap();
        assert_eq!(pair, *test_pair());
        let pair = KeyPair::read_from_path(&dir_path).unwrap();
        assert_eq!(pair, *test_pair());
    }

    #[test]
    fn test_read_key_pair_to_default() {
        test_write_key_pair_to_default();

        let pair = KeyPair::read_from_default().unwrap();
        assert_eq!(pair, *test_pair());
    }
}
