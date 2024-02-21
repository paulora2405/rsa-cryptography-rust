use crate::{
    error::{RsaError, RsaResult},
    key::{Key, KeyPair},
};
use std::{fs::read_to_string, path::Path, str::FromStr};

impl KeyPair {}

impl Key {
    /// Reads a [`Key`] from a file or dir path,
    /// if it is a directory, the default key names
    /// [`Key::DEFAULT_PRIVATE_KEY_NAME`] or
    /// [`Key::DEFAULT_PUBLIC_KEY_NAME`] are used,
    /// in this order of priority.
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

    /// Reads a [`Key`] from default directory,
    /// the default key names
    /// [`Key::DEFAULT_PRIVATE_KEY_NAME`] or
    /// [`Key::DEFAULT_PUBLIC_KEY_NAME`] are used,
    /// in this order of priority.
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
        file::tests::{KEY_DIR_PATH, PRIV_KEY_PATH, PUB_KEY_PATH},
        tests::pair,
    };
    use std::path::PathBuf;

    #[test]
    fn test_read_key_from_file() {
        let pub_path = PathBuf::from(PUB_KEY_PATH);
        let priv_path = PathBuf::from(PRIV_KEY_PATH);
        let dir_path = PathBuf::from(KEY_DIR_PATH);
        test_write_key_to_file();

        let key = Key::read_from_path(&pub_path).unwrap();
        assert_eq!(key, pair().public_key);

        let key = Key::read_from_path(&priv_path).unwrap();
        assert_eq!(key, pair().private_key);

        // reads the private key
        let key = Key::read_from_path(&dir_path).unwrap();
        assert_eq!(key, pair().private_key);
    }

    #[test]
    fn test_read_key_pair_to_file() {
        todo!()
    }

    #[test]
    fn test_read_key_pair_to_default() {
        todo!()
    }
}
