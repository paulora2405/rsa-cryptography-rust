use std::{fs::create_dir_all, path::PathBuf};

use clap::crate_name;
use directories::ProjectDirs;

use super::Key;

mod reading;
mod writing;

impl Key {
    pub(super) const DEFAULT_DIR: &'static str = crate_name!();
    pub const DEFAULT_PUBLIC_KEY_EXTENSION: &'static str = "pub";
    pub const DEFAULT_PUBLIC_KEY_NAME: &'static str = "rrsa_key.pub";
    pub const DEFAULT_PRIVATE_KEY_NAME: &'static str = "rrsa_key";

    /// Returns the default keys directory, or `cwd` if it cannot be retrived.
    ///
    /// This directory is plataform specific.
    ///
    /// On Linux this is: `$XDG_CONFIG_HOME/rrsa/`
    ///
    /// On macOS this is: `$HOME/Library/Application Support/rrsa/`
    ///
    /// On Windows this is: `{FOLDERID_RoamingAppData}\rrsa\config`
    ///
    /// See the documentation of [`ProjectDirs::config_dir()`] for more information.
    #[must_use]
    pub fn default_dir() -> PathBuf {
        if let Some(project_dirs) = ProjectDirs::from("", "", Key::DEFAULT_DIR) {
            let default_dir = project_dirs.config_dir();
            if create_dir_all(default_dir).is_ok() {
                return default_dir.to_path_buf();
            }
        }
        PathBuf::new()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    pub(crate) const PUB_KEY_PATH: &str = "./keys/tests/test_key.pub";
    pub(crate) const PRIV_KEY_PATH: &str = "./keys/tests/test_key";
    pub(crate) const KEY_DIR_PATH: &str = "./keys/tests/key/";
    pub(crate) const PAIR_KEY_PATH: &str = "./keys/tests/test_pair";
    pub(crate) const PAIR_DIR_PATH: &str = "./keys/tests/pair";
}
