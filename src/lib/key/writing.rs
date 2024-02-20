use super::{Key, KeyVariant};
use crate::key::IsDefaultExponent;
use clap::crate_name;
use std::fmt;

impl Key {
    pub(super) const BIGUINT_STR_RADIX: u32 = 16;
    pub(super) const APP_CONFIG_DIR: &'static str = crate_name!();
    pub(super) const PUBLIC_KEY_FILE_EXTENSION: &'static str = "pub";
    pub(super) const DEFAULT_KEY_NAME: &'static str = "rrsa_key";
    /// Header for a Public Key with the default exponent.
    pub(super) const PUBLIC_KEY_NORMAL_HEADER: &'static str = "rrsa";
    /// Header for a Public Key with a non default exponent.
    pub(super) const PUBLIC_KEY_NDEX_HEADER: &'static str = "rrsa-ndex";
    pub(super) const PUBLIC_KEY_SPLIT_CHAR: char = ' ';
    pub(super) const PRIVATE_KEY_HEADER: &'static str = "-----BEGIN RSA-RUST PRIVATE KEY-----";
    pub(super) const PRIVATE_KEY_FOOTER: &'static str = "-----END RSA-RUST PRIVATE KEY-----";
    pub(super) const KEY_FILE_STR_RADIX_REGEX: &'static str = r"^[0-9a-f]+$";
    pub(super) const PRIVATE_KEY_SPLIT_CHAR: char = '\n';
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.variant {
            KeyVariant::PublicKey => {
                if self.exponent.is_default_exponent() {
                    writeln!(
                        f,
                        "{}{}{}",
                        Key::PUBLIC_KEY_NORMAL_HEADER,
                        Key::PUBLIC_KEY_SPLIT_CHAR,
                        self.modulus.to_str_radix(Key::BIGUINT_STR_RADIX)
                    )
                } else {
                    writeln!(
                        f,
                        "{}{}{}{}{}",
                        Key::PUBLIC_KEY_NDEX_HEADER,
                        Key::PUBLIC_KEY_SPLIT_CHAR,
                        &self.modulus.to_str_radix(Key::BIGUINT_STR_RADIX),
                        Key::PUBLIC_KEY_SPLIT_CHAR,
                        &self.exponent.to_str_radix(Key::BIGUINT_STR_RADIX)
                    )
                }
            }
            KeyVariant::PrivateKey => {
                writeln!(
                    f,
                    "{}{}{}{}{}{}{}",
                    Key::PRIVATE_KEY_HEADER,
                    Key::PRIVATE_KEY_SPLIT_CHAR,
                    self.modulus.to_str_radix(Key::BIGUINT_STR_RADIX),
                    Key::PRIVATE_KEY_SPLIT_CHAR,
                    self.exponent.to_str_radix(Key::BIGUINT_STR_RADIX),
                    Key::PRIVATE_KEY_SPLIT_CHAR,
                    Key::PRIVATE_KEY_FOOTER
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_public_key_writing() {
        let mut public_key = Key {
            exponent: BigUint::from(Key::DEFAULT_EXPONENT),
            modulus: BigUint::from(0x9668_f701_u64),
            variant: KeyVariant::PublicKey,
        };
        assert_eq!("rrsa 9668f701\n", public_key.to_string());

        public_key = Key {
            exponent: BigUint::from(0x5b97_u64),
            modulus: BigUint::from(0x11c6_8c75_u64),
            variant: KeyVariant::PublicKey,
        };
        assert_eq!("rrsa-ndex 11c68c75 5b97\n", public_key.to_string());
    }

    #[test]
    fn test_private_key_writing() {
        let mut private_key = Key {
            exponent: BigUint::from(0x147B_7F71_u64),
            modulus: BigUint::from(0x9668_F701_u64),
            variant: KeyVariant::PrivateKey,
        };
        assert_eq!(
            r"-----BEGIN RSA-RUST PRIVATE KEY-----
9668f701
147b7f71
-----END RSA-RUST PRIVATE KEY-----
",
            private_key.to_string()
        );

        private_key = Key {
            exponent: BigUint::from(0x037A_21E7_u64),
            modulus: BigUint::from(0x11C6_8C75_u64),
            variant: KeyVariant::PrivateKey,
        };
        assert_eq!(
            r"-----BEGIN RSA-RUST PRIVATE KEY-----
11c68c75
37a21e7
-----END RSA-RUST PRIVATE KEY-----
",
            private_key.to_string()
        );
    }
}
