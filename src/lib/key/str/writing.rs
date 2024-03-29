use crate::key::{IsDefaultExponent, Key, KeyVariant};
use std::fmt;

impl Key {
    pub(crate) const BIGUINT_STR_RADIX: u32 = 16;
    pub(crate) const KEY_FILE_STR_RADIX_REGEX: &'static str = r"^[0-9a-f]+$";
    /// Header for a Public Key with the default exponent.
    pub(crate) const PUBLIC_KEY_NORMAL_HEADER: &'static str = "rrsa";
    /// Header for a Public Key with a non default exponent.
    pub(crate) const PUBLIC_KEY_NDEX_HEADER: &'static str = "rrsa-ndex";
    pub(crate) const PUBLIC_KEY_SPLIT_CHAR: char = ' ';
    pub(crate) const PRIVATE_KEY_HEADER: &'static str = "-----BEGIN RSA-RUST PRIVATE KEY-----";
    pub(crate) const PRIVATE_KEY_FOOTER: &'static str = "-----END RSA-RUST PRIVATE KEY-----";
    pub(crate) const PRIVATE_KEY_SPLIT_CHAR: char = '\n';
}

impl fmt::Display for Key {
    /// Formats the given [`Key`] as a string,
    /// which can represent the file content of it.
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
    use super::*;
    use crate::key::tests::test_pair;
    use num_bigint::BigUint;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_public_key_writing() {
        assert_eq!("rrsa 9668f701\n", test_pair().public_key.to_string());

        let public_ndex_key = Key {
            exponent: BigUint::from(0x5b97_u64),
            modulus: BigUint::from(0x11c6_8c75_u64),
            variant: KeyVariant::PublicKey,
        };
        assert_eq!("rrsa-ndex 11c68c75 5b97\n", public_ndex_key.to_string());
    }

    #[test]
    fn test_private_key_writing() {
        assert_eq!(
            r"-----BEGIN RSA-RUST PRIVATE KEY-----
9668f701
147b7f71
-----END RSA-RUST PRIVATE KEY-----
",
            test_pair().private_key.to_string()
        );
    }
}
