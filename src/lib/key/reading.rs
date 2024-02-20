use super::{Key, KeyVariant};
use crate::error::{RsaError, RsaResult};
use num_bigint::BigUint;
use num_traits::Num;
use regex::Regex;
use std::str::FromStr;

impl FromStr for Key {
    type Err = RsaError;

    /// Extracts a [`Key`] from the given string slice,
    /// that represented the file content of it.
    fn from_str(s: &str) -> RsaResult<Self> {
        if s.starts_with(Key::PUBLIC_KEY_NDEX_HEADER) {
            Key::public_ndex_key_from_str(s)
        } else if s.starts_with(Key::PUBLIC_KEY_NORMAL_HEADER) {
            Key::public_dex_key_from_str(s)
        } else if s.starts_with(Key::PRIVATE_KEY_HEADER) {
            Key::private_key_from_str(s)
        } else {
            Err(RsaError::ImproperlyFormattedStr(
                "because it did not start with a correct header".into(),
            ))
        }
    }
}

impl Key {
    fn public_ndex_key_from_str(s: &str) -> RsaResult<Self> {
        let reg = Regex::new(Key::KEY_FILE_STR_RADIX_REGEX).unwrap();
        let pieces: Vec<_> = s.split(Key::PUBLIC_KEY_SPLIT_CHAR).collect();

        // example: "rrsa-ndex 11c68c75 5b97\n"
        if pieces.len() != 3 {
            return Err(RsaError::ImproperlyFormattedStr(
                "because it had the wrong number of pieces for a public ndex key".into(),
            ));
        }
        if !reg.is_match(pieces[1].trim()) || !reg.is_match(pieces[2].trim()) {
            return Err(RsaError::ImproperlyFormattedStr(
                "because the exponent and/or modulus values had invalid characters".into(),
            ));
        }

        Ok(Key {
            exponent: BigUint::from_str_radix(pieces[2].trim(), Key::BIGUINT_STR_RADIX)?,
            modulus: BigUint::from_str_radix(pieces[1].trim(), Key::BIGUINT_STR_RADIX)?,
            variant: KeyVariant::PublicKey,
        })
    }

    fn public_dex_key_from_str(s: &str) -> RsaResult<Self> {
        let reg = Regex::new(Key::KEY_FILE_STR_RADIX_REGEX).unwrap();
        let pieces: Vec<_> = s.split(Key::PUBLIC_KEY_SPLIT_CHAR).collect();

        // example: "rrsa 9668f701\n"
        if pieces.len() != 2 {
            return Err(RsaError::ImproperlyFormattedStr(
                "because it had the wrong number of pieces for a public key".into(),
            ));
        }
        if !reg.is_match(pieces[1].trim()) {
            return Err(RsaError::ImproperlyFormattedStr(
                "because the modulus values had invalid characters".into(),
            ));
        }

        Ok(Key {
            exponent: BigUint::from(Key::DEFAULT_EXPONENT),
            modulus: BigUint::from_str_radix(pieces[1].trim(), Key::BIGUINT_STR_RADIX)?,
            variant: KeyVariant::PublicKey,
        })
    }

    fn private_key_from_str(s: &str) -> RsaResult<Self> {
        let reg = Regex::new(Key::KEY_FILE_STR_RADIX_REGEX).unwrap();
        let pieces: Vec<_> = s.split(Key::PRIVATE_KEY_SPLIT_CHAR).collect();

        // example: r"
        // -----BEGIN RSA-RUST PRIVATE KEY-----
        // 9668f701
        // 147b7f71
        // -----END RSA-RUST PRIVATE KEY-----
        // "
        if pieces.len() != 5 {
            return Err(RsaError::ImproperlyFormattedStr(
                "because it had the wrong number of pieces for a private key".into(),
            ));
        }
        if pieces[0] != Key::PRIVATE_KEY_HEADER || pieces[3] != Key::PRIVATE_KEY_FOOTER {
            return Err(RsaError::ImproperlyFormattedStr(
                "because it didn't have correct header and/or footer for a private key".into(),
            ));
        }
        if !reg.is_match(pieces[1].trim()) || !reg.is_match(pieces[2].trim()) {
            return Err(RsaError::ImproperlyFormattedStr(
                "because the exponent and/or modulus values had invalid characters".into(),
            ));
        }

        Ok(Key {
            exponent: BigUint::from_str_radix(pieces[2].trim(), Key::BIGUINT_STR_RADIX)?,
            modulus: BigUint::from_str_radix(pieces[1].trim(), Key::BIGUINT_STR_RADIX)?,
            variant: KeyVariant::PrivateKey,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_from_str_error() {
        // invalid header
        let key_str = "not-a-header\n";
        assert!(Key::from_str(key_str).is_err());

        // wrong qnt of pieces
        let key_str = "rrsa-ndex 23424 14143 55345\n";
        assert!(Key::from_str(key_str).is_err());

        // invalid char
        let key_str = "rrsa-ndex 2342g4 14143\n";
        assert!(Key::from_str(key_str).is_err());

        // invalid char
        let key_str = "rrsa-ndex 23424 14h143\n";
        assert!(Key::from_str(key_str).is_err());

        // wrong qnt of pieces
        let key_str = "rrsa 23424 14143\n";
        assert!(Key::from_str(key_str).is_err());

        // invalid char
        let key_str = "rrsa 2342p4\n";
        assert!(Key::from_str(key_str).is_err());

        // wrong qnt of pieces
        let key_str = r"-----BEGIN RSA-RUST PRIVATE KEY-----
147b7f71
-----END RSA-RUST PRIVATE KEY-----
";
        assert!(Key::from_str(key_str).is_err());

        // invalid char
        let key_str = r"-----BEGIN RSA-RUST PRIVATE KEY-----
9668f701h
147b7f71
-----END RSA-RUST PRIVATE KEY-----
";
        assert!(Key::from_str(key_str).is_err());

        // correct public ndex
        let key_str = "rrsa-ndex 23424 14143\n";
        assert!(Key::from_str(key_str).is_ok());

        // correct public dex
        let key_str = "rrsa 23424\n";
        assert!(Key::from_str(key_str).is_ok());

        // correct private
        let key_str = r"-----BEGIN RSA-RUST PRIVATE KEY-----
9668f701
147b7f71
-----END RSA-RUST PRIVATE KEY-----
";
        assert!(Key::from_str(key_str).is_ok());
    }
}
