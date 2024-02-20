use num_bigint::ParseBigIntError;
use thiserror::Error;

/// Type alias for [`RSAError`] type.
pub type RSAResult<T> = std::result::Result<T, RsaError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RsaError {
    #[error("could not encode/decoding correctly")]
    EncodingError,
    #[error("the string was not a properly formatted key {0}")]
    ImproperlyFormattedStr(String),
    #[error("error while creating big int from string: {0}")]
    BigIntError(
        #[from]
        #[source]
        ParseBigIntError,
    ),
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use num_traits::Num;

    use super::RsaError;

    #[test]
    #[ignore = "not a real test"]
    fn test_big_int_error() {
        let err = RsaError::BigIntError(BigUint::from_str_radix("abcdefg", 16).unwrap_err());
        eprintln!("{err}");
    }
}
