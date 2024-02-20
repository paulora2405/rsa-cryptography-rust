//! This module contains the custom error type for this library.

use num_bigint::ParseBigIntError;
use thiserror::Error;

/// Type alias for [`RsaError`] type.
pub type RsaResult<T> = std::result::Result<T, RsaError>;

/// Custom library error.
#[derive(Debug, Error)]
pub enum RsaError {
    #[error("could not encode/decoding correctly")]
    EncodingError,
    #[error("the string was not a properly formatted key {0}")]
    ImproperlyFormattedStr(String),
    #[error("io error related to file: {0}")]
    FileError(
        #[from]
        #[source]
        std::io::Error,
    ),
    #[error("error while creating big int from string: {0}")]
    BigIntError(
        #[from]
        #[source]
        ParseBigIntError,
    ),
}
