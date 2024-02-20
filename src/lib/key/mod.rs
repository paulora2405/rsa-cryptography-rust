//! Module containing all code for [`KeyPair`]/[`Key`] generation,
//! formatting as string, parsing from string,
//! writting and reading from files and validating.

use crate::math::mod_pow;
use num_bigint::BigUint;

mod file;
mod generation;
mod str;

/// Enum to dictate if Key is a Public or Private key.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyVariant {
    /// Has a modules, and can also have a non default exponent.
    PublicKey,
    /// Always has both an modulus and exponent.
    PrivateKey,
}

/// Represents the internal components of a Public or Private key.
///
/// In the case of a Public key with a default exponent, it is still present in the struct,
/// but can be recognized via the [`IsDefaultExponent`] trait, which is
/// implemented for [`BigUint`].
#[derive(Debug, PartialEq, Eq)]
pub struct Key {
    /// `D` or `E` part of the key.
    pub(crate) exponent: BigUint,
    /// `N` part of the key.
    pub(crate) modulus: BigUint,
    pub(crate) variant: KeyVariant,
}

/// Contains both the Public and Private keys.
#[derive(Debug, PartialEq, Eq)]
pub struct KeyPair {
    pub public_key: Key,
    pub private_key: Key,
}

impl KeyPair {
    /// Returns `true` if [`KeyPair`] is valid.
    #[must_use]
    fn is_valid(&self) -> bool {
        if self.public_key.modulus != self.private_key.modulus
            || self.public_key.exponent > self.public_key.modulus
        {
            return false;
        }
        let plain_msg = BigUint::from(12_345_678u64);
        let encoded_msg = mod_pow(
            &plain_msg,
            &self.public_key.exponent,
            &self.public_key.modulus,
        );
        let decoded_msg = mod_pow(
            &encoded_msg,
            &self.private_key.exponent,
            &self.private_key.modulus,
        );
        if plain_msg != decoded_msg {
            return false;
        }
        true
    }
}

/// Trait to determine if something is equal to the default exponent.
pub trait IsDefaultExponent {
    /// Returns if something is equal to the default exponent.
    fn is_default_exponent(&self) -> bool;
}

impl IsDefaultExponent for BigUint {
    #[must_use]
    fn is_default_exponent(&self) -> bool {
        *self == BigUint::from(Key::DEFAULT_EXPONENT)
    }
}
