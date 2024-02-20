use crate::math::mod_pow;
use num_bigint::BigUint;

pub mod generation;
pub mod reading;
pub mod writing;

#[derive(Debug, PartialEq, Eq)]
pub enum KeyVariant {
    PublicKey,
    PrivateKey,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Key {
    /// `D` or `E` part of the key.
    pub(crate) exponent: BigUint,
    /// `N` part of the key.
    pub(crate) modulus: BigUint,
    pub(crate) variant: KeyVariant,
}

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

trait IsDefaultExponent {
    fn is_default_exponent(&self) -> bool;
}

impl IsDefaultExponent for BigUint {
    #[must_use]
    fn is_default_exponent(&self) -> bool {
        *self == BigUint::from(Key::DEFAULT_EXPONENT)
    }
}
