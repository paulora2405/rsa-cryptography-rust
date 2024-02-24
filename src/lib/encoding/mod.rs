use std::io::{BufReader, BufWriter, Read, Write};

use num_bigint::BigUint;
use num_traits::ToPrimitive;

use crate::error::{RsaError, RsaResult};
use crate::key::{Key, KeyVariant};

impl Key {
    const ENCRYPTION_BYTE_OFFSET: usize = 1;

    /// Encodes a buffered reader to a buffered writter
    /// using this Public Key.
    ///
    /// # Errors
    /// - If `self` is not a [`KeyVariant::PublicKey`].
    /// - If any [`std::io::Error`] occurs.
    pub fn encode_buf<R: Read, W: Write>(
        &self,
        input: &mut BufReader<R>,
        output: &mut BufWriter<W>,
    ) -> RsaResult<()> {
        if self.variant != KeyVariant::PublicKey {
            return Err(RsaError::WrongKeyVariant);
        }

        //
        let max_bytes_read = self.modulus.size_in_bytes() - Key::ENCRYPTION_BYTE_OFFSET;
        // ↑ always > 0 because min key size is 32 bits == 4 bytes
        let max_bytes_write = self.modulus.size_in_bytes() + Key::ENCRYPTION_BYTE_OFFSET;
        let mut source_bytes = vec![0u8; max_bytes_read];
        let mut destiny_bytes = Vec::<u8>::with_capacity(max_bytes_read);
        let mut bytes_amount_read = max_bytes_read;

        while bytes_amount_read == max_bytes_read {
            source_bytes.fill(0u8);
            bytes_amount_read = input.read(&mut source_bytes)?;
            if bytes_amount_read == 0 {
                break;
            }
            let message = BigUint::from_bytes_le(&source_bytes);
            let encrypted = message.modpow(&self.exponent, &self.modulus);
            destiny_bytes.clear();
            let _ = destiny_bytes.write(&encrypted.to_bytes_le())?;
            let size_diff = (max_bytes_write) - destiny_bytes.len();
            destiny_bytes.append(&mut vec![0u8; size_diff]);
            let _bytes_amount_written = output.write(&destiny_bytes)?;
        }
        output.flush()?;
        Ok(())
    }

    /// Decodes a buffered reader to a buffered writter
    /// using this Private Key.
    ///
    /// # Errors
    /// - If `self` is not a [`KeyVariant::PrivateKey`].
    /// - If any [`std::io::Error`] occurs.
    pub fn decode_buf<R: Read, W: Write>(
        &self,
        input: &mut BufReader<R>,
        output: &mut BufWriter<W>,
    ) -> RsaResult<()> {
        if self.variant != KeyVariant::PrivateKey {
            return Err(RsaError::WrongKeyVariant);
        }

        let max_bytes = self.modulus.size_in_bytes() + Key::ENCRYPTION_BYTE_OFFSET;
        let mut source_bytes = vec![0u8; max_bytes];
        let mut destiny_bytes = Vec::<u8>::with_capacity(max_bytes);
        let mut bytes_amount_read = max_bytes;

        while bytes_amount_read == max_bytes {
            source_bytes.fill(0u8);
            bytes_amount_read = input.read(&mut source_bytes)?;
            if bytes_amount_read == 0 {
                break;
            }
            let encrypted = BigUint::from_bytes_le(&source_bytes);
            let message = encrypted.modpow(&self.exponent, &self.modulus);
            destiny_bytes.clear();
            let _ = destiny_bytes.write(&message.to_bytes_le())?;
            let _bytes_amount_written = output.write(&destiny_bytes)?;
        }
        output.flush()?;
        Ok(())
    }
}

/// TODO: where to put this
pub trait SizeInBytes {
    fn size_in_bytes(&self) -> usize;
    fn size_in_bytes_floored(&self) -> usize;
}

impl SizeInBytes for BigUint {
    /// The number of bytes necessary to represent `self`
    /// as a whole, so if it is not divisible by `8`,
    /// the ceil of that division.
    ///
    /// # Examples
    /// For a number that needs `14` bits,
    /// at least `2` bytes are necessary to correctly represent it.
    fn size_in_bytes(&self) -> usize {
        // We can safelly cast this u64 to f64 here
        // because the maximum number of bits a BigUint will
        // take in this application is 4096 at any given time
        #[allow(clippy::cast_precision_loss)]
        (self.bits() as f64 / 8.0)
            .ceil()
            .to_usize()
            .unwrap_or(0usize)
    }

    /// The exact number of bytes necessary to represent `self`,
    /// if it is divisible by `8`,
    /// or `1` less byte if `self.bits()` is not divisible by `8`.
    ///
    /// # Examples
    /// For a number that needs `14` bits,
    /// `1` byte is the floor of `1.75` bytes.
    fn size_in_bytes_floored(&self) -> usize {
        (self.bits() / 8).to_usize().unwrap_or(0usize)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;
    use crate::key::tests::test_pair;

    #[test]
    fn test_encode_decode() {
        let pair = test_pair();

        // encode
        let input_f = File::open("messages/lorem.txt").unwrap();
        let output_f = File::create("messages/lorem.txt.encoded").unwrap();
        let mut input = BufReader::new(input_f);
        let mut output = BufWriter::new(output_f);
        pair.public_key.encode_buf(&mut input, &mut output).unwrap();

        // decode
        let input_f = File::open("messages/lorem.txt.encoded").unwrap();
        let output_f = File::create("messages/lorem.txt.decoded").unwrap();
        let mut input = BufReader::new(input_f);
        let mut output = BufWriter::new(output_f);
        pair.private_key
            .decode_buf(&mut input, &mut output)
            .unwrap();
    }
}
