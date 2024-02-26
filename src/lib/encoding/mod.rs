use std::io::{Read, Write};

use num_bigint::BigUint;
use num_traits::ToPrimitive;

use crate::error::{RsaError, RsaResult};
use crate::key::{Key, KeyVariant};

impl Key {
    const ENCRYPTION_BYTE_OFFSET: usize = 1;

    /// Encodes a [`Read`] implementor to a [`Write`] implementor
    /// using this Public Key.
    ///
    /// # Errors
    /// - If `self` is not a [`KeyVariant::PublicKey`].
    /// - If any [`std::io::Error`] occurs.
    pub fn encode<R: Read, W: Write>(&self, input: &mut R, output: &mut W) -> RsaResult<()> {
        if self.variant != KeyVariant::PublicKey {
            return Err(RsaError::WrongKeyVariant);
        }

        let max_bytes_read = self.modulus.size_in_bytes_floored() - Key::ENCRYPTION_BYTE_OFFSET;
        let max_bytes_write = self.modulus.size_in_bytes_floored() + Key::ENCRYPTION_BYTE_OFFSET;
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

    /// Decodes a [`Read`] implementor to a [`Write`] implementor
    /// using this Private Key.
    ///
    /// # Errors
    /// - If `self` is not a [`KeyVariant::PrivateKey`].
    /// - If any [`std::io::Error`] occurs.
    pub fn decode<R: Read, W: Write>(&self, input: &mut R, output: &mut W) -> RsaResult<()> {
        if self.variant != KeyVariant::PrivateKey {
            return Err(RsaError::WrongKeyVariant);
        }

        let max_bytes = self.modulus.size_in_bytes_floored() + Key::ENCRYPTION_BYTE_OFFSET;
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
    use super::*;
    use crate::key::KeyPair;
    use lipsum::lipsum;
    use std::{io::Cursor, str::FromStr};

    #[test]
    fn test_encode_decode() {
        let pair = pair_4096();

        let original = lipsum(112_288).as_bytes().to_vec();

        // encode
        let input1_s = original.clone();
        let output1_s = Vec::with_capacity(input1_s.len());

        let mut input1 = Cursor::new(input1_s);
        let mut output1 = Cursor::new(output1_s);

        pair.public_key.encode(&mut input1, &mut output1).unwrap();

        // decode
        let input2_s = output1.into_inner().clone();
        let output2_s = Vec::with_capacity(input2_s.len());

        let mut input2 = Cursor::new(input2_s);
        let mut output2 = Cursor::new(output2_s);

        pair.private_key.decode(&mut input2, &mut output2).unwrap();

        pretty_assertions::assert_eq!(original, output2.into_inner());
    }

    fn pair_4096() -> KeyPair {
        let pub_str = r"rrsa 8a171c456a76fa677632c86d79e76a08e9bd619d877b665195fb1d8e506c5fb93277da524842690e855d860644e6050da582f0fe632763a120e0d316cfbccc3e44cf6c8a2d3906690d8ab6133466f210e100213762f1a7b674307f491c6eba0f120a59fd9a8084ca43dfc43988837546fa0cf5e471703f6588d12a35607b20a8604bd989573ca3fea13637dfe31d77efc4f2919b6a8afc5dd58f78cb77a2e000210a636a8240a59c37eebda30adfe85025643f0592bafcb47e6d01d9a50132e23944044af48ded1e5c1517cbcb3bfb4f3ed488a778503ddf4d8de19ae2919ca3c6a78fd9338fe75d5800c45d4c7f9fe5a49967d285fe872063155ce41915e68728a2bc61fe33202d446c19a1a2a685e05cc006b9722c2c58287880f4ebe541f07feb5088290b1ddfce91aeddcd2d051bf33a02144ea6ecc6c1248d8de0702678d85edf7d6a82bc02d6d6523a87abc6c8dbf965a87e410dadff0a62fefded77f0dc4a0b1a65587c2c546d35e4b7ef85a159b2359d32e56df33cce92fb2a287fd1ee39cb940de89c30cd29b8eeb483ad5ff3d948bcbf17a4641876c55b1ba2026f4b08b96716c8b1038252d84610e491f14d5e4994025918aa5ea083e42d767eb8ee3e4e78c4f3a6afd69642f4f2704525a69141762f7448c9bd4e6d42c9b18358d6e405115579f7834869a9e68f8b0ce9ccbc7cf46119ce464b244d5b58458f8b
";
        let priv_str = r"-----BEGIN RSA-RUST PRIVATE KEY-----
8a171c456a76fa677632c86d79e76a08e9bd619d877b665195fb1d8e506c5fb93277da524842690e855d860644e6050da582f0fe632763a120e0d316cfbccc3e44cf6c8a2d3906690d8ab6133466f210e100213762f1a7b674307f491c6eba0f120a59fd9a8084ca43dfc43988837546fa0cf5e471703f6588d12a35607b20a8604bd989573ca3fea13637dfe31d77efc4f2919b6a8afc5dd58f78cb77a2e000210a636a8240a59c37eebda30adfe85025643f0592bafcb47e6d01d9a50132e23944044af48ded1e5c1517cbcb3bfb4f3ed488a778503ddf4d8de19ae2919ca3c6a78fd9338fe75d5800c45d4c7f9fe5a49967d285fe872063155ce41915e68728a2bc61fe33202d446c19a1a2a685e05cc006b9722c2c58287880f4ebe541f07feb5088290b1ddfce91aeddcd2d051bf33a02144ea6ecc6c1248d8de0702678d85edf7d6a82bc02d6d6523a87abc6c8dbf965a87e410dadff0a62fefded77f0dc4a0b1a65587c2c546d35e4b7ef85a159b2359d32e56df33cce92fb2a287fd1ee39cb940de89c30cd29b8eeb483ad5ff3d948bcbf17a4641876c55b1ba2026f4b08b96716c8b1038252d84610e491f14d5e4994025918aa5ea083e42d767eb8ee3e4e78c4f3a6afd69642f4f2704525a69141762f7448c9bd4e6d42c9b18358d6e405115579f7834869a9e68f8b0ce9ccbc7cf46119ce464b244d5b58458f8b
29e6a54f72e4b34a9d94ff3828db4d537309620b58c6dadf3ab13de0a70a9b6928a5317bf22d248fa16c2574d5872e555bb985c2caf772c5bba23cab1951e26faa957e0bd7790c36e84304c8830811bf89666eadcdba21f7bcfdd241aefcf23c0c6f53ab1e2c8d1e8ac5e556c7d38bcc83a7571d80465d164413a3c91a8381ff5568ee933c034c87c10720a130db0a3f98f539b57cf8bb67059c493d040a4a09fffc94fa0697f32899d83976b5a0076ffa4896ceec1d0cfcffb7b7ee00a1827d1e7f4306337ab54e97065778212d0c2e999407fb3908b01d87fcdb4e121db8f801196b0eaf14a551af985bfd2b6f36678a307a4e6916388e5d42683356614cd7951c694730d55a7e139e6e1bd0ee36042c1358c704141abe95fd3ab8ab3a7a4c54183dbc1c6c70cafc815263fe1f8e020b4a169e0303376c30c2adc987b68c28996fcd9da0ba83fe52ee2d2fea92145e9ac66c79f753133ba2d52738aaa08e40b7566eb618c10f19b3df04e6cc5f2d3ba9fc7efc7884565a6ef161a737769d5125a76ba2044119a6950e9ccfbfcd4c294a2aa2665d8819a31b50210e4033cd194e0b9d828e684aeada7e68c2f2e8edd1cd5dbbd08ea94da100f1a8c407a8c12b35f0ec004ee592d51946f74ead50e7ba73bab3f75bd197a757c76373f8e1a5c0d7b09e30572751e1084a165f7ccdf82d45c9de1401b4870821012e79e6744431
-----END RSA-RUST PRIVATE KEY-----
";
        let public_key = Key::from_str(pub_str).unwrap();
        let private_key = Key::from_str(priv_str).unwrap();

        KeyPair {
            public_key,
            private_key,
        }
    }
}
