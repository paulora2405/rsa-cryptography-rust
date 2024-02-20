use crate::error::RSAResult;
use crate::key::Key;

impl Key {
    /// Encodes bytes using this [`Key`].
    /// # Errors
    /// If encoding cannot be done successfully.
    pub fn encode_bytes(&self, bytes: &[u8]) -> RSAResult<Vec<u8>> {
        dbg!(bytes);
        todo!()
    }

    /// Decodes bytes using this [`Key`].
    /// # Errors
    /// If decoding cannot be done successfully.
    pub fn decode_bytes(&self, bytes: &[u8]) -> RSAResult<Vec<u8>> {
        dbg!(bytes);
        todo!()
    }
}
