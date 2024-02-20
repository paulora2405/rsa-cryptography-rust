use crate::error::RsaResult;
use crate::key::Key;

impl Key {
    /// Encodes bytes using this [`Key`].
    /// # Errors
    /// If encoding cannot be done successfully.
    pub fn encode_bytes(&self, bytes: &[u8]) -> RsaResult<Vec<u8>> {
        dbg!(bytes);
        todo!()
    }

    /// Decodes bytes using this [`Key`].
    /// # Errors
    /// If decoding cannot be done successfully.
    pub fn decode_bytes(&self, bytes: &[u8]) -> RsaResult<Vec<u8>> {
        dbg!(bytes);
        todo!()
    }
}
