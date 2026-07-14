use std::fmt;

use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Result};

/// uniformly random 256-bit application root key.
pub struct RootKey {
    bytes: Zeroizing<[u8; 32]>,
}

impl RootKey {
    /// imports an already uniformly random 256-bit root key and clears the source.
    ///
    /// passwords, passphrases, api tokens, hashes of low-entropy input, and
    /// other guessable values are not valid root keys.
    #[must_use]
    pub fn import(random_bytes: &mut [u8; 32]) -> Self {
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(random_bytes);
        random_bytes.zeroize();
        Self { bytes }
    }

    /// borrows the root for one application-defined operation.
    ///
    /// the closure can copy or return these bytes. any such copy is owned and
    /// must be cleared by the application.
    pub fn expose<T>(&self, use_key: impl FnOnce(&[u8; 32]) -> T) -> T {
        use_key(&self.bytes)
    }

    pub(crate) fn random() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| Error::RandomUnavailable)?;
        Ok(Self { bytes })
    }

    pub(crate) fn from_zeroizing(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self { bytes }
    }

    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl fmt::Debug for RootKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RootKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_clears_the_source_and_debug_is_redacted() {
        let mut source = [0x42; 32];
        let key = RootKey::import(&mut source);
        assert_eq!(source, [0; 32]);
        assert_eq!(format!("{key:?}"), "RootKey([REDACTED])");
    }
}
