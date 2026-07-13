use std::fmt;

use zeroize::Zeroizing;

use crate::{Error, Result};

/// uniformly random 256-bit application root key.
pub struct RootKey {
    bytes: Zeroizing<[u8; 32]>,
}

impl RootKey {
    /// generates a root key from the operating-system csprng.
    ///
    /// # Errors
    ///
    /// returns [`Error::Random`] if the operating system cannot provide secure
    /// random bytes.
    pub fn generate() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| Error::Random)?;
        Ok(Self { bytes })
    }

    /// imports uniformly random 256-bit key material.
    ///
    /// passwords, passphrases, api tokens, and other low-entropy values are not
    /// valid root keys.
    #[must_use]
    pub fn import(bytes: [u8; 32]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    /// provides temporary borrowed access to the key bytes.
    pub fn expose<R>(&self, function: impl for<'a> FnOnce(&'a [u8; 32]) -> R) -> R {
        function(&self.bytes)
    }

    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub(crate) fn copy_from(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::UnlockFailed);
        }
        let mut root = Self {
            bytes: Zeroizing::new([0; 32]),
        };
        root.bytes.copy_from_slice(bytes);
        Ok(root)
    }
}

impl fmt::Debug for RootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RootKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let key = RootKey::import([0x42; 32]);
        assert_eq!(format!("{key:?}"), "RootKey([REDACTED])");
    }
}
