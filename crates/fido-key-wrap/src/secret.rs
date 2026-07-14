use std::fmt;

use zeroize::{Zeroize, Zeroizing};

use crate::{Error, RecipientId, Result};

const SECRET_BYTES: usize = 32;

/// uniformly random 256-bit application root key.
pub struct RootKey {
    bytes: Zeroizing<[u8; SECRET_BYTES]>,
}

/// uniformly random 256-bit recovery secret for one recovery recipient.
pub struct RecoverySecret {
    bytes: Zeroizing<[u8; SECRET_BYTES]>,
}

impl RecoverySecret {
    /// imports an existing recovery secret and clears the source.
    #[must_use]
    pub fn import(source: &mut [u8; SECRET_BYTES]) -> Self {
        let mut bytes = Zeroizing::new([0u8; SECRET_BYTES]);
        bytes.copy_from_slice(source);
        source.zeroize();
        Self { bytes }
    }

    /// borrows the recovery secret for one application-defined storage operation.
    ///
    /// the closure can copy or return these bytes. any such copy is owned and
    /// must be cleared by the application.
    pub fn expose<T>(&self, use_secret: impl FnOnce(&[u8; SECRET_BYTES]) -> T) -> T {
        use_secret(&self.bytes)
    }

    pub(crate) fn random() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; SECRET_BYTES]);
        getrandom::fill(bytes.as_mut()).map_err(|_| Error::RandomUnavailable)?;
        Ok(Self { bytes })
    }

    pub(crate) fn bytes(&self) -> &[u8; SECRET_BYTES] {
        &self.bytes
    }
}

impl fmt::Debug for RecoverySecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoverySecret([REDACTED])")
    }
}

/// newly created recovery-secret route and its separately stored secret.
pub struct RecoverySecretRecipient {
    recipient_id: RecipientId,
    secret: RecoverySecret,
}

impl RecoverySecretRecipient {
    pub(crate) const fn new(recipient_id: RecipientId, secret: RecoverySecret) -> Self {
        Self {
            recipient_id,
            secret,
        }
    }

    /// returns the recipient selected by this recovery secret.
    #[must_use]
    pub const fn recipient_id(&self) -> RecipientId {
        self.recipient_id
    }

    /// borrows the newly generated recovery secret.
    #[must_use]
    pub const fn secret(&self) -> &RecoverySecret {
        &self.secret
    }

    /// consumes the enrollment result and returns its recovery secret.
    #[must_use]
    pub fn into_secret(self) -> RecoverySecret {
        self.secret
    }
}

impl fmt::Debug for RecoverySecretRecipient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoverySecretRecipient")
            .field("recipient_id", &self.recipient_id)
            .field("secret", &"[REDACTED]")
            .finish()
    }
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

    #[test]
    fn recovery_import_clears_source_and_debug_is_redacted() {
        let mut source = [0x24; SECRET_BYTES];
        let secret = RecoverySecret::import(&mut source);
        assert_eq!(source, [0; SECRET_BYTES]);
        assert_eq!(format!("{secret:?}"), "RecoverySecret([REDACTED])");

        let recipient =
            RecoverySecretRecipient::new(RecipientId::from_bytes([0x42; SECRET_BYTES]), secret);
        let rendered = format!("{recipient:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("RecoverySecret(["));
    }
}
