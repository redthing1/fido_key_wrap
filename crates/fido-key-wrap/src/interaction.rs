use std::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{Error, FidoPolicy, Result};

/// application interaction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InteractionError {
    /// the user cancelled the interaction.
    #[error("cancelled")]
    Cancelled,
    /// the interface does not implement the requested interaction.
    #[error("unsupported interaction")]
    Unsupported,
    /// the interface failed without usable input.
    #[error("interaction layer failed")]
    Failed,
}

/// zeroizing security-key pin.
pub struct Pin(Zeroizing<String>);

impl Pin {
    /// maximum encoded pin length accepted by the interaction boundary.
    pub const MAX_BYTES: usize = 63;

    /// stores a bounded nonempty pin in zeroizing storage.
    ///
    /// # errors
    ///
    /// returns [`Error::InvalidPin`] for an empty, overlong, or nul-containing
    /// value.
    pub fn new(value: String) -> Result<Self> {
        let value = Zeroizing::new(value);
        if value.is_empty() || value.len() > Self::MAX_BYTES || value.as_bytes().contains(&0) {
            return Err(Error::InvalidPin);
        }
        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Pin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Pin([REDACTED])")
    }
}

/// zeroizing opaque application passphrase bytes.
pub struct Passphrase(Zeroizing<Vec<u8>>);

impl Passphrase {
    /// maximum passphrase length accepted by the interaction boundary.
    pub const MAX_BYTES: usize = 1_024;

    /// stores bounded nonempty passphrase bytes in zeroizing storage.
    ///
    /// # errors
    ///
    /// returns [`Error::InvalidPassphrase`] for an empty value or one longer
    /// than 1,024 bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = Zeroizing::new(bytes.into());
        if bytes.is_empty() || bytes.len() > Self::MAX_BYTES {
            return Err(Error::InvalidPassphrase);
        }
        Ok(Self(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn confirmation_matches(&self, other: &Self) -> bool {
        let mut left = Zeroizing::new([0u8; Self::MAX_BYTES]);
        let mut right = Zeroizing::new([0u8; Self::MAX_BYTES]);
        left[..self.0.len()].copy_from_slice(&self.0);
        right[..other.0.len()].copy_from_slice(&other.0);
        let bytes_equal = left.as_slice().ct_eq(right.as_slice());
        let lengths_equal = (self.0.len() as u64).ct_eq(&(other.0.len() as u64));
        bool::from(bytes_equal & lengths_equal)
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Passphrase([REDACTED])")
    }
}

/// root-protection operation requesting interaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    /// generate and protect a new root.
    CreateRoot,
    /// protect a caller-supplied random root.
    ProtectRoot,
    /// recover a root through one selected recipient.
    Unlock,
    /// add another recovery route.
    AddRecipient,
    /// replace a passphrase layer.
    RewrapPassphrase,
    /// verify that a managed credential is present.
    VerifyManagedRecipient,
    /// retire a managed credential from the selected authenticator.
    RetireManagedRecipient,
}

/// security-key ceremony being performed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FidoCeremony {
    /// create a dedicated credential.
    Enrollment,
    /// perform an assertion with an existing credential.
    Assertion,
}

/// reason an application passphrase is requested.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PassphrasePurpose {
    /// recover an existing recipient.
    Unlock,
    /// enter a new passphrase.
    New,
    /// confirm a new passphrase.
    Confirm,
}

/// prompt for choosing one compatible authenticator by touch.
#[derive(Clone, Debug)]
pub struct SelectionPrompt {
    operation: Operation,
    label: String,
    policy: FidoPolicy,
}

impl SelectionPrompt {
    pub(crate) fn new(operation: Operation, label: &str, policy: FidoPolicy) -> Self {
        Self {
            operation,
            label: label.to_owned(),
            policy,
        }
    }

    /// returns the operation being performed.
    #[must_use]
    pub const fn operation(&self) -> Operation {
        self.operation
    }

    /// returns the untrusted recipient label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// returns the recipient's exact security-key recovery policy.
    #[must_use]
    pub const fn policy(&self) -> FidoPolicy {
        self.policy
    }
}

/// prompt requesting a security-key pin.
#[derive(Clone, Debug)]
pub struct PinPrompt {
    operation: Operation,
    label: String,
    ceremony: FidoCeremony,
}

impl PinPrompt {
    pub(crate) fn new(operation: Operation, label: &str, ceremony: FidoCeremony) -> Self {
        Self {
            operation,
            label: label.to_owned(),
            ceremony,
        }
    }

    /// returns the operation being performed.
    #[must_use]
    pub const fn operation(&self) -> Operation {
        self.operation
    }

    /// returns the untrusted recipient label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// returns the security-key ceremony being performed.
    #[must_use]
    pub const fn ceremony(&self) -> FidoCeremony {
        self.ceremony
    }
}

/// prompt requesting an application passphrase.
#[derive(Clone, Debug)]
pub struct PassphrasePrompt {
    operation: Operation,
    label: String,
    purpose: PassphrasePurpose,
}

impl PassphrasePrompt {
    pub(crate) fn new(operation: Operation, label: &str, purpose: PassphrasePurpose) -> Self {
        Self {
            operation,
            label: label.to_owned(),
            purpose,
        }
    }

    /// returns the operation being performed.
    #[must_use]
    pub const fn operation(&self) -> Operation {
        self.operation
    }

    /// returns the untrusted recipient label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// returns why the passphrase is requested.
    #[must_use]
    pub const fn purpose(&self) -> PassphrasePurpose {
        self.purpose
    }
}

/// notification that a security key is waiting for touch.
#[derive(Clone, Debug)]
pub struct TouchPrompt {
    operation: Operation,
    label: String,
    ceremony: FidoCeremony,
    policy: FidoPolicy,
}

impl TouchPrompt {
    pub(crate) fn new(
        operation: Operation,
        label: &str,
        ceremony: FidoCeremony,
        policy: FidoPolicy,
    ) -> Self {
        Self {
            operation,
            label: label.to_owned(),
            ceremony,
            policy,
        }
    }

    /// returns the operation being performed.
    #[must_use]
    pub const fn operation(&self) -> Operation {
        self.operation
    }

    /// returns the untrusted recipient label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// returns the security-key ceremony being performed.
    #[must_use]
    pub const fn ceremony(&self) -> FidoCeremony {
        self.ceremony
    }

    /// returns the recipient's exact security-key recovery policy.
    #[must_use]
    pub const fn policy(&self) -> FidoPolicy {
        self.policy
    }
}

/// synchronous application-supplied interaction.
pub trait Interaction {
    /// asks the user to choose one compatible authenticator by touch.
    fn select_authenticator_by_touch(
        &mut self,
        _prompt: &SelectionPrompt,
    ) -> std::result::Result<(), InteractionError> {
        Err(InteractionError::Unsupported)
    }

    /// requests a security-key pin.
    fn request_pin(&mut self, _prompt: &PinPrompt) -> std::result::Result<Pin, InteractionError> {
        Err(InteractionError::Unsupported)
    }

    /// requests opaque application-passphrase bytes.
    fn request_passphrase(
        &mut self,
        _prompt: &PassphrasePrompt,
    ) -> std::result::Result<Passphrase, InteractionError> {
        Err(InteractionError::Unsupported)
    }

    /// notifies the interface that a security key is waiting for touch.
    fn touch_required(
        &mut self,
        _prompt: &TouchPrompt,
    ) -> std::result::Result<(), InteractionError> {
        Err(InteractionError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Unsupported;
    impl Interaction for Unsupported {}

    #[test]
    fn secrets_are_redacted_and_confirmed_without_early_length_exit() {
        let pin = Pin::new("123456".to_owned()).unwrap();
        let first = Passphrase::new(b"correct horse".to_vec()).unwrap();
        let same = Passphrase::new(b"correct horse".to_vec()).unwrap();
        let different = Passphrase::new(b"correct horse!".to_vec()).unwrap();
        assert_eq!(format!("{pin:?}"), "Pin([REDACTED])");
        assert_eq!(format!("{first:?}"), "Passphrase([REDACTED])");
        assert!(first.confirmation_matches(&same));
        assert!(!first.confirmation_matches(&different));
    }

    #[test]
    fn secret_bounds_are_exact() {
        assert!(Pin::new("x".repeat(Pin::MAX_BYTES)).is_ok());
        assert!(Pin::new("x".repeat(Pin::MAX_BYTES + 1)).is_err());
        assert!(Passphrase::new(vec![b'x'; Passphrase::MAX_BYTES]).is_ok());
        assert!(Passphrase::new(vec![b'x'; Passphrase::MAX_BYTES + 1]).is_err());
    }

    #[test]
    fn interaction_defaults_fail_closed() {
        let mut interaction = Unsupported;
        let prompt = PassphrasePrompt::new(Operation::Unlock, "primary", PassphrasePurpose::Unlock);
        assert!(matches!(
            interaction.request_passphrase(&prompt),
            Err(InteractionError::Unsupported)
        ));
    }
}
