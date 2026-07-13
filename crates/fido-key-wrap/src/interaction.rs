use std::fmt;

use zeroize::Zeroizing;

use crate::{ApplicationId, Error, RecipientPolicy, Result};

const MAX_PIN_BYTES: usize = 63;
const MAX_PASSPHRASE_BYTES: usize = 1024;

/// user-interface cancellation or failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InteractionError {
    /// the user cancelled the interaction.
    Cancelled,
    /// the interface could not complete the interaction.
    Failed,
}

impl From<InteractionError> for Error {
    fn from(value: InteractionError) -> Self {
        match value {
            InteractionError::Cancelled => Self::Cancelled,
            InteractionError::Failed => Self::Interaction,
        }
    }
}

/// zeroizing fido pin value.
pub struct Pin(Zeroizing<String>);

impl Pin {
    /// copies a nonempty fido pin into zeroizing storage.
    ///
    /// # Errors
    ///
    /// returns [`Error::InvalidPin`] for an empty, overlong, or nul-containing
    /// value.
    pub fn new(value: String) -> Result<Self> {
        let value = Zeroizing::new(value);
        if value.is_empty() || value.len() > MAX_PIN_BYTES || value.as_bytes().contains(&0) {
            return Err(Error::InvalidPin);
        }
        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pin([REDACTED])")
    }
}

/// zeroizing application passphrase bytes.
pub struct Passphrase(Zeroizing<Vec<u8>>);

impl Passphrase {
    /// copies passphrase bytes into zeroizing storage.
    ///
    /// # Errors
    ///
    /// returns [`Error::InvalidPassphrase`] for an empty value or one longer
    /// than 1,024 bytes.
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self> {
        let value = Zeroizing::new(value.into());
        if value.is_empty() || value.len() > MAX_PASSPHRASE_BYTES {
            return Err(Error::InvalidPassphrase);
        }
        Ok(Self(value))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passphrase([REDACTED])")
    }
}

/// purpose of a requested interaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    /// create the credential and collect recipient factors.
    Enroll,
    /// prove that the new credential can produce the required assertion.
    Verify,
    /// recover a root key through an existing recipient.
    Unlock,
}

/// prompt shown when touching one of several authenticators selects it.
#[derive(Clone, Debug)]
pub struct SelectionPrompt {
    /// application identity used for the fido operation.
    pub application_id: ApplicationId,
    /// purpose of the interaction.
    pub operation: Operation,
    /// number of compatible authenticators awaiting selection.
    pub compatible_authenticators: usize,
}

/// prompt requesting an authenticator pin.
#[derive(Clone, Debug)]
pub struct PinPrompt {
    /// application identity used for the fido operation.
    pub application_id: ApplicationId,
    /// purpose of the interaction.
    pub operation: Operation,
}

/// prompt requesting an application passphrase.
#[derive(Clone, Debug)]
pub struct PassphrasePrompt {
    /// application identity used for the fido operation.
    pub application_id: ApplicationId,
    /// purpose of the interaction.
    pub operation: Operation,
    /// untrusted display label from the recipient record.
    pub recipient_label: String,
    /// whether this prompt confirms a newly entered passphrase.
    pub confirm: bool,
}

/// notification that an authenticator is waiting for touch.
#[derive(Clone, Debug)]
pub struct TouchPrompt {
    /// application identity used for the fido operation.
    pub application_id: ApplicationId,
    /// purpose of the interaction.
    pub operation: Operation,
    /// untrusted display label from the recipient record.
    pub recipient_label: String,
    /// access policy being performed.
    pub policy: RecipientPolicy,
}

/// synchronous application-supplied user interaction.
pub trait Interaction {
    /// tells the ui that touching one of several authenticators selects it.
    ///
    /// # Errors
    ///
    /// returns cancellation or ui failure before selection begins.
    fn select_authenticator_by_touch(
        &mut self,
        prompt: &SelectionPrompt,
    ) -> std::result::Result<(), InteractionError>;

    /// requests the fido pin for one operation.
    ///
    /// # Errors
    ///
    /// returns cancellation or ui failure without consuming a pin attempt.
    fn request_pin(&mut self, prompt: &PinPrompt) -> std::result::Result<Pin, InteractionError>;

    /// requests application-passphrase bytes.
    ///
    /// # Errors
    ///
    /// returns cancellation or ui failure.
    fn request_passphrase(
        &mut self,
        prompt: &PassphrasePrompt,
    ) -> std::result::Result<Passphrase, InteractionError>;

    /// tells the ui when the authenticator is waiting for touch.
    ///
    /// # Errors
    ///
    /// returns cancellation or ui failure before the operation begins.
    fn touch_required(&mut self, prompt: &TouchPrompt)
    -> std::result::Result<(), InteractionError>;
}
