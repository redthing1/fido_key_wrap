use crate::{Error, Result};

const MAX_LABEL_LEN: usize = 128;

/// fido ceremony required by a recipient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenPolicy {
    /// touch with uv absent.
    Presence,
    /// authenticator pin and touch with uv present.
    UserVerified,
}

impl TokenPolicy {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Presence => 1,
            Self::UserVerified => 2,
        }
    }

    pub(crate) fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Presence),
            2 => Ok(Self::UserVerified),
            _ => Err(Error::InvalidEnvelope),
        }
    }
}

/// recipient policy with an optional application passphrase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecipientPolicy {
    pub(crate) token: TokenPolicy,
    pub(crate) passphrase: bool,
}

impl RecipientPolicy {
    /// adds the version 1 argon2id application-passphrase factor.
    #[must_use]
    pub const fn and_passphrase(mut self) -> Self {
        self.passphrase = true;
        self
    }

    /// returns the token ceremony.
    #[must_use]
    pub const fn token_policy(self) -> TokenPolicy {
        self.token
    }

    /// reports whether an application passphrase is required.
    #[must_use]
    pub const fn has_passphrase(self) -> bool {
        self.passphrase
    }

    pub(crate) const fn factor_code(self) -> u8 {
        if self.passphrase { 1 } else { 0 }
    }
}

/// authenticator presence and touch.
#[must_use]
pub const fn presence() -> RecipientPolicy {
    RecipientPolicy {
        token: TokenPolicy::Presence,
        passphrase: false,
    }
}

/// authenticator pin and touch.
#[must_use]
pub const fn user_verified() -> RecipientPolicy {
    RecipientPolicy {
        token: TokenPolicy::UserVerified,
        passphrase: false,
    }
}

/// request to create one fido recipient.
#[derive(Clone, Debug)]
pub struct Enrollment {
    pub(crate) label: String,
    pub(crate) policy: RecipientPolicy,
}

impl Enrollment {
    /// creates a request. labels are metadata, not identity.
    ///
    /// # Errors
    ///
    /// returns [`Error::InvalidLabel`] for empty, overlong, or control-bearing
    /// labels.
    pub fn new(label: impl Into<String>, policy: RecipientPolicy) -> Result<Self> {
        let label = label.into();
        if label.is_empty() || label.len() > MAX_LABEL_LEN || label.chars().any(char::is_control) {
            return Err(Error::InvalidLabel);
        }
        Ok(Self { label, policy })
    }

    /// returns the label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// returns the recipient policy.
    #[must_use]
    pub const fn policy(&self) -> RecipientPolicy {
        self.policy
    }
}
