use crate::InteractionError;

/// result type returned by this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// actionable, identity-free failure from a security-key operation.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthenticatorFailure {
    /// the supplied pin was incorrect.
    #[error("the security-key pin was incorrect")]
    PinInvalid {
        /// remaining attempts reported by the authenticator, when available.
        retries: Option<u8>,
    },
    /// the authenticator's pin is permanently blocked.
    #[error("the security-key pin is blocked")]
    PinBlocked,
    /// pin authentication is temporarily blocked until the authenticator reconnects.
    #[error("security-key pin authentication is temporarily blocked")]
    PinTemporarilyBlocked,
    /// selection or an authenticator operation timed out.
    #[error("the security-key operation timed out")]
    TimedOut,
    /// the authenticator is occupied by another operation.
    #[error("the security key is busy")]
    Busy,
    /// the selected credential is not available on the presented authenticator.
    #[error("the security-key credential is unavailable")]
    CredentialUnavailable,
    /// communication with the authenticator failed.
    #[error("security-key transport failed")]
    Transport,
    /// the authenticator operation failed without a more useful safe category.
    #[error("the security-key operation failed")]
    OperationFailed,
}

/// bounded public failures from root-key protection operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// an application identity failed validation.
    #[error("invalid application identifier")]
    InvalidApplicationId,
    /// a recipient identity failed canonical parsing.
    #[error("invalid recipient identifier")]
    InvalidRecipientId,
    /// a recipient label failed validation.
    #[error("invalid recipient label")]
    InvalidLabel,
    /// a passphrase was empty or exceeded the input bound.
    #[error("invalid passphrase")]
    InvalidPassphrase,
    /// a security-key pin was empty, overlong, or contained a nul byte.
    #[error("invalid security-key pin")]
    InvalidPin,
    /// argon2 parameters were outside the format-1 bounds.
    #[error("invalid passphrase parameters")]
    InvalidPassphraseParameters,
    /// local argon2 resource ceilings were invalid.
    #[error("invalid passphrase limits")]
    InvalidPassphraseLimits,
    /// native security-key operation limits were invalid.
    #[error("invalid security-key configuration")]
    InvalidFidoConfig,
    /// an encoded envelope was malformed, noncanonical, or unsupported.
    #[error("invalid key envelope")]
    InvalidEnvelope,
    /// the trusted application identity does not match the envelope.
    #[error("the key envelope belongs to another application")]
    ApplicationMismatch,
    /// the selected recipient is absent.
    #[error("recipient not found")]
    RecipientNotFound,
    /// removal would leave no route to the root key.
    #[error("cannot remove the final recipient")]
    WouldRemoveLastRecipient,
    /// an envelope already contains the maximum number of recipients.
    #[error("the key envelope already has the maximum number of recipients")]
    TooManyRecipients,
    /// the selected recipient has no passphrase layer to replace.
    #[error("the recipient does not use a passphrase")]
    RecipientDoesNotUsePassphrase,
    /// two entries of a new passphrase differed.
    #[error("passphrase confirmation did not match")]
    PassphraseConfirmationMismatch,
    /// selected passphrase work exceeds this process's configured ceiling.
    #[error("passphrase work exceeds the local resource limit")]
    PassphraseLimitExceeded,
    /// memory for the admitted argon2 operation could not be reserved.
    #[error("memory for passphrase derivation is unavailable")]
    KdfResourceUnavailable,
    /// this build or protector has no security-key backend.
    #[error("security-key support is unavailable")]
    FidoSupportUnavailable,
    /// no connected authenticator can satisfy the operation.
    #[error("no compatible security key was found")]
    NoCompatibleAuthenticator,
    /// a security-key operation failed without trusted cryptographic output.
    #[error("{0}")]
    Authenticator(#[from] AuthenticatorFailure),
    /// an authenticator response was malformed, contradictory, or cryptographically invalid.
    #[error("the security key returned an invalid response")]
    AuthenticatorResponseInvalid,
    /// application-supplied interaction failed or was cancelled.
    #[error("interaction failed: {0}")]
    Interaction(#[from] InteractionError),
    /// the operating-system random source failed.
    #[error("secure randomness is unavailable")]
    RandomUnavailable,
    /// the supplied root does not authenticate the complete envelope.
    #[error("the root key does not authenticate the key envelope")]
    EnvelopeAuthenticationFailed,
    /// a selected recovery route did not yield an authenticated root.
    #[error("the root key could not be unlocked")]
    UnlockFailed,
}
