use crate::TokenPolicy;

/// result type returned by this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// operation error that does not expose fido protocol internals.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// no connected authenticator supports the required features.
    #[error("no compatible FIDO authenticator was found")]
    NoCompatibleAuthenticator,

    /// the selected authenticator lacks a required operation or extension.
    #[error("the authenticator does not support a required feature")]
    UnsupportedAuthenticator,

    /// the authenticator has no client pin configured.
    #[error("the authenticator has no client PIN configured")]
    PinNotConfigured,

    /// the supplied pin was rejected.
    #[error(
        "the FIDO PIN was invalid{remaining}",
        remaining = retry_suffix(*retries_remaining)
    )]
    PinInvalid {
        /// remaining attempts reported by the authenticator, when available.
        retries_remaining: Option<u8>,
    },

    /// pin authentication is temporarily blocked.
    #[error(
        "FIDO PIN authentication is temporarily blocked; unplug and reconnect the authenticator"
    )]
    PinAuthBlocked,

    /// the authenticator pin is permanently blocked until reset.
    #[error("the FIDO PIN is blocked")]
    PinBlocked,

    /// the bounded authenticator operation timed out.
    #[error("the authenticator operation timed out")]
    TimedOut,

    /// another operation is using the authenticator.
    #[error("the authenticator is busy")]
    AuthenticatorBusy,

    /// the authenticator disappeared or operating-system access failed.
    #[error("the authenticator is unavailable or inaccessible")]
    AuthenticatorUnavailable,

    /// the user cancelled or denied the operation.
    #[error("the operation was cancelled")]
    Cancelled,

    /// the selected authenticator does not hold the requested credential.
    #[error("the selected authenticator does not contain this credential")]
    WrongAuthenticator,

    /// the authenticator can no longer satisfy the recorded exact policy.
    #[error(
        "the authenticator can no longer provide the recorded {policy} policy",
        policy = policy_name(*expected)
    )]
    AuthenticatorPolicyChanged {
        /// exact token policy recorded in the envelope.
        expected: TokenPolicy,
    },

    /// a signed authenticator response failed structural or cryptographic checks.
    #[error("the authenticator returned an invalid signed response")]
    AuthenticatorResponseInvalid,

    /// the protector and envelope use different application ids.
    #[error("the envelope belongs to a different application")]
    ApplicationMismatch,

    /// the serialized key envelope is invalid or noncanonical.
    #[error("the key envelope is invalid")]
    InvalidEnvelope,

    /// a bounded serialized value or collection exceeded its limit.
    #[error("a serialized input exceeded a resource limit")]
    ResourceLimitExceeded,

    /// the requested recipient is absent from the envelope.
    #[error("the envelope does not contain the requested recipient")]
    RecipientNotFound,

    /// the credential is already represented by a recipient.
    #[error("this credential is already present in the envelope")]
    DuplicateRecipient,

    /// removal would leave no recovery recipient.
    #[error("removing the last recipient would make the envelope unrecoverable")]
    WouldRemoveLastRecipient,

    /// the supplied root key does not authenticate the envelope.
    #[error("the supplied root key does not authenticate this envelope")]
    WrongRootKey,

    /// recipient recovery or final envelope authentication failed.
    #[error("the root key could not be unlocked")]
    UnlockFailed,

    /// an application id failed validation.
    #[error("invalid application identifier")]
    InvalidApplicationId,

    /// a recipient label failed validation.
    #[error("invalid recipient label")]
    InvalidLabel,

    /// a recipient id failed validation.
    #[error("invalid recipient identifier")]
    InvalidRecipientId,

    /// a pin value was empty, overlong, or contained a nul byte.
    #[error("invalid PIN value")]
    InvalidPin,

    /// a passphrase was empty or overlong.
    #[error("invalid passphrase value")]
    InvalidPassphrase,

    /// the application interaction implementation failed.
    #[error("the user interaction layer failed")]
    Interaction,

    /// operating-system randomness was unavailable.
    #[error("the operating system random number generator failed")]
    Random,

    /// the native backend returned an unmapped failure.
    #[error("the native FIDO backend failed")]
    Backend,
}

fn retry_suffix(retries: Option<u8>) -> String {
    retries.map_or_else(String::new, |count| format!(" ({count} retries remain)"))
}

const fn policy_name(policy: TokenPolicy) -> &'static str {
    match policy {
        TokenPolicy::Presence => "presence",
        TokenPolicy::UserVerified => "user-verified",
    }
}
