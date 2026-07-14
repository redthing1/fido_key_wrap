use fido_key_wrap::{Error as CoreError, InteractionError};
use pyo3::{create_exception, exceptions::PyException, prelude::*};

create_exception!(
    fido_key_wrap._native,
    Error,
    PyException,
    "a bounded failure raised by the library; its code attribute is an ErrorCode."
);
create_exception!(
    fido_key_wrap._native,
    Cancelled,
    PyException,
    "raise from an interaction callback to cancel the current operation."
);

/// stable categories for bounded library failures.
#[pyclass(
    name = "ErrorCode",
    eq,
    hash,
    frozen,
    skip_from_py_object,
    module = "fido_key_wrap._native"
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ErrorCode {
    #[pyo3(name = "INVALID_APPLICATION_ID")]
    InvalidApplicationId = 1,
    #[pyo3(name = "INVALID_RECIPIENT_ID")]
    InvalidRecipientId = 2,
    #[pyo3(name = "INVALID_LABEL")]
    InvalidLabel = 3,
    #[pyo3(name = "INVALID_PASSPHRASE")]
    InvalidPassphrase = 4,
    #[pyo3(name = "INVALID_PIN")]
    InvalidPin = 5,
    #[pyo3(name = "INVALID_PASSPHRASE_PARAMETERS")]
    InvalidPassphraseParameters = 6,
    #[pyo3(name = "INVALID_PASSPHRASE_LIMITS")]
    InvalidPassphraseLimits = 7,
    #[pyo3(name = "INVALID_ENVELOPE")]
    InvalidEnvelope = 8,
    #[pyo3(name = "APPLICATION_MISMATCH")]
    ApplicationMismatch = 9,
    #[pyo3(name = "RECIPIENT_NOT_FOUND")]
    RecipientNotFound = 10,
    #[pyo3(name = "WOULD_REMOVE_LAST_RECIPIENT")]
    WouldRemoveLastRecipient = 11,
    #[pyo3(name = "TOO_MANY_RECIPIENTS")]
    TooManyRecipients = 12,
    #[pyo3(name = "RECIPIENT_DOES_NOT_USE_PASSPHRASE")]
    RecipientDoesNotUsePassphrase = 13,
    #[pyo3(name = "PASSPHRASE_CONFIRMATION_MISMATCH")]
    PassphraseConfirmationMismatch = 14,
    #[pyo3(name = "PASSPHRASE_LIMIT_EXCEEDED")]
    PassphraseLimitExceeded = 15,
    #[pyo3(name = "KDF_RESOURCE_UNAVAILABLE")]
    KdfResourceUnavailable = 16,
    #[pyo3(name = "FIDO_SUPPORT_UNAVAILABLE")]
    FidoSupportUnavailable = 17,
    #[pyo3(name = "NO_COMPATIBLE_AUTHENTICATOR")]
    NoCompatibleAuthenticator = 18,
    #[pyo3(name = "AUTHENTICATOR_OPERATION_FAILED")]
    AuthenticatorOperationFailed = 19,
    #[pyo3(name = "AUTHENTICATOR_RESPONSE_INVALID")]
    AuthenticatorResponseInvalid = 20,
    #[pyo3(name = "INTERACTION_CANCELLED")]
    InteractionCancelled = 21,
    #[pyo3(name = "INTERACTION_UNSUPPORTED")]
    InteractionUnsupported = 22,
    #[pyo3(name = "INTERACTION_FAILED")]
    InteractionFailed = 23,
    #[pyo3(name = "RANDOM_UNAVAILABLE")]
    RandomUnavailable = 24,
    #[pyo3(name = "ENVELOPE_AUTHENTICATION_FAILED")]
    EnvelopeAuthenticationFailed = 25,
    #[pyo3(name = "UNLOCK_FAILED")]
    UnlockFailed = 26,
    #[pyo3(name = "BUSY")]
    Busy = 27,
    #[pyo3(name = "INTERNAL")]
    Internal = 28,
}

pub fn map_error(py: Python<'_>, error: &CoreError) -> PyErr {
    let code = match error {
        CoreError::InvalidApplicationId => ErrorCode::InvalidApplicationId,
        CoreError::InvalidRecipientId => ErrorCode::InvalidRecipientId,
        CoreError::InvalidLabel => ErrorCode::InvalidLabel,
        CoreError::InvalidPassphrase => ErrorCode::InvalidPassphrase,
        CoreError::InvalidPin => ErrorCode::InvalidPin,
        CoreError::InvalidPassphraseParameters => ErrorCode::InvalidPassphraseParameters,
        CoreError::InvalidPassphraseLimits => ErrorCode::InvalidPassphraseLimits,
        CoreError::InvalidEnvelope => ErrorCode::InvalidEnvelope,
        CoreError::ApplicationMismatch => ErrorCode::ApplicationMismatch,
        CoreError::RecipientNotFound => ErrorCode::RecipientNotFound,
        CoreError::WouldRemoveLastRecipient => ErrorCode::WouldRemoveLastRecipient,
        CoreError::TooManyRecipients => ErrorCode::TooManyRecipients,
        CoreError::RecipientDoesNotUsePassphrase => ErrorCode::RecipientDoesNotUsePassphrase,
        CoreError::PassphraseConfirmationMismatch => ErrorCode::PassphraseConfirmationMismatch,
        CoreError::PassphraseLimitExceeded => ErrorCode::PassphraseLimitExceeded,
        CoreError::KdfResourceUnavailable => ErrorCode::KdfResourceUnavailable,
        CoreError::FidoSupportUnavailable => ErrorCode::FidoSupportUnavailable,
        CoreError::NoCompatibleAuthenticator => ErrorCode::NoCompatibleAuthenticator,
        CoreError::AuthenticatorOperationFailed => ErrorCode::AuthenticatorOperationFailed,
        CoreError::AuthenticatorResponseInvalid => ErrorCode::AuthenticatorResponseInvalid,
        CoreError::Interaction(InteractionError::Cancelled) => ErrorCode::InteractionCancelled,
        CoreError::Interaction(InteractionError::Unsupported) => ErrorCode::InteractionUnsupported,
        CoreError::Interaction(InteractionError::Failed) => ErrorCode::InteractionFailed,
        CoreError::RandomUnavailable => ErrorCode::RandomUnavailable,
        CoreError::EnvelopeAuthenticationFailed => ErrorCode::EnvelopeAuthenticationFailed,
        CoreError::UnlockFailed => ErrorCode::UnlockFailed,
        _ => ErrorCode::Internal,
    };
    let message = if code == ErrorCode::Internal {
        "internal error".to_owned()
    } else {
        error.to_string()
    };
    new_error(py, code, message)
}

pub fn busy_error(py: Python<'_>) -> PyErr {
    new_error(py, ErrorCode::Busy, "the protector is already in use")
}

#[cfg(not(feature = "fido"))]
pub fn unavailable_error(py: Python<'_>) -> PyErr {
    new_error(
        py,
        ErrorCode::FidoSupportUnavailable,
        "security-key support is unavailable",
    )
}

fn new_error(py: Python<'_>, code: ErrorCode, message: impl Into<String>) -> PyErr {
    let error = PyErr::new::<Error, _>(message.into());
    match error.value(py).setattr("code", code) {
        Ok(()) => error,
        Err(attribute_error) => attribute_error,
    }
}
