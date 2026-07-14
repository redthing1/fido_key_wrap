use fido_key_wrap::{AuthenticatorFailure, Error as CoreError, InteractionError};
use pyo3::{create_exception, exceptions::PyException, prelude::*};

create_exception!(
    fido_key_wrap._native,
    Error,
    PyException,
    "a bounded failure with an ErrorCode and optional pin retry count."
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
    #[pyo3(name = "INVALID_FIDO_CONFIG")]
    InvalidFidoConfig = 8,
    #[pyo3(name = "INVALID_ENVELOPE")]
    InvalidEnvelope = 9,
    #[pyo3(name = "APPLICATION_MISMATCH")]
    ApplicationMismatch = 10,
    #[pyo3(name = "RECIPIENT_NOT_FOUND")]
    RecipientNotFound = 11,
    #[pyo3(name = "WOULD_REMOVE_LAST_RECIPIENT")]
    WouldRemoveLastRecipient = 12,
    #[pyo3(name = "TOO_MANY_RECIPIENTS")]
    TooManyRecipients = 13,
    #[pyo3(name = "RECIPIENT_DOES_NOT_USE_PASSPHRASE")]
    RecipientDoesNotUsePassphrase = 14,
    #[pyo3(name = "PASSPHRASE_CONFIRMATION_MISMATCH")]
    PassphraseConfirmationMismatch = 15,
    #[pyo3(name = "PASSPHRASE_LIMIT_EXCEEDED")]
    PassphraseLimitExceeded = 16,
    #[pyo3(name = "KDF_RESOURCE_UNAVAILABLE")]
    KdfResourceUnavailable = 17,
    #[pyo3(name = "FIDO_SUPPORT_UNAVAILABLE")]
    FidoSupportUnavailable = 18,
    #[pyo3(name = "NO_COMPATIBLE_AUTHENTICATOR")]
    NoCompatibleAuthenticator = 19,
    #[pyo3(name = "FIDO_PIN_INVALID")]
    FidoPinInvalid = 20,
    #[pyo3(name = "FIDO_PIN_BLOCKED")]
    FidoPinBlocked = 21,
    #[pyo3(name = "FIDO_PIN_TEMPORARILY_BLOCKED")]
    FidoPinTemporarilyBlocked = 22,
    #[pyo3(name = "FIDO_TIMEOUT")]
    FidoTimeout = 23,
    #[pyo3(name = "FIDO_BUSY")]
    FidoBusy = 24,
    #[pyo3(name = "FIDO_CREDENTIAL_UNAVAILABLE")]
    FidoCredentialUnavailable = 25,
    #[pyo3(name = "FIDO_TRANSPORT")]
    FidoTransport = 26,
    #[pyo3(name = "FIDO_OPERATION_FAILED")]
    FidoOperationFailed = 27,
    #[pyo3(name = "AUTHENTICATOR_RESPONSE_INVALID")]
    AuthenticatorResponseInvalid = 28,
    #[pyo3(name = "INTERACTION_CANCELLED")]
    InteractionCancelled = 29,
    #[pyo3(name = "INTERACTION_UNSUPPORTED")]
    InteractionUnsupported = 30,
    #[pyo3(name = "INTERACTION_FAILED")]
    InteractionFailed = 31,
    #[pyo3(name = "RANDOM_UNAVAILABLE")]
    RandomUnavailable = 32,
    #[pyo3(name = "ENVELOPE_AUTHENTICATION_FAILED")]
    EnvelopeAuthenticationFailed = 33,
    #[pyo3(name = "UNLOCK_FAILED")]
    UnlockFailed = 34,
    #[pyo3(name = "BUSY")]
    Busy = 35,
    #[pyo3(name = "INTERNAL")]
    Internal = 36,
}

pub fn map_error(py: Python<'_>, error: &CoreError) -> PyErr {
    let (code, pin_retries) = match error {
        CoreError::InvalidApplicationId => (ErrorCode::InvalidApplicationId, None),
        CoreError::InvalidRecipientId => (ErrorCode::InvalidRecipientId, None),
        CoreError::InvalidLabel => (ErrorCode::InvalidLabel, None),
        CoreError::InvalidPassphrase => (ErrorCode::InvalidPassphrase, None),
        CoreError::InvalidPin => (ErrorCode::InvalidPin, None),
        CoreError::InvalidPassphraseParameters => (ErrorCode::InvalidPassphraseParameters, None),
        CoreError::InvalidPassphraseLimits => (ErrorCode::InvalidPassphraseLimits, None),
        CoreError::InvalidFidoConfig => (ErrorCode::InvalidFidoConfig, None),
        CoreError::InvalidEnvelope => (ErrorCode::InvalidEnvelope, None),
        CoreError::ApplicationMismatch => (ErrorCode::ApplicationMismatch, None),
        CoreError::RecipientNotFound => (ErrorCode::RecipientNotFound, None),
        CoreError::WouldRemoveLastRecipient => (ErrorCode::WouldRemoveLastRecipient, None),
        CoreError::TooManyRecipients => (ErrorCode::TooManyRecipients, None),
        CoreError::RecipientDoesNotUsePassphrase => {
            (ErrorCode::RecipientDoesNotUsePassphrase, None)
        }
        CoreError::PassphraseConfirmationMismatch => {
            (ErrorCode::PassphraseConfirmationMismatch, None)
        }
        CoreError::PassphraseLimitExceeded => (ErrorCode::PassphraseLimitExceeded, None),
        CoreError::KdfResourceUnavailable => (ErrorCode::KdfResourceUnavailable, None),
        CoreError::FidoSupportUnavailable => (ErrorCode::FidoSupportUnavailable, None),
        CoreError::NoCompatibleAuthenticator => (ErrorCode::NoCompatibleAuthenticator, None),
        CoreError::Authenticator(failure) => match failure {
            AuthenticatorFailure::PinInvalid { retries } => (ErrorCode::FidoPinInvalid, *retries),
            AuthenticatorFailure::PinBlocked => (ErrorCode::FidoPinBlocked, None),
            AuthenticatorFailure::PinTemporarilyBlocked => {
                (ErrorCode::FidoPinTemporarilyBlocked, None)
            }
            AuthenticatorFailure::TimedOut => (ErrorCode::FidoTimeout, None),
            AuthenticatorFailure::Busy => (ErrorCode::FidoBusy, None),
            AuthenticatorFailure::CredentialUnavailable => {
                (ErrorCode::FidoCredentialUnavailable, None)
            }
            AuthenticatorFailure::Transport => (ErrorCode::FidoTransport, None),
            // Includes OperationFailed and future bounded fallback categories.
            _ => (ErrorCode::FidoOperationFailed, None),
        },
        CoreError::AuthenticatorResponseInvalid => (ErrorCode::AuthenticatorResponseInvalid, None),
        CoreError::Interaction(InteractionError::Cancelled) => {
            (ErrorCode::InteractionCancelled, None)
        }
        CoreError::Interaction(InteractionError::Unsupported) => {
            (ErrorCode::InteractionUnsupported, None)
        }
        CoreError::Interaction(InteractionError::Failed) => (ErrorCode::InteractionFailed, None),
        CoreError::RandomUnavailable => (ErrorCode::RandomUnavailable, None),
        CoreError::EnvelopeAuthenticationFailed => (ErrorCode::EnvelopeAuthenticationFailed, None),
        CoreError::UnlockFailed => (ErrorCode::UnlockFailed, None),
        _ => (ErrorCode::Internal, None),
    };
    let message = if code == ErrorCode::Internal {
        "internal error".to_owned()
    } else {
        error.to_string()
    };
    new_error(py, code, pin_retries, message)
}

pub fn busy_error(py: Python<'_>) -> PyErr {
    new_error(py, ErrorCode::Busy, None, "the protector is already in use")
}

#[cfg(not(feature = "fido"))]
pub fn unavailable_error(py: Python<'_>) -> PyErr {
    new_error(
        py,
        ErrorCode::FidoSupportUnavailable,
        None,
        "security-key support is unavailable",
    )
}

fn new_error(
    py: Python<'_>,
    code: ErrorCode,
    pin_retries: Option<u8>,
    message: impl Into<String>,
) -> PyErr {
    let error = PyErr::new::<Error, _>(message.into());
    if let Err(attribute_error) = error.value(py).setattr("code", code) {
        return attribute_error;
    }
    match error.value(py).setattr("pin_retries", pin_retries) {
        Ok(()) => error,
        Err(attribute_error) => attribute_error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_mapping(
        py: Python<'_>,
        failure: AuthenticatorFailure,
        expected: ErrorCode,
        retries: Option<u8>,
    ) {
        let error = map_error(py, &CoreError::Authenticator(failure));
        assert!(error.is_instance_of::<Error>(py));
        let value = error.value(py);
        let code = value.getattr("code").unwrap();
        let expected = Py::new(py, expected).unwrap();
        assert!(code.eq(expected.bind(py)).unwrap());
        assert_eq!(
            value
                .getattr("pin_retries")
                .unwrap()
                .extract::<Option<u8>>()
                .unwrap(),
            retries
        );
    }

    #[test]
    fn preserves_every_actionable_authenticator_failure() {
        Python::initialize();
        Python::attach(|py| {
            for (failure, expected, retries) in [
                (
                    AuthenticatorFailure::PinInvalid { retries: Some(3) },
                    ErrorCode::FidoPinInvalid,
                    Some(3),
                ),
                (
                    AuthenticatorFailure::PinBlocked,
                    ErrorCode::FidoPinBlocked,
                    None,
                ),
                (
                    AuthenticatorFailure::PinTemporarilyBlocked,
                    ErrorCode::FidoPinTemporarilyBlocked,
                    None,
                ),
                (AuthenticatorFailure::TimedOut, ErrorCode::FidoTimeout, None),
                (AuthenticatorFailure::Busy, ErrorCode::FidoBusy, None),
                (
                    AuthenticatorFailure::CredentialUnavailable,
                    ErrorCode::FidoCredentialUnavailable,
                    None,
                ),
                (
                    AuthenticatorFailure::Transport,
                    ErrorCode::FidoTransport,
                    None,
                ),
                (
                    AuthenticatorFailure::OperationFailed,
                    ErrorCode::FidoOperationFailed,
                    None,
                ),
            ] {
                assert_mapping(py, failure, expected, retries);
            }
        });
    }

    #[test]
    fn every_error_has_a_pin_retry_attribute() {
        Python::initialize();
        Python::attach(|py| {
            let error = map_error(py, &CoreError::UnlockFailed);
            assert_eq!(
                error
                    .value(py)
                    .getattr("pin_retries")
                    .unwrap()
                    .extract::<Option<u8>>()
                    .unwrap(),
                None
            );
        });
    }
}
