use pyo3::{prelude::*, types::PyTuple};

#[cfg(feature = "fido")]
use crate::errors::map_error;
#[cfg(not(feature = "fido"))]
use crate::errors::unavailable_error;

/// a bounded reason an authenticator cannot satisfy the required protocol.
#[pyclass(
    name = "AuthenticatorIssue",
    eq,
    hash,
    frozen,
    skip_from_py_object,
    module = "fido_key_wrap._native"
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuthenticatorIssue {
    #[pyo3(name = "UNAVAILABLE")]
    Unavailable = 1,
    #[pyo3(name = "FIDO2_UNAVAILABLE")]
    Fido2Unavailable = 2,
    #[pyo3(name = "ES256_UNAVAILABLE")]
    Es256Unavailable = 3,
    #[pyo3(name = "HMAC_SECRET_UNAVAILABLE")]
    HmacSecretUnavailable = 4,
    #[pyo3(name = "CREDENTIAL_PROTECTION_UNAVAILABLE")]
    CredentialProtectionUnavailable = 5,
    #[pyo3(name = "USER_VERIFICATION_UNAVAILABLE")]
    UserVerificationUnavailable = 6,
    #[pyo3(name = "USER_VERIFICATION_NOT_CONFIGURED")]
    UserVerificationNotConfigured = 7,
    #[pyo3(name = "PRESENCE_RECOVERY_UNAVAILABLE")]
    PresenceRecoveryUnavailable = 8,
}

#[cfg(feature = "fido")]
impl From<fido_key_wrap::AuthenticatorIssue> for AuthenticatorIssue {
    fn from(value: fido_key_wrap::AuthenticatorIssue) -> Self {
        match value {
            fido_key_wrap::AuthenticatorIssue::Fido2Unavailable => Self::Fido2Unavailable,
            fido_key_wrap::AuthenticatorIssue::Es256Unavailable => Self::Es256Unavailable,
            fido_key_wrap::AuthenticatorIssue::HmacSecretUnavailable => Self::HmacSecretUnavailable,
            fido_key_wrap::AuthenticatorIssue::CredentialProtectionUnavailable => {
                Self::CredentialProtectionUnavailable
            }
            fido_key_wrap::AuthenticatorIssue::UserVerificationUnavailable => {
                Self::UserVerificationUnavailable
            }
            fido_key_wrap::AuthenticatorIssue::UserVerificationNotConfigured => {
                Self::UserVerificationNotConfigured
            }
            fido_key_wrap::AuthenticatorIssue::PresenceRecoveryUnavailable => {
                Self::PresenceRecoveryUnavailable
            }
            _ => Self::Unavailable,
        }
    }
}

/// a capability report without authenticator identity.
#[pyclass(name = "AuthenticatorReport", frozen, module = "fido_key_wrap._native")]
pub struct AuthenticatorReport {
    #[pyo3(get)]
    compatible: bool,
    issues: Vec<AuthenticatorIssue>,
}

#[pymethods]
impl AuthenticatorReport {
    #[getter]
    fn issues<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        PyTuple::new(py, self.issues.iter().copied())
    }
}

#[pyfunction]
/// inspects connected authenticators without returning device identity.
pub fn inspect_authenticators(py: Python<'_>) -> PyResult<Vec<AuthenticatorReport>> {
    #[cfg(feature = "fido")]
    {
        py.detach(fido_key_wrap::inspect_authenticators)
            .map(|reports| {
                reports
                    .into_iter()
                    .map(|report| AuthenticatorReport {
                        compatible: report.compatible(),
                        issues: report.issues().iter().copied().map(Into::into).collect(),
                    })
                    .collect()
            })
            .map_err(|error| map_error(py, &error))
    }
    #[cfg(not(feature = "fido"))]
    {
        Err(unavailable_error(py))
    }
}
