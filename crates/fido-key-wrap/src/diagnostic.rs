use fido_key_wrap_libfido2 as native;

use crate::{AuthenticatorFailure, Error, Result};

/// one bounded read-only authenticator capability report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatorReport {
    compatible: bool,
    issues: Vec<AuthenticatorIssue>,
}

impl AuthenticatorReport {
    /// reports whether the authenticator supports every recovery policy.
    #[must_use]
    pub const fn compatible(&self) -> bool {
        self.compatible
    }

    /// returns capability limitations without device identity.
    #[must_use]
    pub fn issues(&self) -> &[AuthenticatorIssue] {
        &self.issues
    }
}

/// capability preventing one or more recovery policies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AuthenticatorIssue {
    /// the authenticator could not be opened or inspected.
    Unavailable,
    /// ctap2/fido2 operations are unavailable.
    Fido2Unavailable,
    /// es256 credential creation is unavailable.
    Es256Unavailable,
    /// the ctap2 `hmac-secret` extension is unavailable.
    HmacSecretUnavailable,
    /// credential protection is unavailable.
    CredentialProtectionUnavailable,
    /// pin-backed user verification is unavailable.
    UserVerificationUnavailable,
    /// user verification is supported but not configured.
    UserVerificationNotConfigured,
    /// the authenticator cannot preserve an exact presence-only recovery route.
    PresenceRecoveryUnavailable,
}

/// inspects connected authenticators without requesting a pin or touch.
///
/// reports contain no serial number, transport path, vendor/product string, or
/// stable device identity. authenticators that cannot be opened for a capability
/// query are reported only as unavailable.
///
/// # errors
///
/// returns [`Error::Authenticator`] when discovery itself
/// cannot complete.
pub fn inspect_authenticators() -> Result<Vec<AuthenticatorReport>> {
    Ok(native::Backend::default()
        .doctor()
        .map_err(|_| Error::Authenticator(AuthenticatorFailure::OperationFailed))?
        .into_iter()
        .map(|report| match report.status {
            native::DeviceStatus::Compatible(capabilities)
            | native::DeviceStatus::Incompatible { capabilities, .. } => report_for(&capabilities),
            native::DeviceStatus::Unavailable(_) => AuthenticatorReport {
                compatible: false,
                issues: vec![AuthenticatorIssue::Unavailable],
            },
        })
        .collect())
}

fn report_for(capabilities: &native::Capabilities) -> AuthenticatorReport {
    let mut issues = Vec::new();
    if !capabilities.fido2 {
        issues.push(AuthenticatorIssue::Fido2Unavailable);
    }
    if !capabilities.es256 {
        issues.push(AuthenticatorIssue::Es256Unavailable);
    }
    if !capabilities.hmac_secret {
        issues.push(AuthenticatorIssue::HmacSecretUnavailable);
    }
    if !capabilities.credential_protection {
        issues.push(AuthenticatorIssue::CredentialProtectionUnavailable);
    }
    if !capabilities.client_pin_supported {
        issues.push(AuthenticatorIssue::UserVerificationUnavailable);
    } else if !capabilities.client_pin_configured {
        issues.push(AuthenticatorIssue::UserVerificationNotConfigured);
    }
    if capabilities.always_uv {
        issues.push(AuthenticatorIssue::PresenceRecoveryUnavailable);
    }
    AuthenticatorReport {
        compatible: issues.is_empty(),
        issues,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete() -> native::Capabilities {
        native::Capabilities {
            fido2: true,
            hmac_secret: true,
            credential_protection: true,
            es256: true,
            client_pin_supported: true,
            client_pin_configured: true,
            internal_uv_supported: false,
            internal_uv_configured: false,
            always_uv: false,
        }
    }

    #[test]
    fn report_contains_only_bounded_capability_results() {
        let report = report_for(&complete());
        assert!(report.compatible());
        assert!(report.issues().is_empty());

        let mut limited = complete();
        limited.hmac_secret = false;
        limited.always_uv = true;
        let report = report_for(&limited);
        assert!(!report.compatible());
        assert_eq!(
            report.issues(),
            [
                AuthenticatorIssue::HmacSecretUnavailable,
                AuthenticatorIssue::PresenceRecoveryUnavailable
            ]
        );
    }

    #[test]
    fn unavailable_issue_contains_no_native_detail() {
        let report = AuthenticatorReport {
            compatible: false,
            issues: vec![AuthenticatorIssue::Unavailable],
        };
        assert_eq!(report.issues(), [AuthenticatorIssue::Unavailable]);
    }
}
