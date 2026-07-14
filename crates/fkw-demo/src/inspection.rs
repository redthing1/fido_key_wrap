use anyhow::Result;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InspectionReport {
    pub(crate) compatible: bool,
    pub(crate) issues: Vec<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum Inspection {
    SupportUnavailable,
    Reports(Vec<InspectionReport>),
}

pub(crate) trait AuthenticatorInspection {
    fn inspect(&mut self) -> Result<Inspection>;
}

pub(crate) struct ProductionInspection;

impl AuthenticatorInspection for ProductionInspection {
    #[cfg(not(feature = "fido"))]
    fn inspect(&mut self) -> Result<Inspection> {
        Ok(Inspection::SupportUnavailable)
    }

    #[cfg(feature = "fido")]
    fn inspect(&mut self) -> Result<Inspection> {
        use fido_key_wrap::AuthenticatorIssue;

        let reports = fido_key_wrap::inspect_authenticators()?
            .into_iter()
            .map(|report| InspectionReport {
                compatible: report.compatible(),
                issues: report
                    .issues()
                    .iter()
                    .map(|issue| match issue {
                        AuthenticatorIssue::Unavailable => {
                            "the security key is unavailable or inaccessible"
                        }
                        AuthenticatorIssue::Fido2Unavailable => "fido2 is unavailable",
                        AuthenticatorIssue::Es256Unavailable => "es256 is unavailable",
                        AuthenticatorIssue::HmacSecretUnavailable => "hmac-secret is unavailable",
                        AuthenticatorIssue::CredentialProtectionUnavailable => {
                            "credential protection is unavailable"
                        }
                        AuthenticatorIssue::UserVerificationUnavailable => {
                            "user verification is unavailable"
                        }
                        AuthenticatorIssue::UserVerificationNotConfigured => {
                            "user verification is not configured"
                        }
                        AuthenticatorIssue::PresenceRecoveryUnavailable => {
                            "exact presence-only recovery is unavailable"
                        }
                        _ => "an unknown capability is unavailable",
                    })
                    .collect(),
            })
            .collect();
        Ok(Inspection::Reports(reports))
    }
}
