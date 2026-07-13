use std::fmt;

use zeroize::Zeroizing;

use crate::{
    ApplicationId, AuthenticatorIssue, AuthenticatorReport, Interaction, Operation, PinPrompt,
    RecipientPolicy, Result, SelectionPrompt, TokenPolicy, TouchPrompt, envelope::PublicKey64,
};

use fido_key_wrap_libfido2 as native;

pub(crate) struct CredentialMaterial {
    pub(crate) credential_id: Vec<u8>,
    pub(crate) public_key: PublicKey64,
    pub(crate) credential_protection: u8,
}

pub(crate) struct PrfRequest<'a> {
    pub(crate) application_id: &'a ApplicationId,
    pub(crate) credential_id: &'a [u8],
    pub(crate) public_key: &'a PublicKey64,
    pub(crate) policy: RecipientPolicy,
    pub(crate) input: &'a [u8; 32],
    pub(crate) label: &'a str,
    pub(crate) operation: Operation,
}

pub(crate) trait AuthenticatorBackend {
    fn inspect(&self) -> Result<Vec<AuthenticatorReport>>;

    fn enroll(
        &mut self,
        application_id: &ApplicationId,
        policy: RecipientPolicy,
        label: &str,
        interaction: &mut dyn Interaction,
    ) -> Result<CredentialMaterial>;

    fn evaluate_prf(
        &mut self,
        request: PrfRequest<'_>,
        interaction: &mut dyn Interaction,
    ) -> Result<Zeroizing<[u8; 32]>>;
}

pub(crate) struct NativeBackend {
    backend: native::Backend,
}

impl NativeBackend {
    pub(crate) fn new() -> Self {
        Self {
            backend: native::Backend::default(),
        }
    }

    fn select(
        &self,
        application_id: &ApplicationId,
        operation: Operation,
        interaction: &mut dyn Interaction,
    ) -> Result<native::Authenticator> {
        let selection = self.backend.prepare_selection().map_err(map_native_error)?;
        let compatible = selection.compatible_authenticators();
        if compatible > 1 {
            interaction
                .select_authenticator_by_touch(&SelectionPrompt {
                    application_id: application_id.clone(),
                    operation,
                    compatible_authenticators: compatible,
                })
                .map_err(crate::Error::from)?;
        }
        selection.select().map_err(map_native_error)
    }
}

impl fmt::Debug for NativeBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeBackend").finish_non_exhaustive()
    }
}

impl AuthenticatorBackend for NativeBackend {
    fn inspect(&self) -> Result<Vec<AuthenticatorReport>> {
        self.backend
            .doctor()
            .map_err(map_native_error)?
            .into_iter()
            .map(|report| {
                let (available, capabilities, issue) = match report.status {
                    native::DeviceStatus::Compatible(capabilities)
                    | native::DeviceStatus::Incompatible { capabilities, .. } => {
                        (true, Some(capabilities), None)
                    }
                    native::DeviceStatus::Unavailable(error) => {
                        (false, None, Some(native_issue(&error)))
                    }
                };
                let capabilities = capabilities.unwrap_or(native::Capabilities {
                    fido2: false,
                    hmac_secret: false,
                    credential_protection: false,
                    es256: false,
                    client_pin_supported: false,
                    client_pin_configured: false,
                    internal_uv_supported: false,
                    internal_uv_configured: false,
                    always_uv: false,
                });
                Ok(AuthenticatorReport {
                    manufacturer: report.manufacturer,
                    product: report.product,
                    available,
                    compatible: capabilities.compatible(),
                    fido2: capabilities.fido2,
                    hmac_secret: capabilities.hmac_secret,
                    credential_protection: capabilities.credential_protection,
                    es256: capabilities.es256,
                    pin_supported: capabilities.client_pin_supported,
                    pin_configured: capabilities.client_pin_configured,
                    always_uv: capabilities.always_uv,
                    issue,
                })
            })
            .collect()
    }

    fn enroll(
        &mut self,
        application_id: &ApplicationId,
        policy: RecipientPolicy,
        label: &str,
        interaction: &mut dyn Interaction,
    ) -> Result<CredentialMaterial> {
        let mut authenticator = self.select(application_id, Operation::Enroll, interaction)?;
        if policy.token == TokenPolicy::Presence
            && !authenticator.capabilities().supports_presence_policy()
        {
            return Err(crate::Error::AuthenticatorPolicyChanged {
                expected: TokenPolicy::Presence,
            });
        }
        let pin = interaction
            .request_pin(&PinPrompt {
                application_id: application_id.clone(),
                operation: Operation::Enroll,
            })
            .map_err(crate::Error::from)?;
        let native_pin = native::Pin::new(pin.as_str()).map_err(map_native_error)?;
        interaction
            .touch_required(&TouchPrompt {
                application_id: application_id.clone(),
                operation: Operation::Enroll,
                recipient_label: label.to_owned(),
                policy,
            })
            .map_err(crate::Error::from)?;
        let enrolled = authenticator
            .enroll(
                native::EnrollmentRequest {
                    relying_party_id: application_id.as_str(),
                    relying_party_name: "FIDO Key Wrap",
                    policy: native_policy(policy.token),
                },
                &native_pin,
            )
            .map_err(map_native_error)?;
        Ok(CredentialMaterial {
            credential_id: enrolled.credential_id,
            public_key: PublicKey64::new(enrolled.es256_public_key)
                .map_err(|_| crate::Error::AuthenticatorResponseInvalid)?,
            credential_protection: match enrolled.protection {
                native::CredentialProtection::OptionalWithCredentialId => 2,
                native::CredentialProtection::UserVerificationRequired => 3,
            },
        })
    }

    fn evaluate_prf(
        &mut self,
        request: PrfRequest<'_>,
        interaction: &mut dyn Interaction,
    ) -> Result<Zeroizing<[u8; 32]>> {
        let mut authenticator =
            self.select(request.application_id, request.operation, interaction)?;
        if request.policy.token == TokenPolicy::Presence
            && !authenticator.capabilities().supports_presence_policy()
        {
            return Err(crate::Error::AuthenticatorPolicyChanged {
                expected: TokenPolicy::Presence,
            });
        }
        let pin = if request.policy.token == TokenPolicy::UserVerified {
            let pin = interaction
                .request_pin(&PinPrompt {
                    application_id: request.application_id.clone(),
                    operation: request.operation,
                })
                .map_err(crate::Error::from)?;
            Some(native::Pin::new(pin.as_str()).map_err(map_native_error)?)
        } else {
            None
        };
        interaction
            .touch_required(&TouchPrompt {
                application_id: request.application_id.clone(),
                operation: request.operation,
                recipient_label: request.label.to_owned(),
                policy: request.policy,
            })
            .map_err(crate::Error::from)?;
        authenticator
            .evaluate(
                native::PrfRequest {
                    relying_party_id: request.application_id.as_str(),
                    credential_id: request.credential_id,
                    es256_public_key: &request.public_key.0,
                    salt: request.input,
                    policy: native_policy(request.policy.token),
                },
                pin.as_ref(),
            )
            .map_err(map_native_error)
    }
}

const fn native_policy(policy: TokenPolicy) -> native::ExactPolicy {
    match policy {
        TokenPolicy::Presence => native::ExactPolicy::Presence,
        TokenPolicy::UserVerified => native::ExactPolicy::UserVerified,
    }
}

#[allow(clippy::needless_pass_by_value)]
fn map_native_error(error: native::Error) -> crate::Error {
    match error {
        native::Error::NoAuthenticators | native::Error::NoCompatibleAuthenticators => {
            crate::Error::NoCompatibleAuthenticator
        }
        native::Error::PinInvalid { retries } => crate::Error::PinInvalid {
            retries_remaining: retries,
        },
        native::Error::PinBlocked => crate::Error::PinBlocked,
        native::Error::PinAuthBlocked => crate::Error::PinAuthBlocked,
        native::Error::PinRequired => crate::Error::PinNotConfigured,
        native::Error::SelectionTimedOut | native::Error::TimedOut => crate::Error::TimedOut,
        native::Error::Busy => crate::Error::AuthenticatorBusy,
        native::Error::Transport => crate::Error::AuthenticatorUnavailable,
        native::Error::CredentialNotFound => crate::Error::WrongAuthenticator,
        native::Error::Unsupported => crate::Error::UnsupportedAuthenticator,
        native::Error::VerificationFailed | native::Error::Protocol => {
            crate::Error::AuthenticatorResponseInvalid
        }
        native::Error::UserAction => crate::Error::Cancelled,
        native::Error::RandomUnavailable => crate::Error::Random,
        _ => crate::Error::Backend,
    }
}

const fn native_issue(error: &native::Error) -> AuthenticatorIssue {
    match error {
        native::Error::Busy => AuthenticatorIssue::Busy,
        native::Error::SelectionTimedOut | native::Error::TimedOut => AuthenticatorIssue::TimedOut,
        native::Error::Transport => AuthenticatorIssue::Inaccessible,
        _ => AuthenticatorIssue::Backend,
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use std::collections::HashMap;

    use hmac::{Hmac, Mac};
    use p256::{ProjectivePoint, elliptic_curve::sec1::ToSec1Point};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{
        PassphrasePrompt, PinPrompt, SelectionPrompt, TouchPrompt, interaction::InteractionError,
    };

    struct FakeCredential {
        presence_root: [u8; 32],
        verified_root: [u8; 32],
    }

    pub(crate) struct FakeBackend {
        next_id: u64,
        credentials: HashMap<Vec<u8>, FakeCredential>,
    }

    impl FakeBackend {
        pub(crate) fn new() -> Self {
            Self {
                next_id: 1,
                credentials: HashMap::new(),
            }
        }
    }

    impl AuthenticatorBackend for FakeBackend {
        fn inspect(&self) -> Result<Vec<AuthenticatorReport>> {
            Ok(vec![AuthenticatorReport {
                manufacturer: Some("Test".to_owned()),
                product: Some("Deterministic fake authenticator".to_owned()),
                available: true,
                compatible: true,
                fido2: true,
                hmac_secret: true,
                credential_protection: true,
                es256: true,
                pin_supported: true,
                pin_configured: true,
                always_uv: false,
                issue: None,
            }])
        }

        fn enroll(
            &mut self,
            application_id: &ApplicationId,
            policy: RecipientPolicy,
            label: &str,
            interaction: &mut dyn Interaction,
        ) -> Result<CredentialMaterial> {
            interaction
                .select_authenticator_by_touch(&SelectionPrompt {
                    application_id: application_id.clone(),
                    operation: Operation::Enroll,
                    compatible_authenticators: 1,
                })
                .map_err(crate::Error::from)?;
            let _pin = interaction
                .request_pin(&PinPrompt {
                    application_id: application_id.clone(),
                    operation: Operation::Enroll,
                })
                .map_err(crate::Error::from)?;
            interaction
                .touch_required(&TouchPrompt {
                    application_id: application_id.clone(),
                    operation: Operation::Enroll,
                    recipient_label: label.to_owned(),
                    policy,
                })
                .map_err(crate::Error::from)?;

            let id_number = self.next_id;
            self.next_id += 1;
            let mut credential_id = b"fake-credential-v1".to_vec();
            credential_id.extend_from_slice(&id_number.to_be_bytes());
            let presence_root: [u8; 32] = Sha256::digest(
                [b"fake-presence-root".as_slice(), &id_number.to_be_bytes()].concat(),
            )
            .into();
            let verified_root: [u8; 32] = Sha256::digest(
                [b"fake-verified-root".as_slice(), &id_number.to_be_bytes()].concat(),
            )
            .into();
            self.credentials.insert(
                credential_id.clone(),
                FakeCredential {
                    presence_root,
                    verified_root,
                },
            );

            let point = ProjectivePoint::GENERATOR.to_affine().to_sec1_point(false);
            let public_bytes: [u8; 64] = point.as_bytes()[1..]
                .try_into()
                .expect("uncompressed P-256 point has 64 coordinate bytes");
            Ok(CredentialMaterial {
                credential_id,
                public_key: PublicKey64::new(public_bytes)?,
                credential_protection: match policy.token {
                    TokenPolicy::Presence => 2,
                    TokenPolicy::UserVerified => 3,
                },
            })
        }

        fn evaluate_prf(
            &mut self,
            request: PrfRequest<'_>,
            interaction: &mut dyn Interaction,
        ) -> Result<Zeroizing<[u8; 32]>> {
            let credential = self
                .credentials
                .get(request.credential_id)
                .ok_or(crate::Error::WrongAuthenticator)?;
            let _ = request.public_key;
            interaction
                .select_authenticator_by_touch(&SelectionPrompt {
                    application_id: request.application_id.clone(),
                    operation: request.operation,
                    compatible_authenticators: 1,
                })
                .map_err(crate::Error::from)?;
            if request.policy.token == TokenPolicy::UserVerified {
                let _pin = interaction
                    .request_pin(&PinPrompt {
                        application_id: request.application_id.clone(),
                        operation: request.operation,
                    })
                    .map_err(crate::Error::from)?;
            }
            interaction
                .touch_required(&TouchPrompt {
                    application_id: request.application_id.clone(),
                    operation: request.operation,
                    recipient_label: request.label.to_owned(),
                    policy: request.policy,
                })
                .map_err(crate::Error::from)?;
            let root = match request.policy.token {
                TokenPolicy::Presence => &credential.presence_root,
                TokenPolicy::UserVerified => &credential.verified_root,
            };
            let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(root)
                .expect("HMAC accepts a 32-byte key");
            mac.update(request.input);
            Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
        }
    }

    pub(crate) struct TestInteraction {
        pub(crate) passphrase: Vec<u8>,
        pub(crate) confirmation: Option<Vec<u8>>,
        pub(crate) cancel_on_touch: Option<usize>,
        pub(crate) pin_requests: usize,
        pub(crate) touch_requests: usize,
        pub(crate) passphrase_requests: usize,
        pub(crate) pin_operations: Vec<Operation>,
        pub(crate) touch_operations: Vec<Operation>,
        pub(crate) passphrase_operations: Vec<Operation>,
        pub(crate) touch_policies: Vec<RecipientPolicy>,
    }

    impl TestInteraction {
        pub(crate) fn new(passphrase: &[u8]) -> Self {
            Self {
                passphrase: passphrase.to_vec(),
                confirmation: None,
                cancel_on_touch: None,
                pin_requests: 0,
                touch_requests: 0,
                passphrase_requests: 0,
                pin_operations: Vec::new(),
                touch_operations: Vec::new(),
                passphrase_operations: Vec::new(),
                touch_policies: Vec::new(),
            }
        }
    }

    impl Interaction for TestInteraction {
        fn select_authenticator_by_touch(
            &mut self,
            _prompt: &SelectionPrompt,
        ) -> std::result::Result<(), InteractionError> {
            Ok(())
        }

        fn request_pin(
            &mut self,
            prompt: &PinPrompt,
        ) -> std::result::Result<crate::Pin, InteractionError> {
            self.pin_requests += 1;
            self.pin_operations.push(prompt.operation);
            crate::Pin::new("123456".to_owned()).map_err(|_| InteractionError::Failed)
        }

        fn request_passphrase(
            &mut self,
            prompt: &PassphrasePrompt,
        ) -> std::result::Result<crate::Passphrase, InteractionError> {
            self.passphrase_requests += 1;
            self.passphrase_operations.push(prompt.operation);
            let value = if prompt.confirm {
                self.confirmation
                    .as_ref()
                    .unwrap_or(&self.passphrase)
                    .clone()
            } else {
                self.passphrase.clone()
            };
            crate::Passphrase::new(value).map_err(|_| InteractionError::Failed)
        }

        fn touch_required(
            &mut self,
            prompt: &TouchPrompt,
        ) -> std::result::Result<(), InteractionError> {
            self.touch_requests += 1;
            self.touch_operations.push(prompt.operation);
            self.touch_policies.push(prompt.policy);
            if self.cancel_on_touch == Some(self.touch_requests) {
                return Err(InteractionError::Cancelled);
            }
            Ok(())
        }
    }
}
