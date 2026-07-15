use zeroize::Zeroizing;

use crate::RecipientId;
#[cfg(any(feature = "testing", test))]
use crate::policy::FidoStorage;
use crate::{
    ApplicationId, Error, Interaction, Operation, Result, envelope::PublicKey64, policy::FidoPolicy,
};

#[cfg(any(feature = "fido", feature = "testing", test))]
use crate::AuthenticatorFailure;
#[cfg(feature = "fido")]
use crate::FidoConfig;

#[cfg(any(feature = "fido", feature = "testing", test))]
use crate::interaction::{FidoCeremony, PinPrompt, SelectionPrompt, TouchPrompt};

#[cfg(feature = "fido")]
use fido_key_wrap_libfido2 as native;

const PRF_RESULT_BYTES: usize = 32;

pub(crate) struct CredentialMaterial {
    pub(crate) credential_id: Vec<u8>,
    pub(crate) public_key: PublicKey64,
}

#[derive(Clone, Copy)]
#[cfg_attr(
    not(any(feature = "fido", feature = "testing", test)),
    allow(dead_code)
)]
pub(crate) struct CredentialBinding<'a> {
    pub(crate) application_id: &'a ApplicationId,
    pub(crate) recipient_id: RecipientId,
    pub(crate) credential_id: &'a [u8],
    pub(crate) public_key: &'a PublicKey64,
    pub(crate) policy: FidoPolicy,
    pub(crate) label: &'a str,
}

#[cfg_attr(
    not(any(feature = "fido", feature = "testing", test)),
    allow(dead_code)
)]
pub(crate) struct ManagedRequest<'a> {
    pub(crate) credential: CredentialBinding<'a>,
    pub(crate) operation: Operation,
}

pub(crate) struct ManagedEnrollment {
    pub(crate) credential: CredentialMaterial,
    pub(crate) policy: FidoPolicy,
    session: ManagedSession,
}

enum ManagedSession {
    #[cfg(feature = "fido")]
    Native {
        authenticator: native::Authenticator,
        pin: native::Pin,
        cleanup: Box<native::PendingManagedCredential>,
    },
    #[cfg(any(feature = "testing", test))]
    Fake { device: usize },
}

#[cfg_attr(
    not(any(feature = "fido", feature = "testing", test)),
    allow(dead_code)
)]
pub(crate) struct PrfRequest<'a> {
    pub(crate) credential: CredentialBinding<'a>,
    pub(crate) input: &'a [u8; PRF_RESULT_BYTES],
    pub(crate) operation: Operation,
}

pub(crate) enum AuthenticatorBackend {
    Unavailable,
    #[cfg(feature = "fido")]
    Native(NativeBackend),
    #[cfg(any(feature = "testing", test))]
    Fake(fake::FakeBackend),
}

impl AuthenticatorBackend {
    pub(crate) const fn unavailable() -> Self {
        Self::Unavailable
    }

    #[cfg(feature = "fido")]
    pub(crate) fn system(config: FidoConfig) -> Self {
        Self::Native(NativeBackend::new(config))
    }

    #[cfg(any(feature = "testing", test))]
    pub(crate) fn fake() -> Self {
        Self::Fake(fake::FakeBackend::new())
    }

    pub(crate) fn enroll(
        &mut self,
        application_id: &ApplicationId,
        policy: FidoPolicy,
        label: &str,
        operation: Operation,
        interaction: &mut dyn Interaction,
    ) -> Result<CredentialMaterial> {
        #[cfg(not(any(feature = "fido", feature = "testing", test)))]
        let _ = (application_id, policy, label, operation, &interaction);
        match self {
            Self::Unavailable => Err(Error::FidoSupportUnavailable),
            #[cfg(feature = "fido")]
            Self::Native(backend) => {
                backend.enroll(application_id, policy, label, operation, interaction)
            }
            #[cfg(any(feature = "testing", test))]
            Self::Fake(backend) => {
                backend.enroll(application_id, policy, label, operation, interaction)
            }
        }
    }

    pub(crate) fn enroll_managed(
        &mut self,
        application_id: &ApplicationId,
        recipient_id: RecipientId,
        policy: FidoPolicy,
        label: &str,
        operation: Operation,
        interaction: &mut dyn Interaction,
    ) -> Result<ManagedEnrollment> {
        #[cfg(not(any(feature = "fido", feature = "testing", test)))]
        let _ = (
            application_id,
            recipient_id,
            policy,
            label,
            operation,
            &interaction,
        );
        match self {
            Self::Unavailable => Err(Error::FidoSupportUnavailable),
            #[cfg(feature = "fido")]
            Self::Native(backend) => backend.enroll_managed(
                application_id,
                recipient_id,
                policy,
                label,
                operation,
                interaction,
            ),
            #[cfg(any(feature = "testing", test))]
            Self::Fake(backend) => backend.enroll_managed(
                application_id,
                recipient_id,
                policy,
                label,
                operation,
                interaction,
            ),
        }
    }

    pub(crate) fn evaluate(
        &mut self,
        request: &PrfRequest<'_>,
        interaction: &mut dyn Interaction,
    ) -> Result<Zeroizing<[u8; PRF_RESULT_BYTES]>> {
        #[cfg(not(any(feature = "fido", feature = "testing", test)))]
        let _ = (request, &interaction);
        match self {
            Self::Unavailable => Err(Error::FidoSupportUnavailable),
            #[cfg(feature = "fido")]
            Self::Native(backend) => backend.evaluate(request, interaction),
            #[cfg(any(feature = "testing", test))]
            Self::Fake(backend) => backend.evaluate(request, interaction),
        }
    }

    pub(crate) fn verify_managed(
        &mut self,
        request: &ManagedRequest<'_>,
        interaction: &mut dyn Interaction,
    ) -> Result<()> {
        #[cfg(not(any(feature = "fido", feature = "testing", test)))]
        let _ = (request, &interaction);
        match self {
            Self::Unavailable => Err(Error::FidoSupportUnavailable),
            #[cfg(feature = "fido")]
            Self::Native(backend) => backend.verify_managed(request, interaction),
            #[cfg(any(feature = "testing", test))]
            Self::Fake(backend) => backend.verify_managed(request, interaction),
        }
    }

    pub(crate) fn retire_managed(
        &mut self,
        request: &ManagedRequest<'_>,
        interaction: &mut dyn Interaction,
    ) -> Result<()> {
        #[cfg(not(any(feature = "fido", feature = "testing", test)))]
        let _ = (request, &interaction);
        match self {
            Self::Unavailable => Err(Error::FidoSupportUnavailable),
            #[cfg(feature = "fido")]
            Self::Native(backend) => backend.retire_managed(request, interaction),
            #[cfg(any(feature = "testing", test))]
            Self::Fake(backend) => backend.retire_managed(request, interaction),
        }
    }

    pub(crate) fn evaluate_managed_enrollment(
        &mut self,
        enrollment: &mut ManagedEnrollment,
        request: &PrfRequest<'_>,
        interaction: &mut dyn Interaction,
    ) -> Result<Zeroizing<[u8; PRF_RESULT_BYTES]>> {
        #[cfg(not(any(feature = "fido", feature = "testing", test)))]
        let _ = (request, interaction);
        match (&mut enrollment.session, self) {
            #[cfg(feature = "fido")]
            (
                ManagedSession::Native {
                    authenticator, pin, ..
                },
                Self::Native(_),
            ) => evaluate_native_managed(authenticator, pin, request, interaction),
            #[cfg(any(feature = "testing", test))]
            (ManagedSession::Fake { device }, Self::Fake(backend)) => {
                backend.evaluate_managed_on_device(*device, request, interaction)
            }
            #[allow(unreachable_patterns)]
            _ => Err(Error::AuthenticatorResponseInvalid),
        }
    }

    pub(crate) fn cleanup_managed_enrollment(
        &mut self,
        enrollment: &mut ManagedEnrollment,
        request: &ManagedRequest<'_>,
        interaction: &mut dyn Interaction,
    ) -> Result<()> {
        #[cfg(not(any(feature = "fido", feature = "testing", test)))]
        let _ = (request, interaction);
        match (&mut enrollment.session, self) {
            #[cfg(feature = "fido")]
            (
                ManagedSession::Native {
                    authenticator,
                    pin,
                    cleanup,
                },
                Self::Native(_),
            ) => {
                cleanup_native_managed_enrollment(authenticator, pin, cleanup, request, interaction)
            }
            #[cfg(any(feature = "testing", test))]
            (ManagedSession::Fake { device }, Self::Fake(backend)) => {
                backend.cleanup_managed_enrollment_on_device(*device, request, interaction)
            }
            #[allow(unreachable_patterns)]
            _ => Err(Error::AuthenticatorResponseInvalid),
        }
    }

    #[cfg(any(feature = "testing", test))]
    pub(crate) fn fake_mut(&mut self) -> &mut fake::FakeBackend {
        match self {
            Self::Fake(backend) => backend,
            Self::Unavailable => panic!("backend is unavailable, not fake"),
            #[cfg(feature = "fido")]
            Self::Native(_) => panic!("backend is native, not fake"),
        }
    }
}

#[cfg(feature = "fido")]
pub(crate) struct NativeBackend {
    backend: native::Backend,
}

#[cfg(feature = "fido")]
impl NativeBackend {
    fn new(config: FidoConfig) -> Self {
        let native_config = native::Config::new(
            config.operation_timeout(),
            config.selection_timeout(),
            config.max_devices(),
        )
        .expect("safe fido configuration satisfies native bounds");
        Self {
            backend: native::Backend::new(native_config),
        }
    }

    fn select(
        &self,
        operation: Operation,
        label: &str,
        policy: FidoPolicy,
        interaction: &mut dyn Interaction,
    ) -> Result<native::Authenticator> {
        let selection = self
            .backend
            .prepare_selection(native_policy(policy))
            .map_err(|error| map_native_error(&error))?;
        if selection.compatible_authenticators() > 1 {
            interaction
                .select_authenticator_by_touch(&SelectionPrompt::new(operation, label, policy))?;
        }
        let authenticator = selection
            .select()
            .map_err(|error| map_native_error(&error))?;
        let supports_policy = match policy {
            FidoPolicy::Presence => authenticator.capabilities().supports_presence_policy(),
            FidoPolicy::UserVerification => authenticator.capabilities().supports_verified_policy(),
        };
        if !supports_policy {
            return Err(Error::NoCompatibleAuthenticator);
        }
        Ok(authenticator)
    }

    fn select_managed(
        &self,
        operation: Operation,
        label: &str,
        policy: FidoPolicy,
        capability: native::ManagedCapability,
        interaction: &mut dyn Interaction,
    ) -> Result<native::Authenticator> {
        let selection = self
            .backend
            .prepare_managed_selection(capability)
            .map_err(|error| map_native_error(&error))?;
        if selection.compatible_authenticators() > 1 {
            interaction
                .select_authenticator_by_touch(&SelectionPrompt::new(operation, label, policy))?;
        }
        selection.select().map_err(|error| map_native_error(&error))
    }

    fn enroll(
        &mut self,
        application_id: &ApplicationId,
        policy: FidoPolicy,
        label: &str,
        operation: Operation,
        interaction: &mut dyn Interaction,
    ) -> Result<CredentialMaterial> {
        let mut authenticator = self.select(operation, label, policy, interaction)?;

        // Credential creation always uses UV. The policy controls the exact
        // credProtect level and the separate recovery assertion that follows.
        let pin =
            interaction.request_pin(&PinPrompt::new(operation, label, FidoCeremony::Enrollment))?;
        let native_pin =
            native::Pin::new(pin.as_str()).map_err(|error| map_native_error(&error))?;
        drop(pin);
        interaction.touch_required(&TouchPrompt::new(
            operation,
            label,
            FidoCeremony::Enrollment,
            policy,
        ))?;
        let enrolled = match authenticator.enroll(
            native::EnrollmentRequest {
                relying_party_id: application_id.as_str(),
                relying_party_name: "fido key wrap",
                policy: native_policy(policy),
                storage: native::CredentialStorage::NonDiscoverable,
            },
            &native_pin,
        ) {
            Ok(enrolled) => enrolled,
            Err(failure) => {
                let (error, managed_cleanup) = failure.into_parts();
                if managed_cleanup.is_some() {
                    return Err(AuthenticatorFailure::CredentialMayRemain.into());
                }
                return Err(map_native_error(&error));
            }
        };
        drop(native_pin);

        let protection_matches = matches!(
            (policy, enrolled.credential().protection),
            (
                FidoPolicy::Presence,
                native::CredentialProtection::OptionalWithCredentialId
            ) | (
                FidoPolicy::UserVerification,
                native::CredentialProtection::UserVerificationRequired
            )
        );
        if !protection_matches {
            return Err(Error::AuthenticatorResponseInvalid);
        }
        let public_key = PublicKey64::new(enrolled.credential().es256_public_key)
            .map_err(|_| Error::AuthenticatorResponseInvalid)?;
        let (credential, managed_cleanup) = enrolled.into_parts();
        if managed_cleanup.is_some() {
            return Err(AuthenticatorFailure::CredentialMayRemain.into());
        }
        Ok(CredentialMaterial {
            credential_id: credential.credential_id,
            public_key,
        })
    }

    fn enroll_managed(
        &mut self,
        application_id: &ApplicationId,
        recipient_id: RecipientId,
        policy: FidoPolicy,
        label: &str,
        operation: Operation,
        interaction: &mut dyn Interaction,
    ) -> Result<ManagedEnrollment> {
        let mut authenticator = self.select_managed(
            operation,
            label,
            policy,
            native::ManagedCapability::Enrollment(native_policy(policy)),
            interaction,
        )?;
        let pin =
            interaction.request_pin(&PinPrompt::new(operation, label, FidoCeremony::Enrollment))?;
        let native_pin =
            native::Pin::new(pin.as_str()).map_err(|error| map_native_error(&error))?;
        drop(pin);
        interaction.touch_required(&TouchPrompt::new(
            operation,
            label,
            FidoCeremony::Enrollment,
            policy,
        ))?;
        let enrolled = authenticator.enroll(
            native::EnrollmentRequest {
                relying_party_id: application_id.as_str(),
                relying_party_name: "fido key wrap",
                policy: native_policy(policy),
                storage: native::CredentialStorage::ManagedDiscoverable {
                    user_id: recipient_id.as_bytes(),
                },
            },
            &native_pin,
        );
        let enrolled = match enrolled {
            Ok(enrolled) => enrolled,
            Err(failure) => {
                let (error, pending) = failure.into_parts();
                let original = map_native_error(&error);
                let Some(pending) = pending else {
                    return Err(original);
                };
                return reject_pending_managed(
                    &mut authenticator,
                    &native_pin,
                    &pending,
                    label,
                    policy,
                    original,
                    interaction,
                );
            }
        };
        let expected_protection = native_protection(policy);
        if enrolled.credential().protection != expected_protection {
            return reject_created_managed(
                &mut authenticator,
                &native_pin,
                enrolled,
                label,
                policy,
                Error::AuthenticatorResponseInvalid,
                interaction,
            );
        }
        let Ok(public_key) = PublicKey64::new(enrolled.credential().es256_public_key) else {
            return reject_created_managed(
                &mut authenticator,
                &native_pin,
                enrolled,
                label,
                policy,
                Error::AuthenticatorResponseInvalid,
                interaction,
            );
        };
        let (credential, cleanup) = enrolled.into_parts();
        let cleanup = cleanup.ok_or(AuthenticatorFailure::CredentialMayRemain)?;
        Ok(ManagedEnrollment {
            credential: CredentialMaterial {
                credential_id: credential.credential_id,
                public_key,
            },
            policy,
            session: ManagedSession::Native {
                authenticator,
                pin: native_pin,
                cleanup,
            },
        })
    }

    fn evaluate(
        &mut self,
        request: &PrfRequest<'_>,
        interaction: &mut dyn Interaction,
    ) -> Result<Zeroizing<[u8; PRF_RESULT_BYTES]>> {
        let mut authenticator = self.select(
            request.operation,
            request.credential.label,
            request.credential.policy,
            interaction,
        )?;
        let pin = match request.credential.policy {
            FidoPolicy::Presence => None,
            FidoPolicy::UserVerification => {
                let pin = interaction.request_pin(&PinPrompt::new(
                    request.operation,
                    request.credential.label,
                    FidoCeremony::Assertion,
                ))?;
                let native_pin =
                    native::Pin::new(pin.as_str()).map_err(|error| map_native_error(&error))?;
                drop(pin);
                Some(native_pin)
            }
        };
        interaction.touch_required(&TouchPrompt::new(
            request.operation,
            request.credential.label,
            FidoCeremony::Assertion,
            request.credential.policy,
        ))?;

        // The client-data challenge is fresh for each native call. The PRF
        // input below is a distinct, stable value bound to this record.
        let result = authenticator.evaluate(
            native::PrfRequest {
                relying_party_id: request.credential.application_id.as_str(),
                credential_id: request.credential.credential_id,
                es256_public_key: request.credential.public_key.as_bytes(),
                salt: request.input,
                policy: native_policy(request.credential.policy),
            },
            pin.as_ref(),
        );
        drop(pin);
        result.map_err(|error| map_native_error(&error))
    }

    fn verify_managed(
        &mut self,
        request: &ManagedRequest<'_>,
        interaction: &mut dyn Interaction,
    ) -> Result<()> {
        let mut authenticator = self.select_managed(
            request.operation,
            request.credential.label,
            request.credential.policy,
            native::ManagedCapability::Management,
            interaction,
        )?;
        let pin = request_native_pin(request, interaction)?;
        touch_managed(request, interaction)?;
        authenticator
            .verify_managed(native_managed_credential(request), &pin)
            .map_err(|error| map_native_error(&error))
    }

    fn retire_managed(
        &mut self,
        request: &ManagedRequest<'_>,
        interaction: &mut dyn Interaction,
    ) -> Result<()> {
        let mut authenticator = self.select_managed(
            request.operation,
            request.credential.label,
            request.credential.policy,
            native::ManagedCapability::Management,
            interaction,
        )?;
        let pin = request_native_pin(request, interaction)?;
        retire_native_managed(&mut authenticator, &pin, request, interaction)
    }
}

#[cfg(feature = "fido")]
fn cleanup_native_pending(
    authenticator: &mut native::Authenticator,
    pin: &native::Pin,
    pending: &native::PendingManagedCredential,
    label: &str,
    policy: FidoPolicy,
    interaction: &mut dyn Interaction,
) -> bool {
    let cleanup = match authenticator.prepare_managed_cleanup(pending, pin) {
        Ok(Some(cleanup)) => cleanup,
        Ok(None) => return true,
        Err(_) => return false,
    };
    interaction
        .touch_required(&TouchPrompt::new(
            Operation::RetireManagedRecipient,
            label,
            FidoCeremony::Assertion,
            policy,
        ))
        .is_ok()
        && cleanup.finish().is_ok()
}

#[cfg(feature = "fido")]
fn reject_created_managed(
    authenticator: &mut native::Authenticator,
    pin: &native::Pin,
    enrolled: native::Enrollment,
    label: &str,
    policy: FidoPolicy,
    original: Error,
    interaction: &mut dyn Interaction,
) -> Result<ManagedEnrollment> {
    let (_, Some(pending)) = enrolled.into_parts() else {
        return Err(AuthenticatorFailure::CredentialMayRemain.into());
    };
    reject_pending_managed(
        authenticator,
        pin,
        &pending,
        label,
        policy,
        original,
        interaction,
    )
}

#[cfg(feature = "fido")]
fn reject_pending_managed(
    authenticator: &mut native::Authenticator,
    pin: &native::Pin,
    pending: &native::PendingManagedCredential,
    label: &str,
    policy: FidoPolicy,
    original: Error,
    interaction: &mut dyn Interaction,
) -> Result<ManagedEnrollment> {
    if cleanup_native_pending(authenticator, pin, pending, label, policy, interaction) {
        Err(original)
    } else {
        Err(AuthenticatorFailure::CredentialMayRemain.into())
    }
}

#[cfg(feature = "fido")]
fn request_native_pin(
    request: &ManagedRequest<'_>,
    interaction: &mut dyn Interaction,
) -> Result<native::Pin> {
    let pin = interaction.request_pin(&PinPrompt::new(
        request.operation,
        request.credential.label,
        FidoCeremony::Assertion,
    ))?;
    let native_pin = native::Pin::new(pin.as_str()).map_err(|error| map_native_error(&error))?;
    drop(pin);
    Ok(native_pin)
}

#[cfg(feature = "fido")]
fn touch_managed(request: &ManagedRequest<'_>, interaction: &mut dyn Interaction) -> Result<()> {
    interaction.touch_required(&TouchPrompt::new(
        request.operation,
        request.credential.label,
        FidoCeremony::Assertion,
        request.credential.policy,
    ))?;
    Ok(())
}

#[cfg(feature = "fido")]
fn native_managed_credential<'a>(request: &'a ManagedRequest<'a>) -> native::ManagedCredential<'a> {
    native::ManagedCredential {
        relying_party_id: request.credential.application_id.as_str(),
        user_id: request.credential.recipient_id.as_bytes(),
        credential_id: request.credential.credential_id,
        es256_public_key: request.credential.public_key.as_bytes(),
        protection: native_protection(request.credential.policy),
    }
}

#[cfg(feature = "fido")]
fn evaluate_native_managed(
    authenticator: &mut native::Authenticator,
    pin: &native::Pin,
    request: &PrfRequest<'_>,
    interaction: &mut dyn Interaction,
) -> Result<Zeroizing<[u8; PRF_RESULT_BYTES]>> {
    interaction.touch_required(&TouchPrompt::new(
        request.operation,
        request.credential.label,
        FidoCeremony::Assertion,
        request.credential.policy,
    ))?;
    let managed = ManagedRequest {
        credential: request.credential,
        operation: request.operation,
    };
    authenticator
        .evaluate_managed_enrollment(
            native::PrfRequest {
                relying_party_id: request.credential.application_id.as_str(),
                credential_id: request.credential.credential_id,
                es256_public_key: request.credential.public_key.as_bytes(),
                salt: request.input,
                policy: native_policy(request.credential.policy),
            },
            native_managed_credential(&managed),
            pin,
        )
        .map_err(|error| map_native_error(&error))
}

#[cfg(feature = "fido")]
fn retire_native_managed(
    authenticator: &mut native::Authenticator,
    pin: &native::Pin,
    request: &ManagedRequest<'_>,
    interaction: &mut dyn Interaction,
) -> Result<()> {
    touch_managed(request, interaction)?;
    authenticator
        .retire_managed(native_managed_credential(request), pin)
        .map_err(|error| map_native_error(&error))
}

#[cfg(feature = "fido")]
fn cleanup_native_managed_enrollment(
    authenticator: &mut native::Authenticator,
    pin: &native::Pin,
    cleanup: &native::PendingManagedCredential,
    request: &ManagedRequest<'_>,
    interaction: &mut dyn Interaction,
) -> Result<()> {
    let Some(cleanup) = authenticator
        .prepare_managed_cleanup(cleanup, pin)
        .map_err(|error| map_native_error(&error))?
    else {
        return Ok(());
    };
    touch_managed(request, interaction)?;
    cleanup.finish().map_err(|error| map_native_error(&error))
}

#[cfg(feature = "fido")]
const fn native_policy(policy: FidoPolicy) -> native::ExactPolicy {
    match policy {
        FidoPolicy::Presence => native::ExactPolicy::Presence,
        FidoPolicy::UserVerification => native::ExactPolicy::UserVerified,
    }
}

#[cfg(feature = "fido")]
const fn native_protection(policy: FidoPolicy) -> native::CredentialProtection {
    match policy {
        FidoPolicy::Presence => native::CredentialProtection::OptionalWithCredentialId,
        FidoPolicy::UserVerification => native::CredentialProtection::UserVerificationRequired,
    }
}

#[cfg(feature = "fido")]
fn map_native_error(error: &native::Error) -> Error {
    match error {
        native::Error::NoAuthenticators | native::Error::NoCompatibleAuthenticators => {
            Error::NoCompatibleAuthenticator
        }
        native::Error::VerificationFailed | native::Error::Protocol => {
            Error::AuthenticatorResponseInvalid
        }
        native::Error::RandomUnavailable => Error::RandomUnavailable,
        native::Error::PinInvalid { retries } => {
            AuthenticatorFailure::PinInvalid { retries: *retries }.into()
        }
        native::Error::PinBlocked => AuthenticatorFailure::PinBlocked.into(),
        native::Error::PinAuthBlocked => AuthenticatorFailure::PinTemporarilyBlocked.into(),
        native::Error::SelectionTimedOut | native::Error::TimedOut => {
            AuthenticatorFailure::TimedOut.into()
        }
        native::Error::Busy => AuthenticatorFailure::Busy.into(),
        native::Error::CredentialNotFound => AuthenticatorFailure::CredentialUnavailable.into(),
        native::Error::CredentialStoreFull => AuthenticatorFailure::CredentialStoreFull.into(),
        native::Error::CredentialMayRemain => AuthenticatorFailure::CredentialMayRemain.into(),
        native::Error::CredentialManagementUnsupported => Error::NoCompatibleAuthenticator,
        native::Error::CredentialMismatch => Error::AuthenticatorResponseInvalid,
        native::Error::RetirementUncertain => AuthenticatorFailure::RetirementUncertain.into(),
        native::Error::Transport => AuthenticatorFailure::Transport.into(),
        _ => AuthenticatorFailure::OperationFailed.into(),
    }
}

#[cfg(any(feature = "testing", test))]
pub(crate) mod fake {
    use std::collections::HashMap;

    use hmac::{Hmac, Mac};
    use p256::{ProjectivePoint, elliptic_curve::sec1::ToSec1Point};
    use sha2::{Digest, Sha256};

    use super::{
        ApplicationId, AuthenticatorFailure, CredentialMaterial, Error, FidoCeremony, FidoPolicy,
        FidoStorage, Interaction, ManagedEnrollment, ManagedRequest, ManagedSession, Operation,
        PRF_RESULT_BYTES, PinPrompt, PrfRequest, PublicKey64, RecipientId, Result, SelectionPrompt,
        TouchPrompt, Zeroizing,
    };

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub(crate) struct Counters {
        pub(crate) selections: usize,
        pub(crate) enrollments: usize,
        pub(crate) assertions: usize,
        pub(crate) retirements: usize,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum FailurePoint {
        Selection,
        Enrollment,
        ManagedEnrollment,
        Assertion,
        Retirement,
        AbsenceCheck,
        VerifiedResponse,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) enum FailureKind {
        NoCompatibleAuthenticator,
        Authenticator(AuthenticatorFailure),
        InvalidResponse,
    }

    impl FailureKind {
        fn into_error(self) -> Error {
            match self {
                Self::NoCompatibleAuthenticator => Error::NoCompatibleAuthenticator,
                Self::Authenticator(failure) => Error::Authenticator(failure),
                Self::InvalidResponse => Error::AuthenticatorResponseInvalid,
            }
        }
    }

    struct FakeCredential {
        application_id: String,
        public_key: PublicKey64,
        enrollment_policy: FidoPolicy,
        storage: FidoStorage,
        user_id: Option<RecipientId>,
        presence_root: [u8; PRF_RESULT_BYTES],
        verified_root: [u8; PRF_RESULT_BYTES],
    }

    struct FakeDevice {
        credentials: HashMap<Vec<u8>, FakeCredential>,
        managed_capacity: usize,
    }

    impl FakeDevice {
        fn new() -> Self {
            Self {
                credentials: HashMap::new(),
                managed_capacity: 25,
            }
        }
    }

    pub(crate) struct FakeBackend {
        next_id: u64,
        devices: Vec<FakeDevice>,
        visible_devices: usize,
        selected_device: usize,
        counters: Counters,
        fail_next: Option<(FailurePoint, FailureKind)>,
    }

    impl FakeBackend {
        pub(crate) fn new() -> Self {
            Self {
                next_id: 1,
                devices: vec![FakeDevice::new()],
                visible_devices: 1,
                selected_device: 0,
                counters: Counters::default(),
                fail_next: None,
            }
        }

        pub(crate) const fn counters(&self) -> Counters {
            self.counters
        }

        #[cfg(test)]
        pub(crate) fn fail_next(&mut self, point: FailurePoint) {
            let failure = match point {
                FailurePoint::Selection => FailureKind::NoCompatibleAuthenticator,
                FailurePoint::Enrollment
                | FailurePoint::ManagedEnrollment
                | FailurePoint::Assertion
                | FailurePoint::Retirement => {
                    FailureKind::Authenticator(AuthenticatorFailure::OperationFailed)
                }
                FailurePoint::AbsenceCheck => {
                    FailureKind::Authenticator(AuthenticatorFailure::RetirementUncertain)
                }
                FailurePoint::VerifiedResponse => FailureKind::InvalidResponse,
            };
            assert!(self.fail_next_with(point, failure));
        }

        pub(crate) fn fail_next_with(&mut self, point: FailurePoint, failure: FailureKind) -> bool {
            if self.fail_next.is_some() {
                return false;
            }
            self.fail_next = Some((point, failure));
            true
        }

        pub(crate) fn set_compatible_authenticators(&mut self, count: usize) {
            while self.devices.len() < count {
                self.devices.push(FakeDevice::new());
            }
            self.visible_devices = count;
            if self.selected_device >= count {
                self.selected_device = 0;
            }
        }

        #[cfg(feature = "testing")]
        pub(crate) fn select_authenticator(&mut self, index: usize) -> Result<()> {
            if index >= self.visible_devices {
                return Err(Error::NoCompatibleAuthenticator);
            }
            self.selected_device = index;
            Ok(())
        }

        pub(crate) fn set_managed_capacity(&mut self, capacity: usize) {
            if let Some(device) = self.devices.get_mut(self.selected_device) {
                device.managed_capacity = capacity;
            }
        }

        pub(crate) fn forget_credential(&mut self, credential_id: &[u8]) {
            if let Some(device) = self.devices.get_mut(self.selected_device) {
                device.credentials.remove(credential_id);
            }
        }

        #[cfg(feature = "testing")]
        pub(crate) fn reset(&mut self) {
            *self = Self::new();
        }

        #[cfg(test)]
        pub(crate) fn seed_credential(
            &mut self,
            application_id: &ApplicationId,
            policy: FidoPolicy,
        ) -> CredentialMaterial {
            self.seed_credential_with_storage(
                application_id,
                policy,
                FidoStorage::NonDiscoverable,
                None,
            )
        }

        fn seed_credential_with_storage(
            &mut self,
            application_id: &ApplicationId,
            policy: FidoPolicy,
            storage: FidoStorage,
            user_id: Option<RecipientId>,
        ) -> CredentialMaterial {
            let id_number = self.next_id;
            self.next_id = self
                .next_id
                .checked_add(1)
                .expect("test credential id overflow");
            let mut credential_id = b"fake-credential-format-1".to_vec();
            credential_id.extend_from_slice(&id_number.to_be_bytes());

            let point = ProjectivePoint::GENERATOR.to_affine().to_sec1_point(false);
            let public_bytes: [u8; 64] = point.as_bytes()[1..]
                .try_into()
                .expect("uncompressed P-256 point has 64 coordinate bytes");
            let public_key = PublicKey64::new(public_bytes).expect("generator is a valid point");
            let presence_root = credential_root(b"presence", id_number);
            let verified_root = credential_root(b"verified", id_number);
            self.devices[self.selected_device].credentials.insert(
                credential_id.clone(),
                FakeCredential {
                    application_id: application_id.as_str().to_owned(),
                    public_key: public_key.clone(),
                    enrollment_policy: policy,
                    storage,
                    user_id,
                    presence_root,
                    verified_root,
                },
            );
            CredentialMaterial {
                credential_id,
                public_key,
            }
        }

        fn select(
            &mut self,
            operation: Operation,
            label: &str,
            policy: FidoPolicy,
            interaction: &mut dyn Interaction,
        ) -> Result<usize> {
            self.counters.selections += 1;
            if let Some(failure) = self.take_failure(FailurePoint::Selection) {
                return Err(failure.into_error());
            }
            if self.visible_devices == 0 {
                return Err(Error::NoCompatibleAuthenticator);
            }
            if self.visible_devices > 1 {
                interaction.select_authenticator_by_touch(&SelectionPrompt::new(
                    operation, label, policy,
                ))?;
            }
            Ok(self.selected_device)
        }

        pub(super) fn enroll(
            &mut self,
            application_id: &ApplicationId,
            policy: FidoPolicy,
            label: &str,
            operation: Operation,
            interaction: &mut dyn Interaction,
        ) -> Result<CredentialMaterial> {
            let device = self.select(operation, label, policy, interaction)?;
            let pin = interaction.request_pin(&PinPrompt::new(
                operation,
                label,
                FidoCeremony::Enrollment,
            ))?;
            drop(pin);
            interaction.touch_required(&TouchPrompt::new(
                operation,
                label,
                FidoCeremony::Enrollment,
                policy,
            ))?;
            self.counters.enrollments += 1;
            if let Some(failure) = self.take_failure(FailurePoint::Enrollment) {
                return Err(failure.into_error());
            }
            if let Some(failure) = self.take_failure(FailurePoint::VerifiedResponse) {
                return Err(failure.into_error());
            }
            let _ = device;
            Ok(self.seed_credential_with_storage(
                application_id,
                policy,
                FidoStorage::NonDiscoverable,
                None,
            ))
        }

        pub(super) fn enroll_managed(
            &mut self,
            application_id: &ApplicationId,
            recipient_id: RecipientId,
            policy: FidoPolicy,
            label: &str,
            operation: Operation,
            interaction: &mut dyn Interaction,
        ) -> Result<ManagedEnrollment> {
            let device = self.select(operation, label, policy, interaction)?;
            let pin = interaction.request_pin(&PinPrompt::new(
                operation,
                label,
                FidoCeremony::Enrollment,
            ))?;
            drop(pin);
            interaction.touch_required(&TouchPrompt::new(
                operation,
                label,
                FidoCeremony::Enrollment,
                policy,
            ))?;
            self.counters.enrollments += 1;
            let used = self.devices[device]
                .credentials
                .values()
                .filter(|credential| credential.storage == FidoStorage::Managed)
                .count();
            if used >= self.devices[device].managed_capacity {
                return Err(AuthenticatorFailure::CredentialStoreFull.into());
            }
            if let Some(failure) = self.take_failure(FailurePoint::ManagedEnrollment) {
                if failure == FailureKind::Authenticator(AuthenticatorFailure::CredentialMayRemain)
                {
                    self.seed_credential_with_storage(
                        application_id,
                        policy,
                        FidoStorage::Managed,
                        Some(recipient_id),
                    );
                }
                return Err(failure.into_error());
            }
            let credential = self.seed_credential_with_storage(
                application_id,
                policy,
                FidoStorage::Managed,
                Some(recipient_id),
            );
            Ok(ManagedEnrollment {
                credential,
                policy,
                session: ManagedSession::Fake { device },
            })
        }

        pub(super) fn evaluate(
            &mut self,
            request: &PrfRequest<'_>,
            interaction: &mut dyn Interaction,
        ) -> Result<Zeroizing<[u8; PRF_RESULT_BYTES]>> {
            let device = self.select(
                request.operation,
                request.credential.label,
                request.credential.policy,
                interaction,
            )?;
            if request.credential.policy == FidoPolicy::UserVerification {
                let pin = interaction.request_pin(&PinPrompt::new(
                    request.operation,
                    request.credential.label,
                    FidoCeremony::Assertion,
                ))?;
                drop(pin);
            }
            interaction.touch_required(&TouchPrompt::new(
                request.operation,
                request.credential.label,
                FidoCeremony::Assertion,
                request.credential.policy,
            ))?;
            self.counters.assertions += 1;
            if let Some(failure) = self.take_failure(FailurePoint::Assertion) {
                return Err(failure.into_error());
            }
            if let Some(failure) = self.take_failure(FailurePoint::VerifiedResponse) {
                return Err(failure.into_error());
            }

            let credential = self.devices[device]
                .credentials
                .get(request.credential.credential_id)
                .ok_or(AuthenticatorFailure::CredentialUnavailable)?;
            if credential.application_id != request.credential.application_id.as_str() {
                return Err(AuthenticatorFailure::OperationFailed.into());
            }
            if credential.public_key != *request.credential.public_key {
                return Err(Error::AuthenticatorResponseInvalid);
            }
            if credential.enrollment_policy == FidoPolicy::UserVerification
                && request.credential.policy == FidoPolicy::Presence
            {
                return Err(AuthenticatorFailure::OperationFailed.into());
            }
            let root = match request.credential.policy {
                FidoPolicy::Presence => &credential.presence_root,
                FidoPolicy::UserVerification => &credential.verified_root,
            };
            let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(root)
                .expect("HMAC accepts a 32-byte key");
            mac.update(request.input);
            Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
        }

        pub(super) fn evaluate_managed_on_device(
            &mut self,
            device: usize,
            request: &PrfRequest<'_>,
            interaction: &mut dyn Interaction,
        ) -> Result<Zeroizing<[u8; PRF_RESULT_BYTES]>> {
            interaction.touch_required(&TouchPrompt::new(
                request.operation,
                request.credential.label,
                FidoCeremony::Assertion,
                request.credential.policy,
            ))?;
            self.counters.assertions += 1;
            if let Some(failure) = self.take_failure(FailurePoint::Assertion) {
                return Err(failure.into_error());
            }
            if let Some(failure) = self.take_failure(FailurePoint::VerifiedResponse) {
                return Err(failure.into_error());
            }
            let managed = ManagedRequest {
                credential: request.credential,
                operation: request.operation,
            };
            let credential = self.managed_credential(device, &managed)?;
            let root = match request.credential.policy {
                FidoPolicy::Presence => &credential.presence_root,
                FidoPolicy::UserVerification => &credential.verified_root,
            };
            let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(root)
                .expect("HMAC accepts a 32-byte key");
            mac.update(request.input);
            Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
        }

        pub(super) fn verify_managed(
            &mut self,
            request: &ManagedRequest<'_>,
            interaction: &mut dyn Interaction,
        ) -> Result<()> {
            let device = self.select(
                request.operation,
                request.credential.label,
                request.credential.policy,
                interaction,
            )?;
            let pin = interaction.request_pin(&PinPrompt::new(
                request.operation,
                request.credential.label,
                FidoCeremony::Assertion,
            ))?;
            drop(pin);
            self.touch_and_verify_managed(device, request, interaction)
        }

        pub(super) fn retire_managed(
            &mut self,
            request: &ManagedRequest<'_>,
            interaction: &mut dyn Interaction,
        ) -> Result<()> {
            let device = self.select(
                request.operation,
                request.credential.label,
                request.credential.policy,
                interaction,
            )?;
            let pin = interaction.request_pin(&PinPrompt::new(
                request.operation,
                request.credential.label,
                FidoCeremony::Assertion,
            ))?;
            drop(pin);
            self.retire_managed_on_device(device, request, interaction)
        }

        pub(super) fn retire_managed_on_device(
            &mut self,
            device: usize,
            request: &ManagedRequest<'_>,
            interaction: &mut dyn Interaction,
        ) -> Result<()> {
            self.touch_and_verify_managed(device, request, interaction)?;
            self.counters.retirements += 1;
            let deletion = if let Some(failure) = self.take_failure(FailurePoint::Retirement) {
                Err(failure.into_error())
            } else {
                self.devices[device]
                    .credentials
                    .remove(request.credential.credential_id);
                Ok(())
            };
            let presence = if let Some(failure) = self.take_failure(FailurePoint::AbsenceCheck) {
                Err(failure.into_error())
            } else {
                Ok(self.devices[device]
                    .credentials
                    .contains_key(request.credential.credential_id))
            };
            match (deletion, presence) {
                (_, Ok(false)) => Ok(()),
                (Ok(()), Ok(true)) => Err(Error::AuthenticatorResponseInvalid),
                (Err(error), Ok(true)) => Err(error),
                (_, Err(Error::AuthenticatorResponseInvalid)) => {
                    Err(Error::AuthenticatorResponseInvalid)
                }
                _ => Err(AuthenticatorFailure::RetirementUncertain.into()),
            }
        }

        pub(super) fn cleanup_managed_enrollment_on_device(
            &mut self,
            device: usize,
            request: &ManagedRequest<'_>,
            interaction: &mut dyn Interaction,
        ) -> Result<()> {
            match self.managed_credential(device, request) {
                Ok(_) => self.retire_managed_on_device(device, request, interaction),
                Err(Error::Authenticator(AuthenticatorFailure::CredentialUnavailable)) => Ok(()),
                Err(error) => Err(error),
            }
        }

        fn touch_and_verify_managed(
            &mut self,
            device: usize,
            request: &ManagedRequest<'_>,
            interaction: &mut dyn Interaction,
        ) -> Result<()> {
            interaction.touch_required(&TouchPrompt::new(
                request.operation,
                request.credential.label,
                FidoCeremony::Assertion,
                request.credential.policy,
            ))?;
            self.counters.assertions += 1;
            if let Some(failure) = self.take_failure(FailurePoint::Assertion) {
                return Err(failure.into_error());
            }
            if let Some(failure) = self.take_failure(FailurePoint::VerifiedResponse) {
                return Err(failure.into_error());
            }
            self.managed_credential(device, request).map(|_| ())
        }

        fn managed_credential(
            &self,
            device: usize,
            request: &ManagedRequest<'_>,
        ) -> Result<&FakeCredential> {
            let credential = self.devices[device]
                .credentials
                .get(request.credential.credential_id)
                .ok_or(AuthenticatorFailure::CredentialUnavailable)?;
            if credential.application_id != request.credential.application_id.as_str()
                || credential.storage != FidoStorage::Managed
                || credential.user_id != Some(request.credential.recipient_id)
                || credential.enrollment_policy != request.credential.policy
            {
                return Err(AuthenticatorFailure::CredentialUnavailable.into());
            }
            if credential.public_key != *request.credential.public_key {
                return Err(Error::AuthenticatorResponseInvalid);
            }
            Ok(credential)
        }

        fn take_failure(&mut self, point: FailurePoint) -> Option<FailureKind> {
            if self.fail_next.as_ref().map(|(next, _)| *next) == Some(point) {
                self.fail_next.take().map(|(_, failure)| failure)
            } else {
                None
            }
        }
    }

    fn credential_root(label: &[u8], id: u64) -> [u8; PRF_RESULT_BYTES] {
        let mut digest = Sha256::new();
        digest.update(b"fido-key-wrap deterministic test credential");
        digest.update(label);
        digest.update(id.to_be_bytes());
        digest.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InteractionError, Pin};
    use p256::{
        ProjectivePoint,
        elliptic_curve::{Group, sec1::ToSec1Point},
    };

    #[derive(Default)]
    struct ScriptedInteraction {
        selections: usize,
        pins: usize,
        touches: usize,
    }

    impl Interaction for ScriptedInteraction {
        fn select_authenticator_by_touch(
            &mut self,
            _prompt: &SelectionPrompt,
        ) -> std::result::Result<(), InteractionError> {
            self.selections += 1;
            Ok(())
        }

        fn request_pin(
            &mut self,
            _prompt: &PinPrompt,
        ) -> std::result::Result<Pin, InteractionError> {
            self.pins += 1;
            Pin::new("123456".to_owned()).map_err(|_| InteractionError::Failed)
        }

        fn touch_required(
            &mut self,
            _prompt: &TouchPrompt,
        ) -> std::result::Result<(), InteractionError> {
            self.touches += 1;
            Ok(())
        }
    }

    fn request<'a>(
        application_id: &'a ApplicationId,
        credential: &'a CredentialMaterial,
        policy: FidoPolicy,
        input: &'a [u8; PRF_RESULT_BYTES],
    ) -> PrfRequest<'a> {
        PrfRequest {
            credential: CredentialBinding {
                application_id,
                recipient_id: RecipientId::from_bytes([0x42; 32]),
                credential_id: &credential.credential_id,
                public_key: &credential.public_key,
                policy,
                label: "primary",
            },
            input,
            operation: Operation::Unlock,
        }
    }

    fn managed_request<'a>(
        application_id: &'a ApplicationId,
        recipient_id: RecipientId,
        credential: &'a CredentialMaterial,
        policy: FidoPolicy,
    ) -> ManagedRequest<'a> {
        ManagedRequest {
            credential: CredentialBinding {
                application_id,
                recipient_id,
                credential_id: &credential.credential_id,
                public_key: &credential.public_key,
                policy,
                label: "managed",
            },
            operation: Operation::AddRecipient,
        }
    }

    #[cfg(feature = "fido")]
    #[test]
    fn native_errors_map_to_curated_identity_free_failures() {
        assert!(matches!(
            map_native_error(&native::Error::PinInvalid { retries: Some(3) }),
            Error::Authenticator(AuthenticatorFailure::PinInvalid { retries: Some(3) })
        ));
        assert!(matches!(
            map_native_error(&native::Error::PinBlocked),
            Error::Authenticator(AuthenticatorFailure::PinBlocked)
        ));
        assert!(matches!(
            map_native_error(&native::Error::PinAuthBlocked),
            Error::Authenticator(AuthenticatorFailure::PinTemporarilyBlocked)
        ));
        for error in [native::Error::SelectionTimedOut, native::Error::TimedOut] {
            assert!(matches!(
                map_native_error(&error),
                Error::Authenticator(AuthenticatorFailure::TimedOut)
            ));
        }
        assert!(matches!(
            map_native_error(&native::Error::Busy),
            Error::Authenticator(AuthenticatorFailure::Busy)
        ));
        assert!(matches!(
            map_native_error(&native::Error::CredentialNotFound),
            Error::Authenticator(AuthenticatorFailure::CredentialUnavailable)
        ));
        assert!(matches!(
            map_native_error(&native::Error::CredentialStoreFull),
            Error::Authenticator(AuthenticatorFailure::CredentialStoreFull)
        ));
        assert!(matches!(
            map_native_error(&native::Error::CredentialMayRemain),
            Error::Authenticator(AuthenticatorFailure::CredentialMayRemain)
        ));
        assert!(matches!(
            map_native_error(&native::Error::RetirementUncertain),
            Error::Authenticator(AuthenticatorFailure::RetirementUncertain)
        ));
        assert!(matches!(
            map_native_error(&native::Error::Transport),
            Error::Authenticator(AuthenticatorFailure::Transport)
        ));
        assert!(matches!(
            map_native_error(&native::Error::Native {
                operation: "private operation",
                code: 12_345,
            }),
            Error::Authenticator(AuthenticatorFailure::OperationFailed)
        ));
        for error in [native::Error::VerificationFailed, native::Error::Protocol] {
            assert!(matches!(
                map_native_error(&error),
                Error::AuthenticatorResponseInvalid
            ));
        }

        let rendered = map_native_error(&native::Error::Native {
            operation: "sensitive/native/path",
            code: 54_321,
        })
        .to_string();
        assert!(!rendered.contains("sensitive"));
        assert!(!rendered.contains("54321"));
    }

    #[test]
    fn unavailable_backend_fails_before_interaction() {
        let application_id = ApplicationId::new("org.example.backend-test").unwrap();
        let mut backend = AuthenticatorBackend::unavailable();
        let mut interaction = ScriptedInteraction::default();
        assert!(matches!(
            backend.enroll(
                &application_id,
                FidoPolicy::Presence,
                "primary",
                Operation::AddRecipient,
                &mut interaction,
            ),
            Err(Error::FidoSupportUnavailable)
        ));
        assert_eq!(interaction.pins, 0);
        assert_eq!(interaction.touches, 0);
    }

    #[test]
    fn fake_models_exact_presence_and_uv_branches() {
        let application_id = ApplicationId::new("org.example.backend-test").unwrap();
        let mut backend = AuthenticatorBackend::fake();
        let credential = backend
            .fake_mut()
            .seed_credential(&application_id, FidoPolicy::Presence);
        let input = [0x55; PRF_RESULT_BYTES];
        let mut interaction = ScriptedInteraction::default();
        let presence = backend
            .evaluate(
                &request(&application_id, &credential, FidoPolicy::Presence, &input),
                &mut interaction,
            )
            .unwrap();
        let verified = backend
            .evaluate(
                &request(
                    &application_id,
                    &credential,
                    FidoPolicy::UserVerification,
                    &input,
                ),
                &mut interaction,
            )
            .unwrap();
        assert_ne!(*presence, *verified);
        assert_eq!(interaction.pins, 1);
        assert_eq!(backend.fake_mut().counters().assertions, 2);
    }

    #[test]
    fn managed_enrollment_cleanup_is_exact_and_idempotent() {
        let application_id = ApplicationId::new("org.example.backend-test").unwrap();
        let policy = FidoPolicy::Presence;
        let recipient = RecipientId::from_bytes([0x42; 32]);
        let mut backend = fake::FakeBackend::new();
        let mut enroll = ScriptedInteraction::default();
        let enrollment = backend
            .enroll_managed(
                &application_id,
                recipient,
                policy,
                "managed",
                Operation::AddRecipient,
                &mut enroll,
            )
            .unwrap();
        let request = managed_request(&application_id, recipient, &enrollment.credential, policy);

        let mut cleanup = ScriptedInteraction::default();
        backend
            .cleanup_managed_enrollment_on_device(0, &request, &mut cleanup)
            .unwrap();
        backend
            .cleanup_managed_enrollment_on_device(0, &request, &mut cleanup)
            .unwrap();
        assert_eq!(cleanup.touches, 1);

        let recipient = RecipientId::from_bytes([0x43; 32]);
        let enrollment = backend
            .enroll_managed(
                &application_id,
                recipient,
                policy,
                "managed",
                Operation::AddRecipient,
                &mut enroll,
            )
            .unwrap();
        backend.forget_credential(&enrollment.credential.credential_id);
        let request = managed_request(&application_id, recipient, &enrollment.credential, policy);
        let mut absent = ScriptedInteraction::default();
        backend
            .cleanup_managed_enrollment_on_device(0, &request, &mut absent)
            .unwrap();
        assert_eq!(absent.touches, 0);
    }

    #[test]
    fn uv_required_fake_credential_rejects_presence() {
        let application_id = ApplicationId::new("org.example.backend-test").unwrap();
        let mut backend = AuthenticatorBackend::fake();
        let credential = backend
            .fake_mut()
            .seed_credential(&application_id, FidoPolicy::UserVerification);
        let input = [0x66; PRF_RESULT_BYTES];
        let mut interaction = ScriptedInteraction::default();
        assert!(matches!(
            backend.evaluate(
                &request(&application_id, &credential, FidoPolicy::Presence, &input,),
                &mut interaction,
            ),
            Err(Error::Authenticator(AuthenticatorFailure::OperationFailed))
        ));
    }

    #[test]
    fn fake_failure_injection_is_one_shot_and_counted() {
        let application_id = ApplicationId::new("org.example.backend-test").unwrap();
        let mut backend = AuthenticatorBackend::fake();
        let credential = backend
            .fake_mut()
            .seed_credential(&application_id, FidoPolicy::Presence);
        backend
            .fake_mut()
            .fail_next(fake::FailurePoint::VerifiedResponse);
        let input = [0x77; PRF_RESULT_BYTES];
        let mut interaction = ScriptedInteraction::default();
        assert!(matches!(
            backend.evaluate(
                &request(&application_id, &credential, FidoPolicy::Presence, &input,),
                &mut interaction,
            ),
            Err(Error::AuthenticatorResponseInvalid)
        ));
        assert!(
            backend
                .evaluate(
                    &request(&application_id, &credential, FidoPolicy::Presence, &input,),
                    &mut interaction,
                )
                .is_ok()
        );
        assert_eq!(backend.fake_mut().counters().assertions, 2);
    }

    #[test]
    fn fake_rejects_wrong_credential_and_altered_valid_public_key() {
        let application_id = ApplicationId::new("org.example.backend-test").unwrap();
        let mut backend = AuthenticatorBackend::fake();
        let credential = backend
            .fake_mut()
            .seed_credential(&application_id, FidoPolicy::Presence);
        let input = [0x78; PRF_RESULT_BYTES];
        let mut interaction = ScriptedInteraction::default();

        let unknown_credential_id = b"unknown-credential".to_vec();
        let mut wrong_credential =
            request(&application_id, &credential, FidoPolicy::Presence, &input);
        wrong_credential.credential.credential_id = &unknown_credential_id;
        assert!(matches!(
            backend.evaluate(&wrong_credential, &mut interaction),
            Err(Error::Authenticator(
                AuthenticatorFailure::CredentialUnavailable
            ))
        ));

        let alternate_point = ProjectivePoint::GENERATOR
            .double()
            .to_affine()
            .to_sec1_point(false);
        let alternate_bytes: [u8; 64] = alternate_point.as_bytes()[1..]
            .try_into()
            .expect("uncompressed P-256 point has 64 coordinate bytes");
        let alternate_public_key =
            PublicKey64::new(alternate_bytes).expect("twice the generator is a valid point");
        let mut wrong_public_key =
            request(&application_id, &credential, FidoPolicy::Presence, &input);
        wrong_public_key.credential.public_key = &alternate_public_key;
        assert!(matches!(
            backend.evaluate(&wrong_public_key, &mut interaction),
            Err(Error::AuthenticatorResponseInvalid)
        ));
        assert_eq!(backend.fake_mut().counters().assertions, 2);
    }

    #[test]
    fn fake_binds_prf_output_to_the_exact_input() {
        let application_id = ApplicationId::new("org.example.backend-test").unwrap();
        let mut backend = AuthenticatorBackend::fake();
        let credential = backend
            .fake_mut()
            .seed_credential(&application_id, FidoPolicy::Presence);
        let mut interaction = ScriptedInteraction::default();
        let first_input = [0x79; PRF_RESULT_BYTES];
        let second_input = [0x7a; PRF_RESULT_BYTES];

        let first = backend
            .evaluate(
                &request(
                    &application_id,
                    &credential,
                    FidoPolicy::Presence,
                    &first_input,
                ),
                &mut interaction,
            )
            .unwrap();
        let second = backend
            .evaluate(
                &request(
                    &application_id,
                    &credential,
                    FidoPolicy::Presence,
                    &second_input,
                ),
                &mut interaction,
            )
            .unwrap();

        assert_ne!(*first, *second);
        assert_eq!(backend.fake_mut().counters().assertions, 2);
    }

    #[test]
    fn fake_selection_prompt_is_used_only_for_multiple_endpoints() {
        let application_id = ApplicationId::new("org.example.backend-test").unwrap();
        let mut backend = AuthenticatorBackend::fake();
        backend.fake_mut().set_compatible_authenticators(2);
        let credential = backend
            .fake_mut()
            .seed_credential(&application_id, FidoPolicy::Presence);
        let input = [0x88; PRF_RESULT_BYTES];
        let mut interaction = ScriptedInteraction::default();
        backend
            .evaluate(
                &request(&application_id, &credential, FidoPolicy::Presence, &input),
                &mut interaction,
            )
            .unwrap();
        assert_eq!(interaction.selections, 1);
        assert_eq!(backend.fake_mut().counters().selections, 1);
    }
}
