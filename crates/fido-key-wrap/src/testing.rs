//! deterministic security-key support for downstream rust tests.
//!
//! enabling this feature creates a non-hardware authenticator. keep it in
//! development dependencies and never use it as a production authenticator.

use crate::{
    ApplicationId, AuthenticatorFailure, Error, KeyEnvelope, KeyProtector, RecipientId, Result,
    backend::fake::{Counters, FailureKind, FailurePoint},
    envelope::RecipientRecord,
};

/// one deterministic fake-authenticator operation stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FakeStep {
    /// device discovery and touch selection.
    Selection,
    /// credential creation.
    Enrollment,
    /// evaluation of an existing credential.
    Assertion,
}

/// one bounded failure scheduled for a deterministic fake operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FakeFailure {
    /// no compatible authenticator is available.
    NoCompatibleAuthenticator,
    /// the supplied pin is incorrect.
    PinInvalid {
        /// remaining attempts reported to the application.
        retries: Option<u8>,
    },
    /// the pin is permanently blocked.
    PinBlocked,
    /// pin authentication is temporarily blocked.
    PinTemporarilyBlocked,
    /// the operation times out.
    TimedOut,
    /// the authenticator is busy.
    Busy,
    /// the selected credential is unavailable.
    CredentialUnavailable,
    /// authenticator transport fails.
    Transport,
    /// the operation fails without a narrower category.
    OperationFailed,
    /// the authenticator returns malformed or invalid cryptographic output.
    InvalidResponse,
}

/// deterministic operation counts observed by a fake authenticator.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FakeCounters {
    selections: usize,
    enrollments: usize,
    assertions: usize,
}

impl FakeCounters {
    /// returns the number of selection attempts.
    #[must_use]
    pub const fn selections(self) -> usize {
        self.selections
    }

    /// returns the number of enrollment ceremonies reaching the authenticator.
    #[must_use]
    pub const fn enrollments(self) -> usize {
        self.enrollments
    }

    /// returns the number of assertion ceremonies reaching the authenticator.
    #[must_use]
    pub const fn assertions(self) -> usize {
        self.assertions
    }
}

impl From<Counters> for FakeCounters {
    fn from(value: Counters) -> Self {
        Self {
            selections: value.selections,
            enrollments: value.enrollments,
            assertions: value.assertions,
        }
    }
}

/// deterministic authenticator and its ordinary key protector.
///
/// this concrete type exposes scenarios, not a replaceable backend or raw
/// cryptographic values.
pub struct FakeAuthenticator {
    protector: KeyProtector,
}

impl FakeAuthenticator {
    /// constructs an empty deterministic authenticator for one application.
    #[must_use]
    pub fn new(application_id: ApplicationId) -> Self {
        Self {
            protector: KeyProtector::fake(application_id),
        }
    }

    /// borrows the ordinary protector connected to this authenticator.
    pub const fn protector(&mut self) -> &mut KeyProtector {
        &mut self.protector
    }

    /// sets the number of compatible authenticators visible to selection.
    ///
    /// zero simulates absence. values above 32 are rejected.
    pub fn set_compatible_authenticators(&mut self, count: usize) -> Result<()> {
        if count > 32 {
            return Err(Error::InvalidFidoConfig);
        }
        self.protector
            .fake_backend_mut()
            .set_compatible_authenticators(count);
        Ok(())
    }

    /// schedules one failure at one exact future operation stage.
    pub fn fail_next(&mut self, step: FakeStep, failure: FakeFailure) {
        self.protector
            .fake_backend_mut()
            .fail_next_with(failure_point(step), failure_kind(failure));
    }

    /// removes the credential referenced by one FIDO recipient.
    pub fn forget_recipient(
        &mut self,
        envelope: &KeyEnvelope,
        recipient: RecipientId,
    ) -> Result<()> {
        let credential_id = match envelope.find(recipient)? {
            RecipientRecord::Fido(record) => record.credential_id.clone(),
            RecipientRecord::FidoAndPassphrase(record) => record.credential_id.clone(),
            RecipientRecord::Passphrase(_) | RecipientRecord::RecoverySecret(_) => {
                return Err(Error::InvalidEnvelope);
            }
        };
        self.protector
            .fake_backend_mut()
            .forget_credential(&credential_id);
        Ok(())
    }

    /// returns deterministic operation counts.
    #[must_use]
    pub fn counters(&mut self) -> FakeCounters {
        self.protector.fake_backend_mut().counters().into()
    }

    /// clears credentials, scheduled failures, counts, and device settings.
    pub fn clear(&mut self) {
        self.protector.fake_backend_mut().reset();
    }
}

const fn failure_point(step: FakeStep) -> FailurePoint {
    match step {
        FakeStep::Selection => FailurePoint::Selection,
        FakeStep::Enrollment => FailurePoint::Enrollment,
        FakeStep::Assertion => FailurePoint::Assertion,
    }
}

const fn failure_kind(failure: FakeFailure) -> FailureKind {
    match failure {
        FakeFailure::NoCompatibleAuthenticator => FailureKind::NoCompatibleAuthenticator,
        FakeFailure::PinInvalid { retries } => {
            FailureKind::Authenticator(AuthenticatorFailure::PinInvalid { retries })
        }
        FakeFailure::PinBlocked => FailureKind::Authenticator(AuthenticatorFailure::PinBlocked),
        FakeFailure::PinTemporarilyBlocked => {
            FailureKind::Authenticator(AuthenticatorFailure::PinTemporarilyBlocked)
        }
        FakeFailure::TimedOut => FailureKind::Authenticator(AuthenticatorFailure::TimedOut),
        FakeFailure::Busy => FailureKind::Authenticator(AuthenticatorFailure::Busy),
        FakeFailure::CredentialUnavailable => {
            FailureKind::Authenticator(AuthenticatorFailure::CredentialUnavailable)
        }
        FakeFailure::Transport => FailureKind::Authenticator(AuthenticatorFailure::Transport),
        FakeFailure::OperationFailed => {
            FailureKind::Authenticator(AuthenticatorFailure::OperationFailed)
        }
        FakeFailure::InvalidResponse => FailureKind::InvalidResponse,
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Enrollment, Error, FidoPolicy, Interaction, InteractionError, Passphrase,
        PassphraseParameters, PassphrasePrompt, PassphrasePurpose, Pin, PinPrompt, SelectionPrompt,
        TouchPrompt,
    };

    use super::*;

    #[derive(Default)]
    struct RecordingInteraction {
        selections: usize,
        pins: usize,
        touches: usize,
        events: Vec<&'static str>,
    }

    impl Interaction for RecordingInteraction {
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
            self.events.push("pin");
            Pin::new("123456".to_owned()).map_err(|_| InteractionError::Failed)
        }

        fn request_passphrase(
            &mut self,
            prompt: &PassphrasePrompt,
        ) -> std::result::Result<Passphrase, InteractionError> {
            self.events.push(match prompt.purpose() {
                PassphrasePurpose::Unlock => "unlock passphrase",
                PassphrasePurpose::New => "new passphrase",
                PassphrasePurpose::Confirm => "confirm passphrase",
            });
            Passphrase::new(b"test passphrase".to_vec()).map_err(|_| InteractionError::Failed)
        }

        fn touch_required(
            &mut self,
            prompt: &TouchPrompt,
        ) -> std::result::Result<(), InteractionError> {
            self.touches += 1;
            self.events.push(match prompt.ceremony() {
                crate::FidoCeremony::Enrollment => "enrollment touch",
                crate::FidoCeremony::Assertion => "assertion touch",
            });
            Ok(())
        }
    }

    fn application() -> ApplicationId {
        ApplicationId::new("org.example.downstream-test").unwrap()
    }

    #[test]
    fn exercises_the_ordinary_protector_without_native_fido() {
        let mut authenticator = FakeAuthenticator::new(application());
        authenticator.set_compatible_authenticators(2).unwrap();
        let mut interaction = RecordingInteraction::default();
        let (root, envelope, recipient) = authenticator
            .protector()
            .create_root(
                Enrollment::fido("primary", FidoPolicy::UserVerification).unwrap(),
                &mut interaction,
            )
            .unwrap();
        assert_eq!(interaction.selections, 2);
        assert_eq!(interaction.pins, 2);
        assert_eq!(interaction.touches, 2);

        let recovered = authenticator
            .protector()
            .unlock(&envelope, recipient, &mut interaction)
            .unwrap();
        assert_eq!(recovered.bytes(), root.bytes());
        assert_eq!(authenticator.counters().enrollments(), 1);
        assert_eq!(authenticator.counters().assertions(), 2);

        authenticator
            .forget_recipient(&envelope, recipient)
            .unwrap();
        assert!(matches!(
            authenticator
                .protector()
                .unlock(&envelope, recipient, &mut interaction),
            Err(Error::Authenticator(
                AuthenticatorFailure::CredentialUnavailable
            ))
        ));
    }

    #[test]
    fn combined_presence_preserves_factor_order() {
        let mut authenticator = FakeAuthenticator::new(application());
        let parameters = PassphraseParameters::new(65_536, 3, 1).unwrap();
        let enrollment = Enrollment::fido_and_passphrase_with_parameters(
            "primary",
            FidoPolicy::Presence,
            parameters,
        )
        .unwrap();
        let mut interaction = RecordingInteraction::default();
        let (_root, envelope, recipient) = authenticator
            .protector()
            .create_root(enrollment, &mut interaction)
            .unwrap();
        assert_eq!(
            interaction.events,
            [
                "pin",
                "enrollment touch",
                "assertion touch",
                "new passphrase",
                "confirm passphrase",
            ]
        );

        interaction.events.clear();
        authenticator
            .protector()
            .unlock(&envelope, recipient, &mut interaction)
            .unwrap();
        assert_eq!(interaction.events, ["assertion touch", "unlock passphrase"]);
    }

    #[test]
    fn injects_every_curated_failure_without_raw_material() {
        let failures = [
            FakeFailure::NoCompatibleAuthenticator,
            FakeFailure::PinInvalid { retries: Some(2) },
            FakeFailure::PinBlocked,
            FakeFailure::PinTemporarilyBlocked,
            FakeFailure::TimedOut,
            FakeFailure::Busy,
            FakeFailure::CredentialUnavailable,
            FakeFailure::Transport,
            FakeFailure::OperationFailed,
            FakeFailure::InvalidResponse,
        ];

        for failure in failures {
            let mut authenticator = FakeAuthenticator::new(application());
            authenticator.fail_next(FakeStep::Selection, failure);
            let mut interaction = RecordingInteraction::default();
            let Err(error) = authenticator.protector().create_root(
                Enrollment::fido("primary", FidoPolicy::Presence).unwrap(),
                &mut interaction,
            ) else {
                panic!("scheduled failure was not returned: {failure:?}");
            };
            assert_fake_failure(failure, error);
            assert_eq!(authenticator.counters().selections(), 1);
            assert_eq!(authenticator.counters().enrollments(), 0);
        }
    }

    #[test]
    fn rejects_unbounded_device_counts_and_clear_restores_defaults() {
        let mut authenticator = FakeAuthenticator::new(application());
        let mut interaction = RecordingInteraction::default();
        let (_root, old_envelope, old_recipient) = authenticator
            .protector()
            .create_root(
                Enrollment::fido("old", FidoPolicy::Presence).unwrap(),
                &mut interaction,
            )
            .unwrap();
        assert!(authenticator.set_compatible_authenticators(32).is_ok());
        assert!(matches!(
            authenticator.set_compatible_authenticators(33),
            Err(Error::InvalidFidoConfig)
        ));
        authenticator.set_compatible_authenticators(0).unwrap();
        authenticator.fail_next(FakeStep::Selection, FakeFailure::Busy);
        authenticator.clear();
        assert_eq!(authenticator.counters(), FakeCounters::default());
        assert!(matches!(
            authenticator
                .protector()
                .unlock(&old_envelope, old_recipient, &mut interaction),
            Err(Error::Authenticator(
                AuthenticatorFailure::CredentialUnavailable
            ))
        ));

        assert!(
            authenticator
                .protector()
                .create_root(
                    Enrollment::fido("primary", FidoPolicy::Presence).unwrap(),
                    &mut interaction,
                )
                .is_ok()
        );
    }

    fn assert_fake_failure(expected: FakeFailure, actual: Error) {
        let matches = match (expected, actual) {
            (FakeFailure::NoCompatibleAuthenticator, Error::NoCompatibleAuthenticator)
            | (FakeFailure::PinBlocked, Error::Authenticator(AuthenticatorFailure::PinBlocked))
            | (
                FakeFailure::PinTemporarilyBlocked,
                Error::Authenticator(AuthenticatorFailure::PinTemporarilyBlocked),
            )
            | (FakeFailure::TimedOut, Error::Authenticator(AuthenticatorFailure::TimedOut))
            | (FakeFailure::Busy, Error::Authenticator(AuthenticatorFailure::Busy))
            | (
                FakeFailure::CredentialUnavailable,
                Error::Authenticator(AuthenticatorFailure::CredentialUnavailable),
            )
            | (FakeFailure::Transport, Error::Authenticator(AuthenticatorFailure::Transport))
            | (
                FakeFailure::OperationFailed,
                Error::Authenticator(AuthenticatorFailure::OperationFailed),
            )
            | (FakeFailure::InvalidResponse, Error::AuthenticatorResponseInvalid) => true,
            (
                FakeFailure::PinInvalid { retries: expected },
                Error::Authenticator(AuthenticatorFailure::PinInvalid { retries: actual }),
            ) => expected == actual,
            _ => false,
        };
        assert!(matches, "unexpected failure category");
    }
}
