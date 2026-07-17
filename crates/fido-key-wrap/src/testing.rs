//! deterministic security-key support for downstream rust tests.
//!
//! the `testing` feature provides an in-memory authenticator. enable it only
//! as a development dependency.

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
    /// managed discoverable-credential creation.
    ManagedEnrollment,
    /// evaluation of an existing credential.
    Assertion,
    /// managed credential deletion.
    Retirement,
    /// post-deletion absence verification.
    AbsenceCheck,
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
    /// a managed enrollment or cleanup may have left a credential behind.
    CredentialMayRemain,
    /// managed-credential deletion could not be confirmed.
    RetirementUncertain,
    /// authenticator transport fails.
    Transport,
    /// the operation fails without a narrower category.
    OperationFailed,
    /// the authenticator returns malformed or invalid cryptographic output.
    InvalidResponse,
}

/// invalid deterministic-failure scheduling.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum FakeScheduleError {
    /// the selected failure cannot occur at that operation stage.
    #[error("the fake failure is not valid at that operation stage")]
    InvalidCombination,
    /// one unconsumed failure is already scheduled.
    #[error("a fake failure is already scheduled")]
    AlreadyScheduled,
}

/// deterministic operation counts observed by a fake authenticator.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FakeCounters {
    selections: usize,
    enrollments: usize,
    assertions: usize,
    retirements: usize,
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

    /// returns the number of managed credential deletions attempted.
    #[must_use]
    pub const fn retirements(self) -> usize {
        self.retirements
    }
}

impl From<Counters> for FakeCounters {
    fn from(value: Counters) -> Self {
        Self {
            selections: value.selections,
            enrollments: value.enrollments,
            assertions: value.assertions,
            retirements: value.retirements,
        }
    }
}

/// deterministic authenticator and its key protector.
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

    /// chooses which visible fake authenticator responds to later operations.
    pub fn select_authenticator(&mut self, index: usize) -> Result<()> {
        self.protector
            .fake_backend_mut()
            .select_authenticator(index)
    }

    /// sets managed-credential capacity on the selected fake authenticator.
    pub fn set_managed_capacity(&mut self, capacity: usize) -> Result<()> {
        if capacity > 256 {
            return Err(Error::InvalidFidoConfig);
        }
        self.protector
            .fake_backend_mut()
            .set_managed_capacity(capacity);
        Ok(())
    }

    /// schedules one failure at one exact future operation stage.
    ///
    /// # errors
    ///
    /// returns [`FakeScheduleError::InvalidCombination`] when the requested
    /// failure cannot occur at that stage, or
    /// [`FakeScheduleError::AlreadyScheduled`] while another failure remains
    /// queued.
    pub fn fail_next(
        &mut self,
        step: FakeStep,
        failure: FakeFailure,
    ) -> std::result::Result<(), FakeScheduleError> {
        if !valid_failure(step, failure) {
            return Err(FakeScheduleError::InvalidCombination);
        }
        if !self
            .protector
            .fake_backend_mut()
            .fail_next_with(failure_point(step), failure_kind(failure))
        {
            return Err(FakeScheduleError::AlreadyScheduled);
        }
        Ok(())
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
            RecipientRecord::FidoAndLocalSecret(record) => record.credential_id.clone(),
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
        FakeStep::ManagedEnrollment => FailurePoint::ManagedEnrollment,
        FakeStep::Assertion => FailurePoint::Assertion,
        FakeStep::Retirement => FailurePoint::Retirement,
        FakeStep::AbsenceCheck => FailurePoint::AbsenceCheck,
    }
}

const fn valid_failure(step: FakeStep, failure: FakeFailure) -> bool {
    match step {
        FakeStep::Selection => matches!(
            failure,
            FakeFailure::NoCompatibleAuthenticator
                | FakeFailure::TimedOut
                | FakeFailure::Busy
                | FakeFailure::Transport
                | FakeFailure::OperationFailed
                | FakeFailure::InvalidResponse
        ),
        FakeStep::Enrollment => matches!(
            failure,
            FakeFailure::PinInvalid { .. }
                | FakeFailure::PinBlocked
                | FakeFailure::PinTemporarilyBlocked
                | FakeFailure::TimedOut
                | FakeFailure::Busy
                | FakeFailure::Transport
                | FakeFailure::OperationFailed
                | FakeFailure::InvalidResponse
        ),
        FakeStep::ManagedEnrollment => matches!(
            failure,
            FakeFailure::PinInvalid { .. }
                | FakeFailure::PinBlocked
                | FakeFailure::PinTemporarilyBlocked
                | FakeFailure::TimedOut
                | FakeFailure::Busy
                | FakeFailure::CredentialMayRemain
                | FakeFailure::Transport
                | FakeFailure::OperationFailed
        ),
        FakeStep::Assertion | FakeStep::Retirement => matches!(
            failure,
            FakeFailure::PinInvalid { .. }
                | FakeFailure::PinBlocked
                | FakeFailure::PinTemporarilyBlocked
                | FakeFailure::TimedOut
                | FakeFailure::Busy
                | FakeFailure::CredentialUnavailable
                | FakeFailure::Transport
                | FakeFailure::OperationFailed
                | FakeFailure::InvalidResponse
        ),
        FakeStep::AbsenceCheck => matches!(
            failure,
            FakeFailure::RetirementUncertain | FakeFailure::InvalidResponse
        ),
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
        FakeFailure::CredentialMayRemain => {
            FailureKind::Authenticator(AuthenticatorFailure::CredentialMayRemain)
        }
        FakeFailure::RetirementUncertain => {
            FailureKind::Authenticator(AuthenticatorFailure::RetirementUncertain)
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
        Enrollment, Error, FidoPolicy, Interaction, InteractionError, LocalSecret, Passphrase,
        PassphraseParameters, PassphrasePrompt, PassphrasePurpose, Pin, PinPrompt, RecipientPolicy,
        SelectionPrompt, TouchPrompt,
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
    fn managed_credentials_are_scoped_to_one_fake_authenticator() {
        let mut authenticator = FakeAuthenticator::new(application());
        authenticator.set_compatible_authenticators(2).unwrap();
        authenticator.select_authenticator(0).unwrap();
        let mut interaction = RecordingInteraction::default();
        let (root, envelope, recipient) = authenticator
            .protector()
            .create_root(
                Enrollment::managed_fido("managed", FidoPolicy::UserVerification).unwrap(),
                &mut interaction,
            )
            .unwrap();

        authenticator.select_authenticator(1).unwrap();
        assert!(matches!(
            authenticator.protector().verify_managed_recipient(
                &envelope,
                &root,
                recipient,
                &mut interaction,
            ),
            Err(Error::Authenticator(
                AuthenticatorFailure::CredentialUnavailable
            ))
        ));

        authenticator.select_authenticator(0).unwrap();
        authenticator
            .protector()
            .verify_managed_recipient(&envelope, &root, recipient, &mut interaction)
            .unwrap();
    }

    #[test]
    fn managed_capacity_failure_is_actionable() {
        let mut authenticator = FakeAuthenticator::new(application());
        authenticator.set_managed_capacity(0).unwrap();
        let mut interaction = RecordingInteraction::default();
        assert!(matches!(
            authenticator.protector().create_root(
                Enrollment::managed_fido("managed", FidoPolicy::UserVerification).unwrap(),
                &mut interaction,
            ),
            Err(Error::Authenticator(
                AuthenticatorFailure::CredentialStoreFull
            ))
        ));
    }

    #[test]
    fn uncertain_managed_enrollment_leaves_capacity_consumed() {
        let mut authenticator = FakeAuthenticator::new(application());
        authenticator.set_managed_capacity(1).unwrap();
        authenticator
            .fail_next(
                FakeStep::ManagedEnrollment,
                FakeFailure::CredentialMayRemain,
            )
            .unwrap();
        let mut interaction = RecordingInteraction::default();
        assert!(matches!(
            authenticator.protector().create_root(
                Enrollment::managed_fido("uncertain", FidoPolicy::UserVerification).unwrap(),
                &mut interaction,
            ),
            Err(Error::Authenticator(
                AuthenticatorFailure::CredentialMayRemain
            ))
        ));
        assert!(matches!(
            authenticator.protector().create_root(
                Enrollment::managed_fido("next", FidoPolicy::UserVerification).unwrap(),
                &mut interaction,
            ),
            Err(Error::Authenticator(
                AuthenticatorFailure::CredentialStoreFull
            ))
        ));
    }

    #[test]
    fn managed_retirement_failures_report_the_resulting_state() {
        for (step, failure, expected, remains) in [
            (
                FakeStep::Retirement,
                FakeFailure::OperationFailed,
                AuthenticatorFailure::OperationFailed,
                true,
            ),
            (
                FakeStep::AbsenceCheck,
                FakeFailure::RetirementUncertain,
                AuthenticatorFailure::RetirementUncertain,
                false,
            ),
        ] {
            let mut authenticator = FakeAuthenticator::new(application());
            let mut interaction = RecordingInteraction::default();
            let (root, envelope, recipient) = authenticator
                .protector()
                .create_root(
                    Enrollment::managed_fido("managed", FidoPolicy::UserVerification).unwrap(),
                    &mut interaction,
                )
                .unwrap();
            authenticator.fail_next(step, failure).unwrap();
            let result = authenticator.protector().retire_managed_recipient(
                &envelope,
                &root,
                recipient,
                &mut interaction,
            );
            match result {
                Err(Error::Authenticator(actual)) => assert_eq!(actual, expected),
                _ => panic!("retirement returned the wrong result"),
            }
            let present = authenticator
                .protector()
                .verify_managed_recipient(&envelope, &root, recipient, &mut interaction)
                .is_ok();
            assert_eq!(present, remains);
        }
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
    fn fido_and_local_secret_requires_both_factors() {
        let mut authenticator = FakeAuthenticator::new(application());
        let mut interaction = RecordingInteraction::default();
        let (root, envelope, local) = authenticator
            .protector()
            .create_root_with_fido_and_local_secret("paired machine", &mut interaction)
            .unwrap();

        assert_eq!(
            envelope.recipients()[0].policy(),
            RecipientPolicy::FidoPresenceAndLocalSecret
        );
        assert_eq!(
            interaction.events,
            ["pin", "enrollment touch", "assertion touch"]
        );
        local.secret().expose(|secret| {
            assert!(
                !envelope
                    .encode()
                    .windows(secret.len())
                    .any(|window| window == secret)
            );
        });

        let assertions = authenticator.counters().assertions();
        assert!(matches!(
            authenticator
                .protector()
                .unlock(&envelope, local.recipient_id(), &mut interaction),
            Err(Error::UnlockFailed)
        ));
        assert_eq!(authenticator.counters().assertions(), assertions);

        let recovered = authenticator
            .protector()
            .unlock_with_fido_and_local_secret(
                &envelope,
                local.recipient_id(),
                local.secret(),
                &mut interaction,
            )
            .unwrap();
        assert_eq!(recovered.bytes(), root.bytes());

        let mut wrong_bytes = [0x5a; 32];
        let wrong = LocalSecret::import(&mut wrong_bytes);
        assert_eq!(wrong_bytes, [0; 32]);
        assert!(matches!(
            authenticator.protector().unlock_with_fido_and_local_secret(
                &envelope,
                local.recipient_id(),
                &wrong,
                &mut interaction,
            ),
            Err(Error::UnlockFailed)
        ));

        authenticator
            .forget_recipient(&envelope, local.recipient_id())
            .unwrap();
        assert!(matches!(
            authenticator.protector().unlock_with_fido_and_local_secret(
                &envelope,
                local.recipient_id(),
                local.secret(),
                &mut interaction,
            ),
            Err(Error::Authenticator(
                AuthenticatorFailure::CredentialUnavailable
            ))
        ));
    }

    #[test]
    fn fido_and_local_secret_addition_is_transactional() {
        let mut authenticator = FakeAuthenticator::new(application());
        let (root, mut envelope, _recovery) = authenticator
            .protector()
            .create_root_with_recovery_secret("recovery")
            .unwrap();
        let before = envelope.encode();
        authenticator
            .fail_next(FakeStep::Assertion, FakeFailure::Transport)
            .unwrap();

        let mut interaction = RecordingInteraction::default();
        assert!(matches!(
            authenticator.protector().add_fido_and_local_secret(
                &mut envelope,
                &root,
                "paired machine",
                &mut interaction,
            ),
            Err(Error::Authenticator(AuthenticatorFailure::Transport))
        ));
        assert_eq!(envelope.encode(), before);

        let local = authenticator
            .protector()
            .add_fido_and_local_secret(&mut envelope, &root, "paired machine", &mut interaction)
            .unwrap();
        assert_ne!(envelope.encode(), before);
        let recovered = authenticator
            .protector()
            .unlock_with_fido_and_local_secret(
                &envelope,
                local.recipient_id(),
                local.secret(),
                &mut interaction,
            )
            .unwrap();
        assert_eq!(recovered.bytes(), root.bytes());
    }

    #[test]
    fn failure_schedules_reject_impossible_and_overlapping_scenarios() {
        let mut authenticator = FakeAuthenticator::new(application());
        assert_eq!(
            authenticator.fail_next(
                FakeStep::Selection,
                FakeFailure::PinInvalid { retries: Some(2) }
            ),
            Err(FakeScheduleError::InvalidCombination)
        );
        authenticator
            .fail_next(FakeStep::Selection, FakeFailure::Busy)
            .unwrap();
        assert_eq!(
            authenticator.fail_next(FakeStep::Assertion, FakeFailure::Transport),
            Err(FakeScheduleError::AlreadyScheduled)
        );

        let mut interaction = RecordingInteraction::default();
        assert!(matches!(
            authenticator.protector().create_root(
                Enrollment::fido("primary", FidoPolicy::Presence).unwrap(),
                &mut interaction,
            ),
            Err(Error::Authenticator(AuthenticatorFailure::Busy))
        ));
        assert_eq!(authenticator.counters().selections(), 1);
        assert_eq!(authenticator.counters().enrollments(), 0);
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
        authenticator
            .fail_next(FakeStep::Selection, FakeFailure::Busy)
            .unwrap();
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
}
