use zeroize::Zeroizing;

use crate::{
    ApplicationId, Error, Interaction, Operation, Result, envelope::PublicKey64, policy::FidoPolicy,
};

#[cfg(any(feature = "fido", test))]
use crate::interaction::{FidoCeremony, PinPrompt, SelectionPrompt, TouchPrompt};

#[cfg(feature = "fido")]
use fido_key_wrap_libfido2 as native;

const PRF_RESULT_BYTES: usize = 32;

pub(crate) struct CredentialMaterial {
    pub(crate) credential_id: Vec<u8>,
    pub(crate) public_key: PublicKey64,
}

#[cfg_attr(not(any(feature = "fido", test)), allow(dead_code))]
pub(crate) struct PrfRequest<'a> {
    pub(crate) application_id: &'a ApplicationId,
    pub(crate) credential_id: &'a [u8],
    pub(crate) public_key: &'a PublicKey64,
    pub(crate) policy: FidoPolicy,
    pub(crate) input: &'a [u8; PRF_RESULT_BYTES],
    pub(crate) label: &'a str,
    pub(crate) operation: Operation,
}

pub(crate) enum AuthenticatorBackend {
    Unavailable,
    #[cfg(feature = "fido")]
    Native(NativeBackend),
    #[cfg(test)]
    Fake(fake::FakeBackend),
}

impl AuthenticatorBackend {
    pub(crate) const fn unavailable() -> Self {
        Self::Unavailable
    }

    #[cfg(feature = "fido")]
    pub(crate) fn system() -> Self {
        Self::Native(NativeBackend::new())
    }

    #[cfg(test)]
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
        #[cfg(not(any(feature = "fido", test)))]
        let _ = (application_id, policy, label, operation, &interaction);
        match self {
            Self::Unavailable => Err(Error::FidoSupportUnavailable),
            #[cfg(feature = "fido")]
            Self::Native(backend) => {
                backend.enroll(application_id, policy, label, operation, interaction)
            }
            #[cfg(test)]
            Self::Fake(backend) => {
                backend.enroll(application_id, policy, label, operation, interaction)
            }
        }
    }

    pub(crate) fn evaluate(
        &mut self,
        request: &PrfRequest<'_>,
        interaction: &mut dyn Interaction,
    ) -> Result<Zeroizing<[u8; PRF_RESULT_BYTES]>> {
        #[cfg(not(any(feature = "fido", test)))]
        let _ = (request, &interaction);
        match self {
            Self::Unavailable => Err(Error::FidoSupportUnavailable),
            #[cfg(feature = "fido")]
            Self::Native(backend) => backend.evaluate(request, interaction),
            #[cfg(test)]
            Self::Fake(backend) => backend.evaluate(request, interaction),
        }
    }

    #[cfg(test)]
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
    fn new() -> Self {
        Self {
            backend: native::Backend::default(),
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
        let enrolled = authenticator
            .enroll(
                native::EnrollmentRequest {
                    relying_party_id: application_id.as_str(),
                    relying_party_name: "fido key wrap",
                    policy: native_policy(policy),
                },
                &native_pin,
            )
            .map_err(|error| map_native_error(&error))?;
        drop(native_pin);

        let protection_matches = matches!(
            (policy, enrolled.protection),
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
        let public_key = PublicKey64::new(enrolled.es256_public_key)
            .map_err(|_| Error::AuthenticatorResponseInvalid)?;
        Ok(CredentialMaterial {
            credential_id: enrolled.credential_id,
            public_key,
        })
    }

    fn evaluate(
        &mut self,
        request: &PrfRequest<'_>,
        interaction: &mut dyn Interaction,
    ) -> Result<Zeroizing<[u8; PRF_RESULT_BYTES]>> {
        let mut authenticator = self.select(
            request.operation,
            request.label,
            request.policy,
            interaction,
        )?;
        let pin = match request.policy {
            FidoPolicy::Presence => None,
            FidoPolicy::UserVerification => {
                let pin = interaction.request_pin(&PinPrompt::new(
                    request.operation,
                    request.label,
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
            request.label,
            FidoCeremony::Assertion,
            request.policy,
        ))?;

        // The client-data challenge is fresh for each native call. The PRF
        // input below is a distinct, stable value bound to this record.
        let result = authenticator.evaluate(
            native::PrfRequest {
                relying_party_id: request.application_id.as_str(),
                credential_id: request.credential_id,
                es256_public_key: request.public_key.as_bytes(),
                salt: request.input,
                policy: native_policy(request.policy),
            },
            pin.as_ref(),
        );
        drop(pin);
        result.map_err(|error| map_native_error(&error))
    }
}

#[cfg(feature = "fido")]
const fn native_policy(policy: FidoPolicy) -> native::ExactPolicy {
    match policy {
        FidoPolicy::Presence => native::ExactPolicy::Presence,
        FidoPolicy::UserVerification => native::ExactPolicy::UserVerified,
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
        _ => Error::AuthenticatorOperationFailed,
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use std::collections::HashMap;

    use hmac::{Hmac, Mac};
    use p256::{ProjectivePoint, elliptic_curve::sec1::ToSec1Point};
    use sha2::{Digest, Sha256};

    use super::*;

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub(crate) struct Counters {
        pub(crate) selections: usize,
        pub(crate) enrollments: usize,
        pub(crate) assertions: usize,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum FailurePoint {
        Selection,
        Enrollment,
        Assertion,
        VerifiedResponse,
    }

    struct FakeCredential {
        application_id: String,
        public_key: PublicKey64,
        enrollment_policy: FidoPolicy,
        presence_root: [u8; PRF_RESULT_BYTES],
        verified_root: [u8; PRF_RESULT_BYTES],
    }

    pub(crate) struct FakeBackend {
        next_id: u64,
        compatible_authenticators: usize,
        credentials: HashMap<Vec<u8>, FakeCredential>,
        counters: Counters,
        fail_next: Option<FailurePoint>,
    }

    impl FakeBackend {
        pub(crate) fn new() -> Self {
            Self {
                next_id: 1,
                compatible_authenticators: 1,
                credentials: HashMap::new(),
                counters: Counters::default(),
                fail_next: None,
            }
        }

        pub(crate) const fn counters(&self) -> Counters {
            self.counters
        }

        pub(crate) fn fail_next(&mut self, point: FailurePoint) {
            self.fail_next = Some(point);
        }

        pub(crate) fn set_compatible_authenticators(&mut self, count: usize) {
            self.compatible_authenticators = count;
        }

        pub(crate) fn forget_credential(&mut self, credential_id: &[u8]) {
            self.credentials.remove(credential_id);
        }

        pub(crate) fn seed_credential(
            &mut self,
            application_id: &ApplicationId,
            policy: FidoPolicy,
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
            self.credentials.insert(
                credential_id.clone(),
                FakeCredential {
                    application_id: application_id.as_str().to_owned(),
                    public_key: public_key.clone(),
                    enrollment_policy: policy,
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
        ) -> Result<()> {
            self.counters.selections += 1;
            if self.take_failure(FailurePoint::Selection) || self.compatible_authenticators == 0 {
                return Err(Error::NoCompatibleAuthenticator);
            }
            if self.compatible_authenticators > 1 {
                interaction.select_authenticator_by_touch(&SelectionPrompt::new(
                    operation, label, policy,
                ))?;
            }
            Ok(())
        }

        pub(super) fn enroll(
            &mut self,
            application_id: &ApplicationId,
            policy: FidoPolicy,
            label: &str,
            operation: Operation,
            interaction: &mut dyn Interaction,
        ) -> Result<CredentialMaterial> {
            self.select(operation, label, policy, interaction)?;
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
            if self.take_failure(FailurePoint::Enrollment) {
                return Err(Error::AuthenticatorOperationFailed);
            }
            if self.take_failure(FailurePoint::VerifiedResponse) {
                return Err(Error::AuthenticatorResponseInvalid);
            }
            Ok(self.seed_credential(application_id, policy))
        }

        pub(super) fn evaluate(
            &mut self,
            request: &PrfRequest<'_>,
            interaction: &mut dyn Interaction,
        ) -> Result<Zeroizing<[u8; PRF_RESULT_BYTES]>> {
            self.select(
                request.operation,
                request.label,
                request.policy,
                interaction,
            )?;
            if request.policy == FidoPolicy::UserVerification {
                let pin = interaction.request_pin(&PinPrompt::new(
                    request.operation,
                    request.label,
                    FidoCeremony::Assertion,
                ))?;
                drop(pin);
            }
            interaction.touch_required(&TouchPrompt::new(
                request.operation,
                request.label,
                FidoCeremony::Assertion,
                request.policy,
            ))?;
            self.counters.assertions += 1;
            if self.take_failure(FailurePoint::Assertion) {
                return Err(Error::AuthenticatorOperationFailed);
            }

            let credential = self
                .credentials
                .get(request.credential_id)
                .ok_or(Error::AuthenticatorOperationFailed)?;
            if credential.application_id != request.application_id.as_str() {
                return Err(Error::AuthenticatorOperationFailed);
            }
            if credential.public_key != *request.public_key {
                return Err(Error::AuthenticatorResponseInvalid);
            }
            if credential.enrollment_policy == FidoPolicy::UserVerification
                && request.policy == FidoPolicy::Presence
            {
                return Err(Error::AuthenticatorOperationFailed);
            }
            if self.fail_next == Some(FailurePoint::VerifiedResponse) {
                self.fail_next = None;
                return Err(Error::AuthenticatorResponseInvalid);
            }

            let root = match request.policy {
                FidoPolicy::Presence => &credential.presence_root,
                FidoPolicy::UserVerification => &credential.verified_root,
            };
            let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(root)
                .expect("HMAC accepts a 32-byte key");
            mac.update(request.input);
            Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
        }

        fn take_failure(&mut self, point: FailurePoint) -> bool {
            if self.fail_next == Some(point) {
                self.fail_next = None;
                true
            } else {
                false
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
            application_id,
            credential_id: &credential.credential_id,
            public_key: &credential.public_key,
            policy,
            input,
            label: "primary",
            operation: Operation::Unlock,
        }
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
            Err(Error::AuthenticatorOperationFailed)
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
        let wrong_credential = PrfRequest {
            credential_id: &unknown_credential_id,
            ..request(&application_id, &credential, FidoPolicy::Presence, &input)
        };
        assert!(matches!(
            backend.evaluate(&wrong_credential, &mut interaction),
            Err(Error::AuthenticatorOperationFailed)
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
        let wrong_public_key = PrfRequest {
            public_key: &alternate_public_key,
            ..request(&application_id, &credential, FidoPolicy::Presence, &input)
        };
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
