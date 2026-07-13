use subtle::ConstantTimeEq;

use crate::{
    ApplicationId, Enrollment, Error, Interaction, KeyEnvelope, Operation, Passphrase,
    PassphrasePrompt, RecipientId, Result, RootKey,
    backend::{AuthenticatorBackend, NativeBackend, PrfRequest},
    crypto,
    envelope::{
        MAX_CREDENTIAL_ID, MAX_RECIPIENTS, PassphraseHeader, PublicKey64, RecipientRecord,
        compute_recipient_id,
    },
};

/// fido recipient and key-envelope operations.
pub struct KeyProtector {
    application_id: ApplicationId,
    backend: Box<dyn AuthenticatorBackend>,
}

impl KeyProtector {
    /// creates a protector using libfido2.
    #[must_use]
    pub fn system(application_id: ApplicationId) -> Self {
        Self {
            application_id,
            backend: Box::new(NativeBackend::new()),
        }
    }

    /// inspects authenticator capabilities without requesting a pin or touch.
    ///
    /// # Errors
    ///
    /// returns a discovery or allocation error.
    pub fn inspect_authenticators(&self) -> Result<Vec<crate::AuthenticatorReport>> {
        self.backend.inspect()
    }

    /// generates a root key and protects it with the first recipient.
    ///
    /// # Errors
    ///
    /// returns an error when randomness, interaction, enrollment, proof, or
    /// wrapping fails. no envelope is returned on partial failure.
    pub fn provision(
        &mut self,
        enrollment: Enrollment,
        interaction: &mut dyn Interaction,
    ) -> Result<(RootKey, KeyEnvelope, RecipientId)> {
        let root = RootKey::generate()?;
        let (envelope, recipient) = self.protect_existing(&root, enrollment, interaction)?;
        Ok((root, envelope, recipient))
    }

    /// protects an existing uniformly random root key with its first recipient.
    ///
    /// # Errors
    ///
    /// returns an error when interaction, enrollment, proof, or wrapping
    /// fails. no envelope is returned on partial failure.
    pub fn protect_existing(
        &mut self,
        root: &RootKey,
        enrollment: Enrollment,
        interaction: &mut dyn Interaction,
    ) -> Result<(KeyEnvelope, RecipientId)> {
        let mut envelope_id = [0u8; 32];
        getrandom::fill(&mut envelope_id).map_err(|_| Error::Random)?;
        let mut envelope = KeyEnvelope {
            application_id: self.application_id.clone(),
            envelope_id,
            recipients: Vec::new(),
            mac: [0u8; 32],
        };
        let recipient =
            self.add_recipient_inner(&mut envelope, root, enrollment, interaction, true)?;
        Ok((envelope, recipient))
    }

    /// unlocks one recipient and verifies the envelope before
    /// returning the root key.
    ///
    /// # Errors
    ///
    /// returns an actionable device error before decryption or
    /// [`Error::UnlockFailed`] for cryptographic failure.
    pub fn unlock(
        &mut self,
        envelope: &KeyEnvelope,
        recipient_id: RecipientId,
        interaction: &mut dyn Interaction,
    ) -> Result<RootKey> {
        self.require_application(envelope)?;
        let recipient = envelope.find(recipient_id)?;
        let input = crypto::prf_input(recipient, &envelope.application_id, &envelope.envelope_id)?;
        let prf_result = self.backend.evaluate_prf(
            PrfRequest {
                application_id: &envelope.application_id,
                credential_id: &recipient.credential_id,
                public_key: &recipient.public_key,
                policy: recipient.policy,
                input: &input,
                label: &recipient.label,
                operation: Operation::Unlock,
            },
            interaction,
        )?;
        let outer = crypto::unwrap_token_layer(
            recipient,
            &envelope.application_id,
            &envelope.envelope_id,
            &prf_result,
        )?;
        let passphrase = if recipient.policy.passphrase {
            Some(self.request_passphrase(recipient, Operation::Unlock, false, interaction)?)
        } else {
            None
        };
        let root = crypto::finish_unwrap(
            recipient,
            &envelope.application_id,
            &envelope.envelope_id,
            &outer,
            passphrase.as_ref(),
        )?;
        crypto::verify_envelope_mac(envelope, &root).map_err(|_| Error::UnlockFailed)?;
        Ok(root)
    }

    /// enrolls and adds one recipient.
    ///
    /// # Errors
    ///
    /// returns an error without modifying `envelope` unless enrollment, proof,
    /// wrapping, and envelope authentication all succeed.
    pub fn add_recipient(
        &mut self,
        envelope: &mut KeyEnvelope,
        root: &RootKey,
        enrollment: Enrollment,
        interaction: &mut dyn Interaction,
    ) -> Result<RecipientId> {
        self.require_application(envelope)?;
        self.add_recipient_inner(envelope, root, enrollment, interaction, false)
    }

    /// removes one recipient from the authenticated envelope.
    ///
    /// old complete copies of an envelope remain usable; applications needing
    /// stronger revocation must rotate the root and enforce freshness.
    ///
    /// # Errors
    ///
    /// returns an error for the wrong root, unknown recipient, or an attempt
    /// to remove the final recovery recipient.
    pub fn remove_recipient(
        &mut self,
        envelope: &mut KeyEnvelope,
        root: &RootKey,
        recipient_id: RecipientId,
    ) -> Result<()> {
        self.require_application(envelope)?;
        crypto::verify_envelope_mac(envelope, root)?;
        let mut staged = envelope.clone();
        let index = staged
            .recipients
            .binary_search_by_key(&recipient_id, |recipient| recipient.id)
            .map_err(|_| Error::RecipientNotFound)?;
        if envelope.recipients.len() == 1 {
            return Err(Error::WouldRemoveLastRecipient);
        }
        staged.recipients.remove(index);
        staged.mac = crypto::compute_envelope_mac(&staged, root)?;
        *envelope = staged;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn add_recipient_inner(
        &mut self,
        envelope: &mut KeyEnvelope,
        root: &RootKey,
        enrollment: Enrollment,
        interaction: &mut dyn Interaction,
        allow_empty: bool,
    ) -> Result<RecipientId> {
        if envelope.recipients.is_empty() {
            if !allow_empty {
                return Err(Error::InvalidEnvelope);
            }
        } else {
            crypto::verify_envelope_mac(envelope, root)?;
        }
        if envelope.recipients.len() >= MAX_RECIPIENTS {
            return Err(Error::ResourceLimitExceeded);
        }

        let credential = self.backend.enroll(
            &envelope.application_id,
            enrollment.policy,
            &enrollment.label,
            interaction,
        )?;
        if credential.credential_id.is_empty()
            || credential.credential_id.len() > MAX_CREDENTIAL_ID
            || credential.credential_protection
                != RecipientRecord::expected_credential_protection(enrollment.policy.token)
        {
            return Err(Error::AuthenticatorResponseInvalid);
        }
        let public_key = PublicKey64::new(credential.public_key.0)?;
        let id = compute_recipient_id(
            &envelope.application_id,
            &credential.credential_id,
            &public_key,
            enrollment.policy,
        )?;
        if envelope.recipients.iter().any(|recipient| {
            recipient.id == id || recipient.credential_id == credential.credential_id
        }) {
            return Err(Error::DuplicateRecipient);
        }

        let mut prf_nonce = [0u8; 32];
        let mut token_nonce = [0u8; 12];
        getrandom::fill(&mut prf_nonce).map_err(|_| Error::Random)?;
        getrandom::fill(&mut token_nonce).map_err(|_| Error::Random)?;
        let passphrase_header = if enrollment.policy.passphrase {
            let mut salt = [0u8; 16];
            let mut nonce = [0u8; 12];
            getrandom::fill(&mut salt).map_err(|_| Error::Random)?;
            getrandom::fill(&mut nonce).map_err(|_| Error::Random)?;
            Some(PassphraseHeader { salt, nonce })
        } else {
            None
        };
        let mut record = RecipientRecord {
            id,
            label: enrollment.label,
            credential_id: credential.credential_id,
            public_key,
            policy: enrollment.policy,
            credential_protection: credential.credential_protection,
            prf_nonce,
            token_nonce,
            passphrase: passphrase_header,
            wrapped_key: Vec::new(),
        };

        let input = crypto::prf_input(&record, &envelope.application_id, &envelope.envelope_id)?;
        let prf_result = self.backend.evaluate_prf(
            PrfRequest {
                application_id: &envelope.application_id,
                credential_id: &record.credential_id,
                public_key: &record.public_key,
                policy: record.policy,
                input: &input,
                label: &record.label,
                operation: Operation::Verify,
            },
            interaction,
        )?;
        let passphrase = if record.policy.passphrase {
            let first = self.request_passphrase(&record, Operation::Enroll, false, interaction)?;
            let second = self.request_passphrase(&record, Operation::Enroll, true, interaction)?;
            if !bool::from(first.as_bytes().ct_eq(second.as_bytes())) {
                return Err(Error::InvalidPassphrase);
            }
            Some(first)
        } else {
            None
        };
        record.wrapped_key = crypto::wrap_root(
            &record,
            &envelope.application_id,
            &envelope.envelope_id,
            root,
            &prf_result,
            passphrase.as_ref(),
        )?;

        let mut staged = envelope.clone();
        staged.recipients.push(record);
        staged.recipients.sort_by_key(|recipient| recipient.id);
        staged.mac = crypto::compute_envelope_mac(&staged, root)?;
        *envelope = staged;
        Ok(id)
    }

    fn request_passphrase(
        &self,
        recipient: &RecipientRecord,
        operation: Operation,
        confirm: bool,
        interaction: &mut dyn Interaction,
    ) -> Result<Passphrase> {
        interaction
            .request_passphrase(&PassphrasePrompt {
                application_id: self.application_id.clone(),
                operation,
                recipient_label: recipient.label.clone(),
                confirm,
            })
            .map_err(Error::from)
    }

    fn require_application(&self, envelope: &KeyEnvelope) -> Result<()> {
        if envelope.application_id == self.application_id {
            Ok(())
        } else {
            Err(Error::ApplicationMismatch)
        }
    }

    #[cfg(test)]
    pub(crate) fn fake(application_id: ApplicationId) -> Self {
        Self {
            application_id,
            backend: Box::new(crate::backend::fake::FakeBackend::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{backend::fake::TestInteraction, policy};

    fn same_root(left: &RootKey, right: &RootKey) -> bool {
        left.expose(|left| right.expose(|right| left == right))
    }

    #[test]
    fn token_only_round_trip_and_canonical_decode() {
        let application = ApplicationId::new("org.example.test-vault").unwrap();
        let mut protector = KeyProtector::fake(application);
        let mut interaction = TestInteraction::new(b"unused");
        let (root, envelope, recipient) = protector
            .provision(
                Enrollment::new("primary", policy::user_verified()).unwrap(),
                &mut interaction,
            )
            .unwrap();
        let encoded = envelope.encode();
        let decoded = KeyEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded.encode(), encoded);
        let unlocked = protector
            .unlock(&decoded, recipient, &mut interaction)
            .unwrap();
        assert!(same_root(&root, &unlocked));
        assert_eq!(interaction.pin_requests, 3);
        assert_eq!(
            interaction.pin_operations,
            [Operation::Enroll, Operation::Verify, Operation::Unlock]
        );
        assert_eq!(
            interaction.touch_operations,
            [Operation::Enroll, Operation::Verify, Operation::Unlock]
        );
    }

    #[test]
    fn presence_does_not_request_pin_after_enrollment() {
        let application = ApplicationId::new("org.example.presence-test").unwrap();
        let mut protector = KeyProtector::fake(application);
        let mut interaction = TestInteraction::new(b"unused");
        let (_root, envelope, recipient) = protector
            .provision(
                Enrollment::new("primary", policy::presence()).unwrap(),
                &mut interaction,
            )
            .unwrap();
        assert_eq!(interaction.pin_requests, 1);
        protector
            .unlock(&envelope, recipient, &mut interaction)
            .unwrap();
        assert_eq!(interaction.pin_requests, 1);
    }

    #[test]
    fn passphrase_is_confirmed_and_requested_after_token_unwrap() {
        let application = ApplicationId::new("org.example.passphrase-test").unwrap();
        let mut protector = KeyProtector::fake(application);
        let mut interaction = TestInteraction::new(b"correct horse battery staple");
        let (root, envelope, recipient) = protector
            .provision(
                Enrollment::new("primary", policy::user_verified().and_passphrase()).unwrap(),
                &mut interaction,
            )
            .unwrap();
        assert_eq!(interaction.passphrase_requests, 2);
        let unlocked = protector
            .unlock(&envelope, recipient, &mut interaction)
            .unwrap();
        assert_eq!(interaction.passphrase_requests, 3);
        assert_eq!(
            interaction.passphrase_operations,
            [Operation::Enroll, Operation::Enroll, Operation::Unlock]
        );
        assert_eq!(
            interaction.touch_policies,
            [policy::user_verified().and_passphrase(); 3]
        );
        assert!(same_root(&root, &unlocked));
    }

    #[test]
    fn backup_recipient_recovers_same_root_and_removal_is_authenticated() {
        let application = ApplicationId::new("org.example.backup-test").unwrap();
        let mut protector = KeyProtector::fake(application);
        let mut interaction = TestInteraction::new(b"unused");
        let (root, mut envelope, primary) = protector
            .provision(
                Enrollment::new("primary", policy::user_verified()).unwrap(),
                &mut interaction,
            )
            .unwrap();
        let backup = protector
            .add_recipient(
                &mut envelope,
                &root,
                Enrollment::new("backup", policy::user_verified()).unwrap(),
                &mut interaction,
            )
            .unwrap();
        let recovered = protector
            .unlock(&envelope, backup, &mut interaction)
            .unwrap();
        assert!(same_root(&root, &recovered));
        protector
            .remove_recipient(&mut envelope, &root, primary)
            .unwrap();
        assert_eq!(envelope.recipients().len(), 1);
        assert_eq!(envelope.recipients()[0].id(), backup);
    }

    #[test]
    fn wrong_root_cannot_mutate_envelope() {
        let application = ApplicationId::new("org.example.wrong-root-test").unwrap();
        let mut protector = KeyProtector::fake(application);
        let mut interaction = TestInteraction::new(b"unused");
        let (_root, mut envelope, _primary) = protector
            .provision(
                Enrollment::new("primary", policy::user_verified()).unwrap(),
                &mut interaction,
            )
            .unwrap();
        let before = envelope.encode();
        let wrong = RootKey::generate().unwrap();
        let result = protector.add_recipient(
            &mut envelope,
            &wrong,
            Enrollment::new("bad backup", policy::user_verified()).unwrap(),
            &mut interaction,
        );
        assert!(matches!(result, Err(Error::WrongRootKey)));
        assert_eq!(envelope.encode(), before);
    }

    #[test]
    fn envelope_mac_tamper_converges_to_unlock_failed() {
        let application = ApplicationId::new("org.example.mac-test").unwrap();
        let mut protector = KeyProtector::fake(application);
        let mut interaction = TestInteraction::new(b"unused");
        let (_root, mut envelope, recipient) = protector
            .provision(
                Enrollment::new("primary", policy::user_verified()).unwrap(),
                &mut interaction,
            )
            .unwrap();
        envelope.mac[0] ^= 1;
        assert!(matches!(
            protector.unlock(&envelope, recipient, &mut interaction),
            Err(Error::UnlockFailed)
        ));
    }

    #[test]
    fn outer_tamper_fails_before_passphrase_prompt() {
        let application = ApplicationId::new("org.example.outer-tamper-test").unwrap();
        let mut protector = KeyProtector::fake(application);
        let mut interaction = TestInteraction::new(b"correct passphrase");
        let (_root, mut envelope, recipient) = protector
            .provision(
                Enrollment::new("primary", policy::user_verified().and_passphrase()).unwrap(),
                &mut interaction,
            )
            .unwrap();
        assert_eq!(interaction.passphrase_requests, 2);
        envelope.recipients[0].wrapped_key[0] ^= 1;
        assert!(matches!(
            protector.unlock(&envelope, recipient, &mut interaction),
            Err(Error::UnlockFailed)
        ));
        assert_eq!(interaction.passphrase_requests, 2);
    }

    #[test]
    fn wrong_passphrase_converges_to_unlock_failed() {
        let application = ApplicationId::new("org.example.wrong-passphrase-test").unwrap();
        let mut protector = KeyProtector::fake(application);
        let mut interaction = TestInteraction::new(b"correct passphrase");
        let (_root, envelope, recipient) = protector
            .provision(
                Enrollment::new("primary", policy::user_verified().and_passphrase()).unwrap(),
                &mut interaction,
            )
            .unwrap();
        interaction.passphrase = b"wrong passphrase".to_vec();
        assert!(matches!(
            protector.unlock(&envelope, recipient, &mut interaction),
            Err(Error::UnlockFailed)
        ));
    }

    #[test]
    fn partial_recipient_rollback_fails_but_complete_old_envelope_remains_valid() {
        let application = ApplicationId::new("org.example.rollback-test").unwrap();
        let mut protector = KeyProtector::fake(application);
        let mut interaction = TestInteraction::new(b"unused");
        let (root, mut envelope, primary) = protector
            .provision(
                Enrollment::new("primary", policy::user_verified()).unwrap(),
                &mut interaction,
            )
            .unwrap();
        let backup = protector
            .add_recipient(
                &mut envelope,
                &root,
                Enrollment::new("backup", policy::user_verified()).unwrap(),
                &mut interaction,
            )
            .unwrap();
        let old_complete = envelope.clone();
        let removed_record = envelope.find(primary).unwrap().clone();
        protector
            .remove_recipient(&mut envelope, &root, primary)
            .unwrap();

        let mut spliced = envelope.clone();
        spliced.recipients.push(removed_record);
        spliced.recipients.sort_by_key(|record| record.id);
        assert!(matches!(
            protector.unlock(&spliced, backup, &mut interaction),
            Err(Error::UnlockFailed)
        ));

        let recovered = protector
            .unlock(&old_complete, primary, &mut interaction)
            .unwrap();
        assert!(same_root(&root, &recovered));
    }

    #[test]
    fn last_recipient_cannot_be_removed() {
        let application = ApplicationId::new("org.example.last-recipient-test").unwrap();
        let mut protector = KeyProtector::fake(application);
        let mut interaction = TestInteraction::new(b"unused");
        let (root, mut envelope, primary) = protector
            .provision(
                Enrollment::new("primary", policy::user_verified()).unwrap(),
                &mut interaction,
            )
            .unwrap();
        assert!(matches!(
            protector.remove_recipient(&mut envelope, &root, primary),
            Err(Error::WouldRemoveLastRecipient)
        ));
    }

    #[test]
    fn missing_recipient_causes_no_interaction() {
        let application = ApplicationId::new("org.example.missing-recipient-test").unwrap();
        let mut protector = KeyProtector::fake(application);
        let mut interaction = TestInteraction::new(b"unused");
        let (_root, envelope, _primary) = protector
            .provision(
                Enrollment::new("primary", policy::user_verified()).unwrap(),
                &mut interaction,
            )
            .unwrap();
        let before = (
            interaction.pin_requests,
            interaction.touch_requests,
            interaction.passphrase_requests,
        );
        assert!(matches!(
            protector.unlock(
                &envelope,
                RecipientId::from_bytes([0xff; 32]),
                &mut interaction
            ),
            Err(Error::RecipientNotFound)
        ));
        assert_eq!(
            before,
            (
                interaction.pin_requests,
                interaction.touch_requests,
                interaction.passphrase_requests,
            )
        );
    }

    #[test]
    fn passphrase_confirmation_failure_is_transactional() {
        let application = ApplicationId::new("org.example.confirmation-test").unwrap();
        let mut protector = KeyProtector::fake(application);
        let mut interaction = TestInteraction::new(b"correct passphrase");
        let (root, mut envelope, _primary) = protector
            .provision(
                Enrollment::new("primary", policy::user_verified()).unwrap(),
                &mut interaction,
            )
            .unwrap();
        let before = envelope.encode();
        interaction.confirmation = Some(b"different passphrase".to_vec());
        assert!(matches!(
            protector.add_recipient(
                &mut envelope,
                &root,
                Enrollment::new("backup", policy::user_verified().and_passphrase()).unwrap(),
                &mut interaction,
            ),
            Err(Error::InvalidPassphrase)
        ));
        assert_eq!(envelope.encode(), before);
    }

    #[test]
    fn cancelled_proof_assertion_is_transactional() {
        let application = ApplicationId::new("org.example.cancelled-proof-test").unwrap();
        let mut protector = KeyProtector::fake(application);
        let mut interaction = TestInteraction::new(b"unused");
        let (root, mut envelope, _primary) = protector
            .provision(
                Enrollment::new("primary", policy::user_verified()).unwrap(),
                &mut interaction,
            )
            .unwrap();
        let before = envelope.encode();
        interaction.cancel_on_touch = Some(interaction.touch_requests + 2);
        assert!(matches!(
            protector.add_recipient(
                &mut envelope,
                &root,
                Enrollment::new("backup", policy::user_verified()).unwrap(),
                &mut interaction,
            ),
            Err(Error::Cancelled)
        ));
        assert_eq!(envelope.encode(), before);
    }
}
