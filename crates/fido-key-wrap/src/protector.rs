use subtle::ConstantTimeEq;

#[cfg(test)]
use std::cell::Cell;

use crate::{
    ApplicationId, Enrollment, Error, Interaction, KeyEnvelope, Operation, Passphrase,
    PassphraseLimits, PassphraseParameters, PassphrasePrompt, PassphrasePurpose, RecipientId,
    RecoverySecret, RecoverySecretRecipient, Result, RootKey,
    backend::{AuthenticatorBackend, PrfRequest},
    crypto::{self, DerivedKey},
    envelope::{
        FidoAndPassphraseRecipient, FidoRecipient, KdfDescriptor, MAX_CREDENTIAL_ID,
        MAX_RECIPIENTS, PassphraseRecipient, RecipientRecord, RecoverySecretRecord,
    },
    policy::{RecipientPolicy, validate_label},
};

#[cfg(feature = "fido")]
use crate::FidoConfig;

const ROOT_BYTES: usize = 32;
const WRAPPED_ROOT_BYTES: usize = 48;
const COMBINED_WRAPPED_ROOT_BYTES: usize = 64;
const RANDOM_ATTEMPTS: usize = 32;

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum StagedFault {
    CanonicalDecode,
    RootMismatch,
    EnvelopeMac,
}

#[cfg(test)]
thread_local! {
    static STAGED_FAULT: Cell<Option<StagedFault>> = const { Cell::new(None) };
}

#[cfg(test)]
fn fail_next_staged_validation(fault: StagedFault) {
    STAGED_FAULT.set(Some(fault));
}

#[cfg(test)]
fn take_staged_fault(fault: StagedFault) -> bool {
    if STAGED_FAULT.get() == Some(fault) {
        STAGED_FAULT.set(None);
        true
    } else {
        false
    }
}

/// concrete facade for root protection and recovery.
pub struct KeyProtector {
    application_id: ApplicationId,
    passphrase_limits: PassphraseLimits,
    backend: AuthenticatorBackend,
}

impl KeyProtector {
    /// constructs a protector without security-key support.
    ///
    /// passphrase operations are fully functional. selecting a security-key
    /// policy returns [`Error::FidoSupportUnavailable`] before interaction.
    #[must_use]
    pub const fn new(application_id: ApplicationId) -> Self {
        Self {
            application_id,
            passphrase_limits: PassphraseLimits::DESKTOP,
            backend: AuthenticatorBackend::unavailable(),
        }
    }

    /// constructs a protector backed by the system fido transport.
    ///
    /// construction performs no device discovery or interaction.
    #[cfg(feature = "fido")]
    #[must_use]
    pub fn system(application_id: ApplicationId) -> Self {
        Self::system_with_config(application_id, FidoConfig::default())
    }

    /// constructs a protector with trusted native-operation limits.
    ///
    /// construction performs no device discovery or interaction.
    #[cfg(feature = "fido")]
    #[must_use]
    pub fn system_with_config(application_id: ApplicationId, config: FidoConfig) -> Self {
        Self {
            application_id,
            passphrase_limits: PassphraseLimits::DESKTOP,
            backend: AuthenticatorBackend::system(config),
        }
    }

    /// replaces this process's immutable passphrase-work admission ceiling.
    #[must_use]
    pub const fn with_passphrase_limits(mut self, limits: PassphraseLimits) -> Self {
        self.passphrase_limits = limits;
        self
    }

    /// generates a random root and immediately protects it through one route.
    ///
    /// # errors
    ///
    /// returns an error without exposing an unprotected generated root when
    /// enrollment, interaction, derivation, or staged route verification fails.
    pub fn create_root(
        &mut self,
        enrollment: Enrollment,
        interaction: &mut dyn Interaction,
    ) -> Result<(RootKey, KeyEnvelope, RecipientId)> {
        let root = RootKey::random()?;
        let (envelope, recipient) =
            self.protect_root_for_operation(&root, enrollment, Operation::CreateRoot, interaction)?;
        Ok((root, envelope, recipient))
    }

    /// protects an existing uniformly random root through one route.
    ///
    /// # errors
    ///
    /// returns an error when enrollment, interaction, derivation, or staged
    /// route verification fails.
    pub fn protect_root(
        &mut self,
        root: &RootKey,
        enrollment: Enrollment,
        interaction: &mut dyn Interaction,
    ) -> Result<(KeyEnvelope, RecipientId)> {
        self.protect_root_for_operation(root, enrollment, Operation::ProtectRoot, interaction)
    }

    /// generates a random root and protects it with a new recovery secret.
    ///
    /// the recovery secret is returned only after the complete staged envelope
    /// has been recovered and authenticated.
    pub fn create_root_with_recovery_secret(
        &self,
        label: impl Into<String>,
    ) -> Result<(RootKey, KeyEnvelope, RecoverySecretRecipient)> {
        let root = RootKey::random()?;
        let (envelope, recovery) = self.protect_root_with_recovery_secret(&root, label)?;
        Ok((root, envelope, recovery))
    }

    /// protects an existing uniformly random root with a new recovery secret.
    pub fn protect_root_with_recovery_secret(
        &self,
        root: &RootKey,
        label: impl Into<String>,
    ) -> Result<(KeyEnvelope, RecoverySecretRecipient)> {
        let label = validate_recovery_label(label)?;
        let envelope = KeyEnvelope {
            application_id: self.application_id.clone(),
            envelope_id: random_array()?,
            recipients: Vec::new(),
            mac: [0; ROOT_BYTES],
        };
        let (record, secret, key) = Self::new_recovery_secret_record(&envelope, root, label)?;
        let id = record.id();
        let envelope = Self::stage_record(envelope, record, root, &RecoveryKeys::Recovery(key))?;
        Ok((envelope, RecoverySecretRecipient::new(id, secret)))
    }

    /// recovers a root through exactly one selected recipient.
    ///
    /// # errors
    ///
    /// returns an error without searching another recipient or weakening the
    /// selected policy.
    pub fn unlock(
        &mut self,
        envelope: &KeyEnvelope,
        recipient: RecipientId,
        interaction: &mut dyn Interaction,
    ) -> Result<RootKey> {
        self.require_application(envelope)?;
        let record = envelope.find(recipient)?;
        self.admit_record(record)?;

        let root = match record {
            RecipientRecord::Passphrase(passphrase_record) => {
                let passphrase = request_passphrase(
                    interaction,
                    Operation::Unlock,
                    &passphrase_record.label,
                    PassphrasePurpose::Unlock,
                )?;
                let key = crypto::derive_passphrase_key(
                    record,
                    &self.application_id,
                    &envelope.envelope_id,
                    &passphrase,
                )?;
                drop(passphrase);
                crypto::unwrap_passphrase_root(
                    passphrase_record,
                    &self.application_id,
                    &envelope.envelope_id,
                    &key,
                )?
            }
            RecipientRecord::RecoverySecret(_) => return Err(Error::UnlockFailed),
            RecipientRecord::Fido(fido_record) => {
                let prf = self.evaluate(record, envelope, Operation::Unlock, interaction)?;
                let key = crypto::derive_fido_key(
                    record,
                    &self.application_id,
                    &envelope.envelope_id,
                    &prf,
                )?;
                drop(prf);
                crypto::unwrap_fido_root(
                    fido_record,
                    &self.application_id,
                    &envelope.envelope_id,
                    &key,
                )?
            }
            RecipientRecord::FidoAndPassphrase(combined_record) => {
                let prf = self.evaluate(record, envelope, Operation::Unlock, interaction)?;
                let fido_key = crypto::derive_fido_key(
                    record,
                    &self.application_id,
                    &envelope.envelope_id,
                    &prf,
                )?;
                drop(prf);
                let inner = crypto::unwrap_combined_outer(
                    combined_record,
                    &self.application_id,
                    &envelope.envelope_id,
                    &fido_key,
                )?;
                drop(fido_key);

                let passphrase = request_passphrase(
                    interaction,
                    Operation::Unlock,
                    &combined_record.label,
                    PassphrasePurpose::Unlock,
                )?;
                let passphrase_key = crypto::derive_passphrase_key(
                    record,
                    &self.application_id,
                    &envelope.envelope_id,
                    &passphrase,
                )?;
                drop(passphrase);
                crypto::unwrap_combined_inner(
                    combined_record,
                    &self.application_id,
                    &envelope.envelope_id,
                    &inner,
                    &passphrase_key,
                )?
            }
        };

        if crypto::envelope_mac_matches(envelope, &root)? {
            Ok(root)
        } else {
            Err(Error::UnlockFailed)
        }
    }

    /// recovers a root through exactly one selected recovery-secret recipient.
    pub fn unlock_with_recovery_secret(
        &self,
        envelope: &KeyEnvelope,
        recipient: RecipientId,
        secret: &RecoverySecret,
    ) -> Result<RootKey> {
        self.require_application(envelope)?;
        let RecipientRecord::RecoverySecret(record) =
            envelope.find(recipient).map_err(|_| Error::UnlockFailed)?
        else {
            return Err(Error::UnlockFailed);
        };
        let key = crypto::derive_recovery_secret_key(
            record,
            &self.application_id,
            &envelope.envelope_id,
            secret,
        )?;
        let root = crypto::unwrap_recovery_secret_root(
            record,
            &self.application_id,
            &envelope.envelope_id,
            &key,
        )?;
        if crypto::envelope_mac_matches(envelope, &root)? {
            Ok(root)
        } else {
            Err(Error::UnlockFailed)
        }
    }

    /// adds another alternative recovery route transactionally.
    ///
    /// # errors
    ///
    /// authenticates the current envelope before factor interaction and leaves
    /// it byte-for-byte unchanged on every failure.
    pub fn add_recipient(
        &mut self,
        envelope: &mut KeyEnvelope,
        root: &RootKey,
        enrollment: Enrollment,
        interaction: &mut dyn Interaction,
    ) -> Result<RecipientId> {
        self.require_authenticated(envelope, root)?;
        if envelope.recipients.len() >= MAX_RECIPIENTS {
            return Err(Error::TooManyRecipients);
        }
        self.admit_enrollment(&enrollment)?;

        let (record, keys) = self.enroll_recipient(
            envelope,
            root,
            enrollment,
            Operation::AddRecipient,
            interaction,
        )?;
        let id = record.id();
        let staged = Self::stage_record(envelope.clone(), record, root, &keys)?;
        *envelope = staged;
        Ok(id)
    }

    /// adds a new recovery-secret route transactionally.
    pub fn add_recovery_secret(
        &self,
        envelope: &mut KeyEnvelope,
        root: &RootKey,
        label: impl Into<String>,
    ) -> Result<RecoverySecretRecipient> {
        self.require_authenticated(envelope, root)?;
        if envelope.recipients.len() >= MAX_RECIPIENTS {
            return Err(Error::TooManyRecipients);
        }
        let label = validate_recovery_label(label)?;
        let (record, secret, key) = Self::new_recovery_secret_record(envelope, root, label)?;
        let id = record.id();
        let staged =
            Self::stage_record(envelope.clone(), record, root, &RecoveryKeys::Recovery(key))?;
        *envelope = staged;
        Ok(RecoverySecretRecipient::new(id, secret))
    }

    /// removes one recovery route transactionally.
    ///
    /// # errors
    ///
    /// rejects an absent recipient, a final recipient, an application
    /// mismatch, or a root that does not authenticate the current envelope.
    pub fn remove_recipient(
        &self,
        envelope: &mut KeyEnvelope,
        root: &RootKey,
        recipient: RecipientId,
    ) -> Result<()> {
        self.require_application(envelope)?;
        let index = envelope
            .recipients
            .binary_search_by_key(&recipient, RecipientRecord::id)
            .map_err(|_| Error::RecipientNotFound)?;
        if envelope.recipients.len() == 1 {
            return Err(Error::WouldRemoveLastRecipient);
        }
        crypto::verify_envelope_mac(envelope, root)?;

        let mut staged = envelope.clone();
        staged.recipients.remove(index);
        staged.mac = crypto::compute_envelope_mac(&staged, root)?;
        let staged = canonicalize(&staged)?;
        crypto::verify_envelope_mac(&staged, root)?;
        *envelope = staged;
        Ok(())
    }

    /// replaces a recipient's passphrase while preserving its argon2 work.
    pub fn rewrap_passphrase(
        &mut self,
        envelope: &mut KeyEnvelope,
        root: &RootKey,
        recipient: RecipientId,
        interaction: &mut dyn Interaction,
    ) -> Result<()> {
        self.require_application(envelope)?;
        let parameters = envelope
            .find(recipient)?
            .passphrase_parameters()
            .ok_or(Error::RecipientDoesNotUsePassphrase)?;
        self.rewrap_passphrase_inner(envelope, root, recipient, parameters, interaction)
    }

    /// replaces a recipient's passphrase using the supplied argon2id parameters.
    pub fn rewrap_passphrase_with_parameters(
        &mut self,
        envelope: &mut KeyEnvelope,
        root: &RootKey,
        recipient: RecipientId,
        parameters: PassphraseParameters,
        interaction: &mut dyn Interaction,
    ) -> Result<()> {
        self.rewrap_passphrase_inner(envelope, root, recipient, parameters, interaction)
    }

    fn protect_root_for_operation(
        &mut self,
        root: &RootKey,
        enrollment: Enrollment,
        operation: Operation,
        interaction: &mut dyn Interaction,
    ) -> Result<(KeyEnvelope, RecipientId)> {
        self.admit_enrollment(&enrollment)?;
        let envelope_id = random_array()?;
        let envelope = KeyEnvelope {
            application_id: self.application_id.clone(),
            envelope_id,
            recipients: Vec::new(),
            mac: [0; ROOT_BYTES],
        };
        let (record, keys) =
            self.enroll_recipient(&envelope, root, enrollment, operation, interaction)?;
        let id = record.id();
        let envelope = Self::stage_record(envelope, record, root, &keys)?;
        Ok((envelope, id))
    }

    fn enroll_recipient(
        &mut self,
        envelope: &KeyEnvelope,
        root: &RootKey,
        enrollment: Enrollment,
        operation: Operation,
        interaction: &mut dyn Interaction,
    ) -> Result<(RecipientRecord, RecoveryKeys)> {
        match enrollment.policy {
            RecipientPolicy::Passphrase => self.enroll_passphrase_recipient(
                envelope,
                root,
                enrollment.label,
                enrollment
                    .parameters
                    .ok_or(Error::InvalidPassphraseParameters)?,
                operation,
                interaction,
            ),
            RecipientPolicy::RecoverySecret => Err(Error::InvalidEnvelope),
            RecipientPolicy::Fido(policy) => self.enroll_fido_recipient(
                envelope,
                root,
                enrollment.label,
                policy,
                operation,
                interaction,
            ),
            RecipientPolicy::FidoAndPassphrase(policy) => self.enroll_combined_recipient(
                envelope,
                root,
                enrollment.label,
                policy,
                enrollment
                    .parameters
                    .ok_or(Error::InvalidPassphraseParameters)?,
                operation,
                interaction,
            ),
        }
    }

    fn enroll_passphrase_recipient(
        &self,
        envelope: &KeyEnvelope,
        root: &RootKey,
        label: String,
        parameters: PassphraseParameters,
        operation: Operation,
        interaction: &mut dyn Interaction,
    ) -> Result<(RecipientRecord, RecoveryKeys)> {
        let mut record = RecipientRecord::Passphrase(PassphraseRecipient {
            id: Self::unique_recipient_id(envelope)?,
            label,
            kdf: KdfDescriptor {
                parameters,
                salt: Self::unique_salt(envelope)?,
            },
            passphrase_nonce: random_array()?,
            wrapped_root: [0; WRAPPED_ROOT_BYTES],
        });
        let passphrase = request_new_passphrase(interaction, operation, record.label())?;
        let key = crypto::derive_passphrase_key(
            &record,
            &self.application_id,
            &envelope.envelope_id,
            &passphrase,
        )?;
        drop(passphrase);
        if let RecipientRecord::Passphrase(inner) = &mut record {
            inner.wrapped_root = crypto::wrap_passphrase_root(
                inner,
                &self.application_id,
                &envelope.envelope_id,
                root,
                &key,
            )?;
        }
        Ok((record, RecoveryKeys::Passphrase(key)))
    }

    fn new_recovery_secret_record(
        envelope: &KeyEnvelope,
        root: &RootKey,
        label: String,
    ) -> Result<(RecipientRecord, RecoverySecret, DerivedKey)> {
        let secret = RecoverySecret::random()?;
        let mut record = RecipientRecord::RecoverySecret(RecoverySecretRecord {
            id: Self::unique_recipient_id(envelope)?,
            label,
            recovery_nonce: random_array()?,
            wrapped_root: [0; WRAPPED_ROOT_BYTES],
        });
        let RecipientRecord::RecoverySecret(inner) = &record else {
            unreachable!("constructed recovery-secret record")
        };
        let key = crypto::derive_recovery_secret_key(
            inner,
            &envelope.application_id,
            &envelope.envelope_id,
            &secret,
        )?;
        if let RecipientRecord::RecoverySecret(inner) = &mut record {
            inner.wrapped_root = crypto::wrap_recovery_secret_root(
                inner,
                &envelope.application_id,
                &envelope.envelope_id,
                root,
                &key,
            )?;
        }
        Ok((record, secret, key))
    }

    fn enroll_fido_recipient(
        &mut self,
        envelope: &KeyEnvelope,
        root: &RootKey,
        label: String,
        policy: crate::FidoPolicy,
        operation: Operation,
        interaction: &mut dyn Interaction,
    ) -> Result<(RecipientRecord, RecoveryKeys)> {
        let credential =
            self.backend
                .enroll(&self.application_id, policy, &label, operation, interaction)?;
        Self::validate_credential(envelope, &credential.credential_id)?;
        let mut record = RecipientRecord::Fido(FidoRecipient {
            id: Self::unique_recipient_id(envelope)?,
            label,
            credential_id: credential.credential_id,
            public_key: credential.public_key,
            policy,
            prf_nonce: random_array()?,
            fido_nonce: random_array()?,
            wrapped_root: [0; WRAPPED_ROOT_BYTES],
        });
        let prf = self.evaluate(&record, envelope, operation, interaction)?;
        let key =
            crypto::derive_fido_key(&record, &self.application_id, &envelope.envelope_id, &prf)?;
        drop(prf);
        if let RecipientRecord::Fido(inner) = &mut record {
            inner.wrapped_root = crypto::wrap_fido_root(
                inner,
                &self.application_id,
                &envelope.envelope_id,
                root,
                &key,
            )?;
        }
        Ok((record, RecoveryKeys::Fido(key)))
    }

    #[allow(clippy::too_many_arguments)]
    fn enroll_combined_recipient(
        &mut self,
        envelope: &KeyEnvelope,
        root: &RootKey,
        label: String,
        policy: crate::FidoPolicy,
        parameters: PassphraseParameters,
        operation: Operation,
        interaction: &mut dyn Interaction,
    ) -> Result<(RecipientRecord, RecoveryKeys)> {
        let credential =
            self.backend
                .enroll(&self.application_id, policy, &label, operation, interaction)?;
        Self::validate_credential(envelope, &credential.credential_id)?;
        let mut record = RecipientRecord::FidoAndPassphrase(FidoAndPassphraseRecipient {
            id: Self::unique_recipient_id(envelope)?,
            label,
            credential_id: credential.credential_id,
            public_key: credential.public_key,
            policy,
            prf_nonce: random_array()?,
            fido_nonce: random_array()?,
            kdf: KdfDescriptor {
                parameters,
                salt: Self::unique_salt(envelope)?,
            },
            passphrase_nonce: random_array()?,
            wrapped_root: [0; COMBINED_WRAPPED_ROOT_BYTES],
        });
        let prf = self.evaluate(&record, envelope, operation, interaction)?;
        let fido_key =
            crypto::derive_fido_key(&record, &self.application_id, &envelope.envelope_id, &prf)?;
        drop(prf);
        let passphrase = request_new_passphrase(interaction, operation, record.label())?;
        let passphrase_key = crypto::derive_passphrase_key(
            &record,
            &self.application_id,
            &envelope.envelope_id,
            &passphrase,
        )?;
        drop(passphrase);
        if let RecipientRecord::FidoAndPassphrase(inner) = &mut record {
            inner.wrapped_root = crypto::wrap_combined_root(
                inner,
                &self.application_id,
                &envelope.envelope_id,
                root,
                &passphrase_key,
                &fido_key,
            )?;
        }
        Ok((
            record,
            RecoveryKeys::Combined {
                passphrase: passphrase_key,
                fido: fido_key,
            },
        ))
    }

    fn rewrap_passphrase_inner(
        &mut self,
        envelope: &mut KeyEnvelope,
        root: &RootKey,
        recipient: RecipientId,
        parameters: PassphraseParameters,
        interaction: &mut dyn Interaction,
    ) -> Result<()> {
        self.require_application(envelope)?;
        let current = envelope.find(recipient)?.clone();
        if !current.policy().uses_passphrase() {
            return Err(Error::RecipientDoesNotUsePassphrase);
        }
        crypto::verify_envelope_mac(envelope, root)?;
        self.admit_parameters(parameters)?;

        let (replacement, keys) = match &current {
            RecipientRecord::Passphrase(old) => {
                self.rewrap_passphrase_record(envelope, root, old, parameters, interaction)?
            }
            RecipientRecord::RecoverySecret(_) => {
                return Err(Error::RecipientDoesNotUsePassphrase);
            }
            RecipientRecord::Fido(_) => return Err(Error::RecipientDoesNotUsePassphrase),
            RecipientRecord::FidoAndPassphrase(old) => {
                self.rewrap_combined_record(envelope, root, old, parameters, interaction)?
            }
        };

        let mut staged = envelope.clone();
        let index = staged
            .recipients
            .binary_search_by_key(&recipient, RecipientRecord::id)
            .map_err(|_| Error::RecipientNotFound)?;
        staged.recipients[index] = replacement;
        let staged = Self::stage_existing_record(staged, recipient, root, &keys)?;
        *envelope = staged;
        Ok(())
    }

    fn rewrap_passphrase_record(
        &self,
        envelope: &KeyEnvelope,
        root: &RootKey,
        old: &PassphraseRecipient,
        parameters: PassphraseParameters,
        interaction: &mut dyn Interaction,
    ) -> Result<(RecipientRecord, RecoveryKeys)> {
        let mut replacement = RecipientRecord::Passphrase(PassphraseRecipient {
            id: old.id,
            label: old.label.clone(),
            kdf: KdfDescriptor {
                parameters,
                salt: Self::unique_salt(envelope)?,
            },
            passphrase_nonce: fresh_array(&old.passphrase_nonce)?,
            wrapped_root: [0; WRAPPED_ROOT_BYTES],
        });
        let passphrase = request_new_passphrase(
            interaction,
            Operation::RewrapPassphrase,
            replacement.label(),
        )?;
        let key = crypto::derive_passphrase_key(
            &replacement,
            &self.application_id,
            &envelope.envelope_id,
            &passphrase,
        )?;
        drop(passphrase);
        if let RecipientRecord::Passphrase(inner) = &mut replacement {
            inner.wrapped_root = crypto::wrap_passphrase_root(
                inner,
                &self.application_id,
                &envelope.envelope_id,
                root,
                &key,
            )?;
        }
        Ok((replacement, RecoveryKeys::Passphrase(key)))
    }

    fn rewrap_combined_record(
        &mut self,
        envelope: &KeyEnvelope,
        root: &RootKey,
        old: &FidoAndPassphraseRecipient,
        parameters: PassphraseParameters,
        interaction: &mut dyn Interaction,
    ) -> Result<(RecipientRecord, RecoveryKeys)> {
        let mut replacement = RecipientRecord::FidoAndPassphrase(FidoAndPassphraseRecipient {
            id: old.id,
            label: old.label.clone(),
            credential_id: old.credential_id.clone(),
            public_key: old.public_key.clone(),
            policy: old.policy,
            prf_nonce: fresh_array(&old.prf_nonce)?,
            fido_nonce: fresh_array(&old.fido_nonce)?,
            kdf: KdfDescriptor {
                parameters,
                salt: Self::unique_salt(envelope)?,
            },
            passphrase_nonce: fresh_array(&old.passphrase_nonce)?,
            wrapped_root: [0; COMBINED_WRAPPED_ROOT_BYTES],
        });
        let prf = self.evaluate(
            &replacement,
            envelope,
            Operation::RewrapPassphrase,
            interaction,
        )?;
        let fido_key = crypto::derive_fido_key(
            &replacement,
            &self.application_id,
            &envelope.envelope_id,
            &prf,
        )?;
        drop(prf);
        let passphrase = request_new_passphrase(
            interaction,
            Operation::RewrapPassphrase,
            replacement.label(),
        )?;
        let passphrase_key = crypto::derive_passphrase_key(
            &replacement,
            &self.application_id,
            &envelope.envelope_id,
            &passphrase,
        )?;
        drop(passphrase);
        if let RecipientRecord::FidoAndPassphrase(inner) = &mut replacement {
            inner.wrapped_root = crypto::wrap_combined_root(
                inner,
                &self.application_id,
                &envelope.envelope_id,
                root,
                &passphrase_key,
                &fido_key,
            )?;
        }
        Ok((
            replacement,
            RecoveryKeys::Combined {
                passphrase: passphrase_key,
                fido: fido_key,
            },
        ))
    }

    fn stage_record(
        mut staged: KeyEnvelope,
        record: RecipientRecord,
        root: &RootKey,
        keys: &RecoveryKeys,
    ) -> Result<KeyEnvelope> {
        let recipient = record.id();
        staged.recipients.push(record);
        staged.recipients.sort_by_key(RecipientRecord::id);
        Self::stage_existing_record(staged, recipient, root, keys)
    }

    fn stage_existing_record(
        mut staged: KeyEnvelope,
        recipient: RecipientId,
        root: &RootKey,
        keys: &RecoveryKeys,
    ) -> Result<KeyEnvelope> {
        staged.mac = crypto::compute_envelope_mac(&staged, root)?;
        let staged = canonicalize(&staged)?;
        #[cfg(test)]
        let staged = {
            let mut staged = staged;
            if take_staged_fault(StagedFault::EnvelopeMac) {
                staged.mac[0] ^= 1;
            }
            staged
        };
        let recovered = recover_with_keys(
            staged.find(recipient)?,
            &staged.application_id,
            &staged.envelope_id,
            keys,
        )?;
        #[cfg(test)]
        let recovered = if take_staged_fault(StagedFault::RootMismatch) {
            let mut wrong = zeroize::Zeroizing::new(root.expose(|bytes| *bytes));
            wrong[0] ^= 1;
            RootKey::from_zeroizing(wrong)
        } else {
            recovered
        };
        if !roots_match(root, &recovered) || !crypto::envelope_mac_matches(&staged, &recovered)? {
            return Err(Error::UnlockFailed);
        }
        Ok(staged)
    }

    fn evaluate(
        &mut self,
        record: &RecipientRecord,
        envelope: &KeyEnvelope,
        operation: Operation,
        interaction: &mut dyn Interaction,
    ) -> Result<zeroize::Zeroizing<[u8; 32]>> {
        let (credential_id, public_key, policy) = match record {
            RecipientRecord::Passphrase(_) | RecipientRecord::RecoverySecret(_) => {
                return Err(Error::InvalidEnvelope);
            }
            RecipientRecord::Fido(inner) => (&inner.credential_id, &inner.public_key, inner.policy),
            RecipientRecord::FidoAndPassphrase(inner) => {
                (&inner.credential_id, &inner.public_key, inner.policy)
            }
        };
        let input = crypto::prf_input(record, &self.application_id, &envelope.envelope_id)?;
        self.backend.evaluate(
            &PrfRequest {
                application_id: &self.application_id,
                credential_id,
                public_key,
                policy,
                input: &input,
                label: record.label(),
                operation,
            },
            interaction,
        )
    }

    fn require_application(&self, envelope: &KeyEnvelope) -> Result<()> {
        if envelope.application_id == self.application_id {
            Ok(())
        } else {
            Err(Error::ApplicationMismatch)
        }
    }

    fn require_authenticated(&self, envelope: &KeyEnvelope, root: &RootKey) -> Result<()> {
        self.require_application(envelope)?;
        crypto::verify_envelope_mac(envelope, root)
    }

    fn admit_enrollment(&self, enrollment: &Enrollment) -> Result<()> {
        if let Some(parameters) = enrollment.parameters {
            self.admit_parameters(parameters)?;
        }
        Ok(())
    }

    fn admit_record(&self, record: &RecipientRecord) -> Result<()> {
        if let Some(parameters) = record.passphrase_parameters() {
            self.admit_parameters(parameters)?;
        }
        Ok(())
    }

    fn admit_parameters(&self, parameters: PassphraseParameters) -> Result<()> {
        if self.passphrase_limits.accepts(parameters) {
            Ok(())
        } else {
            Err(Error::PassphraseLimitExceeded)
        }
    }

    fn unique_recipient_id(envelope: &KeyEnvelope) -> Result<RecipientId> {
        for _ in 0..RANDOM_ATTEMPTS {
            let id = RecipientId::from_bytes(random_array()?);
            if envelope.find(id).is_err() {
                return Ok(id);
            }
        }
        Err(Error::RandomUnavailable)
    }

    fn unique_salt(envelope: &KeyEnvelope) -> Result<[u8; 16]> {
        for _ in 0..RANDOM_ATTEMPTS {
            let salt = random_array()?;
            let duplicate = envelope.recipients.iter().any(|record| match record {
                RecipientRecord::Passphrase(inner) => inner.kdf.salt == salt,
                RecipientRecord::RecoverySecret(_) | RecipientRecord::Fido(_) => false,
                RecipientRecord::FidoAndPassphrase(inner) => inner.kdf.salt == salt,
            });
            if !duplicate {
                return Ok(salt);
            }
        }
        Err(Error::RandomUnavailable)
    }

    fn validate_credential(envelope: &KeyEnvelope, credential_id: &[u8]) -> Result<()> {
        if credential_id.is_empty()
            || credential_id.len() > MAX_CREDENTIAL_ID
            || envelope.recipients.iter().any(|record| match record {
                RecipientRecord::Passphrase(_) | RecipientRecord::RecoverySecret(_) => false,
                RecipientRecord::Fido(inner) => inner.credential_id == credential_id,
                RecipientRecord::FidoAndPassphrase(inner) => inner.credential_id == credential_id,
            })
        {
            return Err(Error::AuthenticatorResponseInvalid);
        }
        Ok(())
    }

    #[cfg(any(feature = "testing", test))]
    pub(crate) fn fake(application_id: ApplicationId) -> Self {
        Self {
            application_id,
            passphrase_limits: PassphraseLimits::DESKTOP,
            backend: AuthenticatorBackend::fake(),
        }
    }

    #[cfg(any(feature = "testing", test))]
    pub(crate) fn fake_backend_mut(&mut self) -> &mut crate::backend::fake::FakeBackend {
        self.backend.fake_mut()
    }
}

enum RecoveryKeys {
    Passphrase(DerivedKey),
    Recovery(DerivedKey),
    Fido(DerivedKey),
    Combined {
        passphrase: DerivedKey,
        fido: DerivedKey,
    },
}

fn recover_with_keys(
    record: &RecipientRecord,
    application_id: &ApplicationId,
    envelope_id: &[u8; 32],
    keys: &RecoveryKeys,
) -> Result<RootKey> {
    match (record, keys) {
        (RecipientRecord::Passphrase(record), RecoveryKeys::Passphrase(key)) => {
            crypto::unwrap_passphrase_root(record, application_id, envelope_id, key)
        }
        (RecipientRecord::RecoverySecret(record), RecoveryKeys::Recovery(key)) => {
            crypto::unwrap_recovery_secret_root(record, application_id, envelope_id, key)
        }
        (RecipientRecord::Fido(record), RecoveryKeys::Fido(key)) => {
            crypto::unwrap_fido_root(record, application_id, envelope_id, key)
        }
        (
            RecipientRecord::FidoAndPassphrase(record),
            RecoveryKeys::Combined { passphrase, fido },
        ) => {
            let inner = crypto::unwrap_combined_outer(record, application_id, envelope_id, fido)?;
            crypto::unwrap_combined_inner(record, application_id, envelope_id, &inner, passphrase)
        }
        _ => Err(Error::InvalidEnvelope),
    }
}

fn validate_recovery_label(label: impl Into<String>) -> Result<String> {
    let label = label.into();
    validate_label(&label).map_err(|()| Error::InvalidLabel)?;
    Ok(label)
}

fn request_passphrase(
    interaction: &mut dyn Interaction,
    operation: Operation,
    label: &str,
    purpose: PassphrasePurpose,
) -> Result<Passphrase> {
    interaction
        .request_passphrase(&PassphrasePrompt::new(operation, label, purpose))
        .map_err(Error::from)
}

fn request_new_passphrase(
    interaction: &mut dyn Interaction,
    operation: Operation,
    label: &str,
) -> Result<Passphrase> {
    let passphrase = request_passphrase(interaction, operation, label, PassphrasePurpose::New)?;
    let confirmation =
        request_passphrase(interaction, operation, label, PassphrasePurpose::Confirm)?;
    if !passphrase.confirmation_matches(&confirmation) {
        return Err(Error::PassphraseConfirmationMismatch);
    }
    drop(confirmation);
    Ok(passphrase)
}

fn canonicalize(envelope: &KeyEnvelope) -> Result<KeyEnvelope> {
    let encoded = envelope.encode();
    #[cfg(test)]
    let encoded = {
        let mut encoded = encoded;
        if take_staged_fault(StagedFault::CanonicalDecode) {
            encoded.push(0);
        }
        encoded
    };
    KeyEnvelope::decode(&encoded)
}

fn roots_match(left: &RootKey, right: &RootKey) -> bool {
    bool::from(left.bytes().ct_eq(right.bytes()))
}

fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|_| Error::RandomUnavailable)?;
    Ok(bytes)
}

fn fresh_array<const N: usize>(old: &[u8; N]) -> Result<[u8; N]> {
    for _ in 0..RANDOM_ATTEMPTS {
        let value = random_array()?;
        if &value != old {
            return Ok(value);
        }
    }
    Err(Error::RandomUnavailable)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use crate::{AuthenticatorFailure, FidoPolicy, InteractionError, Pin};

    struct ScriptedInteraction {
        passphrases: VecDeque<Vec<u8>>,
        events: Vec<&'static str>,
    }

    impl ScriptedInteraction {
        fn new(values: &[&[u8]]) -> Self {
            Self {
                passphrases: values.iter().map(|value| value.to_vec()).collect(),
                events: Vec::new(),
            }
        }
    }

    impl Interaction for ScriptedInteraction {
        fn request_passphrase(
            &mut self,
            prompt: &PassphrasePrompt,
        ) -> std::result::Result<Passphrase, InteractionError> {
            self.events.push(match prompt.purpose() {
                PassphrasePurpose::Unlock => "unlock passphrase",
                PassphrasePurpose::New => "new passphrase",
                PassphrasePurpose::Confirm => "confirm passphrase",
            });
            Passphrase::new(
                self.passphrases
                    .pop_front()
                    .ok_or(InteractionError::Failed)?,
            )
            .map_err(|_| InteractionError::Failed)
        }

        fn request_pin(
            &mut self,
            _prompt: &crate::PinPrompt,
        ) -> std::result::Result<Pin, InteractionError> {
            self.events.push("pin");
            Pin::new("123456".to_owned()).map_err(|_| InteractionError::Failed)
        }

        fn touch_required(
            &mut self,
            prompt: &crate::TouchPrompt,
        ) -> std::result::Result<(), InteractionError> {
            self.events.push(match prompt.ceremony() {
                crate::FidoCeremony::Enrollment => "enrollment touch",
                crate::FidoCeremony::Assertion => "assertion touch",
            });
            Ok(())
        }
    }

    struct CancelledInteraction;

    impl Interaction for CancelledInteraction {
        fn request_passphrase(
            &mut self,
            _prompt: &PassphrasePrompt,
        ) -> std::result::Result<Passphrase, InteractionError> {
            Err(InteractionError::Cancelled)
        }
    }

    struct UnsupportedInteraction;

    impl Interaction for UnsupportedInteraction {}

    fn application() -> ApplicationId {
        ApplicationId::new("org.example.protector-test").unwrap()
    }

    fn test_parameters() -> PassphraseParameters {
        PassphraseParameters::new(65_536, 3, 1).unwrap()
    }

    fn enrollment(label: &str) -> Enrollment {
        Enrollment::passphrase_with_parameters(label, test_parameters()).unwrap()
    }

    #[test]
    fn passphrase_lifecycle_is_transactional() {
        crypto::reset_passphrase_derivations();
        let mut protector =
            KeyProtector::new(application()).with_passphrase_limits(PassphraseLimits::PROTOCOL_MAX);
        let mut interaction = ScriptedInteraction::new(&[b"first", b"first"]);
        let (root, mut envelope, first) = protector
            .create_root(enrollment("first"), &mut interaction)
            .unwrap();
        assert_eq!(crypto::passphrase_derivations(), 1);

        crypto::reset_passphrase_derivations();
        let mut open = ScriptedInteraction::new(&[b"first"]);
        let recovered = protector.unlock(&envelope, first, &mut open).unwrap();
        assert!(roots_match(&root, &recovered));
        assert_eq!(crypto::passphrase_derivations(), 1);

        let mut add = ScriptedInteraction::new(&[b"second", b"second"]);
        let second = protector
            .add_recipient(&mut envelope, &root, enrollment("second"), &mut add)
            .unwrap();
        protector
            .remove_recipient(&mut envelope, &root, first)
            .unwrap();
        assert_eq!(envelope.recipients().len(), 1);
        assert_eq!(envelope.recipients()[0].id(), second);

        let before = envelope.encode();
        let mut wrong = ScriptedInteraction::new(&[b"wrong"]);
        assert!(matches!(
            protector.unlock(&envelope, second, &mut wrong),
            Err(Error::UnlockFailed)
        ));
        assert_eq!(envelope.encode(), before);
    }

    #[test]
    fn recovery_secret_lifecycle_is_noninteractive_and_transactional() {
        let mut protector = KeyProtector::new(application());
        let (root, mut envelope, recovery) = protector
            .create_root_with_recovery_secret("recovery")
            .unwrap();
        let recipient = recovery.recipient_id();
        assert_eq!(
            envelope.recipients()[0].policy(),
            RecipientPolicy::RecoverySecret
        );

        let encoded = envelope.encode();
        recovery.secret().expose(|secret| {
            assert!(!encoded.windows(secret.len()).any(|window| window == secret));
        });

        let recovered = protector
            .unlock_with_recovery_secret(&envelope, recipient, recovery.secret())
            .unwrap();
        assert!(roots_match(&root, &recovered));

        let mut exported = recovery.secret().expose(|secret| *secret);
        let imported = RecoverySecret::import(&mut exported);
        assert_eq!(exported, [0; 32]);
        let recovered = protector
            .unlock_with_recovery_secret(&envelope, recipient, &imported)
            .unwrap();
        assert!(roots_match(&root, &recovered));

        let mut wrong_bytes = [0x81; 32];
        let wrong = RecoverySecret::import(&mut wrong_bytes);
        assert!(matches!(
            protector.unlock_with_recovery_secret(&envelope, recipient, &wrong),
            Err(Error::UnlockFailed)
        ));

        let mut no_interaction = ScriptedInteraction::new(&[]);
        assert!(matches!(
            protector.unlock(&envelope, recipient, &mut no_interaction),
            Err(Error::UnlockFailed)
        ));
        assert!(no_interaction.events.is_empty());

        let second = protector
            .add_recovery_secret(&mut envelope, &root, "second recovery")
            .unwrap();
        assert_eq!(envelope.recipients().len(), 2);
        protector
            .remove_recipient(&mut envelope, &root, recipient)
            .unwrap();
        let recovered = protector
            .unlock_with_recovery_secret(&envelope, second.recipient_id(), second.secret())
            .unwrap();
        assert!(roots_match(&root, &recovered));
    }

    #[test]
    fn recovery_secret_binds_context_and_failed_additions_do_not_publish() {
        let protector = KeyProtector::new(application());
        let (root, envelope, recovery) = protector
            .create_root_with_recovery_secret("recovery")
            .unwrap();

        for mutate in [
            |record: &mut RecoverySecretRecord| record.label.push('x'),
            |record: &mut RecoverySecretRecord| record.recovery_nonce[0] ^= 1,
            |record: &mut RecoverySecretRecord| record.wrapped_root[0] ^= 1,
        ] {
            let mut hostile = envelope.clone();
            let RecipientRecord::RecoverySecret(record) = &mut hostile.recipients[0] else {
                panic!("fixture must contain a recovery-secret recipient");
            };
            mutate(record);
            assert!(matches!(
                protector.unlock_with_recovery_secret(
                    &hostile,
                    recovery.recipient_id(),
                    recovery.secret(),
                ),
                Err(Error::UnlockFailed)
            ));
        }

        let absent = RecipientId::from_bytes([0x7a; 32]);
        assert!(matches!(
            protector.unlock_with_recovery_secret(&envelope, absent, recovery.secret()),
            Err(Error::UnlockFailed)
        ));

        let mut hostile = envelope.clone();
        hostile.envelope_id[0] ^= 1;
        assert!(matches!(
            protector.unlock_with_recovery_secret(
                &hostile,
                recovery.recipient_id(),
                recovery.secret(),
            ),
            Err(Error::UnlockFailed)
        ));

        let mut hostile = envelope.clone();
        let RecipientRecord::RecoverySecret(record) = &mut hostile.recipients[0] else {
            panic!("fixture must contain a recovery-secret recipient");
        };
        let changed_id = RecipientId::from_bytes([0x6b; 32]);
        record.id = changed_id;
        assert!(matches!(
            protector.unlock_with_recovery_secret(&hostile, changed_id, recovery.secret()),
            Err(Error::UnlockFailed)
        ));

        let mut hostile = envelope.clone();
        hostile.application_id = ApplicationId::new("org.example.other-application").unwrap();
        let other_protector = KeyProtector::new(hostile.application_id.clone());
        assert!(matches!(
            other_protector.unlock_with_recovery_secret(
                &hostile,
                recovery.recipient_id(),
                recovery.secret(),
            ),
            Err(Error::UnlockFailed)
        ));

        let mut mutable = envelope;
        let original = mutable.encode();
        let wrong_root = RootKey::import(&mut [0x45; 32]);
        assert!(matches!(
            protector.add_recovery_secret(&mut mutable, &wrong_root, "new recovery"),
            Err(Error::EnvelopeAuthenticationFailed)
        ));
        assert_eq!(mutable.encode(), original);

        for fault in [
            StagedFault::CanonicalDecode,
            StagedFault::RootMismatch,
            StagedFault::EnvelopeMac,
        ] {
            fail_next_staged_validation(fault);
            assert!(
                protector
                    .add_recovery_secret(&mut mutable, &root, "new recovery")
                    .is_err()
            );
            assert_eq!(mutable.encode(), original);
        }
    }

    #[test]
    fn passphrase_rewrap_preserves_identity_root_and_old_complete_copy() {
        let mut protector =
            KeyProtector::new(application()).with_passphrase_limits(PassphraseLimits::PROTOCOL_MAX);
        let mut create = ScriptedInteraction::new(&[b"old secret", b"old secret"]);
        let (root, mut envelope, recipient) = protector
            .create_root(enrollment("primary"), &mut create)
            .unwrap();
        let old_bytes = envelope.encode();

        crypto::reset_passphrase_derivations();
        let mut rewrap = ScriptedInteraction::new(&[b"new secret", b"new secret"]);
        protector
            .rewrap_passphrase(&mut envelope, &root, recipient, &mut rewrap)
            .unwrap();
        assert_eq!(crypto::passphrase_derivations(), 1);
        assert_ne!(envelope.encode(), old_bytes);
        assert_eq!(envelope.recipients()[0].id(), recipient);

        let mut open_new = ScriptedInteraction::new(&[b"new secret"]);
        let recovered = protector
            .unlock(&envelope, recipient, &mut open_new)
            .unwrap();
        assert!(roots_match(&root, &recovered));

        let old_envelope = KeyEnvelope::decode(&old_bytes).unwrap();
        let mut open_old = ScriptedInteraction::new(&[b"old secret"]);
        let recovered_old = protector
            .unlock(&old_envelope, recipient, &mut open_old)
            .unwrap();
        assert!(roots_match(&root, &recovered_old));

        let mut obsolete = ScriptedInteraction::new(&[b"old secret"]);
        assert!(matches!(
            protector.unlock(&envelope, recipient, &mut obsolete),
            Err(Error::UnlockFailed)
        ));
    }

    #[test]
    fn explicit_cost_change_preserves_the_root_and_old_complete_copy() {
        let mut protector =
            KeyProtector::new(application()).with_passphrase_limits(PassphraseLimits::PROTOCOL_MAX);
        let mut create = ScriptedInteraction::new(&[b"old", b"old"]);
        let (root, mut current, recipient) = protector
            .create_root(enrollment("primary"), &mut create)
            .unwrap();
        let old = current.clone();
        let replacement = PassphraseParameters::new(65_536, 4, 2).unwrap();

        let mut rewrap = ScriptedInteraction::new(&[b"new", b"new"]);
        protector
            .rewrap_passphrase_with_parameters(
                &mut current,
                &root,
                recipient,
                replacement,
                &mut rewrap,
            )
            .unwrap();
        assert_eq!(
            current.recipients()[0].passphrase_parameters(),
            Some(replacement)
        );

        let mut open_old = ScriptedInteraction::new(&[b"old"]);
        let old_root = protector.unlock(&old, recipient, &mut open_old).unwrap();
        let mut open_new = ScriptedInteraction::new(&[b"new"]);
        let new_root = protector
            .unlock(&current, recipient, &mut open_new)
            .unwrap();
        assert!(roots_match(&root, &old_root));
        assert!(roots_match(&root, &new_root));
    }

    #[test]
    fn removal_does_not_invalidate_an_old_complete_copy() {
        let mut protector =
            KeyProtector::new(application()).with_passphrase_limits(PassphraseLimits::PROTOCOL_MAX);
        let mut create = ScriptedInteraction::new(&[b"primary", b"primary"]);
        let (root, mut current, _primary) = protector
            .create_root(enrollment("primary"), &mut create)
            .unwrap();
        let mut add = ScriptedInteraction::new(&[b"removed", b"removed"]);
        let removed = protector
            .add_recipient(&mut current, &root, enrollment("removed"), &mut add)
            .unwrap();
        let old = current.clone();

        protector
            .remove_recipient(&mut current, &root, removed)
            .unwrap();
        let mut no_prompt = ScriptedInteraction::new(&[]);
        assert!(matches!(
            protector.unlock(&current, removed, &mut no_prompt),
            Err(Error::RecipientNotFound)
        ));
        let mut open_old = ScriptedInteraction::new(&[b"removed"]);
        let recovered = protector.unlock(&old, removed, &mut open_old).unwrap();
        assert!(roots_match(&root, &recovered));
    }

    #[test]
    fn mutation_failures_leave_the_exact_envelope_unchanged() {
        let mut protector =
            KeyProtector::new(application()).with_passphrase_limits(PassphraseLimits::PROTOCOL_MAX);
        let mut create = ScriptedInteraction::new(&[b"primary", b"primary"]);
        let (root, mut envelope, recipient) = protector
            .create_root(enrollment("primary"), &mut create)
            .unwrap();
        let original = envelope.encode();

        let wrong_root = RootKey::import(&mut [0x77; 32]);
        let mut no_prompt = ScriptedInteraction::new(&[]);
        assert!(matches!(
            protector.add_recipient(
                &mut envelope,
                &wrong_root,
                enrollment("secondary"),
                &mut no_prompt
            ),
            Err(Error::EnvelopeAuthenticationFailed)
        ));
        assert!(no_prompt.events.is_empty());
        assert_eq!(envelope.encode(), original);

        crypto::reset_passphrase_derivations();
        let mut mismatch = ScriptedInteraction::new(&[b"one", b"two"]);
        assert!(matches!(
            protector.add_recipient(&mut envelope, &root, enrollment("secondary"), &mut mismatch),
            Err(Error::PassphraseConfirmationMismatch)
        ));
        assert_eq!(crypto::passphrase_derivations(), 0);
        assert_eq!(envelope.encode(), original);

        assert!(matches!(
            protector.remove_recipient(&mut envelope, &root, recipient),
            Err(Error::WouldRemoveLastRecipient)
        ));
        assert_eq!(envelope.encode(), original);

        let mut unsupported = UnsupportedInteraction;
        assert!(matches!(
            protector.add_recipient(
                &mut envelope,
                &root,
                enrollment("unsupported"),
                &mut unsupported,
            ),
            Err(Error::Interaction(InteractionError::Unsupported))
        ));
        assert_eq!(envelope.encode(), original);
    }

    #[test]
    fn final_recipient_removal_fails_for_every_structural_suite() {
        let cases = [
            Enrollment::passphrase_with_parameters("passphrase", test_parameters()).unwrap(),
            Enrollment::fido("fido", FidoPolicy::Presence).unwrap(),
            Enrollment::fido_and_passphrase_with_parameters(
                "combined",
                FidoPolicy::Presence,
                test_parameters(),
            )
            .unwrap(),
        ];

        for enrollment in cases {
            let mut protector = KeyProtector::fake(application());
            let mut create = ScriptedInteraction::new(&[b"secret", b"secret"]);
            let (root, mut envelope, recipient) =
                protector.create_root(enrollment, &mut create).unwrap();
            let original = envelope.encode();
            assert!(matches!(
                protector.remove_recipient(&mut envelope, &root, recipient),
                Err(Error::WouldRemoveLastRecipient)
            ));
            assert_eq!(envelope.encode(), original);
        }

        let protector = KeyProtector::new(application());
        let (root, mut envelope, recovery) = protector
            .create_root_with_recovery_secret("recovery")
            .unwrap();
        let original = envelope.encode();
        assert!(matches!(
            protector.remove_recipient(&mut envelope, &root, recovery.recipient_id()),
            Err(Error::WouldRemoveLastRecipient)
        ));
        assert_eq!(envelope.encode(), original);
    }

    #[test]
    fn allocation_and_staged_validation_failures_never_publish() {
        let mut protector =
            KeyProtector::new(application()).with_passphrase_limits(PassphraseLimits::PROTOCOL_MAX);
        let mut create = ScriptedInteraction::new(&[b"primary", b"primary"]);
        let (root, mut envelope, _) = protector
            .create_root(enrollment("primary"), &mut create)
            .unwrap();
        let original = envelope.encode();

        crypto::fail_next_argon2_allocation();
        let mut allocation = ScriptedInteraction::new(&[b"new", b"new"]);
        assert!(matches!(
            protector.add_recipient(
                &mut envelope,
                &root,
                enrollment("allocation"),
                &mut allocation,
            ),
            Err(Error::KdfResourceUnavailable)
        ));
        assert_eq!(envelope.encode(), original);

        for (fault, expected) in [
            (StagedFault::CanonicalDecode, Error::InvalidEnvelope),
            (StagedFault::RootMismatch, Error::UnlockFailed),
            (StagedFault::EnvelopeMac, Error::UnlockFailed),
        ] {
            fail_next_staged_validation(fault);
            let mut interaction = ScriptedInteraction::new(&[b"new", b"new"]);
            let result = protector.add_recipient(
                &mut envelope,
                &root,
                enrollment("staged failure"),
                &mut interaction,
            );
            assert_eq!(
                std::mem::discriminant(&result.unwrap_err()),
                std::mem::discriminant(&expected)
            );
            assert_eq!(envelope.encode(), original);
        }
    }

    #[test]
    fn selected_hostile_work_is_refused_before_prompt_or_derivation() {
        let mut creator =
            KeyProtector::new(application()).with_passphrase_limits(PassphraseLimits::PROTOCOL_MAX);
        let mut interaction = ScriptedInteraction::new(&[b"secret", b"secret"]);
        let (_root, envelope, recipient) = creator
            .create_root(enrollment("primary"), &mut interaction)
            .unwrap();

        let mut hostile = envelope.clone();
        if let RecipientRecord::Passphrase(record) = &mut hostile.recipients[0] {
            record.kdf.parameters = PassphraseParameters::new(262_144, 6, 4).unwrap();
        } else {
            panic!("test envelope must contain a passphrase recipient");
        }
        let hostile = KeyEnvelope::decode(&hostile.encode()).unwrap();
        let mut protector = KeyProtector::new(application());
        let mut no_prompt = ScriptedInteraction::new(&[]);
        crypto::reset_passphrase_derivations();
        assert!(matches!(
            protector.unlock(&hostile, recipient, &mut no_prompt),
            Err(Error::PassphraseLimitExceeded)
        ));
        assert!(no_prompt.events.is_empty());
        assert_eq!(crypto::passphrase_derivations(), 0);
    }

    #[test]
    fn unselected_record_tampering_converges_on_unlock_failed_after_one_kdf() {
        let mut protector =
            KeyProtector::new(application()).with_passphrase_limits(PassphraseLimits::PROTOCOL_MAX);
        let mut create = ScriptedInteraction::new(&[b"first", b"first"]);
        let (root, mut envelope, first) = protector
            .create_root(enrollment("first"), &mut create)
            .unwrap();
        let mut add = ScriptedInteraction::new(&[b"second", b"second"]);
        protector
            .add_recipient(&mut envelope, &root, enrollment("second"), &mut add)
            .unwrap();

        let unselected = envelope
            .recipients
            .iter_mut()
            .find(|record| record.id() != first)
            .unwrap();
        if let RecipientRecord::Passphrase(record) = unselected {
            record.label = "changed".to_owned();
        }
        let tampered = KeyEnvelope::decode(&envelope.encode()).unwrap();

        crypto::reset_passphrase_derivations();
        let mut open = ScriptedInteraction::new(&[b"first"]);
        assert!(matches!(
            protector.unlock(&tampered, first, &mut open),
            Err(Error::UnlockFailed)
        ));
        assert_eq!(crypto::passphrase_derivations(), 1);
    }

    #[test]
    fn mutation_authorization_and_cancellation_fail_without_publication() {
        let mut protector =
            KeyProtector::new(application()).with_passphrase_limits(PassphraseLimits::PROTOCOL_MAX);
        let mut create = ScriptedInteraction::new(&[b"first", b"first"]);
        let (root, mut envelope, first) = protector
            .create_root(enrollment("first"), &mut create)
            .unwrap();
        let mut add = ScriptedInteraction::new(&[b"second", b"second"]);
        let second = protector
            .add_recipient(&mut envelope, &root, enrollment("second"), &mut add)
            .unwrap();
        let original = envelope.encode();
        let wrong_root = RootKey::import(&mut [0x99; 32]);

        assert!(matches!(
            protector.remove_recipient(&mut envelope, &wrong_root, second),
            Err(Error::EnvelopeAuthenticationFailed)
        ));
        assert_eq!(envelope.encode(), original);

        let mut no_prompt = ScriptedInteraction::new(&[]);
        assert!(matches!(
            protector.rewrap_passphrase(&mut envelope, &wrong_root, first, &mut no_prompt),
            Err(Error::EnvelopeAuthenticationFailed)
        ));
        assert!(no_prompt.events.is_empty());
        assert_eq!(envelope.encode(), original);

        let missing = RecipientId::from_bytes([0xff; 32]);
        assert!(matches!(
            protector.remove_recipient(&mut envelope, &root, missing),
            Err(Error::RecipientNotFound)
        ));
        assert_eq!(envelope.encode(), original);

        let mut cancelled = CancelledInteraction;
        assert!(matches!(
            protector.add_recipient(
                &mut envelope,
                &root,
                enrollment("cancelled"),
                &mut cancelled
            ),
            Err(Error::Interaction(InteractionError::Cancelled))
        ));
        assert_eq!(envelope.encode(), original);

        let other_application = ApplicationId::new("org.example.other-application").unwrap();
        let mut other = KeyProtector::new(other_application);
        assert!(matches!(
            other.unlock(&envelope, first, &mut no_prompt),
            Err(Error::ApplicationMismatch)
        ));
        assert!(no_prompt.events.is_empty());
    }

    #[test]
    fn rewrap_limit_refusal_precedes_interaction() {
        let mut protector =
            KeyProtector::new(application()).with_passphrase_limits(PassphraseLimits::PROTOCOL_MAX);
        let mut create = ScriptedInteraction::new(&[b"secret", b"secret"]);
        let (root, mut envelope, recipient) = protector
            .create_root(enrollment("primary"), &mut create)
            .unwrap();
        let original = envelope.encode();
        let expensive = PassphraseParameters::new(262_144, 6, 4).unwrap();
        let mut default_limits = KeyProtector::new(application());
        let mut no_prompt = ScriptedInteraction::new(&[]);
        assert!(matches!(
            default_limits.rewrap_passphrase_with_parameters(
                &mut envelope,
                &root,
                recipient,
                expensive,
                &mut no_prompt
            ),
            Err(Error::PassphraseLimitExceeded)
        ));
        assert!(no_prompt.events.is_empty());
        assert_eq!(envelope.encode(), original);
    }

    #[test]
    fn limit_and_backend_refusals_precede_interaction() {
        let expensive = PassphraseParameters::new(262_144, 6, 4).unwrap();
        let mut protector = KeyProtector::new(application());
        let mut interaction = ScriptedInteraction::new(&[]);
        assert!(matches!(
            protector.create_root(
                Enrollment::passphrase_with_parameters("expensive", expensive).unwrap(),
                &mut interaction
            ),
            Err(Error::PassphraseLimitExceeded)
        ));
        assert!(interaction.events.is_empty());

        assert!(matches!(
            protector.create_root(
                Enrollment::fido("key", FidoPolicy::Presence).unwrap(),
                &mut interaction
            ),
            Err(Error::FidoSupportUnavailable)
        ));
        assert!(interaction.events.is_empty());
    }

    #[test]
    fn combined_prompts_for_fido_before_passphrase() {
        let mut protector = KeyProtector::fake(application());
        let enrollment = Enrollment::fido_and_passphrase_with_parameters(
            "combined",
            FidoPolicy::Presence,
            test_parameters(),
        )
        .unwrap();
        let mut create = ScriptedInteraction::new(&[b"secret", b"secret"]);
        let (_root, envelope, recipient) = protector.create_root(enrollment, &mut create).unwrap();
        assert_eq!(
            create.events,
            [
                "pin",
                "enrollment touch",
                "assertion touch",
                "new passphrase",
                "confirm passphrase"
            ]
        );

        let mut open = ScriptedInteraction::new(&[b"secret"]);
        protector.unlock(&envelope, recipient, &mut open).unwrap();
        assert_eq!(open.events, ["assertion touch", "unlock passphrase"]);
        let counters = protector.fake_backend_mut().counters();
        assert_eq!(counters.enrollments, 1);
        assert_eq!(counters.assertions, 2);
    }

    #[test]
    fn combined_context_and_outer_ciphertext_fail_before_passphrase() {
        type Mutation = fn(&mut FidoAndPassphraseRecipient);

        let mut protector = KeyProtector::fake(application());
        let enrollment = Enrollment::fido_and_passphrase_with_parameters(
            "combined",
            FidoPolicy::Presence,
            test_parameters(),
        )
        .unwrap();
        let mut create = ScriptedInteraction::new(&[b"secret", b"secret"]);
        let (_root, envelope, recipient) = protector.create_root(enrollment, &mut create).unwrap();

        let cases: [(&str, Mutation); 2] = [
            ("altered PRF input", |record| record.prf_nonce[0] ^= 1),
            ("altered outer ciphertext", |record| {
                record.wrapped_root[0] ^= 1;
            }),
        ];
        for (name, mutate) in cases {
            let mut altered = envelope.clone();
            let RecipientRecord::FidoAndPassphrase(record) = &mut altered.recipients[0] else {
                panic!("fixture must contain a combined recipient");
            };
            mutate(record);

            crypto::reset_passphrase_derivations();
            let before = protector.fake_backend_mut().counters();
            let mut open = ScriptedInteraction::new(&[]);
            assert!(
                matches!(
                    protector.unlock(&altered, recipient, &mut open),
                    Err(Error::UnlockFailed)
                ),
                "{name}"
            );
            assert_eq!(open.events, ["assertion touch"], "{name}");
            assert_eq!(crypto::passphrase_derivations(), 0, "{name}");
            let after = protector.fake_backend_mut().counters();
            assert_eq!(after.assertions, before.assertions + 1, "{name}");
        }
    }

    #[test]
    fn fido_only_routes_never_derive_a_passphrase() {
        for policy in [FidoPolicy::Presence, FidoPolicy::UserVerification] {
            crypto::reset_passphrase_derivations();
            let mut protector = KeyProtector::fake(application());
            let mut create = ScriptedInteraction::new(&[]);
            let (root, envelope, recipient) = protector
                .create_root(
                    Enrollment::fido("security key", policy).unwrap(),
                    &mut create,
                )
                .unwrap();
            assert_eq!(crypto::passphrase_derivations(), 0);

            let mut open = ScriptedInteraction::new(&[]);
            let recovered = protector.unlock(&envelope, recipient, &mut open).unwrap();
            assert!(roots_match(&root, &recovered));
            assert_eq!(crypto::passphrase_derivations(), 0);
            assert!(!open.events.iter().any(|event| event.contains("passphrase")));
        }
    }

    #[test]
    fn failed_combined_rewrap_is_transactional_and_skips_passphrase() {
        use crate::backend::fake::FailurePoint;

        let mut protector = KeyProtector::fake(application());
        let enrollment = Enrollment::fido_and_passphrase_with_parameters(
            "combined",
            FidoPolicy::Presence,
            test_parameters(),
        )
        .unwrap();
        let mut create = ScriptedInteraction::new(&[b"old", b"old"]);
        let (root, mut envelope, recipient) =
            protector.create_root(enrollment, &mut create).unwrap();
        let original = envelope.encode();
        let before = protector.fake_backend_mut().counters();
        protector
            .fake_backend_mut()
            .fail_next(FailurePoint::Assertion);

        let mut rewrap = ScriptedInteraction::new(&[]);
        assert!(matches!(
            protector.rewrap_passphrase(&mut envelope, &root, recipient, &mut rewrap),
            Err(Error::Authenticator(AuthenticatorFailure::OperationFailed))
        ));
        assert_eq!(envelope.encode(), original);
        assert_eq!(rewrap.events, ["assertion touch"]);
        let after = protector.fake_backend_mut().counters();
        assert_eq!(after.enrollments, before.enrollments);
        assert_eq!(after.assertions, before.assertions + 1);
    }

    #[test]
    fn combined_rewrap_rejects_bad_flags_and_wrong_credential_transactionally() {
        use crate::backend::fake::FailurePoint;

        let mut protector = KeyProtector::fake(application());
        let enrollment = Enrollment::fido_and_passphrase_with_parameters(
            "combined",
            FidoPolicy::Presence,
            test_parameters(),
        )
        .unwrap();
        let mut create = ScriptedInteraction::new(&[b"old", b"old"]);
        let (root, mut envelope, recipient) =
            protector.create_root(enrollment, &mut create).unwrap();
        let original = envelope.encode();

        protector
            .fake_backend_mut()
            .fail_next(FailurePoint::VerifiedResponse);
        let mut bad_flags = ScriptedInteraction::new(&[]);
        assert!(matches!(
            protector.rewrap_passphrase(&mut envelope, &root, recipient, &mut bad_flags),
            Err(Error::AuthenticatorResponseInvalid)
        ));
        assert_eq!(bad_flags.events, ["assertion touch"]);
        assert_eq!(envelope.encode(), original);

        let credential_id = match envelope.find(recipient).unwrap() {
            RecipientRecord::FidoAndPassphrase(record) => record.credential_id.clone(),
            _ => panic!("fixture must contain a combined recipient"),
        };
        protector
            .fake_backend_mut()
            .forget_credential(&credential_id);
        let mut wrong_credential = ScriptedInteraction::new(&[]);
        assert!(matches!(
            protector.rewrap_passphrase(&mut envelope, &root, recipient, &mut wrong_credential,),
            Err(Error::Authenticator(
                AuthenticatorFailure::CredentialUnavailable
            ))
        ));
        assert_eq!(wrong_credential.events, ["assertion touch"]);
        assert_eq!(envelope.encode(), original);
    }
}
