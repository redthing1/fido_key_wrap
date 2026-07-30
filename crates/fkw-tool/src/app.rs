use std::path::Path;

use anyhow::{Context, Result, bail};
use fido_key_wrap::{
    ApplicationId, Enrollment, FidoPolicy, Interaction, KeyEnvelope, KeyProtector,
    PassphraseParameters, RecipientPolicy, RecoverySecretRecipient, RootKey,
};
use fido_key_wrap_platform::{RecoverySecretStore, StoreError};
use zeroize::Zeroizing;

use crate::{
    cli::{Access, KdfOptions},
    container::{EncryptedSecret, MAX_SECRET_BYTES, SecretFile},
    storage,
};

pub(crate) const APPLICATION_ID: &str = "tool.fido-key-wrap.local";
const LABEL: &str = "primary";

pub(crate) struct Inspection {
    pub(crate) policy: RecipientPolicy,
    pub(crate) parameters: Option<PassphraseParameters>,
}

pub(crate) struct Application<'a> {
    trusted_id: ApplicationId,
    protector: KeyProtector,
    interaction: &'a mut dyn Interaction,
    recovery_store: Option<&'a dyn RecoverySecretStore>,
}

impl<'a> Application<'a> {
    pub(crate) fn new(
        trusted_id: ApplicationId,
        protector: KeyProtector,
        interaction: &'a mut dyn Interaction,
        recovery_store: Option<&'a dyn RecoverySecretStore>,
    ) -> Self {
        Self {
            trusted_id,
            protector,
            interaction,
            recovery_store,
        }
    }

    pub(crate) fn seal(
        &mut self,
        path: &Path,
        access: Access,
        kdf: KdfOptions,
        plaintext: &[u8],
    ) -> Result<()> {
        self.seal_with(path, access, kdf, plaintext, storage::create_atomic)
    }

    fn seal_with(
        &mut self,
        path: &Path,
        access: Access,
        kdf: KdfOptions,
        plaintext: &[u8],
        publish: impl FnOnce(&Path, &[u8]) -> std::result::Result<(), storage::CreateError>,
    ) -> Result<()> {
        storage::ensure_absent(path)?;
        validate_plaintext(plaintext)?;

        let (root, envelope, pending) = self.create_root(access, kdf)?;
        let container = self.prepare_container(&root, &envelope, plaintext)?;
        if let Some(pending) = &pending {
            self.store_recovery_secret(pending)?;
        }

        match publish(path, &container) {
            Ok(()) => Ok(()),
            Err(error) => {
                let may_be_published = error.may_be_published();
                let error = error.into_error();
                let Some(pending) = pending else {
                    return Err(error);
                };
                if may_be_published {
                    return Err(
                        error.context("publication is uncertain; the mac factor was retained")
                    );
                }
                self.recovery_store()?
                    .remove(pending.recipient_id(), pending.secret())
                    .context("the secret was not saved and its mac factor may remain")?;
                Err(error)
            }
        }
    }

    pub(crate) fn unseal(&mut self, path: &Path) -> Result<Zeroizing<Vec<u8>>> {
        let loaded = self.load(path)?;
        let root = self.unlock(&loaded.envelope)?;
        loaded.container.secret().decrypt(
            &root,
            &self.trusted_id,
            loaded.container.envelope_bytes(),
        )
    }

    pub(crate) fn inspect(&self, path: &Path) -> Result<Inspection> {
        let loaded = self.load(path)?;
        let recipient = loaded.envelope.recipients()[0];
        Ok(Inspection {
            policy: recipient.policy(),
            parameters: recipient.passphrase_parameters(),
        })
    }

    #[cfg(all(target_os = "macos", feature = "macos-user-presence"))]
    pub(crate) fn forget(&mut self, path: &Path) -> Result<()> {
        let loaded = self.load(path)?;
        let recipient = loaded.envelope.recipients()[0];
        if recipient.policy() != RecipientPolicy::RecoverySecret {
            bail!("this secret does not use mac user presence");
        }

        let store = self.recovery_store()?;
        let secret = store.load(recipient.id())?;
        let root = self.protector.unlock_with_recovery_secret(
            &loaded.envelope,
            recipient.id(),
            &secret,
        )?;
        loaded.container.secret().decrypt(
            &root,
            &self.trusted_id,
            loaded.container.envelope_bytes(),
        )?;
        store.remove(recipient.id(), &secret)?;
        Ok(())
    }

    fn create_root(
        &mut self,
        access: Access,
        kdf: KdfOptions,
    ) -> Result<(RootKey, KeyEnvelope, Option<RecoverySecretRecipient>)> {
        #[cfg(all(target_os = "macos", feature = "macos-user-presence"))]
        if access == Access::MacUserPresence {
            reject_kdf(kdf)?;
            let (root, envelope, pending) =
                self.protector.create_root_with_recovery_secret(LABEL)?;
            return Ok((root, envelope, Some(pending)));
        }

        let enrollment = enrollment(access, kdf)?;
        let (root, envelope, _) = self.protector.create_root(enrollment, self.interaction)?;
        Ok((root, envelope, None))
    }

    fn prepare_container(
        &self,
        root: &RootKey,
        envelope: &KeyEnvelope,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let envelope = self.canonical(envelope)?;
        let envelope_bytes = envelope.encode();
        let encrypted =
            EncryptedSecret::encrypt(root, &self.trusted_id, &envelope_bytes, plaintext)?;
        let container = SecretFile::new(envelope_bytes, encrypted)?;
        Ok(container.encode())
    }

    fn load(&self, path: &Path) -> Result<LoadedSecret> {
        let container = SecretFile::decode(&storage::read_private(path)?)?;
        let envelope = KeyEnvelope::decode(container.envelope_bytes())?;
        self.validate_envelope(&envelope)?;
        Ok(LoadedSecret {
            container,
            envelope,
        })
    }

    fn canonical(&self, envelope: &KeyEnvelope) -> Result<KeyEnvelope> {
        let decoded = KeyEnvelope::decode(&envelope.encode())?;
        self.validate_envelope(&decoded)?;
        Ok(decoded)
    }

    fn validate_envelope(&self, envelope: &KeyEnvelope) -> Result<()> {
        if envelope.application_id() != &self.trusted_id {
            bail!("the sealed file belongs to another application");
        }
        let recipients = envelope.recipients();
        if recipients.len() != 1 {
            bail!("the sealed file must contain exactly one recovery route");
        }
        match recipients[0].policy() {
            RecipientPolicy::Passphrase
            | RecipientPolicy::RecoverySecret
            | RecipientPolicy::Fido(FidoPolicy::Presence | FidoPolicy::UserVerification)
            | RecipientPolicy::FidoAndPassphrase(
                FidoPolicy::Presence | FidoPolicy::UserVerification,
            ) => Ok(()),
            RecipientPolicy::ManagedFido(_) | RecipientPolicy::FidoPresenceAndLocalSecret => {
                bail!("the sealed file uses an unsupported recovery route")
            }
        }
    }

    fn unlock(&mut self, envelope: &KeyEnvelope) -> Result<RootKey> {
        let recipient = envelope.recipients()[0];
        if recipient.policy() == RecipientPolicy::RecoverySecret {
            let secret = self.recovery_store()?.load(recipient.id())?;
            return self
                .protector
                .unlock_with_recovery_secret(envelope, recipient.id(), &secret)
                .map_err(Into::into);
        }
        self.protector
            .unlock(envelope, recipient.id(), self.interaction)
            .map_err(Into::into)
    }

    fn recovery_store(&self) -> Result<&dyn RecoverySecretStore> {
        self.recovery_store
            .context("mac user-presence storage is unavailable")
    }

    fn store_recovery_secret(&self, pending: &RecoverySecretRecipient) -> Result<()> {
        let store = self.recovery_store()?;
        if let Err(error) = store.create(pending.recipient_id(), pending.secret()) {
            if error != StoreError::StateUncertain {
                return Err(error.into());
            }
            return match store.remove(pending.recipient_id(), pending.secret()) {
                Ok(_) => Err(error.into()),
                Err(cleanup) => Err(anyhow::anyhow!(cleanup)
                    .context("mac factor creation failed and cleanup could not be confirmed")),
            };
        }
        Ok(())
    }
}

struct LoadedSecret {
    container: SecretFile,
    envelope: KeyEnvelope,
}

fn enrollment(access: Access, kdf: KdfOptions) -> Result<Enrollment> {
    let parameters = optional_parameters(kdf)?;
    match (access, parameters) {
        (Access::Passphrase, None) => Enrollment::passphrase(LABEL).map_err(Into::into),
        (Access::Passphrase, Some(parameters)) => {
            Enrollment::passphrase_with_parameters(LABEL, parameters).map_err(Into::into)
        }
        #[cfg(feature = "fido")]
        (Access::FidoPresence, None) => {
            Enrollment::fido(LABEL, FidoPolicy::Presence).map_err(Into::into)
        }
        #[cfg(feature = "fido")]
        (Access::FidoUserVerification, None) => {
            Enrollment::fido(LABEL, FidoPolicy::UserVerification).map_err(Into::into)
        }
        #[cfg(feature = "fido")]
        (Access::FidoPresencePlusPassphrase, None) => {
            Enrollment::fido_and_passphrase(LABEL, FidoPolicy::Presence).map_err(Into::into)
        }
        #[cfg(feature = "fido")]
        (Access::FidoPresencePlusPassphrase, Some(parameters)) => {
            Enrollment::fido_and_passphrase_with_parameters(LABEL, FidoPolicy::Presence, parameters)
                .map_err(Into::into)
        }
        #[cfg(feature = "fido")]
        (Access::FidoUserVerificationPlusPassphrase, None) => {
            Enrollment::fido_and_passphrase(LABEL, FidoPolicy::UserVerification).map_err(Into::into)
        }
        #[cfg(feature = "fido")]
        (Access::FidoUserVerificationPlusPassphrase, Some(parameters)) => {
            Enrollment::fido_and_passphrase_with_parameters(
                LABEL,
                FidoPolicy::UserVerification,
                parameters,
            )
            .map_err(Into::into)
        }
        #[cfg(feature = "fido")]
        (Access::FidoPresence | Access::FidoUserVerification, Some(_)) => {
            bail!("argon2 options apply only to passphrase-bearing access policies")
        }
        #[cfg(all(target_os = "macos", feature = "macos-user-presence"))]
        (Access::MacUserPresence, _) => unreachable!("mac access was handled before enrollment"),
    }
}

fn optional_parameters(options: KdfOptions) -> Result<Option<PassphraseParameters>> {
    match (options.memory_mib, options.passes, options.lanes) {
        (None, None, None) => Ok(None),
        (Some(memory), Some(passes), Some(lanes)) => {
            let memory_kib = memory
                .checked_mul(1024)
                .context("--memory-mib is too large")?;
            Ok(Some(PassphraseParameters::new(memory_kib, passes, lanes)?))
        }
        _ => bail!("--memory-mib, --passes, and --lanes must be supplied together"),
    }
}

#[cfg(all(target_os = "macos", feature = "macos-user-presence"))]
fn reject_kdf(options: KdfOptions) -> Result<()> {
    if options == KdfOptions::default() {
        Ok(())
    } else {
        bail!("argon2 options apply only to passphrase-bearing access policies")
    }
}

fn validate_plaintext(plaintext: &[u8]) -> Result<()> {
    if plaintext.is_empty() || plaintext.len() > MAX_SECRET_BYTES {
        bail!("the secret must contain between 1 byte and 1 MiB");
    }
    Ok(())
}

pub(crate) const fn policy_text(policy: RecipientPolicy) -> &'static str {
    match policy {
        RecipientPolicy::Passphrase => "passphrase",
        RecipientPolicy::RecoverySecret => "mac user presence",
        RecipientPolicy::Fido(FidoPolicy::Presence) => "security-key presence",
        RecipientPolicy::Fido(FidoPolicy::UserVerification) => "security-key user verification",
        RecipientPolicy::FidoAndPassphrase(FidoPolicy::Presence) => {
            "security-key presence and passphrase"
        }
        RecipientPolicy::FidoAndPassphrase(FidoPolicy::UserVerification) => {
            "security-key user verification and passphrase"
        }
        RecipientPolicy::ManagedFido(_) | RecipientPolicy::FidoPresenceAndLocalSecret => {
            "unsupported"
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, fs, path::PathBuf};

    #[cfg(all(target_os = "macos", feature = "macos-user-presence"))]
    use std::sync::Mutex;

    use fido_key_wrap::{
        InteractionError, Passphrase, PassphrasePrompt, PinPrompt, SelectionPrompt, TouchPrompt,
    };
    use fido_key_wrap::{RecipientId, RecoverySecret};
    use fido_key_wrap_platform::testing::MemoryRecoverySecretStore;

    use super::*;

    #[test]
    fn passphrase_round_trip_accepts_arbitrary_bytes() {
        let directory = TestDirectory::new();
        let path = directory.path.join("secret.fkw");
        let mut interaction = ScriptedInteraction::new(&["one", "one", "one"]);
        let application_id = ApplicationId::new(APPLICATION_ID).unwrap();
        let protector = KeyProtector::new(application_id.clone());
        let mut application = Application::new(application_id, protector, &mut interaction, None);
        let low_cost = KdfOptions {
            memory_mib: Some(64),
            passes: Some(3),
            lanes: Some(1),
        };

        application
            .seal(&path, Access::Passphrase, low_cost, b"\0binary\xff")
            .unwrap();
        assert_eq!(
            application.unseal(&path).unwrap().as_slice(),
            b"\0binary\xff"
        );
        let inspection = application.inspect(&path).unwrap();
        assert_eq!(inspection.policy, RecipientPolicy::Passphrase);
        assert_eq!(inspection.parameters.unwrap().memory_kib(), 65_536);
    }

    #[test]
    #[cfg(all(target_os = "macos", feature = "macos-user-presence"))]
    fn mac_factor_round_trip_and_forget_are_exact() {
        let directory = TestDirectory::new();
        let path = directory.path.join("secret.fkw");
        let application_id = ApplicationId::new(APPLICATION_ID).unwrap();
        let store = MemoryRecoverySecretStore::new(application_id.clone());
        let protector = KeyProtector::new(application_id.clone());
        let mut interaction = ScriptedInteraction::new(&[]);
        let mut application =
            Application::new(application_id, protector, &mut interaction, Some(&store));

        application
            .seal(
                &path,
                Access::MacUserPresence,
                KdfOptions::default(),
                b"protected",
            )
            .unwrap();
        assert_eq!(application.unseal(&path).unwrap().as_slice(), b"protected");
        application.forget(&path).unwrap();
        assert!(application.unseal(&path).is_err());
    }

    #[test]
    fn uncertain_factor_creation_is_cleaned_up_exactly() {
        let application_id = ApplicationId::new(APPLICATION_ID).unwrap();
        let store = UncertainCreateStore {
            inner: MemoryRecoverySecretStore::new(application_id.clone()),
        };
        let protector = KeyProtector::new(application_id.clone());
        let (_, _, pending) = protector
            .create_root_with_recovery_secret("pending")
            .unwrap();
        let recipient = pending.recipient_id();
        let mut interaction = ScriptedInteraction::new(&[]);
        let application =
            Application::new(application_id, protector, &mut interaction, Some(&store));

        assert!(application.store_recovery_secret(&pending).is_err());
        assert_eq!(
            store.inner.load(recipient).unwrap_err(),
            StoreError::Missing
        );
    }

    #[test]
    #[cfg(all(target_os = "macos", feature = "macos-user-presence"))]
    fn publication_failure_retains_only_a_possibly_published_factor() {
        for may_be_published in [false, true] {
            let directory = TestDirectory::new();
            let path = directory.path.join("secret.fkw");
            let application_id = ApplicationId::new(APPLICATION_ID).unwrap();
            let store = RecordingStore {
                inner: MemoryRecoverySecretStore::new(application_id.clone()),
                recipient: Mutex::new(None),
            };
            let protector = KeyProtector::new(application_id.clone());
            let mut interaction = ScriptedInteraction::new(&[]);
            let mut application =
                Application::new(application_id, protector, &mut interaction, Some(&store));

            let result = application.seal_with(
                &path,
                Access::MacUserPresence,
                KdfOptions::default(),
                b"protected",
                |_, _| {
                    let error = anyhow::anyhow!("injected publication failure");
                    Err(if may_be_published {
                        storage::CreateError::uncertain(error)
                    } else {
                        storage::CreateError::unpublished(error)
                    })
                },
            );

            assert!(result.is_err());
            let recipient = store.recipient.lock().unwrap().expect("recorded recipient");
            assert_eq!(store.inner.load(recipient).is_ok(), may_be_published);
        }
    }

    struct UncertainCreateStore {
        inner: MemoryRecoverySecretStore,
    }

    #[cfg(all(target_os = "macos", feature = "macos-user-presence"))]
    struct RecordingStore {
        inner: MemoryRecoverySecretStore,
        recipient: Mutex<Option<RecipientId>>,
    }

    #[cfg(all(target_os = "macos", feature = "macos-user-presence"))]
    impl RecoverySecretStore for RecordingStore {
        fn create(
            &self,
            recipient: RecipientId,
            secret: &RecoverySecret,
        ) -> fido_key_wrap_platform::Result<()> {
            self.inner.create(recipient, secret)?;
            *self.recipient.lock().unwrap() = Some(recipient);
            Ok(())
        }

        fn load(&self, recipient: RecipientId) -> fido_key_wrap_platform::Result<RecoverySecret> {
            self.inner.load(recipient)
        }

        fn remove(
            &self,
            recipient: RecipientId,
            expected: &RecoverySecret,
        ) -> fido_key_wrap_platform::Result<fido_key_wrap_platform::Removal> {
            self.inner.remove(recipient, expected)
        }
    }

    impl RecoverySecretStore for UncertainCreateStore {
        fn create(
            &self,
            recipient: RecipientId,
            secret: &RecoverySecret,
        ) -> fido_key_wrap_platform::Result<()> {
            self.inner.create(recipient, secret)?;
            Err(StoreError::StateUncertain)
        }

        fn load(&self, recipient: RecipientId) -> fido_key_wrap_platform::Result<RecoverySecret> {
            self.inner.load(recipient)
        }

        fn remove(
            &self,
            recipient: RecipientId,
            expected: &RecoverySecret,
        ) -> fido_key_wrap_platform::Result<fido_key_wrap_platform::Removal> {
            self.inner.remove(recipient, expected)
        }
    }

    struct ScriptedInteraction {
        values: VecDeque<Vec<u8>>,
    }

    impl ScriptedInteraction {
        fn new(values: &[&str]) -> Self {
            Self {
                values: values
                    .iter()
                    .map(|value| value.as_bytes().to_vec())
                    .collect(),
            }
        }
    }

    impl Interaction for ScriptedInteraction {
        fn select_authenticator_by_touch(
            &mut self,
            _prompt: &SelectionPrompt,
        ) -> std::result::Result<(), InteractionError> {
            Err(InteractionError::Unsupported)
        }

        fn request_pin(
            &mut self,
            _prompt: &PinPrompt,
        ) -> std::result::Result<fido_key_wrap::Pin, InteractionError> {
            Err(InteractionError::Unsupported)
        }

        fn request_passphrase(
            &mut self,
            _prompt: &PassphrasePrompt,
        ) -> std::result::Result<Passphrase, InteractionError> {
            let value = self.values.pop_front().ok_or(InteractionError::Failed)?;
            Passphrase::new(value).map_err(|_| InteractionError::Failed)
        }

        fn touch_required(
            &mut self,
            _prompt: &TouchPrompt,
        ) -> std::result::Result<(), InteractionError> {
            Err(InteractionError::Unsupported)
        }
    }

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            for _ in 0..32 {
                let mut random = [0u8; 12];
                getrandom::fill(&mut random).unwrap();
                let name = random.map(|byte| format!("{byte:02x}")).concat();
                let path = std::env::temp_dir().join(format!("fkw-tool-app-{name}"));
                match fs::create_dir(&path) {
                    Ok(()) => return Self { path },
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("failed to create test directory: {error}"),
                }
            }
            panic!("failed to allocate test directory")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
