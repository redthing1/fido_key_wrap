use std::path::Path;

use anyhow::{Result, bail};
use fido_key_wrap::{
    ApplicationId, Enrollment, FidoPolicy, Interaction, KeyEnvelope, KeyProtector,
    PassphraseParameters, RecipientPolicy, RootKey,
};
use zeroize::Zeroizing;

use crate::{
    cli::Access,
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
}

impl<'a> Application<'a> {
    pub(crate) fn new(
        trusted_id: ApplicationId,
        protector: KeyProtector,
        interaction: &'a mut dyn Interaction,
    ) -> Self {
        Self {
            trusted_id,
            protector,
            interaction,
        }
    }

    pub(crate) fn seal(&mut self, path: &Path, access: Access, plaintext: &[u8]) -> Result<()> {
        storage::ensure_absent(path)?;
        validate_plaintext(plaintext)?;

        let enrollment = enrollment(access)?;
        let (root, envelope, _) = self.protector.create_root(enrollment, self.interaction)?;
        let container = self.prepare_container(&root, &envelope, plaintext)?;
        storage::create_atomic(path, &container)
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
            | RecipientPolicy::Fido(FidoPolicy::Presence | FidoPolicy::UserVerification)
            | RecipientPolicy::FidoAndPassphrase(
                FidoPolicy::Presence | FidoPolicy::UserVerification,
            ) => Ok(()),
            RecipientPolicy::RecoverySecret
            | RecipientPolicy::ManagedFido(_)
            | RecipientPolicy::FidoPresenceAndLocalSecret => {
                bail!("the sealed file uses an unsupported recovery route")
            }
        }
    }

    fn unlock(&mut self, envelope: &KeyEnvelope) -> Result<RootKey> {
        let recipient = envelope.recipients()[0];
        self.protector
            .unlock(envelope, recipient.id(), self.interaction)
            .map_err(Into::into)
    }
}

struct LoadedSecret {
    container: SecretFile,
    envelope: KeyEnvelope,
}

fn enrollment(access: Access) -> Result<Enrollment> {
    match access {
        Access::Passphrase => Enrollment::passphrase(LABEL).map_err(Into::into),
        Access::FidoPresence => Enrollment::fido(LABEL, FidoPolicy::Presence).map_err(Into::into),
        Access::FidoUserVerification => {
            Enrollment::fido(LABEL, FidoPolicy::UserVerification).map_err(Into::into)
        }
        Access::FidoPresencePlusPassphrase => {
            Enrollment::fido_and_passphrase(LABEL, FidoPolicy::Presence).map_err(Into::into)
        }
        Access::FidoUserVerificationPlusPassphrase => {
            Enrollment::fido_and_passphrase(LABEL, FidoPolicy::UserVerification).map_err(Into::into)
        }
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
        RecipientPolicy::Fido(FidoPolicy::Presence) => "security-key presence",
        RecipientPolicy::Fido(FidoPolicy::UserVerification) => "security-key user verification",
        RecipientPolicy::FidoAndPassphrase(FidoPolicy::Presence) => {
            "security-key presence and passphrase"
        }
        RecipientPolicy::FidoAndPassphrase(FidoPolicy::UserVerification) => {
            "security-key user verification and passphrase"
        }
        RecipientPolicy::RecoverySecret
        | RecipientPolicy::ManagedFido(_)
        | RecipientPolicy::FidoPresenceAndLocalSecret => "unsupported",
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, fs, path::PathBuf};

    use fido_key_wrap::{
        InteractionError, Passphrase, PassphrasePrompt, PinPrompt, SelectionPrompt, TouchPrompt,
    };

    use super::*;

    #[test]
    fn passphrase_round_trip_accepts_arbitrary_bytes() {
        let directory = TestDirectory::new();
        let path = directory.path.join("secret.fkw");
        let mut interaction = ScriptedInteraction::new(&["one", "one", "one"]);
        let application_id = ApplicationId::new(APPLICATION_ID).unwrap();
        let protector = KeyProtector::new(application_id.clone());
        let mut application = Application::new(application_id, protector, &mut interaction);
        application
            .seal(&path, Access::Passphrase, b"\0binary\xff")
            .unwrap();
        assert_eq!(
            application.unseal(&path).unwrap().as_slice(),
            b"\0binary\xff"
        );
        let inspection = application.inspect(&path).unwrap();
        assert_eq!(inspection.policy, RecipientPolicy::Passphrase);
        assert_eq!(
            inspection.parameters.unwrap(),
            PassphraseParameters::DESKTOP
        );
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
