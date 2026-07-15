use std::{
    io::{self, IsTerminal, Write},
    path::Path,
    str::FromStr,
};

use anyhow::{Context, Result, bail};
use fido_key_wrap::{
    ApplicationId, Enrollment, FidoPolicy, KeyEnvelope, PassphraseParameters, RecipientId,
    RecipientPolicy, RootKey,
};
use zeroize::Zeroizing;

use crate::{
    access::KeyAccess,
    cli::{Access, KdfOptions},
    container::{EncryptedNote, NoteFile},
    storage,
};

pub(crate) const APPLICATION_ID: &str = "demo.fido-key-wrap.example";

pub(crate) struct RecipientChoice {
    pub(crate) id: RecipientId,
    pub(crate) label: String,
    pub(crate) policy: RecipientPolicy,
    pub(crate) parameters: Option<PassphraseParameters>,
}

pub(crate) trait AppUi {
    fn choose_recipient(&mut self, choices: &[RecipientChoice]) -> Result<RecipientId>;
    fn confirm_offline_passphrase_route(&mut self) -> Result<()>;
    fn confirm_root_rotation(&mut self) -> Result<()>;
    fn confirm_managed_retirement(&mut self, label: &str, final_route: bool) -> Result<()>;
}

pub(crate) struct TerminalUi;

impl AppUi for TerminalUi {
    fn choose_recipient(&mut self, choices: &[RecipientChoice]) -> Result<RecipientId> {
        require_interactive_recipient_choice(io::stdin().is_terminal())?;
        eprintln!("choose a recipient:");
        for (index, choice) in choices.iter().enumerate() {
            eprintln!(
                "  {}. {} — {}",
                index + 1,
                choice.label,
                policy_text(choice.policy)
            );
        }
        eprint!("recipient [1-{}]: ", choices.len());
        io::stderr()
            .flush()
            .context("failed to show recipient choices")?;
        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .context("failed to read the recipient choice")?;
        let index = answer
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|index| (1..=choices.len()).contains(index))
            .context("choose one of the listed recipient numbers")?;
        Ok(choices[index - 1].id)
    }

    fn confirm_offline_passphrase_route(&mut self) -> Result<()> {
        confirm(
            "this adds an alternative passphrase-only route; copied files will permit offline passphrase guessing",
        )
    }

    fn confirm_root_rotation(&mut self) -> Result<()> {
        confirm(
            "root rotation replaces every current recovery route and re-encrypts the note; old complete copies remain usable",
        )
    }

    fn confirm_managed_retirement(&mut self, label: &str, final_route: bool) -> Result<()> {
        if final_route {
            confirm(&format!(
                "retiring {label} permanently disables the final recovery route in this file"
            ))
        } else {
            confirm(&format!(
                "retiring {label} permanently disables that route in every copy of this note"
            ))
        }
    }
}

fn require_interactive_recipient_choice(interactive: bool) -> Result<()> {
    if !interactive {
        bail!(
            "select a recipient with --recipient or --using; run `fkw recipients FILE --details` to list ids"
        );
    }
    Ok(())
}

fn confirm(message: &str) -> Result<()> {
    if !io::stdin().is_terminal() {
        bail!("confirmation requires an interactive terminal");
    }
    eprintln!("{message}");
    eprint!("type yes to continue: ");
    io::stderr()
        .flush()
        .context("failed to show confirmation")?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .context("failed to read confirmation")?;
    if answer.trim() != "yes" {
        bail!("operation cancelled");
    }
    Ok(())
}

pub(crate) struct Application<'a> {
    trusted_id: ApplicationId,
    access: &'a mut dyn KeyAccess,
    ui: &'a mut dyn AppUi,
}

impl<'a> Application<'a> {
    pub(crate) fn new(
        trusted_id: ApplicationId,
        access: &'a mut dyn KeyAccess,
        ui: &'a mut dyn AppUi,
    ) -> Self {
        Self {
            trusted_id,
            access,
            ui,
        }
    }

    pub(crate) fn create(
        &mut self,
        path: &Path,
        access: Access,
        label: String,
        kdf: KdfOptions,
        plaintext: &[u8],
    ) -> Result<RecipientId> {
        let _lock = storage::NoteLock::acquire(path)?;
        storage::ensure_absent(path)?;
        validate_plaintext(plaintext)?;
        let enrollment = enrollment(access, label, kdf)?;
        let managed = enrollment.policy() == RecipientPolicy::ManagedFido;
        let (root, envelope, recipient) = self.access.create_root(enrollment)?;
        managed_publication(
            (|| {
                self.validate_envelope(&envelope)?;
                let envelope_bytes = envelope.encode();
                let encrypted =
                    EncryptedNote::encrypt(&root, &self.trusted_id, &envelope_bytes, plaintext)?;
                let container = NoteFile::new(envelope_bytes, encrypted)?;
                storage::create_atomic(path, &container.encode())
            })(),
            managed,
        )?;
        Ok(recipient)
    }

    pub(crate) fn open(
        &mut self,
        path: &Path,
        selector: Option<&str>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let loaded = self.load(path)?;
        let recipient = self.select_recipient(&loaded.envelope, selector)?;
        let root = self.access.unlock(&loaded.envelope, recipient)?;
        loaded
            .container
            .note()
            .decrypt(&root, &self.trusted_id, loaded.container.envelope_bytes())
    }

    pub(crate) fn recipients(&self, path: &Path) -> Result<Vec<RecipientChoice>> {
        let loaded = self.load(path)?;
        Ok(choices(&loaded.envelope))
    }

    pub(crate) fn add_recipient(
        &mut self,
        path: &Path,
        using: Option<&str>,
        access: Access,
        label: &str,
        kdf: KdfOptions,
    ) -> Result<RecipientId> {
        let enrollment = enrollment(access, label.to_owned(), kdf)?;
        let managed = enrollment.policy() == RecipientPolicy::ManagedFido;
        let _lock = storage::NoteLock::acquire(path)?;
        let mut loaded = self.load(path)?;
        if loaded
            .envelope
            .recipients()
            .iter()
            .any(|recipient| recipient.label() == label)
        {
            bail!("a recipient with that label already exists");
        }
        if enrollment.policy() == RecipientPolicy::Passphrase
            && !loaded
                .envelope
                .recipients()
                .iter()
                .any(|recipient| recipient.policy() == RecipientPolicy::Passphrase)
        {
            self.ui.confirm_offline_passphrase_route()?;
        }
        let authorizer = self.select_recipient(&loaded.envelope, using)?;
        let root = self.access.unlock(&loaded.envelope, authorizer)?;
        let plaintext = loaded.container.note().decrypt(
            &root,
            &self.trusted_id,
            loaded.container.envelope_bytes(),
        )?;
        let recipient = self
            .access
            .add_recipient(&mut loaded.envelope, &root, enrollment)?;
        managed_publication(
            (|| {
                let staged_envelope = self.canonical_stage(&loaded.envelope)?;
                let staged = self.stage_container(
                    &staged_envelope,
                    &root,
                    &plaintext,
                    loaded.container.note().nonce(),
                )?;
                storage::replace_atomic_if_unchanged(path, &loaded.original_bytes, &staged.encode())
            })(),
            managed,
        )?;
        Ok(recipient)
    }

    pub(crate) fn remove_recipient(
        &mut self,
        path: &Path,
        recipient_selector: &str,
        using: Option<&str>,
    ) -> Result<RecipientChoice> {
        let _lock = storage::NoteLock::acquire(path)?;
        let mut loaded = self.load(path)?;
        let recipient = resolve_recipient(&loaded.envelope, recipient_selector)?;
        let removed = choices(&loaded.envelope)
            .into_iter()
            .find(|choice| choice.id == recipient)
            .context("recipient not found")?;
        if removed.policy == RecipientPolicy::ManagedFido {
            bail!("retire managed security-key routes with `fkw retire-key`");
        }
        if loaded.envelope.recipients().len() == 1 {
            bail!("cannot remove the final recipient");
        }
        let authorizer = self.select_recipient(&loaded.envelope, using)?;
        let root = self.access.unlock(&loaded.envelope, authorizer)?;
        let plaintext = loaded.container.note().decrypt(
            &root,
            &self.trusted_id,
            loaded.container.envelope_bytes(),
        )?;
        self.access
            .remove_recipient(&mut loaded.envelope, &root, recipient)?;
        let staged_envelope = self.canonical_stage(&loaded.envelope)?;
        let staged = self.stage_container(
            &staged_envelope,
            &root,
            &plaintext,
            loaded.container.note().nonce(),
        )?;
        storage::replace_atomic_if_unchanged(path, &loaded.original_bytes, &staged.encode())?;
        Ok(removed)
    }

    pub(crate) fn rewrap_passphrase(
        &mut self,
        path: &Path,
        recipient_selector: &str,
        using: Option<&str>,
        kdf: KdfOptions,
    ) -> Result<RecipientId> {
        let parameters = optional_parameters(kdf)?;
        let _lock = storage::NoteLock::acquire(path)?;
        let mut loaded = self.load(path)?;
        let recipient = resolve_recipient(&loaded.envelope, recipient_selector)?;
        let summary = loaded
            .envelope
            .recipients()
            .into_iter()
            .find(|summary| summary.id() == recipient)
            .context("recipient not found")?;
        if summary.passphrase_parameters().is_none() {
            bail!("the selected recipient does not use a passphrase");
        }
        let authorizer = self.select_recipient(&loaded.envelope, using)?;
        let root = self.access.unlock(&loaded.envelope, authorizer)?;
        let plaintext = loaded.container.note().decrypt(
            &root,
            &self.trusted_id,
            loaded.container.envelope_bytes(),
        )?;
        self.access
            .rewrap_passphrase(&mut loaded.envelope, &root, recipient, parameters)?;
        let staged_envelope = self.canonical_stage(&loaded.envelope)?;
        let staged = self.stage_container(
            &staged_envelope,
            &root,
            &plaintext,
            loaded.container.note().nonce(),
        )?;
        storage::replace_atomic_if_unchanged(path, &loaded.original_bytes, &staged.encode())?;
        Ok(recipient)
    }

    pub(crate) fn verify_managed_recipient(
        &mut self,
        path: &Path,
        recipient_selector: &str,
        using: Option<&str>,
    ) -> Result<RecipientChoice> {
        let loaded = self.load(path)?;
        let recipient = resolve_recipient(&loaded.envelope, recipient_selector)?;
        let selected = choices(&loaded.envelope)
            .into_iter()
            .find(|choice| choice.id == recipient)
            .context("recipient not found")?;
        if selected.policy != RecipientPolicy::ManagedFido {
            bail!("the selected recipient is not a managed security-key route");
        }
        let authorizer = self.select_recipient(&loaded.envelope, using)?;
        let root = self.access.unlock(&loaded.envelope, authorizer)?;
        self.access
            .verify_managed_recipient(&loaded.envelope, &root, recipient)?;
        Ok(selected)
    }

    pub(crate) fn retire_managed_recipient(
        &mut self,
        path: &Path,
        recipient_selector: &str,
        using: Option<&str>,
        confirmed: bool,
    ) -> Result<(RecipientChoice, bool)> {
        let _lock = storage::NoteLock::acquire(path)?;
        let loaded = self.load(path)?;
        let recipient = resolve_recipient(&loaded.envelope, recipient_selector)?;
        let selected = choices(&loaded.envelope)
            .into_iter()
            .find(|choice| choice.id == recipient)
            .context("recipient not found")?;
        if selected.policy != RecipientPolicy::ManagedFido {
            bail!("the selected recipient is not a managed security-key route");
        }
        let final_route = loaded.envelope.recipients().len() == 1;
        if !confirmed {
            self.ui
                .confirm_managed_retirement(&selected.label, final_route)?;
        }
        let authorizer = self.select_recipient(&loaded.envelope, using)?;
        let root = self.access.unlock(&loaded.envelope, authorizer)?;
        let staged = if final_route {
            None
        } else {
            let plaintext = loaded.container.note().decrypt(
                &root,
                &self.trusted_id,
                loaded.container.envelope_bytes(),
            )?;
            let mut envelope = loaded.envelope.clone();
            self.access
                .remove_recipient(&mut envelope, &root, recipient)?;
            let envelope = self.canonical_stage(&envelope)?;
            Some(self.stage_container(
                &envelope,
                &root,
                &plaintext,
                loaded.container.note().nonce(),
            )?)
        };

        self.access
            .retire_managed_recipient(&loaded.envelope, &root, recipient)?;
        if let Some(staged) = staged {
            if let Err(error) =
                storage::replace_atomic_if_unchanged(path, &loaded.original_bytes, &staged.encode())
            {
                return Err(error).context(
                    "the managed credential was retired, but the note update could not be confirmed",
                );
            }
        }
        Ok((selected, final_route))
    }

    pub(crate) fn rotate_root(
        &mut self,
        path: &Path,
        using: Option<&str>,
        access: Access,
        label: String,
        kdf: KdfOptions,
        confirmed: bool,
    ) -> Result<RecipientId> {
        let enrollment = enrollment(access, label, kdf)?;
        let managed = enrollment.policy() == RecipientPolicy::ManagedFido;
        let _lock = storage::NoteLock::acquire(path)?;
        let loaded = self.load(path)?;
        if !confirmed {
            self.ui.confirm_root_rotation()?;
        }
        let authorizer = self.select_recipient(&loaded.envelope, using)?;
        let old_root = self.access.unlock(&loaded.envelope, authorizer)?;
        let plaintext = loaded.container.note().decrypt(
            &old_root,
            &self.trusted_id,
            loaded.container.envelope_bytes(),
        )?;
        let (new_root, envelope, recipient) = self.access.create_root(enrollment)?;
        managed_publication(
            (|| {
                let staged_envelope = self.canonical_stage(&envelope)?;
                let staged = self.stage_container(
                    &staged_envelope,
                    &new_root,
                    &plaintext,
                    loaded.container.note().nonce(),
                )?;
                storage::replace_atomic_if_unchanged(path, &loaded.original_bytes, &staged.encode())
            })(),
            managed,
        )?;
        Ok(recipient)
    }

    fn load(&self, path: &Path) -> Result<LoadedNote> {
        let original_bytes = storage::read_private(path)?;
        let container = NoteFile::decode(&original_bytes)?;
        let envelope = KeyEnvelope::decode(container.envelope_bytes())?;
        self.validate_envelope(&envelope)?;
        Ok(LoadedNote {
            original_bytes,
            container,
            envelope,
        })
    }

    fn canonical_stage(&self, envelope: &KeyEnvelope) -> Result<KeyEnvelope> {
        let staged = KeyEnvelope::decode(&envelope.encode())
            .context("the staged key envelope failed canonical decoding")?;
        self.validate_envelope(&staged)?;
        Ok(staged)
    }

    fn validate_envelope(&self, envelope: &KeyEnvelope) -> Result<()> {
        if envelope.application_id() != &self.trusted_id {
            bail!("the note belongs to another application identity");
        }
        for recipient in envelope.recipients() {
            ensure_allowed_policy(recipient.policy())?;
        }
        Ok(())
    }

    fn select_recipient(
        &mut self,
        envelope: &KeyEnvelope,
        selector: Option<&str>,
    ) -> Result<RecipientId> {
        if let Some(selector) = selector {
            return resolve_recipient(envelope, selector);
        }
        let choices = choices(envelope);
        match choices.as_slice() {
            [choice] => Ok(choice.id),
            _ => self.ui.choose_recipient(&choices),
        }
    }

    fn stage_container(
        &self,
        envelope: &KeyEnvelope,
        root: &RootKey,
        plaintext: &[u8],
        previous_nonce: [u8; 12],
    ) -> Result<NoteFile> {
        let envelope_bytes = envelope.encode();
        for _ in 0..8 {
            let encrypted =
                EncryptedNote::encrypt(root, &self.trusted_id, &envelope_bytes, plaintext)?;
            if encrypted.nonce() == previous_nonce {
                continue;
            }
            let staged = NoteFile::new(envelope_bytes, encrypted)?;
            let recovered =
                staged
                    .note()
                    .decrypt(root, &self.trusted_id, staged.envelope_bytes())?;
            if recovered.as_slice() != plaintext {
                bail!("the staged encrypted note failed verification");
            }
            return Ok(staged);
        }
        bail!("secure randomness repeated the previous note nonce")
    }
}

fn managed_publication<T>(result: Result<T>, managed: bool) -> Result<T> {
    if managed {
        result.context(
            "the note was not confirmed saved; a managed credential may remain on the security key",
        )
    } else {
        result
    }
}

struct LoadedNote {
    original_bytes: Vec<u8>,
    container: NoteFile,
    envelope: KeyEnvelope,
}

fn choices(envelope: &KeyEnvelope) -> Vec<RecipientChoice> {
    envelope
        .recipients()
        .into_iter()
        .map(|recipient| RecipientChoice {
            id: recipient.id(),
            label: recipient.label().to_owned(),
            policy: recipient.policy(),
            parameters: recipient.passphrase_parameters(),
        })
        .collect()
}

pub(crate) fn resolve_recipient(envelope: &KeyEnvelope, selector: &str) -> Result<RecipientId> {
    let recipients = envelope.recipients();
    if selector.len() == 64 {
        if let Ok(id) = RecipientId::from_str(selector) {
            return recipients
                .iter()
                .any(|recipient| recipient.id() == id)
                .then_some(id)
                .context("no recipient has that id");
        }
    }

    let labeled = recipients
        .iter()
        .filter(|recipient| recipient.label() == selector)
        .collect::<Vec<_>>();
    match labeled.as_slice() {
        [recipient] => return Ok(recipient.id()),
        [_, _, ..] => bail!("that recipient label is ambiguous; use an id"),
        [] => {}
    }

    let prefix = selector.strip_prefix("id:").unwrap_or(selector);
    if prefix.is_empty()
        || prefix.len() >= 64
        || !prefix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("a recipient selector must be an exact id, lowercase id prefix, or label");
    }
    let matching = recipients
        .iter()
        .filter(|recipient| recipient.id().to_string().starts_with(prefix))
        .collect::<Vec<_>>();
    match matching.as_slice() {
        [recipient] => Ok(recipient.id()),
        [_, _, ..] => bail!("that recipient id prefix is ambiguous"),
        [] => bail!("no recipient matches that selector"),
    }
}

pub(crate) fn enrollment(access: Access, label: String, kdf: KdfOptions) -> Result<Enrollment> {
    let parameters = optional_parameters(kdf)?;
    let enrollment = match (access, parameters) {
        (Access::ApplicationPassphrase, None) => Enrollment::passphrase(label),
        (Access::ApplicationPassphrase, Some(parameters)) => {
            Enrollment::passphrase_with_parameters(label, parameters)
        }
        (Access::FidoPresence, None) => Enrollment::fido(label, FidoPolicy::Presence),
        (Access::FidoUserVerification, None) => {
            Enrollment::fido(label, FidoPolicy::UserVerification)
        }
        (Access::FidoManaged, None) => Enrollment::managed_fido(label),
        (Access::FidoPresencePlusPassphrase, None) => {
            Enrollment::fido_and_passphrase(label, FidoPolicy::Presence)
        }
        (Access::FidoPresencePlusPassphrase, Some(parameters)) => {
            Enrollment::fido_and_passphrase_with_parameters(label, FidoPolicy::Presence, parameters)
        }
        (Access::FidoUserVerificationPlusPassphrase, None) => {
            Enrollment::fido_and_passphrase(label, FidoPolicy::UserVerification)
        }
        (Access::FidoUserVerificationPlusPassphrase, Some(parameters)) => {
            Enrollment::fido_and_passphrase_with_parameters(
                label,
                FidoPolicy::UserVerification,
                parameters,
            )
        }
        (Access::FidoPresence | Access::FidoUserVerification | Access::FidoManaged, Some(_)) => {
            bail!("argon2 options apply only to passphrase-bearing access policies")
        }
    }?;
    Ok(enrollment)
}

fn optional_parameters(options: KdfOptions) -> Result<Option<PassphraseParameters>> {
    match (options.memory_mib, options.passes, options.lanes) {
        (None, None, None) => Ok(None),
        (Some(memory_mib), Some(passes), Some(lanes)) => {
            let memory_in_kib = memory_mib
                .checked_mul(1024)
                .context("--memory-mib is too large")?;
            Ok(Some(PassphraseParameters::new(
                memory_in_kib,
                passes,
                lanes,
            )?))
        }
        _ => bail!("--memory-mib, --passes, and --lanes must be supplied together"),
    }
}

fn ensure_allowed_policy(policy: RecipientPolicy) -> Result<()> {
    match policy {
        RecipientPolicy::Passphrase
        | RecipientPolicy::Fido(FidoPolicy::Presence | FidoPolicy::UserVerification)
        | RecipientPolicy::ManagedFido
        | RecipientPolicy::FidoAndPassphrase(FidoPolicy::Presence | FidoPolicy::UserVerification) => {
            Ok(())
        }
        RecipientPolicy::RecoverySecret => {
            bail!("this application does not support recovery-secret recipients")
        }
    }
}

fn validate_plaintext(plaintext: &[u8]) -> Result<()> {
    if plaintext.is_empty() || plaintext.len() > crate::container::MAX_NOTE_BYTES {
        bail!("the note must contain between 1 byte and 1 MiB");
    }
    std::str::from_utf8(plaintext).context("the note must be utf-8")?;
    Ok(())
}

pub(crate) const fn policy_text(policy: RecipientPolicy) -> &'static str {
    match policy {
        RecipientPolicy::Passphrase => "application passphrase",
        RecipientPolicy::RecoverySecret => "recovery secret",
        RecipientPolicy::Fido(FidoPolicy::Presence) => "security key: presence",
        RecipientPolicy::Fido(FidoPolicy::UserVerification) => "security key: user verification",
        RecipientPolicy::ManagedFido => "managed security key: user verification",
        RecipientPolicy::FidoAndPassphrase(FidoPolicy::Presence) => {
            "security key: presence + application passphrase"
        }
        RecipientPolicy::FidoAndPassphrase(FidoPolicy::UserVerification) => {
            "security key: user verification + application passphrase"
        }
    }
}

pub(crate) fn parameters_text(parameters: Option<PassphraseParameters>) -> Option<String> {
    parameters.map(|parameters| {
        format!(
            "{} mib, {} passes, {} lanes",
            parameters.memory_kib() / 1024,
            parameters.passes(),
            parameters.lanes()
        )
    })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        fs,
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    use fido_key_wrap::{
        Interaction, InteractionError, KeyProtector, Passphrase, PassphrasePrompt, PinPrompt,
        SelectionPrompt, TouchPrompt,
    };

    use super::*;
    use crate::access::ProductionKeyAccess;

    #[test]
    fn kdf_options_are_all_or_none_and_rejected_for_fido_only() {
        let partial = KdfOptions {
            memory_mib: Some(64),
            passes: None,
            lanes: Some(1),
        };
        assert!(enrollment(Access::ApplicationPassphrase, "primary".into(), partial).is_err());

        let complete = KdfOptions {
            memory_mib: Some(64),
            passes: Some(3),
            lanes: Some(1),
        };
        assert!(enrollment(Access::ApplicationPassphrase, "primary".into(), complete).is_ok());
        assert!(enrollment(Access::FidoPresence, "primary".into(), complete).is_err());
    }

    #[test]
    fn policy_allow_list_accepts_every_demo_route() {
        for policy in [
            RecipientPolicy::Passphrase,
            RecipientPolicy::Fido(FidoPolicy::Presence),
            RecipientPolicy::Fido(FidoPolicy::UserVerification),
            RecipientPolicy::ManagedFido,
            RecipientPolicy::FidoAndPassphrase(FidoPolicy::Presence),
            RecipientPolicy::FidoAndPassphrase(FidoPolicy::UserVerification),
        ] {
            ensure_allowed_policy(policy).unwrap();
        }
        assert!(ensure_allowed_policy(RecipientPolicy::RecoverySecret).is_err());
    }

    #[test]
    fn recipient_selectors_accept_exact_id_unique_prefix_and_unique_label() {
        let envelope = mixed_envelope();
        let recipients = envelope.recipients();
        let expected = recipients[1].id();
        let exact = expected.to_string();

        assert_eq!(resolve_recipient(&envelope, &exact).unwrap(), expected);
        assert_eq!(resolve_recipient(&envelope, &exact[..8]).unwrap(), expected);
        assert_eq!(
            resolve_recipient(&envelope, recipients[1].label()).unwrap(),
            expected
        );
    }

    #[test]
    fn recipient_selectors_reject_ambiguous_prefixes_and_duplicate_labels() {
        let ambiguous_prefix = envelope_with_ambiguous_id_prefix();
        assert!(
            resolve_recipient(&ambiguous_prefix, "1")
                .unwrap_err()
                .to_string()
                .contains("prefix is ambiguous")
        );

        let duplicate_label = envelope_with_duplicate_label();
        assert!(
            resolve_recipient(&duplicate_label, "passphrase")
                .unwrap_err()
                .to_string()
                .contains("label is ambiguous")
        );
    }

    #[test]
    fn noninteractive_multi_recipient_choice_requires_an_explicit_selector() {
        let envelope = mixed_envelope();
        assert!(envelope.recipients().len() > 1);
        let mut access = VectorKeyAccess::default();
        let mut ui = NoninteractiveUi;
        let mut application =
            Application::new(envelope.application_id().clone(), &mut access, &mut ui);

        let error = application.select_recipient(&envelope, None).unwrap_err();
        assert!(error.to_string().contains("--recipient or --using"));
        assert_eq!(
            application
                .select_recipient(&envelope, Some("passphrase"))
                .unwrap(),
            envelope.recipients()[0].id()
        );
    }

    #[test]
    fn production_passphrase_lifecycle_is_transactional_and_refreshes_every_note_nonce() {
        let directory = TestDirectory::new();
        let path = directory.path.join("lifecycle.fkd");
        let passphrases = [
            "one", "one", // create
            "one", // open
            "one", "two", "two", // add
            "one", "three", "three", // rewrap
            "three", // remove
            "three", "four", "four",  // rotate
            "four",  // final open
            "three", // obsolete passphrase against current state
            "three", // saved old complete state
        ];
        let interaction = ScriptedInteraction::new(&passphrases);
        let remaining = Arc::clone(&interaction.remaining);
        let application_id = ApplicationId::new(APPLICATION_ID.to_owned()).unwrap();
        let mut access = ProductionKeyAccess::new(application_id.clone(), Box::new(interaction));
        let mut ui = TestUi::default();
        let mut application = Application::new(application_id, &mut access, &mut ui);
        let low_cost = KdfOptions {
            memory_mib: Some(64),
            passes: Some(3),
            lanes: Some(1),
        };

        application
            .create(
                &path,
                Access::ApplicationPassphrase,
                "primary".into(),
                low_cost,
                b"complete lifecycle\n",
            )
            .unwrap();
        assert_eq!(
            application.open(&path, None).unwrap().as_slice(),
            b"complete lifecycle\n"
        );
        let initial_nonce = note_nonce(&path);

        application
            .add_recipient(
                &path,
                Some("primary"),
                Access::ApplicationPassphrase,
                "backup",
                low_cost,
            )
            .unwrap();
        let added_nonce = note_nonce(&path);
        assert_ne!(added_nonce, initial_nonce);

        application
            .rewrap_passphrase(&path, "backup", Some("primary"), KdfOptions::default())
            .unwrap();
        let rewrapped_nonce = note_nonce(&path);
        assert_ne!(rewrapped_nonce, added_nonce);

        application
            .remove_recipient(&path, "primary", Some("backup"))
            .unwrap();
        let removed_nonce = note_nonce(&path);
        assert_ne!(removed_nonce, rewrapped_nonce);

        let old_path = directory.path.join("before-rotation.fkd");
        let old_complete_state = storage::read_private(&path).unwrap();
        storage::create_atomic(&old_path, &old_complete_state).unwrap();

        application
            .rotate_root(
                &path,
                Some("backup"),
                Access::ApplicationPassphrase,
                "rotated".into(),
                low_cost,
                true,
            )
            .unwrap();
        let rotated_nonce = note_nonce(&path);
        assert_ne!(rotated_nonce, removed_nonce);
        assert_eq!(
            application.open(&path, None).unwrap().as_slice(),
            b"complete lifecycle\n"
        );
        assert!(application.open(&path, None).is_err());
        assert_eq!(
            application.open(&old_path, None).unwrap().as_slice(),
            b"complete lifecycle\n"
        );
        assert_ne!(storage::read_private(&path).unwrap(), old_complete_state);
        assert_eq!(application.recipients(&path).unwrap().len(), 1);
        assert_eq!(remaining.lock().unwrap().len(), 0);
    }

    #[test]
    fn failed_application_mutation_preserves_the_complete_original_file() {
        let directory = TestDirectory::new();
        let path = directory.path.join("failure.fkd");
        let interaction = ScriptedInteraction::new(&["one", "one", "wrong"]);
        let application_id = ApplicationId::new(APPLICATION_ID.to_owned()).unwrap();
        let mut access = ProductionKeyAccess::new(application_id.clone(), Box::new(interaction));
        let mut ui = TestUi::default();
        let mut application = Application::new(application_id, &mut access, &mut ui);
        let low_cost = KdfOptions {
            memory_mib: Some(64),
            passes: Some(3),
            lanes: Some(1),
        };
        application
            .create(
                &path,
                Access::ApplicationPassphrase,
                "primary".into(),
                low_cost,
                b"unchanged on failure",
            )
            .unwrap();
        let before = storage::read_private(&path).unwrap();
        assert!(
            application
                .rotate_root(
                    &path,
                    None,
                    Access::ApplicationPassphrase,
                    "replacement".into(),
                    low_cost,
                    true,
                )
                .is_err()
        );
        assert_eq!(storage::read_private(&path).unwrap(), before);
    }

    #[test]
    fn every_fido_policy_is_orchestrated_through_only_the_high_level_seam() {
        let directory = TestDirectory::new();
        let application_id = ApplicationId::new("vectors.fido-key-wrap.example").unwrap();
        for (index, access_policy) in [
            Access::FidoPresence,
            Access::FidoUserVerification,
            Access::FidoManaged,
            Access::FidoPresencePlusPassphrase,
            Access::FidoUserVerificationPlusPassphrase,
        ]
        .into_iter()
        .enumerate()
        {
            let path = directory.path.join(format!("fido-{index}.fkd"));
            let mut access = VectorKeyAccess::default();
            let mut ui = TestUi::default();
            let mut application = Application::new(application_id.clone(), &mut access, &mut ui);
            application
                .create(
                    &path,
                    access_policy,
                    "vector recipient".into(),
                    KdfOptions::default(),
                    b"fido orchestration",
                )
                .unwrap();
            assert_eq!(
                application.open(&path, None).unwrap().as_slice(),
                b"fido orchestration"
            );
            drop(application);
            assert_eq!(access.created, vec![access_policy]);
            assert_eq!(access.unlocks, 1);
        }
    }

    #[test]
    fn managed_publication_failure_reports_the_possible_orphan() {
        let directory = TestDirectory::new();
        let path = directory.path.join("managed-publication.fkd");
        let concurrent = b"concurrent destination".to_vec();
        let application_id = ApplicationId::new("vectors.fido-key-wrap.example").unwrap();
        let mut access = VectorKeyAccess {
            creation_conflict: Some((path.clone(), concurrent.clone())),
            ..VectorKeyAccess::default()
        };
        let mut ui = TestUi::default();
        let mut application = Application::new(application_id, &mut access, &mut ui);

        let result = application.create(
            &path,
            Access::FidoManaged,
            "managed".into(),
            KdfOptions::default(),
            b"not published",
        );

        assert!(matches!(
            result,
            Err(error) if error.to_string().contains("a managed credential may remain")
        ));
        assert_eq!(storage::read_private(&path).unwrap(), concurrent);
        assert_eq!(access.created, [Access::FidoManaged]);
    }

    #[test]
    fn managed_routes_require_the_retirement_workflow() {
        let directory = TestDirectory::new();
        let path = directory.path.join("managed-retirement.fkd");
        let envelope = mixed_demo_envelope();
        let application_id = envelope.application_id().clone();
        store_vector_note(&path, &envelope, b"managed retirement");
        let original = storage::read_private(&path).unwrap();

        let mut access = VectorKeyAccess::default();
        let mut ui = TestUi::default();
        let mut application = Application::new(application_id, &mut access, &mut ui);

        let sole_path = directory.path.join("sole-managed.fkd");
        let managed = managed_envelope();
        store_vector_note(&sole_path, &managed, b"sole managed route");
        let sole_removal = application.remove_recipient(&sole_path, "managed fido", None);
        assert!(matches!(
            sole_removal,
            Err(error) if error.to_string().contains("retire-key")
        ));

        let removal = application.remove_recipient(&path, "managed fido", Some("passphrase"));
        assert!(matches!(
            removal,
            Err(error) if error.to_string().contains("retire-key")
        ));
        assert_eq!(storage::read_private(&path).unwrap(), original);
        assert_eq!(access.unlocks, 0);
        assert_eq!(access.removals, 0);
        assert_eq!(ui.confirmations, 0);
    }

    #[test]
    fn managed_verification_and_nonfinal_retirement_are_exact() {
        let directory = TestDirectory::new();
        let path = directory.path.join("managed-retirement.fkd");
        let envelope = mixed_demo_envelope();
        let application_id = envelope.application_id().clone();
        store_vector_note(&path, &envelope, b"managed retirement");
        let original = storage::read_private(&path).unwrap();

        let mut access = VectorKeyAccess::default();
        let mut ui = TestUi::default();
        let mut application = Application::new(application_id, &mut access, &mut ui);

        application
            .verify_managed_recipient(&path, "managed fido", Some("passphrase"))
            .unwrap();
        let (_, final_route) = application
            .retire_managed_recipient(&path, "managed fido", Some("passphrase"), false)
            .unwrap();
        assert!(!final_route);
        assert_ne!(storage::read_private(&path).unwrap(), original);
        assert_eq!(application.recipients(&path).unwrap().len(), 1);

        drop(application);
        assert_eq!(access.unlocks, 2);
        assert_eq!(access.verifications, 1);
        assert_eq!(access.retirements, 1);
        assert_eq!(access.removals, 1);
        assert_eq!(ui.confirmations, 1);
        assert_eq!(ui.managed_final_routes, [false]);
    }

    #[test]
    fn rejected_managed_retirement_stops_before_key_access() {
        let directory = TestDirectory::new();
        let path = directory.path.join("cancelled-retirement.fkd");
        let envelope = mixed_demo_envelope();
        let application_id = envelope.application_id().clone();
        store_vector_note(&path, &envelope, b"cancelled retirement");
        let original = storage::read_private(&path).unwrap();

        let mut access = VectorKeyAccess::default();
        let mut ui = TestUi {
            reject_managed_retirement: true,
            ..TestUi::default()
        };
        let mut application = Application::new(application_id, &mut access, &mut ui);
        let result =
            application.retire_managed_recipient(&path, "managed fido", Some("passphrase"), false);

        assert!(matches!(result, Err(error) if error.to_string() == "retirement cancelled"));
        assert_eq!(storage::read_private(&path).unwrap(), original);
        assert_eq!(access.unlocks, 0);
        assert_eq!(access.removals, 0);
        assert_eq!(access.retirements, 0);
        assert_eq!(ui.confirmations, 1);
    }

    #[test]
    fn retired_credential_is_reported_when_note_publication_conflicts() {
        let directory = TestDirectory::new();
        let path = directory.path.join("conflicted-retirement.fkd");
        let envelope = mixed_demo_envelope();
        let application_id = envelope.application_id().clone();
        store_vector_note(&path, &envelope, b"conflicted retirement");
        let original = storage::read_private(&path).unwrap();
        let concurrent = b"concurrent note update".to_vec();

        let mut access = VectorKeyAccess {
            retirement_conflict: Some((path.clone(), original, concurrent.clone())),
            ..VectorKeyAccess::default()
        };
        let mut ui = TestUi::default();
        let mut application = Application::new(application_id, &mut access, &mut ui);
        let result =
            application.retire_managed_recipient(&path, "managed fido", Some("passphrase"), true);

        assert!(matches!(
            result,
            Err(error) if error.to_string().contains("the managed credential was retired")
        ));
        assert_eq!(storage::read_private(&path).unwrap(), concurrent);
        assert_eq!(access.unlocks, 1);
        assert_eq!(access.removals, 1);
        assert_eq!(access.retirements, 1);
        assert_eq!(ui.confirmations, 0);
    }

    #[test]
    fn final_managed_retirement_leaves_the_dead_route_recorded() {
        let directory = TestDirectory::new();
        let path = directory.path.join("final-managed.fkd");
        let envelope = managed_envelope();
        let application_id = envelope.application_id().clone();
        store_vector_note(&path, &envelope, b"final managed route");
        let original = storage::read_private(&path).unwrap();

        let mut access = VectorKeyAccess::default();
        let mut ui = TestUi::default();
        let mut application = Application::new(application_id, &mut access, &mut ui);
        let (_, final_route) = application
            .retire_managed_recipient(&path, "managed fido", None, false)
            .unwrap();

        assert!(final_route);
        assert_eq!(storage::read_private(&path).unwrap(), original);
        assert_eq!(access.unlocks, 1);
        assert_eq!(access.retirements, 1);
        assert_eq!(access.removals, 0);
        assert_eq!(ui.confirmations, 1);
        assert_eq!(ui.managed_final_routes, [true]);
    }

    #[test]
    fn fido_mutations_and_rotation_need_no_ctap_fake() {
        let directory = TestDirectory::new();
        let path = directory.path.join("fido-mutations.fkd");
        let application_id = ApplicationId::new("vectors.fido-key-wrap.example").unwrap();
        let mut access = VectorKeyAccess::default();
        let mut ui = TestUi::default();
        let mut application = Application::new(application_id, &mut access, &mut ui);
        application
            .create(
                &path,
                Access::FidoPresence,
                "initial".into(),
                KdfOptions::default(),
                b"fido mutation orchestration",
            )
            .unwrap();
        let initial_nonce = note_nonce(&path);

        application
            .add_recipient(
                &path,
                None,
                Access::FidoUserVerificationPlusPassphrase,
                "new combined",
                KdfOptions::default(),
            )
            .unwrap();
        let added_nonce = note_nonce(&path);
        assert_ne!(added_nonce, initial_nonce);

        application
            .remove_recipient(&path, "fido user verification", Some("fido presence"))
            .unwrap();
        let removed_nonce = note_nonce(&path);
        assert_ne!(removed_nonce, added_nonce);

        application
            .rewrap_passphrase(&path, "uv plus passphrase", None, KdfOptions::default())
            .unwrap();
        let rewrapped_nonce = note_nonce(&path);
        assert_ne!(rewrapped_nonce, removed_nonce);

        application
            .rotate_root(
                &path,
                None,
                Access::FidoUserVerification,
                "rotated".into(),
                KdfOptions::default(),
                true,
            )
            .unwrap();
        assert_ne!(note_nonce(&path), rewrapped_nonce);
        assert_eq!(
            application.open(&path, None).unwrap().as_slice(),
            b"fido mutation orchestration"
        );
        drop(application);
        assert_eq!(access.additions, 1);
        assert_eq!(access.removals, 1);
        assert_eq!(access.rewraps, 1);
        assert_eq!(access.created.len(), 2);
        assert_eq!(access.unlocks, 5);
    }

    #[test]
    fn decoded_application_identity_is_rejected_before_key_access() {
        let directory = TestDirectory::new();
        let path = directory.path.join("wrong-application.fkd");
        let vector = include_str!("../../../test-vectors/format-1-fido-presence.txt");
        let envelope = vector_bytes(vector, "envelope");
        let trusted_id = ApplicationId::new(APPLICATION_ID.to_owned()).unwrap();
        let note = EncryptedNote::encrypt(&vector_root(), &trusted_id, &envelope, b"identity test")
            .unwrap();
        storage::create_atomic(&path, &NoteFile::new(envelope, note).unwrap().encode()).unwrap();

        let mut access = VectorKeyAccess::default();
        let mut ui = TestUi::default();
        let application_id = ApplicationId::new(APPLICATION_ID.to_owned()).unwrap();
        let mut application = Application::new(application_id, &mut access, &mut ui);
        assert!(application.open(&path, None).is_err());
        drop(application);
        assert_eq!(access.unlocks, 0);
    }

    #[cfg(not(feature = "fido"))]
    #[test]
    fn no_feature_production_adapter_rejects_fido_without_interaction_or_file() {
        let directory = TestDirectory::new();
        let path = directory.path.join("unsupported.fkd");
        let application_id = ApplicationId::new(APPLICATION_ID.to_owned()).unwrap();
        let mut access = ProductionKeyAccess::new(
            application_id.clone(),
            Box::new(ScriptedInteraction::new(&[])),
        );
        let mut ui = TestUi::default();
        let mut application = Application::new(application_id, &mut access, &mut ui);
        assert!(
            application
                .create(
                    &path,
                    Access::FidoPresence,
                    "unsupported".into(),
                    KdfOptions::default(),
                    b"not written",
                )
                .is_err()
        );
        assert!(!path.exists());
    }

    fn note_nonce(path: &Path) -> [u8; 12] {
        NoteFile::decode(&storage::read_private(path).unwrap())
            .unwrap()
            .note()
            .nonce()
    }

    #[derive(Default)]
    struct TestUi {
        confirmations: usize,
        managed_final_routes: Vec<bool>,
        reject_managed_retirement: bool,
    }

    impl AppUi for TestUi {
        fn choose_recipient(&mut self, choices: &[RecipientChoice]) -> Result<RecipientId> {
            Ok(choices[0].id)
        }

        fn confirm_offline_passphrase_route(&mut self) -> Result<()> {
            self.confirmations += 1;
            Ok(())
        }

        fn confirm_root_rotation(&mut self) -> Result<()> {
            self.confirmations += 1;
            Ok(())
        }

        fn confirm_managed_retirement(&mut self, _label: &str, final_route: bool) -> Result<()> {
            self.confirmations += 1;
            self.managed_final_routes.push(final_route);
            if self.reject_managed_retirement {
                bail!("retirement cancelled");
            }
            Ok(())
        }
    }

    struct NoninteractiveUi;

    impl AppUi for NoninteractiveUi {
        fn choose_recipient(&mut self, _choices: &[RecipientChoice]) -> Result<RecipientId> {
            require_interactive_recipient_choice(false)?;
            unreachable!("a noninteractive choice always fails")
        }

        fn confirm_offline_passphrase_route(&mut self) -> Result<()> {
            unreachable!("the selector test does not confirm mutations")
        }

        fn confirm_root_rotation(&mut self) -> Result<()> {
            unreachable!("the selector test does not confirm mutations")
        }

        fn confirm_managed_retirement(&mut self, _label: &str, _final_route: bool) -> Result<()> {
            unreachable!("the selector test does not confirm mutations")
        }
    }

    struct ScriptedInteraction {
        remaining: Arc<Mutex<VecDeque<Vec<u8>>>>,
    }

    impl ScriptedInteraction {
        fn new(values: &[&str]) -> Self {
            Self {
                remaining: Arc::new(Mutex::new(
                    values
                        .iter()
                        .map(|value| value.as_bytes().to_vec())
                        .collect(),
                )),
            }
        }
    }

    impl Interaction for ScriptedInteraction {
        fn request_passphrase(
            &mut self,
            _prompt: &PassphrasePrompt,
        ) -> std::result::Result<Passphrase, InteractionError> {
            let value = self
                .remaining
                .lock()
                .map_err(|_| InteractionError::Failed)?
                .pop_front()
                .ok_or(InteractionError::Failed)?;
            Passphrase::new(value).map_err(|_| InteractionError::Failed)
        }

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

        fn touch_required(
            &mut self,
            _prompt: &TouchPrompt,
        ) -> std::result::Result<(), InteractionError> {
            Err(InteractionError::Unsupported)
        }
    }

    #[derive(Default)]
    struct VectorKeyAccess {
        created: Vec<Access>,
        unlocks: usize,
        additions: usize,
        removals: usize,
        verifications: usize,
        retirements: usize,
        rewraps: usize,
        creation_conflict: Option<(std::path::PathBuf, Vec<u8>)>,
        retirement_conflict: Option<(std::path::PathBuf, Vec<u8>, Vec<u8>)>,
    }

    impl KeyAccess for VectorKeyAccess {
        fn create_root(
            &mut self,
            enrollment: Enrollment,
        ) -> Result<(RootKey, KeyEnvelope, RecipientId)> {
            let (access, vector) = vector_for_policy(enrollment.policy())?;
            self.created.push(access);
            let envelope = KeyEnvelope::decode(&vector_bytes(vector, "envelope"))?;
            let recipient = envelope.recipients()[0].id();
            if let Some((path, contents)) = self.creation_conflict.take() {
                storage::create_atomic(&path, &contents)?;
            }
            Ok((vector_root(), envelope, recipient))
        }

        fn unlock(&mut self, _envelope: &KeyEnvelope, _recipient: RecipientId) -> Result<RootKey> {
            self.unlocks += 1;
            Ok(vector_root())
        }

        fn add_recipient(
            &mut self,
            envelope: &mut KeyEnvelope,
            _root: &RootKey,
            enrollment: Enrollment,
        ) -> Result<RecipientId> {
            self.additions += 1;
            *envelope = mixed_demo_envelope();
            envelope
                .recipients()
                .into_iter()
                .find(|recipient| recipient.policy() == enrollment.policy())
                .map(fido_key_wrap::RecipientSummary::id)
                .context("mixed vector lacks the requested policy")
        }

        fn remove_recipient(
            &mut self,
            envelope: &mut KeyEnvelope,
            _root: &RootKey,
            _recipient: RecipientId,
        ) -> Result<()> {
            self.removals += 1;
            let vector = include_str!(
                "../../../test-vectors/format-1-fido-user-verification-plus-passphrase.txt"
            );
            *envelope = KeyEnvelope::decode(&vector_bytes(vector, "envelope"))?;
            Ok(())
        }

        fn verify_managed_recipient(
            &mut self,
            _envelope: &KeyEnvelope,
            _root: &RootKey,
            _recipient: RecipientId,
        ) -> Result<()> {
            self.verifications += 1;
            Ok(())
        }

        fn retire_managed_recipient(
            &mut self,
            _envelope: &KeyEnvelope,
            _root: &RootKey,
            _recipient: RecipientId,
        ) -> Result<()> {
            self.retirements += 1;
            if let Some((path, expected, replacement)) = self.retirement_conflict.take() {
                storage::replace_atomic_if_unchanged(&path, &expected, &replacement)?;
            }
            Ok(())
        }

        fn rewrap_passphrase(
            &mut self,
            envelope: &mut KeyEnvelope,
            _root: &RootKey,
            _recipient: RecipientId,
            _parameters: Option<PassphraseParameters>,
        ) -> Result<()> {
            self.rewraps += 1;
            let vector = include_str!(
                "../../../test-vectors/format-1-fido-user-verification-plus-passphrase.txt"
            );
            *envelope = KeyEnvelope::decode(&vector_bytes(vector, "envelope"))?;
            Ok(())
        }
    }

    fn vector_for_policy(policy: RecipientPolicy) -> Result<(Access, &'static str)> {
        match policy {
            RecipientPolicy::Fido(FidoPolicy::Presence) => Ok((
                Access::FidoPresence,
                include_str!("../../../test-vectors/format-1-fido-presence.txt"),
            )),
            RecipientPolicy::Fido(FidoPolicy::UserVerification) => Ok((
                Access::FidoUserVerification,
                include_str!("../../../test-vectors/format-1-fido-user-verification.txt"),
            )),
            RecipientPolicy::FidoAndPassphrase(FidoPolicy::Presence) => Ok((
                Access::FidoPresencePlusPassphrase,
                include_str!("../../../test-vectors/format-1-fido-presence-plus-passphrase.txt"),
            )),
            RecipientPolicy::FidoAndPassphrase(FidoPolicy::UserVerification) => Ok((
                Access::FidoUserVerificationPlusPassphrase,
                include_str!(
                    "../../../test-vectors/format-1-fido-user-verification-plus-passphrase.txt"
                ),
            )),
            RecipientPolicy::ManagedFido => Ok((
                Access::FidoManaged,
                include_str!("../../../test-vectors/format-1-managed-fido.txt"),
            )),
            RecipientPolicy::Passphrase | RecipientPolicy::RecoverySecret => {
                bail!("expected a fido policy")
            }
        }
    }

    fn vector_root() -> RootKey {
        let vector = include_str!("../../../test-vectors/format-1-fido-presence.txt");
        root_from_vector(vector)
    }

    fn root_from_vector(vector: &str) -> RootKey {
        let mut bytes: [u8; 32] = vector_bytes(vector, "root_key")
            .try_into()
            .expect("root vector contains 32 bytes");
        RootKey::import(&mut bytes)
    }

    fn mixed_envelope() -> KeyEnvelope {
        let vector = include_str!("../../../test-vectors/format-1-mixed.txt");
        KeyEnvelope::decode(&vector_bytes(vector, "envelope")).unwrap()
    }

    fn managed_envelope() -> KeyEnvelope {
        let vector = include_str!("../../../test-vectors/format-1-managed-fido.txt");
        KeyEnvelope::decode(&vector_bytes(vector, "envelope")).unwrap()
    }

    fn store_vector_note(path: &Path, envelope: &KeyEnvelope, plaintext: &[u8]) {
        let encoded = envelope.encode();
        let note = EncryptedNote::encrypt(
            &vector_root(),
            envelope.application_id(),
            &encoded,
            plaintext,
        )
        .unwrap();
        storage::create_atomic(path, &NoteFile::new(encoded, note).unwrap().encode()).unwrap();
    }

    fn mixed_demo_envelope() -> KeyEnvelope {
        let vector = include_str!("../../../test-vectors/format-1-mixed.txt");
        let mut envelope = KeyEnvelope::decode(&vector_bytes(vector, "envelope")).unwrap();
        let recovery = envelope
            .recipients()
            .into_iter()
            .find(|recipient| recipient.policy() == RecipientPolicy::RecoverySecret)
            .unwrap()
            .id();
        KeyProtector::new(envelope.application_id().clone())
            .remove_recipient(&mut envelope, &root_from_vector(vector), recovery)
            .unwrap();
        envelope
    }

    fn envelope_with_ambiguous_id_prefix() -> KeyEnvelope {
        let mut encoded = mixed_envelope().encode();
        let second_id = std::array::from_fn::<_, 32, _>(|index| {
            0x30 + u8::try_from(index).expect("recipient id index fits in u8")
        });
        let position = encoded
            .windows(second_id.len())
            .position(|window| window == second_id)
            .expect("mixed fixture contains its second recipient id");
        encoded[position] = 0x10;
        KeyEnvelope::decode(&encoded).unwrap()
    }

    fn envelope_with_duplicate_label() -> KeyEnvelope {
        const ORIGINAL: &[u8] = b"fido presence";
        const DUPLICATE: &[u8] = b"passphrase";

        let mut encoded = mixed_envelope().encode();
        let position = encoded
            .windows(ORIGINAL.len())
            .position(|window| window == ORIGINAL)
            .expect("mixed fixture contains the presence label");
        assert_eq!(
            encoded[position - 1],
            0x60 | u8::try_from(ORIGINAL.len()).unwrap()
        );
        encoded[position - 1] = 0x60 | u8::try_from(DUPLICATE.len()).unwrap();
        encoded.splice(
            position..position + ORIGINAL.len(),
            DUPLICATE.iter().copied(),
        );
        KeyEnvelope::decode(&encoded).unwrap()
    }

    fn vector_bytes(vector: &str, field: &str) -> Vec<u8> {
        let prefix = format!("{field}=");
        let value = vector
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .unwrap();
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
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
                let path = std::env::temp_dir().join(format!("fkw-demo-app-test-{name}"));
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
