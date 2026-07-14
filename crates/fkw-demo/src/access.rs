use anyhow::Result;
use fido_key_wrap::{
    ApplicationId, Enrollment, Interaction, KeyEnvelope, KeyProtector, PassphraseParameters,
    RecipientId, RootKey,
};

pub(crate) trait KeyAccess {
    fn create_root(
        &mut self,
        enrollment: Enrollment,
    ) -> Result<(RootKey, KeyEnvelope, RecipientId)>;

    fn unlock(&mut self, envelope: &KeyEnvelope, recipient: RecipientId) -> Result<RootKey>;

    fn add_recipient(
        &mut self,
        envelope: &mut KeyEnvelope,
        root: &RootKey,
        enrollment: Enrollment,
    ) -> Result<RecipientId>;

    fn remove_recipient(
        &mut self,
        envelope: &mut KeyEnvelope,
        root: &RootKey,
        recipient: RecipientId,
    ) -> Result<()>;

    fn rewrap_passphrase(
        &mut self,
        envelope: &mut KeyEnvelope,
        root: &RootKey,
        recipient: RecipientId,
        parameters: Option<PassphraseParameters>,
    ) -> Result<()>;
}

pub(crate) struct ProductionKeyAccess {
    protector: KeyProtector,
    interaction: Box<dyn Interaction>,
}

impl ProductionKeyAccess {
    pub(crate) fn new(application_id: ApplicationId, interaction: Box<dyn Interaction>) -> Self {
        Self {
            protector: protector(application_id),
            interaction,
        }
    }
}

#[cfg(feature = "fido")]
fn protector(application_id: ApplicationId) -> KeyProtector {
    KeyProtector::system(application_id)
}

#[cfg(not(feature = "fido"))]
fn protector(application_id: ApplicationId) -> KeyProtector {
    KeyProtector::new(application_id)
}

impl KeyAccess for ProductionKeyAccess {
    fn create_root(
        &mut self,
        enrollment: Enrollment,
    ) -> Result<(RootKey, KeyEnvelope, RecipientId)> {
        self.protector
            .create_root(enrollment, self.interaction.as_mut())
            .map_err(Into::into)
    }

    fn unlock(&mut self, envelope: &KeyEnvelope, recipient: RecipientId) -> Result<RootKey> {
        self.protector
            .unlock(envelope, recipient, self.interaction.as_mut())
            .map_err(Into::into)
    }

    fn add_recipient(
        &mut self,
        envelope: &mut KeyEnvelope,
        root: &RootKey,
        enrollment: Enrollment,
    ) -> Result<RecipientId> {
        self.protector
            .add_recipient(envelope, root, enrollment, self.interaction.as_mut())
            .map_err(Into::into)
    }

    fn remove_recipient(
        &mut self,
        envelope: &mut KeyEnvelope,
        root: &RootKey,
        recipient: RecipientId,
    ) -> Result<()> {
        self.protector
            .remove_recipient(envelope, root, recipient)
            .map_err(Into::into)
    }

    fn rewrap_passphrase(
        &mut self,
        envelope: &mut KeyEnvelope,
        root: &RootKey,
        recipient: RecipientId,
        parameters: Option<PassphraseParameters>,
    ) -> Result<()> {
        match parameters {
            Some(parameters) => self.protector.rewrap_passphrase_with_parameters(
                envelope,
                root,
                recipient,
                parameters,
                self.interaction.as_mut(),
            ),
            None => self.protector.rewrap_passphrase(
                envelope,
                root,
                recipient,
                self.interaction.as_mut(),
            ),
        }
        .map_err(Into::into)
    }
}
