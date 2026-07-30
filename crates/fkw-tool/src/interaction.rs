use fido_key_wrap::{
    Interaction, InteractionError, Operation, Passphrase, PassphrasePrompt, PassphrasePurpose, Pin,
    PinPrompt, SelectionPrompt, TouchPrompt,
};

pub(crate) struct TerminalInteraction;

impl Interaction for TerminalInteraction {
    fn select_authenticator_by_touch(
        &mut self,
        _prompt: &SelectionPrompt,
    ) -> Result<(), InteractionError> {
        eprintln!("touch the security key you want to use");
        Ok(())
    }

    fn request_pin(&mut self, prompt: &PinPrompt) -> Result<Pin, InteractionError> {
        let value = rpassword::prompt_password(format!(
            "security key pin to {}: ",
            action(prompt.operation())
        ))
        .map_err(|_| InteractionError::Failed)?;
        Pin::new(value).map_err(|_| InteractionError::Failed)
    }

    fn request_passphrase(
        &mut self,
        prompt: &PassphrasePrompt,
    ) -> Result<Passphrase, InteractionError> {
        let message = match prompt.purpose() {
            PassphrasePurpose::Unlock => "application passphrase: ",
            PassphrasePurpose::New => "new application passphrase: ",
            PassphrasePurpose::Confirm => "confirm application passphrase: ",
        };
        let value = rpassword::prompt_password(message).map_err(|_| InteractionError::Failed)?;
        Passphrase::new(value.into_bytes()).map_err(|_| InteractionError::Failed)
    }

    fn touch_required(&mut self, prompt: &TouchPrompt) -> Result<(), InteractionError> {
        eprintln!("touch your security key to {}", action(prompt.operation()));
        Ok(())
    }
}

const fn action(operation: Operation) -> &'static str {
    match operation {
        Operation::CreateRoot | Operation::ProtectRoot | Operation::AddRecipient => {
            "seal the secret"
        }
        Operation::Unlock => "unseal the secret",
        Operation::RewrapPassphrase => "change the passphrase",
        Operation::VerifyManagedRecipient => "verify the security key",
        Operation::RetireManagedRecipient => "retire the security key",
    }
}
