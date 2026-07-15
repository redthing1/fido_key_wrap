use fido_key_wrap::{
    FidoCeremony, Interaction, InteractionError, Operation, Passphrase, PassphrasePrompt,
    PassphrasePurpose, Pin, PinPrompt, SelectionPrompt, TouchPrompt,
};

pub(crate) struct TerminalInteraction;

impl Interaction for TerminalInteraction {
    fn select_authenticator_by_touch(
        &mut self,
        prompt: &SelectionPrompt,
    ) -> Result<(), InteractionError> {
        eprintln!(
            "touch the security key you want to use for {}",
            selection_subject(prompt.operation(), prompt.label())
        );
        Ok(())
    }

    fn request_pin(&mut self, prompt: &PinPrompt) -> Result<Pin, InteractionError> {
        let value = rpassword::prompt_password(format!(
            "security key pin to {}: ",
            action(prompt.operation(), prompt.ceremony(), prompt.label())
        ))
        .map_err(|_| InteractionError::Failed)?;
        Pin::new(value).map_err(|_| InteractionError::Failed)
    }

    fn request_passphrase(
        &mut self,
        prompt: &PassphrasePrompt,
    ) -> Result<Passphrase, InteractionError> {
        let purpose = match prompt.purpose() {
            PassphrasePurpose::Unlock => "application passphrase",
            PassphrasePurpose::New => "new application passphrase",
            PassphrasePurpose::Confirm => "confirm application passphrase",
        };
        let value = rpassword::prompt_password(format!("{purpose} for {}: ", prompt.label()))
            .map_err(|_| InteractionError::Failed)?;
        Passphrase::new(value.into_bytes()).map_err(|_| InteractionError::Failed)
    }

    fn touch_required(&mut self, prompt: &TouchPrompt) -> Result<(), InteractionError> {
        eprintln!(
            "touch your security key to {}",
            action(prompt.operation(), prompt.ceremony(), prompt.label())
        );
        Ok(())
    }
}

fn selection_subject(operation: Operation, label: &str) -> String {
    match operation {
        Operation::Unlock => "the note".to_owned(),
        Operation::RewrapPassphrase => format!("the passphrase change for {label}"),
        Operation::VerifyManagedRecipient => format!("verification of {label}"),
        Operation::RetireManagedRecipient => format!("retirement of {label}"),
        Operation::CreateRoot | Operation::ProtectRoot | Operation::AddRecipient => {
            label.to_owned()
        }
    }
}

fn action(operation: Operation, ceremony: FidoCeremony, label: &str) -> String {
    match (operation, ceremony) {
        (Operation::Unlock, _) => "open the note".to_owned(),
        (Operation::RewrapPassphrase, _) => format!("change the passphrase for {label}"),
        (Operation::VerifyManagedRecipient, _) => format!("verify {label}"),
        (Operation::RetireManagedRecipient, _) => format!("retire {label}"),
        (
            Operation::CreateRoot | Operation::ProtectRoot | Operation::AddRecipient,
            FidoCeremony::Enrollment,
        ) => format!("create {label}"),
        (
            Operation::CreateRoot | Operation::ProtectRoot | Operation::AddRecipient,
            FidoCeremony::Assertion,
        ) => format!("check {label}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompts_describe_user_actions_without_protocol_terms() {
        let prompts = [
            selection_subject(Operation::Unlock, "primary"),
            selection_subject(Operation::RewrapPassphrase, "primary"),
            action(Operation::Unlock, FidoCeremony::Assertion, "primary"),
            action(Operation::CreateRoot, FidoCeremony::Enrollment, "primary"),
            action(Operation::CreateRoot, FidoCeremony::Assertion, "primary"),
            action(
                Operation::RewrapPassphrase,
                FidoCeremony::Assertion,
                "primary",
            ),
        ];

        assert_eq!(prompts[0], "the note");
        assert_eq!(prompts[1], "the passphrase change for primary");
        assert_eq!(prompts[2], "open the note");
        assert_eq!(prompts[3], "create primary");
        assert_eq!(prompts[4], "check primary");
        assert_eq!(prompts[5], "change the passphrase for primary");
        for prompt in prompts {
            assert!(!prompt.contains("assertion"));
            assert!(!prompt.contains("enrollment"));
            assert!(!prompt.contains("rewrap"));
        }
    }
}
