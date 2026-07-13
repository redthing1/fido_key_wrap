use std::borrow::Cow;

use fido_key_wrap::{
    Interaction, InteractionError, Operation, Passphrase, PassphrasePrompt, Pin, PinPrompt,
    SelectionPrompt, TouchPrompt,
};

pub(crate) struct TerminalInteraction;

impl TerminalInteraction {
    pub(crate) const fn new() -> Self {
        Self
    }
}

impl Interaction for TerminalInteraction {
    fn select_authenticator_by_touch(
        &mut self,
        prompt: &SelectionPrompt,
    ) -> Result<(), InteractionError> {
        eprintln!(
            "{} compatible fido authenticators are connected; touch the one to {}",
            prompt.compatible_authenticators,
            action_text(prompt.operation)
        );
        Ok(())
    }

    fn request_pin(&mut self, prompt: &PinPrompt) -> Result<Pin, InteractionError> {
        let value =
            rpassword::prompt_password(format!("fido pin to {}: ", action_text(prompt.operation)))
                .map_err(|_| InteractionError::Failed)?;
        Pin::new(value).map_err(|_| InteractionError::Failed)
    }

    fn request_passphrase(
        &mut self,
        prompt: &PassphrasePrompt,
    ) -> Result<Passphrase, InteractionError> {
        let action = if prompt.confirm {
            "confirm application passphrase"
        } else {
            "application passphrase"
        };
        let value = rpassword::prompt_password(format!(
            "{action} for {}: ",
            display_text(&prompt.recipient_label),
        ))
        .map_err(|_| InteractionError::Failed)?;
        Passphrase::new(value.into_bytes()).map_err(|_| InteractionError::Failed)
    }

    fn touch_required(&mut self, prompt: &TouchPrompt) -> Result<(), InteractionError> {
        eprintln!(
            "touch the fido authenticator to {}",
            action_text(prompt.operation)
        );
        Ok(())
    }
}

const fn action_text(operation: Operation) -> &'static str {
    match operation {
        Operation::Enroll => "create the credential",
        Operation::Verify => "verify the recipient",
        Operation::Unlock => "unlock the root key",
    }
}

pub(crate) fn display_text(value: &str) -> Cow<'_, str> {
    if value.len() <= 1024 && !value.chars().any(is_terminal_control) {
        Cow::Borrowed(value)
    } else {
        Cow::Borrowed("[unsafe text]")
    }
}

fn is_terminal_control(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_text_does_not_reflect_controls_or_unbounded_values() {
        assert_eq!(display_text("backup authenticator"), "backup authenticator");
        assert_eq!(display_text("café"), "café");
        assert_eq!(display_text("bad\u{1b}[31m"), "[unsafe text]");
        assert_eq!(display_text("bad\u{202e}txt"), "[unsafe text]");
        assert_eq!(display_text(&"x".repeat(1025)), "[unsafe text]");
    }

    #[test]
    fn opening_and_setup_verification_have_distinct_prompts() {
        assert_eq!(action_text(Operation::Unlock), "unlock the root key");
        assert_eq!(action_text(Operation::Verify), "verify the recipient");
    }
}
