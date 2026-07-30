use std::process::ExitCode;

use anyhow::{Result, ensure};
use clap::{Parser, ValueEnum};
#[cfg(feature = "fido")]
use fido_key_wrap::FidoPolicy;
use fido_key_wrap::{
    ApplicationId, Enrollment, FidoCeremony, Interaction, InteractionError, KeyProtector,
    Operation, Passphrase, PassphrasePrompt, PassphrasePurpose, Pin, PinPrompt, SelectionPrompt,
    TouchPrompt,
};
use subtle::ConstantTimeEq;

#[derive(Debug, Parser)]
#[command(
    name = "fkw-demo",
    about = "perform one in-memory fido-key-wrap round trip"
)]
struct Cli {
    /// factors required to recover the generated root.
    #[arg(value_enum)]
    access: Access,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Access {
    Passphrase,
    #[cfg(feature = "fido")]
    FidoPresence,
    #[cfg(feature = "fido")]
    FidoUserVerification,
    #[cfg(feature = "fido")]
    FidoPresencePlusPassphrase,
    #[cfg(feature = "fido")]
    FidoUserVerificationPlusPassphrase,
}

fn main() -> ExitCode {
    match run(&Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<()> {
    let application = ApplicationId::new("demo.fido-key-wrap.local")?;
    let mut protector = protector(application);
    let mut interaction = TerminalInteraction;
    let enrollment = match cli.access {
        Access::Passphrase => Enrollment::passphrase("demo")?,
        #[cfg(feature = "fido")]
        Access::FidoPresence => Enrollment::fido("demo", FidoPolicy::Presence)?,
        #[cfg(feature = "fido")]
        Access::FidoUserVerification => Enrollment::fido("demo", FidoPolicy::UserVerification)?,
        #[cfg(feature = "fido")]
        Access::FidoPresencePlusPassphrase => {
            Enrollment::fido_and_passphrase("demo", FidoPolicy::Presence)?
        }
        #[cfg(feature = "fido")]
        Access::FidoUserVerificationPlusPassphrase => {
            Enrollment::fido_and_passphrase("demo", FidoPolicy::UserVerification)?
        }
    };

    let (root, envelope, recipient) = protector.create_root(enrollment, &mut interaction)?;
    let decoded = fido_key_wrap::KeyEnvelope::decode(&envelope.encode())?;
    let recovered = protector.unlock(&decoded, recipient, &mut interaction)?;
    let matches =
        root.expose(|expected| recovered.expose(|actual| bool::from(expected.ct_eq(actual))));
    ensure!(matches, "the recovered root did not match");
    println!("round trip succeeded");
    Ok(())
}

#[cfg(feature = "fido")]
fn protector(application: ApplicationId) -> KeyProtector {
    KeyProtector::system(application)
}

#[cfg(not(feature = "fido"))]
fn protector(application: ApplicationId) -> KeyProtector {
    KeyProtector::new(application)
}

struct TerminalInteraction;

impl Interaction for TerminalInteraction {
    fn select_authenticator_by_touch(
        &mut self,
        _prompt: &SelectionPrompt,
    ) -> Result<(), InteractionError> {
        eprintln!("touch the security key you want to use");
        Ok(())
    }

    fn request_pin(&mut self, _prompt: &PinPrompt) -> Result<Pin, InteractionError> {
        let value = rpassword::prompt_password("security key pin: ")
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
        let action = match (prompt.operation(), prompt.ceremony()) {
            (
                Operation::CreateRoot | Operation::ProtectRoot | Operation::AddRecipient,
                FidoCeremony::Enrollment,
            ) => "create the recipient",
            _ => "continue",
        };
        eprintln!("touch your security key to {action}");
        Ok(())
    }
}
