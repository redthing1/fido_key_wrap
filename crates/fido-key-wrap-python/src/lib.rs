mod diagnostics;
mod errors;
mod interaction;
mod prompts;
mod protector;
mod types;

use pyo3::prelude::*;

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("Error", module.py().get_type::<errors::Error>())?;
    module.add("Cancelled", module.py().get_type::<errors::Cancelled>())?;
    module.add_class::<errors::ErrorCode>()?;
    module.add_class::<types::Policy>()?;
    module.add_class::<types::FidoPolicy>()?;
    module.add_class::<types::FidoConfig>()?;
    module.add_class::<types::PassphraseParameters>()?;
    module.add_class::<types::PassphraseLimits>()?;
    module.add_class::<types::Enrollment>()?;
    module.add_class::<types::RecipientId>()?;
    module.add_class::<types::RecipientSummary>()?;
    module.add_class::<types::KeyEnvelope>()?;
    module.add_class::<types::RootKey>()?;
    module.add_class::<types::RecoverySecret>()?;
    module.add_class::<types::RecoverySecretRecipient>()?;
    module.add_class::<types::LocalSecret>()?;
    module.add_class::<types::LocalSecretRecipient>()?;
    module
        .getattr("RootKey")?
        .setattr("__hash__", module.py().None())?;
    module
        .getattr("RecoverySecret")?
        .setattr("__hash__", module.py().None())?;
    module
        .getattr("RecoverySecretRecipient")?
        .setattr("__hash__", module.py().None())?;
    module
        .getattr("LocalSecret")?
        .setattr("__hash__", module.py().None())?;
    module
        .getattr("LocalSecretRecipient")?
        .setattr("__hash__", module.py().None())?;
    module.add_class::<prompts::Operation>()?;
    module.add_class::<prompts::FidoCeremony>()?;
    module.add_class::<prompts::PassphrasePurpose>()?;
    module.add_class::<prompts::SelectionPrompt>()?;
    module.add_class::<prompts::PinPrompt>()?;
    module.add_class::<prompts::PassphrasePrompt>()?;
    module.add_class::<prompts::TouchPrompt>()?;
    module.add_class::<protector::KeyProtector>()?;
    module.add_class::<diagnostics::AuthenticatorIssue>()?;
    module.add_class::<diagnostics::AuthenticatorReport>()?;
    module.add_function(wrap_pyfunction!(
        diagnostics::inspect_authenticators,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        diagnostics::fido_runtime_available,
        module
    )?)?;
    Ok(())
}
