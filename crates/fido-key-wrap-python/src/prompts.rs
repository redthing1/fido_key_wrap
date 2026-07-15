use fido_key_wrap as core;
use pyo3::prelude::*;

use crate::types::FidoPolicy;

/// the library operation requesting interaction.
#[pyclass(
    name = "Operation",
    eq,
    hash,
    frozen,
    skip_from_py_object,
    module = "fido_key_wrap._native"
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Operation {
    #[pyo3(name = "CREATE_ROOT")]
    CreateRoot = 1,
    #[pyo3(name = "PROTECT_ROOT")]
    ProtectRoot = 2,
    #[pyo3(name = "UNLOCK")]
    Unlock = 3,
    #[pyo3(name = "ADD_RECIPIENT")]
    AddRecipient = 4,
    #[pyo3(name = "REWRAP_PASSPHRASE")]
    RewrapPassphrase = 5,
    #[pyo3(name = "VERIFY_MANAGED_RECIPIENT")]
    VerifyManagedRecipient = 6,
    #[pyo3(name = "RETIRE_MANAGED_RECIPIENT")]
    RetireManagedRecipient = 7,
}

impl From<core::Operation> for Operation {
    fn from(value: core::Operation) -> Self {
        match value {
            core::Operation::CreateRoot => Self::CreateRoot,
            core::Operation::ProtectRoot => Self::ProtectRoot,
            core::Operation::Unlock => Self::Unlock,
            core::Operation::AddRecipient => Self::AddRecipient,
            core::Operation::RewrapPassphrase => Self::RewrapPassphrase,
            core::Operation::VerifyManagedRecipient => Self::VerifyManagedRecipient,
            core::Operation::RetireManagedRecipient => Self::RetireManagedRecipient,
        }
    }
}

/// whether a fido prompt belongs to enrollment or assertion.
#[pyclass(
    name = "FidoCeremony",
    eq,
    hash,
    frozen,
    skip_from_py_object,
    module = "fido_key_wrap._native"
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FidoCeremony {
    #[pyo3(name = "ENROLLMENT")]
    Enrollment = 1,
    #[pyo3(name = "ASSERTION")]
    Assertion = 2,
}

impl From<core::FidoCeremony> for FidoCeremony {
    fn from(value: core::FidoCeremony) -> Self {
        match value {
            core::FidoCeremony::Enrollment => Self::Enrollment,
            core::FidoCeremony::Assertion => Self::Assertion,
        }
    }
}

/// the reason an application passphrase is requested.
#[pyclass(
    name = "PassphrasePurpose",
    eq,
    hash,
    frozen,
    skip_from_py_object,
    module = "fido_key_wrap._native"
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PassphrasePurpose {
    #[pyo3(name = "UNLOCK")]
    Unlock = 1,
    #[pyo3(name = "NEW")]
    New = 2,
    #[pyo3(name = "CONFIRM")]
    Confirm = 3,
}

impl From<core::PassphrasePurpose> for PassphrasePurpose {
    fn from(value: core::PassphrasePurpose) -> Self {
        match value {
            core::PassphrasePurpose::Unlock => Self::Unlock,
            core::PassphrasePurpose::New => Self::New,
            core::PassphrasePurpose::Confirm => Self::Confirm,
        }
    }
}

/// asks the user to choose an authenticator by touching it.
#[pyclass(name = "SelectionPrompt", frozen, module = "fido_key_wrap._native")]
pub struct SelectionPrompt {
    #[pyo3(get)]
    operation: Operation,
    #[pyo3(get)]
    label: String,
    #[pyo3(get)]
    policy: FidoPolicy,
}

impl From<&core::SelectionPrompt> for SelectionPrompt {
    fn from(value: &core::SelectionPrompt) -> Self {
        Self {
            operation: value.operation().into(),
            label: value.label().to_owned(),
            policy: value.policy().into(),
        }
    }
}

/// asks the user for the selected authenticator's pin.
#[pyclass(name = "PinPrompt", frozen, module = "fido_key_wrap._native")]
pub struct PinPrompt {
    #[pyo3(get)]
    operation: Operation,
    #[pyo3(get)]
    label: String,
    #[pyo3(get)]
    ceremony: FidoCeremony,
}

impl From<&core::PinPrompt> for PinPrompt {
    fn from(value: &core::PinPrompt) -> Self {
        Self {
            operation: value.operation().into(),
            label: value.label().to_owned(),
            ceremony: value.ceremony().into(),
        }
    }
}

/// asks the user for an application passphrase.
#[pyclass(name = "PassphrasePrompt", frozen, module = "fido_key_wrap._native")]
pub struct PassphrasePrompt {
    #[pyo3(get)]
    operation: Operation,
    #[pyo3(get)]
    label: String,
    #[pyo3(get)]
    purpose: PassphrasePurpose,
}

impl From<&core::PassphrasePrompt> for PassphrasePrompt {
    fn from(value: &core::PassphrasePrompt) -> Self {
        Self {
            operation: value.operation().into(),
            label: value.label().to_owned(),
            purpose: value.purpose().into(),
        }
    }
}

/// asks the user to touch the selected authenticator.
#[pyclass(name = "TouchPrompt", frozen, module = "fido_key_wrap._native")]
pub struct TouchPrompt {
    #[pyo3(get)]
    operation: Operation,
    #[pyo3(get)]
    label: String,
    #[pyo3(get)]
    ceremony: FidoCeremony,
    #[pyo3(get)]
    policy: FidoPolicy,
}

impl From<&core::TouchPrompt> for TouchPrompt {
    fn from(value: &core::TouchPrompt) -> Self {
        Self {
            operation: value.operation().into(),
            label: value.label().to_owned(),
            ceremony: value.ceremony().into(),
            policy: value.policy().into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_enums_preserve_every_core_value() {
        assert_eq!(
            Operation::from(core::Operation::CreateRoot),
            Operation::CreateRoot
        );
        assert_eq!(
            Operation::from(core::Operation::ProtectRoot),
            Operation::ProtectRoot
        );
        assert_eq!(Operation::from(core::Operation::Unlock), Operation::Unlock);
        assert_eq!(
            Operation::from(core::Operation::AddRecipient),
            Operation::AddRecipient
        );
        assert_eq!(
            Operation::from(core::Operation::RewrapPassphrase),
            Operation::RewrapPassphrase
        );
        assert_eq!(
            FidoCeremony::from(core::FidoCeremony::Enrollment),
            FidoCeremony::Enrollment
        );
        assert_eq!(
            FidoCeremony::from(core::FidoCeremony::Assertion),
            FidoCeremony::Assertion
        );
        assert_eq!(
            PassphrasePurpose::from(core::PassphrasePurpose::Unlock),
            PassphrasePurpose::Unlock
        );
        assert_eq!(
            PassphrasePurpose::from(core::PassphrasePurpose::New),
            PassphrasePurpose::New
        );
        assert_eq!(
            PassphrasePurpose::from(core::PassphrasePurpose::Confirm),
            PassphrasePurpose::Confirm
        );
        assert_eq!(
            FidoPolicy::from(core::FidoPolicy::Presence),
            FidoPolicy::Presence
        );
        assert_eq!(
            FidoPolicy::from(core::FidoPolicy::UserVerification),
            FidoPolicy::UserVerification
        );
    }
}
