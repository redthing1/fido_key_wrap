use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use fido_key_wrap as core;
use pyo3::prelude::*;

use crate::{
    errors::{busy_error, map_error},
    interaction::PythonInteraction,
    types::{
        Enrollment, FidoConfig, KeyEnvelope, PassphraseLimits, PassphraseParameters, RecipientId,
        RecoverySecret, RecoverySecretRecipient, RootKey,
    },
};

/// protects and recovers root keys for one trusted application identity.
#[pyclass(name = "KeyProtector", frozen, module = "fido_key_wrap._native")]
pub struct KeyProtector {
    application_id: core::ApplicationId,
    limits: core::PassphraseLimits,
    fido_config: core::FidoConfig,
    busy: AtomicBool,
}

#[pymethods]
impl KeyProtector {
    /// creates a protector from trusted application configuration.
    #[new]
    #[pyo3(signature = (application_id, *, passphrase_limits=None, fido_config=None))]
    fn new(
        py: Python<'_>,
        application_id: String,
        passphrase_limits: Option<PassphraseLimits>,
        fido_config: Option<FidoConfig>,
    ) -> PyResult<Self> {
        let application_id =
            core::ApplicationId::new(application_id).map_err(|error| map_error(py, &error))?;
        #[cfg(not(feature = "fido"))]
        if fido_config.is_some() {
            return Err(crate::errors::unavailable_error(py));
        }
        Ok(Self {
            application_id,
            limits: passphrase_limits.map_or(core::PassphraseLimits::DESKTOP, |limits| limits.core),
            fido_config: fido_config.map_or_else(core::FidoConfig::default, |config| config.core),
            busy: AtomicBool::new(false),
        })
    }

    #[getter]
    fn application_id(&self) -> &str {
        self.application_id.as_str()
    }

    #[getter]
    fn passphrase_limits(&self) -> PassphraseLimits {
        PassphraseLimits { core: self.limits }
    }

    #[getter]
    fn fido_config(&self) -> FidoConfig {
        FidoConfig {
            core: self.fido_config,
        }
    }

    /// generates a random root and protects it through one recovery route.
    fn create_root(
        &self,
        py: Python<'_>,
        enrollment: &Enrollment,
        interaction: Py<PyAny>,
    ) -> PyResult<(RootKey, KeyEnvelope, RecipientId)> {
        let _busy = BusyGuard::enter(py, &self.busy)?;
        let application_id = self.application_id.clone();
        let limits = self.limits;
        let fido_config = self.fido_config;
        let enrollment = enrollment.core.clone();
        let mut interaction = PythonInteraction::new(interaction);
        let result = py.detach(|| {
            let mut protector = protector(application_id, limits, fido_config);
            protector.create_root(enrollment, &mut interaction).map(
                |(root, envelope, recipient)| {
                    (
                        RootKey::new(root),
                        KeyEnvelope { core: envelope },
                        RecipientId { core: recipient },
                    )
                },
            )
        });
        finish(py, &mut interaction, result)
    }

    /// protects an existing uniformly random root through one recovery route.
    fn protect_root(
        &self,
        py: Python<'_>,
        root: &RootKey,
        enrollment: &Enrollment,
        interaction: Py<PyAny>,
    ) -> PyResult<(KeyEnvelope, RecipientId)> {
        let _busy = BusyGuard::enter(py, &self.busy)?;
        let application_id = self.application_id.clone();
        let limits = self.limits;
        let fido_config = self.fido_config;
        let root = Arc::clone(&root.core);
        let enrollment = enrollment.core.clone();
        let mut interaction = PythonInteraction::new(interaction);
        let result = py.detach(|| {
            let mut protector = protector(application_id, limits, fido_config);
            protector
                .protect_root(root.as_ref(), enrollment, &mut interaction)
                .map(|(envelope, recipient)| {
                    (
                        KeyEnvelope { core: envelope },
                        RecipientId { core: recipient },
                    )
                })
        });
        finish(py, &mut interaction, result)
    }

    /// recovers a root through exactly one selected recipient.
    fn unlock(
        &self,
        py: Python<'_>,
        envelope: &KeyEnvelope,
        recipient: &RecipientId,
        interaction: Py<PyAny>,
    ) -> PyResult<RootKey> {
        let _busy = BusyGuard::enter(py, &self.busy)?;
        let application_id = self.application_id.clone();
        let limits = self.limits;
        let fido_config = self.fido_config;
        let envelope = envelope.core.clone();
        let recipient = recipient.core;
        let mut interaction = PythonInteraction::new(interaction);
        let result = py.detach(|| {
            let mut protector = protector(application_id, limits, fido_config);
            protector
                .unlock(&envelope, recipient, &mut interaction)
                .map(RootKey::new)
        });
        finish(py, &mut interaction, result)
    }

    /// returns a new envelope containing one additional recovery recipient.
    fn add_recipient(
        &self,
        py: Python<'_>,
        envelope: &KeyEnvelope,
        root: &RootKey,
        enrollment: &Enrollment,
        interaction: Py<PyAny>,
    ) -> PyResult<(KeyEnvelope, RecipientId)> {
        let _busy = BusyGuard::enter(py, &self.busy)?;
        let application_id = self.application_id.clone();
        let limits = self.limits;
        let fido_config = self.fido_config;
        let mut envelope = envelope.core.clone();
        let root = Arc::clone(&root.core);
        let enrollment = enrollment.core.clone();
        let mut interaction = PythonInteraction::new(interaction);
        let result = py.detach(|| {
            let mut protector = protector(application_id, limits, fido_config);
            protector
                .add_recipient(&mut envelope, root.as_ref(), enrollment, &mut interaction)
                .map(|recipient| {
                    (
                        KeyEnvelope { core: envelope },
                        RecipientId { core: recipient },
                    )
                })
        });
        finish(py, &mut interaction, result)
    }

    /// returns a new envelope without the selected recovery recipient.
    fn remove_recipient(
        &self,
        py: Python<'_>,
        envelope: &KeyEnvelope,
        root: &RootKey,
        recipient: &RecipientId,
    ) -> PyResult<KeyEnvelope> {
        let _busy = BusyGuard::enter(py, &self.busy)?;
        let application_id = self.application_id.clone();
        let limits = self.limits;
        let fido_config = self.fido_config;
        let mut envelope = envelope.core.clone();
        let root = Arc::clone(&root.core);
        let recipient = recipient.core;
        let result = py.detach(|| {
            let protector = protector(application_id, limits, fido_config);
            protector
                .remove_recipient(&mut envelope, root.as_ref(), recipient)
                .map(|()| KeyEnvelope { core: envelope })
        });
        result.map_err(|error| map_error(py, &error))
    }

    /// verifies the exact managed credential recorded by one authenticated recipient.
    fn verify_managed_recipient(
        &self,
        py: Python<'_>,
        envelope: &KeyEnvelope,
        root: &RootKey,
        recipient: &RecipientId,
        interaction: Py<PyAny>,
    ) -> PyResult<()> {
        let _busy = BusyGuard::enter(py, &self.busy)?;
        let application_id = self.application_id.clone();
        let limits = self.limits;
        let fido_config = self.fido_config;
        let envelope = envelope.core.clone();
        let root = Arc::clone(&root.core);
        let recipient = recipient.core;
        let mut interaction = PythonInteraction::new(interaction);
        let result = py.detach(|| {
            let mut protector = protector(application_id, limits, fido_config);
            protector.verify_managed_recipient(
                &envelope,
                root.as_ref(),
                recipient,
                &mut interaction,
            )
        });
        finish(py, &mut interaction, result)
    }

    /// permanently retires the exact managed credential without changing the envelope.
    fn retire_managed_recipient(
        &self,
        py: Python<'_>,
        envelope: &KeyEnvelope,
        root: &RootKey,
        recipient: &RecipientId,
        interaction: Py<PyAny>,
    ) -> PyResult<()> {
        let _busy = BusyGuard::enter(py, &self.busy)?;
        let application_id = self.application_id.clone();
        let limits = self.limits;
        let fido_config = self.fido_config;
        let envelope = envelope.core.clone();
        let root = Arc::clone(&root.core);
        let recipient = recipient.core;
        let mut interaction = PythonInteraction::new(interaction);
        let result = py.detach(|| {
            let mut protector = protector(application_id, limits, fido_config);
            protector.retire_managed_recipient(
                &envelope,
                root.as_ref(),
                recipient,
                &mut interaction,
            )
        });
        finish(py, &mut interaction, result)
    }

    /// returns a new envelope with new passphrase protection for one recipient.
    #[pyo3(signature = (envelope, root, recipient, interaction, parameters=None))]
    fn rewrap_passphrase(
        &self,
        py: Python<'_>,
        envelope: &KeyEnvelope,
        root: &RootKey,
        recipient: &RecipientId,
        interaction: Py<PyAny>,
        parameters: Option<PassphraseParameters>,
    ) -> PyResult<KeyEnvelope> {
        let _busy = BusyGuard::enter(py, &self.busy)?;
        let application_id = self.application_id.clone();
        let limits = self.limits;
        let fido_config = self.fido_config;
        let mut envelope = envelope.core.clone();
        let root = Arc::clone(&root.core);
        let recipient = recipient.core;
        let mut interaction = PythonInteraction::new(interaction);
        let result = py.detach(|| {
            let mut protector = protector(application_id, limits, fido_config);
            let result = match parameters {
                Some(parameters) => protector.rewrap_passphrase_with_parameters(
                    &mut envelope,
                    root.as_ref(),
                    recipient,
                    parameters.core,
                    &mut interaction,
                ),
                None => protector.rewrap_passphrase(
                    &mut envelope,
                    root.as_ref(),
                    recipient,
                    &mut interaction,
                ),
            };
            result.map(|()| KeyEnvelope { core: envelope })
        });
        finish(py, &mut interaction, result)
    }

    /// generates a random root and protects it with a new recovery secret.
    fn create_root_with_recovery_secret(
        &self,
        py: Python<'_>,
        label: String,
    ) -> PyResult<(RootKey, KeyEnvelope, RecoverySecretRecipient)> {
        let _busy = BusyGuard::enter(py, &self.busy)?;
        let application_id = self.application_id.clone();
        let limits = self.limits;
        let fido_config = self.fido_config;
        py.detach(|| {
            protector(application_id, limits, fido_config)
                .create_root_with_recovery_secret(label)
                .map(|(root, envelope, recovery)| {
                    (
                        RootKey::new(root),
                        KeyEnvelope { core: envelope },
                        RecoverySecretRecipient::new(recovery),
                    )
                })
        })
        .map_err(|error| map_error(py, &error))
    }

    /// protects an existing root with a new recovery secret.
    fn protect_root_with_recovery_secret(
        &self,
        py: Python<'_>,
        root: &RootKey,
        label: String,
    ) -> PyResult<(KeyEnvelope, RecoverySecretRecipient)> {
        let _busy = BusyGuard::enter(py, &self.busy)?;
        let application_id = self.application_id.clone();
        let limits = self.limits;
        let fido_config = self.fido_config;
        let root = Arc::clone(&root.core);
        py.detach(|| {
            protector(application_id, limits, fido_config)
                .protect_root_with_recovery_secret(root.as_ref(), label)
                .map(|(envelope, recovery)| {
                    (
                        KeyEnvelope { core: envelope },
                        RecoverySecretRecipient::new(recovery),
                    )
                })
        })
        .map_err(|error| map_error(py, &error))
    }

    /// recovers a root through one selected recovery-secret recipient.
    fn unlock_with_recovery_secret(
        &self,
        py: Python<'_>,
        envelope: &KeyEnvelope,
        recipient: &RecipientId,
        secret: &RecoverySecret,
    ) -> PyResult<RootKey> {
        let _busy = BusyGuard::enter(py, &self.busy)?;
        let application_id = self.application_id.clone();
        let limits = self.limits;
        let fido_config = self.fido_config;
        let envelope = envelope.core.clone();
        let recipient = recipient.core;
        let secret = Arc::clone(&secret.core);
        py.detach(|| {
            protector(application_id, limits, fido_config)
                .unlock_with_recovery_secret(&envelope, recipient, secret.as_ref())
                .map(RootKey::new)
        })
        .map_err(|error| map_error(py, &error))
    }

    /// returns a new envelope containing another recovery-secret route.
    fn add_recovery_secret(
        &self,
        py: Python<'_>,
        envelope: &KeyEnvelope,
        root: &RootKey,
        label: String,
    ) -> PyResult<(KeyEnvelope, RecoverySecretRecipient)> {
        let _busy = BusyGuard::enter(py, &self.busy)?;
        let application_id = self.application_id.clone();
        let limits = self.limits;
        let fido_config = self.fido_config;
        let mut envelope = envelope.core.clone();
        let root = Arc::clone(&root.core);
        py.detach(|| {
            protector(application_id, limits, fido_config)
                .add_recovery_secret(&mut envelope, root.as_ref(), label)
                .map(|recovery| {
                    (
                        KeyEnvelope { core: envelope },
                        RecoverySecretRecipient::new(recovery),
                    )
                })
        })
        .map_err(|error| map_error(py, &error))
    }

    fn __repr__(&self) -> String {
        format!(
            "KeyProtector(application_id={:?})",
            self.application_id.as_str()
        )
    }
}

fn protector(
    application_id: core::ApplicationId,
    limits: core::PassphraseLimits,
    fido_config: core::FidoConfig,
) -> core::KeyProtector {
    #[cfg(feature = "fido")]
    let protector = core::KeyProtector::system_with_config(application_id, fido_config);
    #[cfg(not(feature = "fido"))]
    let protector = {
        let _ = fido_config;
        core::KeyProtector::new(application_id)
    };
    protector.with_passphrase_limits(limits)
}

fn finish<T>(
    py: Python<'_>,
    interaction: &mut PythonInteraction,
    result: core::Result<T>,
) -> PyResult<T> {
    if let Some(error) = interaction.take_pending_if_causal(&result) {
        return Err(error);
    }
    result.map_err(|error| map_error(py, &error))
}

struct BusyGuard<'a>(&'a AtomicBool);

impl<'a> BusyGuard<'a> {
    fn enter(py: Python<'_>, busy: &'a AtomicBool) -> PyResult<Self> {
        busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| busy_error(py))?;
        Ok(Self(busy))
    }
}

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
