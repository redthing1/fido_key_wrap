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
        Enrollment, KeyEnvelope, PassphraseLimits, PassphraseParameters, RecipientId, RootKey,
    },
};

/// protects and recovers root keys for one trusted application identity.
#[pyclass(name = "KeyProtector", frozen, module = "fido_key_wrap._native")]
pub struct KeyProtector {
    application_id: core::ApplicationId,
    limits: core::PassphraseLimits,
    busy: AtomicBool,
}

#[pymethods]
impl KeyProtector {
    /// creates a protector from trusted application configuration.
    #[new]
    #[pyo3(signature = (application_id, passphrase_limits=None))]
    fn new(
        py: Python<'_>,
        application_id: String,
        passphrase_limits: Option<PassphraseLimits>,
    ) -> PyResult<Self> {
        Ok(Self {
            application_id: core::ApplicationId::new(application_id)
                .map_err(|error| map_error(py, &error))?,
            limits: passphrase_limits.map_or(core::PassphraseLimits::DESKTOP, |limits| limits.core),
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
        let enrollment = enrollment.core.clone();
        let mut interaction = PythonInteraction::new(interaction);
        let result = py.detach(|| {
            let mut protector = protector(application_id, limits);
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
        let root = Arc::clone(&root.core);
        let enrollment = enrollment.core.clone();
        let mut interaction = PythonInteraction::new(interaction);
        let result = py.detach(|| {
            let mut protector = protector(application_id, limits);
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
        let envelope = envelope.core.clone();
        let recipient = recipient.core;
        let mut interaction = PythonInteraction::new(interaction);
        let result = py.detach(|| {
            let mut protector = protector(application_id, limits);
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
        let mut envelope = envelope.core.clone();
        let root = Arc::clone(&root.core);
        let enrollment = enrollment.core.clone();
        let mut interaction = PythonInteraction::new(interaction);
        let result = py.detach(|| {
            let mut protector = protector(application_id, limits);
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
        let mut envelope = envelope.core.clone();
        let root = Arc::clone(&root.core);
        let recipient = recipient.core;
        let result = py.detach(|| {
            let protector = protector(application_id, limits);
            protector
                .remove_recipient(&mut envelope, root.as_ref(), recipient)
                .map(|()| KeyEnvelope { core: envelope })
        });
        result.map_err(|error| map_error(py, &error))
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
        let mut envelope = envelope.core.clone();
        let root = Arc::clone(&root.core);
        let recipient = recipient.core;
        let mut interaction = PythonInteraction::new(interaction);
        let result = py.detach(|| {
            let mut protector = protector(application_id, limits);
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
) -> core::KeyProtector {
    #[cfg(feature = "fido")]
    let protector = core::KeyProtector::system(application_id);
    #[cfg(not(feature = "fido"))]
    let protector = core::KeyProtector::new(application_id);
    protector.with_passphrase_limits(limits)
}

fn finish<T>(
    py: Python<'_>,
    interaction: &mut PythonInteraction,
    result: core::Result<T>,
) -> PyResult<T> {
    if let Some(error) = interaction.take_pending() {
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
