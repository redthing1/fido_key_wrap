use std::{str::FromStr, sync::Arc, time::Duration};

use fido_key_wrap as core;
use pyo3::{
    exceptions::PyTypeError,
    prelude::*,
    types::{PyByteArray, PyBytes, PyTuple},
};
use zeroize::Zeroizing;

use crate::errors::map_error;

/// a complete recovery policy for one recipient.
#[pyclass(
    name = "Policy",
    eq,
    hash,
    frozen,
    from_py_object,
    module = "fido_key_wrap._native"
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Policy {
    #[pyo3(name = "PASSPHRASE")]
    Passphrase = 1,
    #[pyo3(name = "RECOVERY_SECRET")]
    RecoverySecret = 2,
    #[pyo3(name = "FIDO_PRESENCE")]
    FidoPresence = 3,
    #[pyo3(name = "FIDO_USER_VERIFICATION")]
    FidoUserVerification = 4,
    #[pyo3(name = "MANAGED_FIDO_PRESENCE")]
    ManagedFidoPresence = 5,
    #[pyo3(name = "MANAGED_FIDO_USER_VERIFICATION")]
    ManagedFidoUserVerification = 6,
    #[pyo3(name = "FIDO_PRESENCE_AND_PASSPHRASE")]
    FidoPresenceAndPassphrase = 7,
    #[pyo3(name = "FIDO_USER_VERIFICATION_AND_PASSPHRASE")]
    FidoUserVerificationAndPassphrase = 8,
    #[pyo3(name = "FIDO_PRESENCE_AND_LOCAL_SECRET")]
    FidoPresenceAndLocalSecret = 9,
}

/// the authenticator requirement within a fido policy.
#[pyclass(
    name = "FidoPolicy",
    eq,
    hash,
    frozen,
    skip_from_py_object,
    module = "fido_key_wrap._native"
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FidoPolicy {
    #[pyo3(name = "PRESENCE")]
    Presence = 1,
    #[pyo3(name = "USER_VERIFICATION")]
    UserVerification = 2,
}

impl From<core::FidoPolicy> for FidoPolicy {
    fn from(value: core::FidoPolicy) -> Self {
        match value {
            core::FidoPolicy::Presence => Self::Presence,
            core::FidoPolicy::UserVerification => Self::UserVerification,
        }
    }
}

impl Policy {
    pub const fn from_core(value: core::RecipientPolicy) -> Self {
        match value {
            core::RecipientPolicy::Passphrase => Self::Passphrase,
            core::RecipientPolicy::RecoverySecret => Self::RecoverySecret,
            core::RecipientPolicy::Fido(core::FidoPolicy::Presence) => Self::FidoPresence,
            core::RecipientPolicy::Fido(core::FidoPolicy::UserVerification) => {
                Self::FidoUserVerification
            }
            core::RecipientPolicy::ManagedFido(core::FidoPolicy::Presence) => {
                Self::ManagedFidoPresence
            }
            core::RecipientPolicy::ManagedFido(core::FidoPolicy::UserVerification) => {
                Self::ManagedFidoUserVerification
            }
            core::RecipientPolicy::FidoAndPassphrase(core::FidoPolicy::Presence) => {
                Self::FidoPresenceAndPassphrase
            }
            core::RecipientPolicy::FidoAndPassphrase(core::FidoPolicy::UserVerification) => {
                Self::FidoUserVerificationAndPassphrase
            }
            core::RecipientPolicy::FidoPresenceAndLocalSecret => Self::FidoPresenceAndLocalSecret,
        }
    }

    pub const fn uses_passphrase(self) -> bool {
        matches!(
            self,
            Self::Passphrase
                | Self::FidoPresenceAndPassphrase
                | Self::FidoUserVerificationAndPassphrase
        )
    }

    const fn python_name(self) -> &'static str {
        match self {
            Self::Passphrase => "Policy.PASSPHRASE",
            Self::RecoverySecret => "Policy.RECOVERY_SECRET",
            Self::FidoPresence => "Policy.FIDO_PRESENCE",
            Self::FidoUserVerification => "Policy.FIDO_USER_VERIFICATION",
            Self::ManagedFidoPresence => "Policy.MANAGED_FIDO_PRESENCE",
            Self::ManagedFidoUserVerification => "Policy.MANAGED_FIDO_USER_VERIFICATION",
            Self::FidoPresenceAndPassphrase => "Policy.FIDO_PRESENCE_AND_PASSPHRASE",
            Self::FidoUserVerificationAndPassphrase => {
                "Policy.FIDO_USER_VERIFICATION_AND_PASSPHRASE"
            }
            Self::FidoPresenceAndLocalSecret => "Policy.FIDO_PRESENCE_AND_LOCAL_SECRET",
        }
    }
}

/// trusted limits for native security-key operations.
#[pyclass(
    name = "FidoConfig",
    eq,
    frozen,
    from_py_object,
    module = "fido_key_wrap._native"
)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FidoConfig {
    pub core: core::FidoConfig,
}

#[pymethods]
impl FidoConfig {
    /// creates validated operation limits expressed in milliseconds.
    #[new]
    fn new(
        py: Python<'_>,
        operation_timeout_ms: u64,
        selection_timeout_ms: u64,
        max_devices: usize,
    ) -> PyResult<Self> {
        Ok(Self {
            core: core::FidoConfig::new(
                Duration::from_millis(operation_timeout_ms),
                Duration::from_millis(selection_timeout_ms),
                max_devices,
            )
            .map_err(|error| map_error(py, &error))?,
        })
    }

    /// returns the standard native-operation profile.
    #[staticmethod]
    fn standard() -> Self {
        Self {
            core: core::FidoConfig::default(),
        }
    }

    #[getter]
    fn operation_timeout_ms(&self) -> u64 {
        timeout_millis(self.core.operation_timeout())
    }

    #[getter]
    fn selection_timeout_ms(&self) -> u64 {
        timeout_millis(self.core.selection_timeout())
    }

    #[getter]
    fn max_devices(&self) -> usize {
        self.core.max_devices()
    }

    fn __repr__(&self) -> String {
        format!(
            "FidoConfig(operation_timeout_ms={}, selection_timeout_ms={}, max_devices={})",
            self.core.operation_timeout().as_millis(),
            self.core.selection_timeout().as_millis(),
            self.core.max_devices()
        )
    }
}

fn timeout_millis(timeout: Duration) -> u64 {
    u64::try_from(timeout.as_millis()).expect("validated fido timeout fits in u64")
}

/// argon2id parameters stored with a passphrase-bearing recipient.
#[pyclass(
    name = "PassphraseParameters",
    eq,
    frozen,
    from_py_object,
    module = "fido_key_wrap._native"
)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PassphraseParameters {
    pub core: core::PassphraseParameters,
}

#[pymethods]
impl PassphraseParameters {
    /// creates a validated argon2id parameter set.
    #[new]
    fn new(py: Python<'_>, memory_kib: u32, passes: u32, lanes: u8) -> PyResult<Self> {
        Ok(Self {
            core: core::PassphraseParameters::new(memory_kib, passes, lanes)
                .map_err(|error| map_error(py, &error))?,
        })
    }

    /// returns the default profile for modern desktop systems.
    #[staticmethod]
    fn desktop() -> Self {
        Self {
            core: core::PassphraseParameters::DESKTOP,
        }
    }

    #[getter]
    fn memory_kib(&self) -> u32 {
        self.core.memory_kib()
    }

    #[getter]
    fn passes(&self) -> u32 {
        self.core.passes()
    }

    #[getter]
    fn lanes(&self) -> u8 {
        self.core.lanes()
    }

    fn __repr__(&self) -> String {
        format!(
            "PassphraseParameters(memory_kib={}, passes={}, lanes={})",
            self.core.memory_kib(),
            self.core.passes(),
            self.core.lanes()
        )
    }
}

/// resource limits applied before accepting envelope-provided argon2 work.
#[pyclass(
    name = "PassphraseLimits",
    eq,
    frozen,
    from_py_object,
    module = "fido_key_wrap._native"
)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PassphraseLimits {
    pub core: core::PassphraseLimits,
}

#[pymethods]
impl PassphraseLimits {
    /// creates validated argon2 resource limits.
    #[new]
    fn new(py: Python<'_>, max_memory_kib: u32, max_work_kib_passes: u64) -> PyResult<Self> {
        Ok(Self {
            core: core::PassphraseLimits::new(max_memory_kib, max_work_kib_passes)
                .map_err(|error| map_error(py, &error))?,
        })
    }

    /// returns the default limits for desktop applications.
    #[staticmethod]
    fn desktop() -> Self {
        Self {
            core: core::PassphraseLimits::DESKTOP,
        }
    }

    /// returns the largest limits representable by the protocol.
    #[staticmethod]
    fn protocol_max() -> Self {
        Self {
            core: core::PassphraseLimits::PROTOCOL_MAX,
        }
    }

    #[getter]
    fn max_memory_kib(&self) -> u32 {
        self.core.max_memory_kib()
    }

    #[getter]
    fn max_work_kib_passes(&self) -> u64 {
        self.core.max_work_kib_passes()
    }

    /// reports whether this process will accept a parameter set.
    fn accepts(&self, parameters: &PassphraseParameters) -> bool {
        self.core.accepts(parameters.core)
    }

    fn __repr__(&self) -> String {
        format!(
            "PassphraseLimits(max_memory_kib={}, max_work_kib_passes={})",
            self.core.max_memory_kib(),
            self.core.max_work_kib_passes()
        )
    }
}

/// a label, recovery policy, and optional passphrase parameters for enrollment.
#[pyclass(
    name = "Enrollment",
    frozen,
    skip_from_py_object,
    module = "fido_key_wrap._native"
)]
#[derive(Clone)]
pub struct Enrollment {
    pub core: core::Enrollment,
    policy: Policy,
    parameters: Option<PassphraseParameters>,
}

#[pymethods]
impl Enrollment {
    /// creates a validated recipient enrollment request.
    #[new]
    #[pyo3(signature = (label, policy, parameters=None))]
    fn new(
        py: Python<'_>,
        label: String,
        policy: Policy,
        parameters: Option<PassphraseParameters>,
    ) -> PyResult<Self> {
        if matches!(
            policy,
            Policy::RecoverySecret | Policy::FidoPresenceAndLocalSecret
        ) {
            return Err(PyTypeError::new_err(
                "this policy uses dedicated KeyProtector methods",
            ));
        }
        if !policy.uses_passphrase() && parameters.is_some() {
            return Err(PyTypeError::new_err(
                "parameters are only valid for passphrase-bearing policies",
            ));
        }
        let parameters = if policy.uses_passphrase() {
            Some(parameters.unwrap_or_else(PassphraseParameters::desktop))
        } else {
            None
        };
        let core = match (policy, parameters) {
            (Policy::Passphrase, Some(parameters)) => {
                core::Enrollment::passphrase_with_parameters(label, parameters.core)
            }
            (Policy::RecoverySecret | Policy::FidoPresenceAndLocalSecret, _) => {
                unreachable!("handled above")
            }
            (Policy::FidoPresence, None) => {
                core::Enrollment::fido(label, core::FidoPolicy::Presence)
            }
            (Policy::FidoUserVerification, None) => {
                core::Enrollment::fido(label, core::FidoPolicy::UserVerification)
            }
            (Policy::ManagedFidoPresence, None) => {
                core::Enrollment::managed_fido(label, core::FidoPolicy::Presence)
            }
            (Policy::ManagedFidoUserVerification, None) => {
                core::Enrollment::managed_fido(label, core::FidoPolicy::UserVerification)
            }
            (Policy::FidoPresenceAndPassphrase, Some(parameters)) => {
                core::Enrollment::fido_and_passphrase_with_parameters(
                    label,
                    core::FidoPolicy::Presence,
                    parameters.core,
                )
            }
            (Policy::FidoUserVerificationAndPassphrase, Some(parameters)) => {
                core::Enrollment::fido_and_passphrase_with_parameters(
                    label,
                    core::FidoPolicy::UserVerification,
                    parameters.core,
                )
            }
            _ => Err(core::Error::InvalidPassphraseParameters),
        }
        .map_err(|error| map_error(py, &error))?;
        Ok(Self {
            core,
            policy,
            parameters,
        })
    }

    #[getter]
    fn label(&self) -> &str {
        self.core.label()
    }

    #[getter]
    fn policy(&self) -> Policy {
        self.policy
    }

    #[getter]
    fn parameters(&self) -> Option<PassphraseParameters> {
        self.parameters
    }

    fn __repr__(&self) -> String {
        format!(
            "Enrollment(label={:?}, policy={})",
            self.core.label(),
            self.policy.python_name()
        )
    }
}

/// the stable identifier of one envelope recipient.
#[pyclass(
    name = "RecipientId",
    eq,
    hash,
    frozen,
    skip_from_py_object,
    module = "fido_key_wrap._native"
)]
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct RecipientId {
    pub core: core::RecipientId,
}

#[pymethods]
impl RecipientId {
    /// parses a lowercase recipient identifier.
    #[new]
    fn new(py: Python<'_>, value: &str) -> PyResult<Self> {
        Ok(Self {
            core: core::RecipientId::from_str(value).map_err(|error| map_error(py, &error))?,
        })
    }

    fn __str__(&self) -> String {
        self.core.to_string()
    }

    fn __repr__(&self) -> String {
        format!("RecipientId('{}')", self.core)
    }
}

/// public metadata for one envelope recipient.
#[pyclass(
    name = "RecipientSummary",
    frozen,
    skip_from_py_object,
    module = "fido_key_wrap._native"
)]
#[derive(Clone)]
pub struct RecipientSummary {
    #[pyo3(get)]
    pub id: RecipientId,
    #[pyo3(get)]
    pub label: String,
    #[pyo3(get)]
    pub policy: Policy,
    #[pyo3(get)]
    pub passphrase_parameters: Option<PassphraseParameters>,
}

#[pymethods]
impl RecipientSummary {
    fn __repr__(&self) -> String {
        format!(
            "RecipientSummary(id=RecipientId('{}'), label={:?}, policy={})",
            self.id.core,
            self.label,
            self.policy.python_name()
        )
    }
}

/// an immutable encoded set of recovery recipients for one root key.
#[pyclass(
    name = "KeyEnvelope",
    frozen,
    skip_from_py_object,
    module = "fido_key_wrap._native"
)]
#[derive(Clone)]
pub struct KeyEnvelope {
    pub core: core::KeyEnvelope,
}

#[pymethods]
impl KeyEnvelope {
    /// validates and decodes an envelope.
    #[staticmethod]
    fn decode(py: Python<'_>, encoded: &[u8]) -> PyResult<Self> {
        Ok(Self {
            core: core::KeyEnvelope::decode(encoded).map_err(|error| map_error(py, &error))?,
        })
    }

    /// returns the canonical encoded envelope.
    fn encode<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.core.encode())
    }

    #[getter]
    fn application_id(&self) -> &str {
        self.core.application_id().as_str()
    }

    #[getter]
    fn recipients<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        let summaries = self
            .core
            .recipients()
            .into_iter()
            .map(|summary| RecipientSummary {
                id: RecipientId { core: summary.id() },
                label: summary.label().to_owned(),
                policy: Policy::from_core(summary.policy()),
                passphrase_parameters: summary
                    .passphrase_parameters()
                    .map(|core| PassphraseParameters { core }),
            })
            .collect::<Vec<_>>();
        PyTuple::new(py, summaries)
    }

    fn __repr__(&self) -> String {
        format!(
            "KeyEnvelope(application_id={:?}, recipients={})",
            self.core.application_id().as_str(),
            self.core.recipients().len()
        )
    }
}

/// an opaque, zeroizing 256-bit application root key.
#[pyclass(name = "RootKey", frozen, module = "fido_key_wrap._native")]
pub struct RootKey {
    pub core: Arc<core::RootKey>,
}

/// an opaque, zeroizing 256-bit recovery secret.
#[pyclass(name = "RecoverySecret", frozen, module = "fido_key_wrap._native")]
pub struct RecoverySecret {
    pub core: Arc<core::RecoverySecret>,
}

impl RecoverySecret {
    pub fn new(core: core::RecoverySecret) -> Self {
        Self {
            core: Arc::new(core),
        }
    }
}

#[allow(clippy::unused_self)]
#[pymethods]
impl RecoverySecret {
    /// imports a uniformly random 32-byte secret and clears the supplied bytearray.
    #[staticmethod]
    fn from_bytearray(py: Python<'_>, material: &Bound<'_, PyAny>) -> PyResult<Self> {
        let mut bytes = take_secret_bytes(
            py,
            material,
            "recovery secret material must contain 32 bytes",
        )?;
        Ok(Self::new(core::RecoverySecret::import(&mut bytes)))
    }

    /// returns one writable copy for application-defined storage.
    fn export<'py>(&self, py: Python<'py>) -> Bound<'py, PyByteArray> {
        self.core
            .expose(|bytes| PyByteArray::new(py, bytes.as_slice()))
    }

    fn __repr__(&self) -> &'static str {
        "RecoverySecret([REDACTED])"
    }

    fn __copy__(&self) -> PyResult<()> {
        Err(PyTypeError::new_err("recovery secrets cannot be copied"))
    }

    fn __deepcopy__(&self, _memo: &Bound<'_, PyAny>) -> PyResult<()> {
        Err(PyTypeError::new_err("recovery secrets cannot be copied"))
    }

    fn __reduce__(&self) -> PyResult<()> {
        Err(PyTypeError::new_err("recovery secrets cannot be pickled"))
    }

    fn __reduce_ex__(&self, _protocol: i32) -> PyResult<()> {
        Err(PyTypeError::new_err("recovery secrets cannot be pickled"))
    }
}

/// a newly generated recovery route and its separately stored secret.
#[pyclass(
    name = "RecoverySecretRecipient",
    frozen,
    module = "fido_key_wrap._native"
)]
pub struct RecoverySecretRecipient {
    recipient_id: core::RecipientId,
    secret: Arc<core::RecoverySecret>,
}

impl RecoverySecretRecipient {
    pub fn new(core: core::RecoverySecretRecipient) -> Self {
        let recipient_id = core.recipient_id();
        Self {
            recipient_id,
            secret: Arc::new(core.into_secret()),
        }
    }
}

#[allow(clippy::unused_self)]
#[pymethods]
impl RecoverySecretRecipient {
    #[getter]
    fn recipient_id(&self) -> RecipientId {
        RecipientId {
            core: self.recipient_id,
        }
    }

    #[getter]
    fn secret(&self) -> RecoverySecret {
        RecoverySecret {
            core: Arc::clone(&self.secret),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "RecoverySecretRecipient(recipient_id=RecipientId('{}'), secret=[REDACTED])",
            self.recipient_id
        )
    }

    fn __copy__(&self) -> PyResult<()> {
        Err(PyTypeError::new_err(
            "recovery secret recipients cannot be copied",
        ))
    }

    fn __deepcopy__(&self, _memo: &Bound<'_, PyAny>) -> PyResult<()> {
        Err(PyTypeError::new_err(
            "recovery secret recipients cannot be copied",
        ))
    }

    fn __reduce__(&self) -> PyResult<()> {
        Err(PyTypeError::new_err(
            "recovery secret recipients cannot be pickled",
        ))
    }

    fn __reduce_ex__(&self, _protocol: i32) -> PyResult<()> {
        Err(PyTypeError::new_err(
            "recovery secret recipients cannot be pickled",
        ))
    }
}

/// an opaque, zeroizing 256-bit secret held separately by the application.
#[pyclass(name = "LocalSecret", frozen, module = "fido_key_wrap._native")]
pub struct LocalSecret {
    pub core: Arc<core::LocalSecret>,
}

impl LocalSecret {
    pub fn new(core: core::LocalSecret) -> Self {
        Self {
            core: Arc::new(core),
        }
    }
}

#[allow(clippy::unused_self)]
#[pymethods]
impl LocalSecret {
    /// imports a uniformly random 32-byte secret and clears the supplied bytearray.
    #[staticmethod]
    fn from_bytearray(py: Python<'_>, material: &Bound<'_, PyAny>) -> PyResult<Self> {
        let mut bytes =
            take_secret_bytes(py, material, "local secret material must contain 32 bytes")?;
        Ok(Self::new(core::LocalSecret::import(&mut bytes)))
    }

    /// returns one writable copy for application-defined storage.
    fn export<'py>(&self, py: Python<'py>) -> Bound<'py, PyByteArray> {
        self.core
            .expose(|bytes| PyByteArray::new(py, bytes.as_slice()))
    }

    fn __repr__(&self) -> &'static str {
        "LocalSecret([REDACTED])"
    }

    fn __copy__(&self) -> PyResult<()> {
        Err(PyTypeError::new_err("local secrets cannot be copied"))
    }

    fn __deepcopy__(&self, _memo: &Bound<'_, PyAny>) -> PyResult<()> {
        Err(PyTypeError::new_err("local secrets cannot be copied"))
    }

    fn __reduce__(&self) -> PyResult<()> {
        Err(PyTypeError::new_err("local secrets cannot be pickled"))
    }

    fn __reduce_ex__(&self, _protocol: i32) -> PyResult<()> {
        Err(PyTypeError::new_err("local secrets cannot be pickled"))
    }
}

/// a newly generated fido route and its separately stored local secret.
#[pyclass(
    name = "LocalSecretRecipient",
    frozen,
    module = "fido_key_wrap._native"
)]
pub struct LocalSecretRecipient {
    recipient_id: core::RecipientId,
    secret: Arc<core::LocalSecret>,
}

impl LocalSecretRecipient {
    pub fn new(core: core::LocalSecretRecipient) -> Self {
        let recipient_id = core.recipient_id();
        Self {
            recipient_id,
            secret: Arc::new(core.into_secret()),
        }
    }
}

#[allow(clippy::unused_self)]
#[pymethods]
impl LocalSecretRecipient {
    #[getter]
    fn recipient_id(&self) -> RecipientId {
        RecipientId {
            core: self.recipient_id,
        }
    }

    #[getter]
    fn secret(&self) -> LocalSecret {
        LocalSecret {
            core: Arc::clone(&self.secret),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "LocalSecretRecipient(recipient_id=RecipientId('{}'), secret=[REDACTED])",
            self.recipient_id
        )
    }

    fn __copy__(&self) -> PyResult<()> {
        Err(PyTypeError::new_err(
            "local secret recipients cannot be copied",
        ))
    }

    fn __deepcopy__(&self, _memo: &Bound<'_, PyAny>) -> PyResult<()> {
        Err(PyTypeError::new_err(
            "local secret recipients cannot be copied",
        ))
    }

    fn __reduce__(&self) -> PyResult<()> {
        Err(PyTypeError::new_err(
            "local secret recipients cannot be pickled",
        ))
    }

    fn __reduce_ex__(&self, _protocol: i32) -> PyResult<()> {
        Err(PyTypeError::new_err(
            "local secret recipients cannot be pickled",
        ))
    }
}

impl RootKey {
    pub fn new(core: core::RootKey) -> Self {
        Self {
            core: Arc::new(core),
        }
    }
}

#[allow(clippy::unused_self)]
#[pymethods]
impl RootKey {
    /// imports a uniformly random 32-byte root and clears the supplied bytearray.
    #[staticmethod]
    fn from_bytearray(py: Python<'_>, material: &Bound<'_, PyAny>) -> PyResult<Self> {
        let mut bytes = take_secret_bytes(py, material, "root key material must contain 32 bytes")?;
        Ok(Self::new(core::RootKey::import(&mut bytes)))
    }

    /// returns one writable copy of the root for application cryptography.
    fn export<'py>(&self, py: Python<'py>) -> Bound<'py, PyByteArray> {
        self.core
            .expose(|bytes| PyByteArray::new(py, bytes.as_slice()))
    }

    fn __repr__(&self) -> &'static str {
        "RootKey([REDACTED])"
    }

    fn __copy__(&self) -> PyResult<()> {
        Err(PyTypeError::new_err("root keys cannot be copied"))
    }

    fn __deepcopy__(&self, _memo: &Bound<'_, PyAny>) -> PyResult<()> {
        Err(PyTypeError::new_err("root keys cannot be copied"))
    }

    fn __reduce__(&self) -> PyResult<()> {
        Err(PyTypeError::new_err("root keys cannot be pickled"))
    }

    fn __reduce_ex__(&self, _protocol: i32) -> PyResult<()> {
        Err(PyTypeError::new_err("root keys cannot be pickled"))
    }
}

fn take_secret_bytes(
    py: Python<'_>,
    value: &Bound<'_, PyAny>,
    invalid_message: &'static str,
) -> PyResult<Zeroizing<[u8; 32]>> {
    let material = take_exact_bytearray(py, value, 32, || PyTypeError::new_err(invalid_message))?;
    if material.len() != 32 {
        return Err(PyTypeError::new_err(invalid_message));
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&material);
    Ok(bytes)
}

pub fn take_exact_bytearray(
    py: Python<'_>,
    value: &Bound<'_, PyAny>,
    maximum_length: usize,
    too_long: impl FnOnce() -> PyErr,
) -> PyResult<Zeroizing<Vec<u8>>> {
    if !value.is_exact_instance_of::<PyByteArray>() {
        return Err(PyTypeError::new_err(
            "secret input must be an exact bytearray",
        ));
    }
    let bytearray = value.cast::<PyByteArray>()?;
    if bytearray.len() > maximum_length {
        wipe_bytearray(py, bytearray)?;
        return Err(too_long());
    }
    let bytes = Zeroizing::new(bytearray.to_vec());
    wipe_bytearray(py, bytearray)?;
    Ok(bytes)
}

fn wipe_bytearray(py: Python<'_>, value: &Bound<'_, PyByteArray>) -> PyResult<()> {
    const CHUNK_LENGTH: isize = 4_096;
    const ZEROES: [u8; 4_096] = [0; 4_096];

    let length = isize::try_from(value.len()).map_err(|_| {
        pyo3::exceptions::PyOverflowError::new_err("bytearray length exceeds python limits")
    })?;
    if length == 0 {
        return Ok(());
    }
    let chunk_length = length.min(CHUNK_LENGTH);
    let chunk_length_usize = usize::try_from(chunk_length).map_err(|_| {
        pyo3::exceptions::PyOverflowError::new_err("bytearray length exceeds python limits")
    })?;
    let full_chunk = PyBytes::new(py, &ZEROES[..chunk_length_usize]);
    let mut start = 0isize;
    while length - start >= chunk_length {
        let stop = start + chunk_length;
        let slice = pyo3::types::PySlice::new(py, start, stop, 1);
        value.set_item(slice, &full_chunk)?;
        start = stop;
    }
    if start < length {
        let slice = pyo3::types::PySlice::new(py, start, length, 1);
        let remainder = usize::try_from(length - start).map_err(|_| {
            pyo3::exceptions::PyOverflowError::new_err("bytearray length exceeds python limits")
        })?;
        value.set_item(slice, PyBytes::new(py, &ZEROES[..remainder]))?;
    }
    Ok(())
}
