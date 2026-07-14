use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::ptr::{self, NonNull};
use std::rc::Rc;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::ffi;

const HARD_MAX_DEVICES: usize = 32;
const MAX_RP_ID_BYTES: usize = 253;
const MAX_NAME_BYTES: usize = 128;
const MAX_CREDENTIAL_ID_BYTES: usize = 1024;
const ES256_PUBLIC_KEY_BYTES: usize = 64;
const SECRET_BYTES: usize = 32;

/// exact assertion policy. the backend never falls back between variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExactPolicy {
    /// require signed `UP=1, UV=0, BE=0, BS=0` and pass no pin to libfido2.
    Presence,
    /// require signed `UP=1, UV=1, BE=0, BS=0` and pass the supplied pin once.
    UserVerified,
}

/// the credential-protection level enforced during enrollment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialProtection {
    /// ctap `userVerificationOptionalWithCredentialID` (level 2).
    OptionalWithCredentialId,
    /// ctap `userVerificationRequired` (level 3).
    UserVerificationRequired,
}

impl ExactPolicy {
    fn protection(self) -> CredentialProtection {
        match self {
            Self::Presence => CredentialProtection::OptionalWithCredentialId,
            Self::UserVerified => CredentialProtection::UserVerificationRequired,
        }
    }

    fn native_protection(self) -> i32 {
        match self.protection() {
            CredentialProtection::OptionalWithCredentialId => {
                ffi::FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID
            }
            CredentialProtection::UserVerificationRequired => ffi::FIDO_CRED_PROT_UV_REQUIRED,
        }
    }
}

/// a nul-terminated, zeroizing utf-8 pin.
///
/// the value cannot be cloned and its `Debug` output is redacted. libfido2
/// receives the pointer only for the duration of one synchronous call.
pub struct Pin {
    bytes: Zeroizing<Vec<u8>>,
}

impl Pin {
    /// stores a pin in zeroizing storage.
    ///
    /// # Errors
    ///
    /// returns [`Error::InvalidInput`] for an empty pin, a pin longer than
    /// ctap permits, or an embedded nul byte.
    pub fn new(pin: &str) -> Result<Self> {
        let pin = pin.as_bytes();
        if pin.is_empty() {
            return Err(Error::InvalidInput("PIN must not be empty"));
        }
        if pin.len() > 63 {
            return Err(Error::InvalidInput("PIN exceeds the CTAP byte limit"));
        }
        if pin.contains(&0) {
            return Err(Error::InvalidInput("PIN contains a NUL byte"));
        }

        let mut bytes = Zeroizing::new(Vec::with_capacity(pin.len() + 1));
        bytes.extend_from_slice(pin);
        bytes.push(0);
        Ok(Self { bytes })
    }

    fn as_ptr(&self) -> *const core::ffi::c_char {
        self.bytes.as_ptr().cast()
    }
}

impl std::fmt::Debug for Pin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Pin([REDACTED])")
    }
}

/// finite bounds for native operations and device selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    operation_timeout: Duration,
    selection_timeout: Duration,
    touch_poll_interval: Duration,
    max_devices: usize,
}

impl Config {
    /// creates a validated configuration.
    ///
    /// # Errors
    ///
    /// returns [`Error::InvalidInput`] when a timeout is zero or cannot be
    /// represented by libfido2, or when the device bound is outside `1..=32`.
    pub fn new(
        operation_timeout: Duration,
        selection_timeout: Duration,
        max_devices: usize,
    ) -> Result<Self> {
        validate_milliseconds(operation_timeout, "operation timeout is out of range")?;
        validate_milliseconds(selection_timeout, "selection timeout is out of range")?;
        if !(1..=HARD_MAX_DEVICES).contains(&max_devices) {
            return Err(Error::InvalidInput("device limit must be between 1 and 32"));
        }

        Ok(Self {
            operation_timeout,
            selection_timeout,
            touch_poll_interval: Duration::from_millis(100),
            max_devices,
        })
    }

    fn operation_milliseconds(self) -> i32 {
        i32::try_from(self.operation_timeout.as_millis()).expect("validated timeout")
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            operation_timeout: Duration::from_secs(30),
            selection_timeout: Duration::from_secs(20),
            touch_poll_interval: Duration::from_millis(100),
            max_devices: 16,
        }
    }
}

fn validate_milliseconds(duration: Duration, message: &'static str) -> Result<()> {
    if duration.as_millis() < 1 || duration.as_millis() > i32::MAX as u128 {
        return Err(Error::InvalidInput(message));
    }
    Ok(())
}

/// read-only authenticator capabilities used by the wrapping protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct Capabilities {
    pub fido2: bool,
    pub hmac_secret: bool,
    pub credential_protection: bool,
    pub es256: bool,
    pub client_pin_supported: bool,
    pub client_pin_configured: bool,
    pub internal_uv_supported: bool,
    pub internal_uv_configured: bool,
    pub always_uv: bool,
}

impl Capabilities {
    /// whether this device satisfies the backend's common format-1 requirements.
    #[must_use]
    pub fn compatible(&self) -> bool {
        self.fido2
            && self.hmac_secret
            && self.credential_protection
            && self.es256
            && self.client_pin_supported
            && self.client_pin_configured
    }

    /// whether exact presence-only recipients are possible on this device.
    #[must_use]
    pub fn supports_presence_policy(&self) -> bool {
        self.compatible() && !self.always_uv
    }

    /// whether pin-backed user-verified recipients are possible on this device.
    #[must_use]
    pub fn supports_verified_policy(&self) -> bool {
        self.compatible()
    }

    fn supports_policy(&self, policy: ExactPolicy) -> bool {
        match policy {
            ExactPolicy::Presence => self.supports_presence_policy(),
            ExactPolicy::UserVerified => self.supports_verified_policy(),
        }
    }
}

/// a reason a discovered device cannot implement the wrapping protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Incompatibility {
    NotFido2,
    MissingHmacSecret,
    MissingCredentialProtection,
    MissingEs256,
    MissingClientPin,
    ClientPinNotConfigured,
}

/// read-only inspection result for one discovered device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceStatus {
    Compatible(Capabilities),
    Incompatible {
        capabilities: Capabilities,
        reasons: Vec<Incompatibility>,
    },
    Unavailable(Error),
}

/// ephemeral presentation information from discovery.
///
/// these fields are not stable device identity and must not be
/// persisted as credential selectors. manufacturer and product are untrusted
/// device metadata and must be escaped for the output context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceReport {
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub status: DeviceStatus,
}

/// parameters for dedicated credential enrollment.
#[derive(Clone, Copy)]
pub struct EnrollmentRequest<'a> {
    pub relying_party_id: &'a str,
    pub relying_party_name: &'a str,
    pub policy: ExactPolicy,
}

/// a newly enrolled credential.
#[derive(PartialEq, Eq)]
pub struct Enrollment {
    pub credential_id: Vec<u8>,
    pub es256_public_key: [u8; ES256_PUBLIC_KEY_BYTES],
    pub protection: CredentialProtection,
}

impl std::fmt::Debug for Enrollment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Enrollment")
            .field("credential_id_len", &self.credential_id.len())
            .field("es256_public_key", &"[PUBLIC KEY]")
            .field("protection", &self.protection)
            .finish()
    }
}

/// parameters for one exact, verified `hmac-secret` assertion.
#[derive(Clone, Copy)]
pub struct PrfRequest<'a> {
    pub relying_party_id: &'a str,
    pub credential_id: &'a [u8],
    pub es256_public_key: &'a [u8; ES256_PUBLIC_KEY_BYTES],
    pub salt: &'a [u8; SECRET_BYTES],
    pub policy: ExactPolicy,
}

/// entry point for system-backed operations.
#[derive(Debug, Clone, Copy)]
pub struct Backend {
    config: Config,
}

impl Backend {
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// enumerates and opens devices only long enough to read `GetInfo`.
    ///
    /// this does not request a pin, a touch, or create a credential.
    ///
    /// # Errors
    ///
    /// returns an allocation or sanitized native discovery error. errors for
    /// individual devices are retained in [`DeviceStatus::Unavailable`].
    pub fn doctor(&self) -> Result<Vec<DeviceReport>> {
        initialize_thread();
        let candidates = manifest(self.config.max_devices)?;
        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        Ok(candidates
            .into_iter()
            .map(|candidate| {
                let presentation = candidate.presentation();
                let status = match RawDevice::open(&candidate, self.config) {
                    Ok(mut device) => match device.capabilities() {
                        Ok(capabilities) => status_for_capabilities(capabilities),
                        Err(error) => DeviceStatus::Unavailable(error),
                    },
                    Err(error) => DeviceStatus::Unavailable(error),
                };
                DeviceReport {
                    manufacturer: presentation.manufacturer,
                    product: presentation.product,
                    status,
                }
            })
            .collect())
    }

    /// opens and inspects candidates satisfying one exact assertion policy.
    ///
    /// the returned set remains open so the caller can describe the exact
    /// selection ceremony before starting it.
    ///
    /// # Errors
    ///
    /// returns a discovery, exact-policy compatibility, or transport error.
    pub fn prepare_selection(&self, policy: ExactPolicy) -> Result<PreparedSelection> {
        initialize_thread();
        let candidates = manifest(self.config.max_devices)?;
        if candidates.is_empty() {
            return Err(Error::NoAuthenticators);
        }

        let mut devices = Vec::new();
        let mut first_unavailable = None;
        let mut found_incompatible = false;
        for candidate in candidates {
            let mut device = match RawDevice::open(&candidate, self.config) {
                Ok(device) => device,
                Err(error) => {
                    first_unavailable.get_or_insert(error);
                    continue;
                }
            };
            let capabilities = match device.capabilities() {
                Ok(capabilities) => capabilities,
                Err(error) => {
                    first_unavailable.get_or_insert(error);
                    continue;
                }
            };
            if capabilities.supports_policy(policy) {
                devices.push((device, capabilities));
            } else {
                found_incompatible = true;
            }
        }

        if devices.is_empty() {
            return if found_incompatible {
                Err(Error::NoCompatibleAuthenticators)
            } else {
                Err(first_unavailable.unwrap_or(Error::NoCompatibleAuthenticators))
            };
        }
        Ok(PreparedSelection {
            devices,
            config: self.config,
        })
    }
}

/// open exact-policy candidates prepared for one selection ceremony.
///
/// the candidate count and the consuming [`PreparedSelection::select`] call
/// refer to the same native device handles.
pub struct PreparedSelection {
    devices: Vec<(RawDevice, Capabilities)>,
    config: Config,
}

impl PreparedSelection {
    /// returns the number of exact-policy candidates in this ceremony.
    #[must_use]
    pub fn compatible_authenticators(&self) -> usize {
        self.devices.len()
    }

    /// selects one prepared authenticator, using touch when several remain.
    ///
    /// # Errors
    ///
    /// returns a bounded selection or transport error.
    pub fn select(mut self) -> Result<Authenticator> {
        match self.devices.len() {
            1 => {
                let (device, capabilities) = self.devices.pop().ok_or(Error::Protocol)?;
                Ok(Authenticator::new(device, capabilities))
            }
            _ => select_by_touch(self.devices, self.config),
        }
    }
}

impl Default for Backend {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

/// an open, thread-affine native authenticator.
///
/// this type is `!Send` and `!Sync`; libfido2 device state remains on the
/// thread where it was opened.
pub struct Authenticator {
    device: RawDevice,
    capabilities: Capabilities,
    _thread_affine: PhantomData<Rc<()>>,
}

impl std::fmt::Debug for Authenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Authenticator")
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}

impl Authenticator {
    fn new(device: RawDevice, capabilities: Capabilities) -> Self {
        Self {
            device,
            capabilities,
            _thread_affine: PhantomData,
        }
    }

    #[must_use]
    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    /// enrolls a non-discoverable, non-backup es256 credential using uv and
    /// verifies packed attestation. the high-level caller must immediately
    /// evaluate its final transcript-derived prf salt before persisting the
    /// recipient.
    ///
    /// # Errors
    ///
    /// returns a sanitized validation, capability, pin, transport, timeout,
    /// protocol, or verification error. an incorrect pin is never retried.
    pub fn enroll(&mut self, request: EnrollmentRequest<'_>, pin: &Pin) -> Result<Enrollment> {
        validate_rp_id(request.relying_party_id)?;
        validate_name(request.relying_party_name)?;
        if request.policy == ExactPolicy::Presence && !self.capabilities.supports_presence_policy()
        {
            return Err(Error::Unsupported);
        }
        if !self.capabilities.supports_verified_policy() {
            return Err(Error::Unsupported);
        }

        let rp_id = c_string(
            request.relying_party_id,
            "relying-party ID contains a NUL byte",
        )?;
        let rp_name = c_string(
            request.relying_party_name,
            "relying-party name contains a NUL byte",
        )?;
        let user_name = c_string("fido-key-wrap", "fixed user name is invalid")?;
        let client_data_hash = Zeroizing::new(random_array()?);
        let user_id = Zeroizing::new(random_array()?);
        let mut credential = Credential::new()?;

        credential.call("set client-data hash", |raw| unsafe {
            ffi::fido_cred_set_clientdata_hash(
                raw,
                client_data_hash.as_ptr(),
                client_data_hash.len(),
            )
        })?;
        credential.call("set relying party", |raw| unsafe {
            ffi::fido_cred_set_rp(raw, rp_id.as_ptr(), rp_name.as_ptr())
        })?;
        credential.call("set user", |raw| unsafe {
            ffi::fido_cred_set_user(
                raw,
                user_id.as_ptr(),
                user_id.len(),
                user_name.as_ptr(),
                user_name.as_ptr(),
                ptr::null(),
            )
        })?;
        credential.call("set ES256", |raw| unsafe {
            ffi::fido_cred_set_type(raw, ffi::COSE_ES256)
        })?;
        credential.call("set extensions", |raw| unsafe {
            ffi::fido_cred_set_extensions(
                raw,
                ffi::FIDO_EXT_HMAC_SECRET | ffi::FIDO_EXT_CRED_PROTECT,
            )
        })?;
        credential.call("set credential protection", |raw| unsafe {
            ffi::fido_cred_set_prot(raw, request.policy.native_protection())
        })?;
        credential.call("set non-discoverable credential", |raw| unsafe {
            ffi::fido_cred_set_rk(raw, ffi::FIDO_OPT_FALSE)
        })?;
        credential.call("require user verification", |raw| unsafe {
            ffi::fido_cred_set_uv(raw, ffi::FIDO_OPT_TRUE)
        })?;
        credential.call("set empty exclusion list", |raw| unsafe {
            ffi::fido_cred_empty_exclude_list(raw)
        })?;

        let result = unsafe {
            ffi::fido_dev_make_cred(self.device.as_ptr(), credential.as_ptr(), pin.as_ptr())
        };
        if result != ffi::FIDO_OK {
            return Err(self.device.translate(result, "make credential"));
        }
        drop(client_data_hash);
        drop(user_id);

        credential.verify(request.policy)?;
        let credential_id = credential.copy_id()?;
        let es256_public_key = credential.copy_public_key()?;
        Ok(Enrollment {
            credential_id,
            es256_public_key,
            protection: request.policy.protection(),
        })
    }

    /// evaluates `hmac-secret` only after complete es256 verification and
    /// exact post-verification UP/UV/BE/BS flag checks.
    ///
    /// # Errors
    ///
    /// returns a sanitized validation, policy, pin, transport, timeout,
    /// protocol, or verification error. no secret is returned unless every
    /// assertion check succeeds.
    pub fn evaluate(
        &mut self,
        request: PrfRequest<'_>,
        pin: Option<&Pin>,
    ) -> Result<Zeroizing<[u8; SECRET_BYTES]>> {
        validate_rp_id(request.relying_party_id)?;
        if request.credential_id.is_empty() || request.credential_id.len() > MAX_CREDENTIAL_ID_BYTES
        {
            return Err(Error::InvalidInput("credential ID length is invalid"));
        }
        match (request.policy, pin) {
            (ExactPolicy::Presence, None) | (ExactPolicy::UserVerified, Some(_)) => {}
            (ExactPolicy::Presence, Some(_)) => {
                return Err(Error::InvalidInput(
                    "presence policy must not receive a PIN",
                ));
            }
            (ExactPolicy::UserVerified, None) => return Err(Error::PinRequired),
        }
        if request.policy == ExactPolicy::Presence && self.capabilities.always_uv {
            return Err(Error::Unsupported);
        }

        let rp_id = c_string(
            request.relying_party_id,
            "relying-party ID contains a NUL byte",
        )?;
        let client_data_hash = Zeroizing::new(random_array()?);
        let mut assertion = Assertion::new()?;
        assertion.call("set relying party", |raw| unsafe {
            ffi::fido_assert_set_rp(raw, rp_id.as_ptr())
        })?;
        assertion.call("set client-data hash", |raw| unsafe {
            ffi::fido_assert_set_clientdata_hash(
                raw,
                client_data_hash.as_ptr(),
                client_data_hash.len(),
            )
        })?;
        assertion.call("set allowed credential", |raw| unsafe {
            ffi::fido_assert_allow_cred(
                raw,
                request.credential_id.as_ptr(),
                request.credential_id.len(),
            )
        })?;
        assertion.call("set hmac-secret extension", |raw| unsafe {
            ffi::fido_assert_set_extensions(raw, ffi::FIDO_EXT_HMAC_SECRET)
        })?;
        assertion.call("set hmac-secret salt", |raw| unsafe {
            ffi::fido_assert_set_hmac_salt(raw, request.salt.as_ptr(), request.salt.len())
        })?;
        assertion.call("require user presence", |raw| unsafe {
            ffi::fido_assert_set_up(raw, ffi::FIDO_OPT_TRUE)
        })?;
        assertion.call("set exact user verification", |raw| unsafe {
            ffi::fido_assert_set_uv(
                raw,
                match request.policy {
                    ExactPolicy::Presence => ffi::FIDO_OPT_FALSE,
                    ExactPolicy::UserVerified => ffi::FIDO_OPT_TRUE,
                },
            )
        })?;

        let pin_pointer = pin.map_or(ptr::null(), Pin::as_ptr);
        let result = unsafe {
            ffi::fido_dev_get_assert(self.device.as_ptr(), assertion.as_ptr(), pin_pointer)
        };
        if result != ffi::FIDO_OK {
            return Err(self.device.translate(result, "get assertion"));
        }
        drop(client_data_hash);

        assertion.verified_secret(
            request.credential_id,
            request.es256_public_key,
            request.policy,
        )
    }
}

fn initialize_thread() {
    unsafe { ffi::fido_init(ffi::FIDO_DISABLE_U2F_FALLBACK) };
}

fn random_array() -> Result<[u8; SECRET_BYTES]> {
    let mut bytes = [0_u8; SECRET_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| Error::RandomUnavailable)?;
    Ok(bytes)
}

fn validate_rp_id(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_RP_ID_BYTES {
        return Err(Error::InvalidInput("relying-party ID length is invalid"));
    }
    if value
        .bytes()
        .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(Error::InvalidInput(
            "relying-party ID contains a forbidden byte",
        ));
    }
    Ok(())
}

fn validate_name(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_NAME_BYTES {
        return Err(Error::InvalidInput("relying-party name length is invalid"));
    }
    if value.contains('\0') {
        return Err(Error::InvalidInput(
            "relying-party name contains a NUL byte",
        ));
    }
    Ok(())
}

fn c_string(value: &str, message: &'static str) -> Result<CString> {
    CString::new(value).map_err(|_| Error::InvalidInput(message))
}

struct Candidate {
    path: CString,
    manufacturer: Option<String>,
    product: Option<String>,
}

impl Candidate {
    fn presentation(&self) -> DeviceReportPresentation {
        DeviceReportPresentation {
            manufacturer: self.manufacturer.clone(),
            product: self.product.clone(),
        }
    }
}

struct DeviceReportPresentation {
    manufacturer: Option<String>,
    product: Option<String>,
}

struct DeviceInfoList {
    raw: NonNull<ffi::fido_dev_info_t>,
    slots: usize,
}

impl DeviceInfoList {
    fn new(slots: usize) -> Result<Self> {
        let raw = NonNull::new(unsafe { ffi::fido_dev_info_new(slots) })
            .ok_or(Error::AllocationFailed)?;
        Ok(Self { raw, slots })
    }
}

impl Drop for DeviceInfoList {
    fn drop(&mut self) {
        let mut raw = self.raw.as_ptr();
        unsafe { ffi::fido_dev_info_free(&raw mut raw, self.slots) };
    }
}

fn manifest(max_devices: usize) -> Result<Vec<Candidate>> {
    let list = DeviceInfoList::new(max_devices)?;
    let mut found = 0_usize;
    let status =
        unsafe { ffi::fido_dev_info_manifest(list.raw.as_ptr(), max_devices, &raw mut found) };
    if status != ffi::FIDO_OK {
        return Err(translate_status(status, "manifest devices"));
    }
    if found > max_devices {
        return Err(Error::Protocol);
    }

    let mut candidates = Vec::with_capacity(found);
    for index in 0..found {
        let info = unsafe { ffi::fido_dev_info_ptr(list.raw.as_ptr(), index) };
        let info = NonNull::new(info.cast_mut()).ok_or(Error::Protocol)?;
        let path = unsafe { ffi::fido_dev_info_path(info.as_ptr()) };
        if path.is_null() {
            continue;
        }
        let path = unsafe { CStr::from_ptr(path) }.to_owned();
        let manufacturer = unsafe {
            sanitized_optional_string(ffi::fido_dev_info_manufacturer_string(info.as_ptr()))
        };
        let product =
            unsafe { sanitized_optional_string(ffi::fido_dev_info_product_string(info.as_ptr())) };
        candidates.push(Candidate {
            path,
            manufacturer,
            product,
        });
    }
    Ok(candidates)
}

unsafe fn sanitized_optional_string(pointer: *const core::ffi::c_char) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    let bytes = unsafe { CStr::from_ptr(pointer) }.to_bytes();
    if bytes.is_empty() {
        return None;
    }
    let value: String = String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_NAME_BYTES)])
        .chars()
        .map(|character| {
            if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect();
    Some(value)
}

struct RawDevice {
    raw: NonNull<ffi::fido_dev_t>,
    opened: bool,
    _thread_affine: PhantomData<Rc<()>>,
}

impl RawDevice {
    fn open(candidate: &Candidate, config: Config) -> Result<Self> {
        let raw = NonNull::new(unsafe { ffi::fido_dev_new() }).ok_or(Error::AllocationFailed)?;
        let mut device = Self {
            raw,
            opened: false,
            _thread_affine: PhantomData,
        };
        let status =
            unsafe { ffi::fido_dev_set_timeout(device.as_ptr(), config.operation_milliseconds()) };
        if status != ffi::FIDO_OK {
            return Err(translate_status(status, "set authenticator timeout"));
        }
        let status = unsafe { ffi::fido_dev_open(device.as_ptr(), candidate.path.as_ptr()) };
        if status != ffi::FIDO_OK {
            return Err(translate_open_status(status));
        }
        device.opened = true;
        Ok(device)
    }

    fn as_ptr(&mut self) -> *mut ffi::fido_dev_t {
        self.raw.as_ptr()
    }

    fn capabilities(&mut self) -> Result<Capabilities> {
        let info = CborInfo::new()?;
        let status = unsafe { ffi::fido_dev_get_cbor_info(self.as_ptr(), info.as_ptr()) };
        if status != ffi::FIDO_OK {
            return Err(self.translate(status, "get authenticator info"));
        }

        let extensions = unsafe {
            copy_string_array(
                ffi::fido_cbor_info_extensions_ptr(info.as_ptr()),
                ffi::fido_cbor_info_extensions_len(info.as_ptr()),
            )?
        };
        let versions = unsafe {
            copy_string_array(
                ffi::fido_cbor_info_versions_ptr(info.as_ptr()),
                ffi::fido_cbor_info_versions_len(info.as_ptr()),
            )?
        };
        let always_uv = unsafe { option_value(info.as_ptr(), "alwaysUv")? }.unwrap_or(false);
        let algorithm_count = unsafe { ffi::fido_cbor_info_algorithm_count(info.as_ptr()) };
        if algorithm_count > 64 {
            return Err(Error::Protocol);
        }
        let es256 = (0..algorithm_count).any(|index| unsafe {
            ffi::fido_cbor_info_algorithm_cose(info.as_ptr(), index) == ffi::COSE_ES256
        });

        Ok(Capabilities {
            fido2: unsafe { ffi::fido_dev_is_fido2(self.raw.as_ptr()) }
                && versions.iter().any(|version| version.starts_with("FIDO_2")),
            hmac_secret: extensions
                .iter()
                .any(|extension| extension == "hmac-secret"),
            credential_protection: unsafe { ffi::fido_dev_supports_cred_prot(self.raw.as_ptr()) }
                && extensions
                    .iter()
                    .any(|extension| extension == "credProtect"),
            es256,
            client_pin_supported: unsafe { ffi::fido_dev_supports_pin(self.raw.as_ptr()) },
            client_pin_configured: unsafe { ffi::fido_dev_has_pin(self.raw.as_ptr()) },
            internal_uv_supported: unsafe { ffi::fido_dev_supports_uv(self.raw.as_ptr()) },
            internal_uv_configured: unsafe { ffi::fido_dev_has_uv(self.raw.as_ptr()) },
            always_uv,
        })
    }

    fn translate(&mut self, status: i32, operation: &'static str) -> Error {
        if status == ffi::FIDO_ERR_PIN_INVALID {
            let mut retries = 0_i32;
            let retry_status =
                unsafe { ffi::fido_dev_get_retry_count(self.as_ptr(), &raw mut retries) };
            let retries = (retry_status == ffi::FIDO_OK)
                .then(|| u8::try_from(retries).ok())
                .flatten();
            Error::PinInvalid { retries }
        } else {
            translate_status(status, operation)
        }
    }
}

impl Drop for RawDevice {
    fn drop(&mut self) {
        if self.opened {
            let _ = unsafe { ffi::fido_dev_close(self.raw.as_ptr()) };
        }
        let mut raw = self.raw.as_ptr();
        unsafe { ffi::fido_dev_free(&raw mut raw) };
    }
}

struct CborInfo(NonNull<ffi::fido_cbor_info_t>);

impl CborInfo {
    fn new() -> Result<Self> {
        NonNull::new(unsafe { ffi::fido_cbor_info_new() })
            .map(Self)
            .ok_or(Error::AllocationFailed)
    }

    fn as_ptr(&self) -> *mut ffi::fido_cbor_info_t {
        self.0.as_ptr()
    }
}

impl Drop for CborInfo {
    fn drop(&mut self) {
        let mut raw = self.0.as_ptr();
        unsafe { ffi::fido_cbor_info_free(&raw mut raw) };
    }
}

unsafe fn copy_string_array(
    pointer: *mut *mut core::ffi::c_char,
    len: usize,
) -> Result<Vec<String>> {
    if len > 128 {
        return Err(Error::Protocol);
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    if pointer.is_null() {
        return Err(Error::Protocol);
    }
    let entries = unsafe { std::slice::from_raw_parts(pointer, len) };
    entries
        .iter()
        .map(|entry| {
            if entry.is_null() {
                return Err(Error::Protocol);
            }
            unsafe { CStr::from_ptr(*entry) }
                .to_str()
                .map(str::to_owned)
                .map_err(|_| Error::Protocol)
        })
        .collect()
}

unsafe fn option_value(info: *const ffi::fido_cbor_info_t, wanted: &str) -> Result<Option<bool>> {
    let len = unsafe { ffi::fido_cbor_info_options_len(info) };
    if len > 128 {
        return Err(Error::Protocol);
    }
    if len == 0 {
        return Ok(None);
    }
    let names = unsafe { ffi::fido_cbor_info_options_name_ptr(info) };
    let values = unsafe { ffi::fido_cbor_info_options_value_ptr(info) };
    if names.is_null() || values.is_null() {
        return Err(Error::Protocol);
    }
    let names = unsafe { std::slice::from_raw_parts(names, len) };
    let values = unsafe { std::slice::from_raw_parts(values, len) };
    for (name, value) in names.iter().zip(values) {
        if name.is_null() {
            return Err(Error::Protocol);
        }
        if unsafe { CStr::from_ptr(*name) }.to_bytes() == wanted.as_bytes() {
            return Ok(Some(*value));
        }
    }
    Ok(None)
}

fn status_for_capabilities(capabilities: Capabilities) -> DeviceStatus {
    let reasons = incompatibilities(&capabilities);
    if reasons.is_empty() {
        DeviceStatus::Compatible(capabilities)
    } else {
        DeviceStatus::Incompatible {
            capabilities,
            reasons,
        }
    }
}

fn incompatibilities(capabilities: &Capabilities) -> Vec<Incompatibility> {
    let mut reasons = Vec::new();
    if !capabilities.fido2 {
        reasons.push(Incompatibility::NotFido2);
    }
    if !capabilities.hmac_secret {
        reasons.push(Incompatibility::MissingHmacSecret);
    }
    if !capabilities.credential_protection {
        reasons.push(Incompatibility::MissingCredentialProtection);
    }
    if !capabilities.es256 {
        reasons.push(Incompatibility::MissingEs256);
    }
    if !capabilities.client_pin_supported {
        reasons.push(Incompatibility::MissingClientPin);
    } else if !capabilities.client_pin_configured {
        reasons.push(Incompatibility::ClientPinNotConfigured);
    }
    reasons
}

fn select_by_touch(
    mut devices: Vec<(RawDevice, Capabilities)>,
    config: Config,
) -> Result<Authenticator> {
    let deadline = Instant::now() + config.selection_timeout;
    for (device, _) in &mut devices {
        let milliseconds = selection_milliseconds(deadline)?;
        let status = unsafe { ffi::fido_dev_set_timeout(device.as_ptr(), milliseconds) };
        if status != ffi::FIDO_OK {
            cancel_all(&mut devices);
            return Err(translate_status(status, "set selection timeout"));
        }
        let status = unsafe { ffi::fido_dev_get_touch_begin(device.as_ptr()) };
        if status != ffi::FIDO_OK {
            cancel_all(&mut devices);
            return Err(translate_status(status, "begin touch selection"));
        }
    }

    loop {
        for index in 0..devices.len() {
            let now = Instant::now();
            if now >= deadline {
                cancel_all(&mut devices);
                return Err(Error::SelectionTimedOut);
            }
            let wait = config.touch_poll_interval.min(deadline - now);
            let milliseconds =
                i32::try_from(wait.as_millis().max(1)).expect("bounded poll timeout");
            let mut touched = 0_i32;
            let status = unsafe {
                ffi::fido_dev_get_touch_status(
                    devices[index].0.as_ptr(),
                    &raw mut touched,
                    milliseconds,
                )
            };
            if status != ffi::FIDO_OK {
                cancel_all(&mut devices);
                return Err(translate_status(status, "poll touch selection"));
            }
            if touched == 1 {
                let (mut selected, capabilities) = devices.swap_remove(index);
                cancel_all(&mut devices);
                let status = unsafe {
                    ffi::fido_dev_set_timeout(selected.as_ptr(), config.operation_milliseconds())
                };
                if status != ffi::FIDO_OK {
                    return Err(translate_status(status, "restore operation timeout"));
                }
                return Ok(Authenticator::new(selected, capabilities));
            }
            if touched != 0 {
                cancel_all(&mut devices);
                return Err(Error::Protocol);
            }
        }
    }
}

fn selection_milliseconds(deadline: Instant) -> Result<i32> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(Error::SelectionTimedOut)?;
    i32::try_from(remaining.as_millis().max(1)).map_err(|_| Error::Protocol)
}

fn cancel_all(devices: &mut [(RawDevice, Capabilities)]) {
    for (device, _) in devices {
        let _ = unsafe { ffi::fido_dev_cancel(device.as_ptr()) };
    }
}

struct Credential(NonNull<ffi::fido_cred_t>);

impl Credential {
    fn new() -> Result<Self> {
        NonNull::new(unsafe { ffi::fido_cred_new() })
            .map(Self)
            .ok_or(Error::AllocationFailed)
    }

    fn as_ptr(&mut self) -> *mut ffi::fido_cred_t {
        self.0.as_ptr()
    }

    fn call(
        &mut self,
        operation: &'static str,
        call: impl FnOnce(*mut ffi::fido_cred_t) -> i32,
    ) -> Result<()> {
        let status = call(self.as_ptr());
        if status == ffi::FIDO_OK {
            Ok(())
        } else {
            Err(translate_status(status, operation))
        }
    }

    fn verify(&self, policy: ExactPolicy) -> Result<()> {
        let raw = self.0.as_ptr();
        let format = unsafe { ffi::fido_cred_fmt(raw) };
        if format.is_null() || unsafe { CStr::from_ptr(format) }.to_bytes() != b"packed" {
            return Err(Error::VerificationFailed);
        }
        if unsafe { ffi::fido_cred_type(raw) } != ffi::COSE_ES256
            || unsafe { ffi::fido_cred_prot(raw) } != policy.native_protection()
        {
            return Err(Error::VerificationFailed);
        }

        let status = if unsafe { ffi::fido_cred_x5c_list_count(raw) } == 0 {
            unsafe { ffi::fido_cred_verify_self(raw) }
        } else {
            unsafe { ffi::fido_cred_verify(raw) }
        };
        if status != ffi::FIDO_OK {
            return Err(Error::VerificationFailed);
        }

        // Creation always requires signed UP and UV, and this construction
        // rejects credentials marked backup-eligible or currently backed up.
        // Inspect the flags only after attestation verification succeeds.
        if !flags_match(
            unsafe { ffi::fido_cred_flags(raw) },
            ExactPolicy::UserVerified,
        ) {
            return Err(Error::VerificationFailed);
        }

        Ok(())
    }

    fn copy_id(&self) -> Result<Vec<u8>> {
        let raw = self.0.as_ptr();
        let len = unsafe { ffi::fido_cred_id_len(raw) };
        if len == 0 || len > MAX_CREDENTIAL_ID_BYTES {
            return Err(Error::Protocol);
        }
        let pointer = unsafe { ffi::fido_cred_id_ptr(raw) };
        if pointer.is_null() {
            return Err(Error::Protocol);
        }
        Ok(unsafe { std::slice::from_raw_parts(pointer, len) }.to_vec())
    }

    fn copy_public_key(&self) -> Result<[u8; ES256_PUBLIC_KEY_BYTES]> {
        let raw = self.0.as_ptr();
        if unsafe { ffi::fido_cred_pubkey_len(raw) } != ES256_PUBLIC_KEY_BYTES {
            return Err(Error::Protocol);
        }
        let pointer = unsafe { ffi::fido_cred_pubkey_ptr(raw) };
        if pointer.is_null() {
            return Err(Error::Protocol);
        }
        let mut key = [0_u8; ES256_PUBLIC_KEY_BYTES];
        key.copy_from_slice(unsafe { std::slice::from_raw_parts(pointer, ES256_PUBLIC_KEY_BYTES) });
        Ok(key)
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        let mut raw = self.0.as_ptr();
        unsafe { ffi::fido_cred_free(&raw mut raw) };
    }
}

struct Assertion(NonNull<ffi::fido_assert_t>);

struct Es256PublicKey(NonNull<ffi::es256_pk_t>);

impl Es256PublicKey {
    fn from_bytes(bytes: &[u8; ES256_PUBLIC_KEY_BYTES]) -> Result<Self> {
        let public_key =
            NonNull::new(unsafe { ffi::es256_pk_new() }).ok_or(Error::AllocationFailed)?;
        let value = Self(public_key);
        let status =
            unsafe { ffi::es256_pk_from_ptr(value.0.as_ptr(), bytes.as_ptr().cast(), bytes.len()) };
        if status != ffi::FIDO_OK {
            return Err(Error::VerificationFailed);
        }
        Ok(value)
    }

    fn as_ptr(&self) -> *const ffi::es256_pk_t {
        self.0.as_ptr()
    }
}

impl Drop for Es256PublicKey {
    fn drop(&mut self) {
        let mut raw = self.0.as_ptr();
        unsafe { ffi::es256_pk_free(&raw mut raw) };
    }
}

impl Assertion {
    fn new() -> Result<Self> {
        NonNull::new(unsafe { ffi::fido_assert_new() })
            .map(Self)
            .ok_or(Error::AllocationFailed)
    }

    fn as_ptr(&mut self) -> *mut ffi::fido_assert_t {
        self.0.as_ptr()
    }

    fn call(
        &mut self,
        operation: &'static str,
        call: impl FnOnce(*mut ffi::fido_assert_t) -> i32,
    ) -> Result<()> {
        let status = call(self.as_ptr());
        if status == ffi::FIDO_OK {
            Ok(())
        } else {
            Err(translate_status(status, operation))
        }
    }

    fn verified_secret(
        &self,
        expected_id: &[u8],
        public_key: &[u8; ES256_PUBLIC_KEY_BYTES],
        policy: ExactPolicy,
    ) -> Result<Zeroizing<[u8; SECRET_BYTES]>> {
        let raw = self.0.as_ptr();
        if unsafe { ffi::fido_assert_count(raw) } != 1 {
            return Err(Error::VerificationFailed);
        }

        let public_key = Es256PublicKey::from_bytes(public_key)?;
        let verify_status =
            unsafe { ffi::fido_assert_verify(raw, 0, ffi::COSE_ES256, public_key.as_ptr().cast()) };
        if verify_status != ffi::FIDO_OK {
            return Err(Error::VerificationFailed);
        }

        // libfido2 verifies flags requested as true, but does not prove the
        // absence of UV when false was requested and does not enforce the
        // backup flags. Inspect only after the signature has verified and
        // require the exact policy branch with BE=0 and BS=0.
        if !flags_match(unsafe { ffi::fido_assert_flags(raw, 0) }, policy) {
            return Err(Error::VerificationFailed);
        }
        let id_len = unsafe { ffi::fido_assert_id_len(raw, 0) };
        let id_pointer = unsafe { ffi::fido_assert_id_ptr(raw, 0) };
        if id_len != expected_id.len()
            || id_pointer.is_null()
            || unsafe { std::slice::from_raw_parts(id_pointer, id_len) } != expected_id
        {
            return Err(Error::VerificationFailed);
        }

        // libfido2 1.17 parses the encrypted hmac-secret result from this
        // assertion's raw authenticator data and decrypts it into the same
        // assertion statement. fido_assert_verify above authenticates that raw
        // data. Do not fetch or copy the decrypted result before signature,
        // exact flags, and credential identity have all been verified.
        let secret_len = unsafe { ffi::fido_assert_hmac_secret_len(raw, 0) };
        let secret_pointer = unsafe { ffi::fido_assert_hmac_secret_ptr(raw, 0) };
        let secret_pointer = exact_secret_pointer(secret_pointer, secret_len)?;
        let mut secret = Zeroizing::new([0_u8; SECRET_BYTES]);
        secret.copy_from_slice(unsafe {
            std::slice::from_raw_parts(secret_pointer.as_ptr(), SECRET_BYTES)
        });
        Ok(secret)
    }
}

fn exact_secret_pointer(secret_pointer: *const u8, secret_len: usize) -> Result<NonNull<u8>> {
    if secret_len != SECRET_BYTES {
        return Err(Error::VerificationFailed);
    }
    NonNull::new(secret_pointer.cast_mut()).ok_or(Error::VerificationFailed)
}

impl Drop for Assertion {
    fn drop(&mut self) {
        let mut raw = self.0.as_ptr();
        unsafe { ffi::fido_assert_free(&raw mut raw) };
    }
}

fn flags_match(flags: u8, policy: ExactPolicy) -> bool {
    let up = flags & ffi::AUTHDATA_UP != 0;
    let uv = flags & ffi::AUTHDATA_UV != 0;
    let backup_eligible = flags & ffi::AUTHDATA_BE != 0;
    let backup_state = flags & ffi::AUTHDATA_BS != 0;
    up && uv == (policy == ExactPolicy::UserVerified) && !backup_eligible && !backup_state
}

fn translate_status(status: i32, operation: &'static str) -> Error {
    match status {
        ffi::FIDO_ERR_TIMEOUT
        | ffi::FIDO_ERR_USER_ACTION_TIMEOUT
        | ffi::FIDO_ERR_ACTION_TIMEOUT
        | ffi::FIDO_ERR_RX => Error::TimedOut,
        ffi::FIDO_ERR_CHANNEL_BUSY => Error::Busy,
        ffi::FIDO_ERR_TX => Error::Transport,
        ffi::FIDO_ERR_PIN_INVALID => Error::PinInvalid { retries: None },
        ffi::FIDO_ERR_PIN_BLOCKED => Error::PinBlocked,
        ffi::FIDO_ERR_PIN_AUTH_BLOCKED => Error::PinAuthBlocked,
        ffi::FIDO_ERR_PIN_NOT_SET | ffi::FIDO_ERR_PIN_REQUIRED => Error::PinRequired,
        ffi::FIDO_ERR_OPERATION_DENIED
        | ffi::FIDO_ERR_KEEPALIVE_CANCEL
        | ffi::FIDO_ERR_NOT_ALLOWED
        | ffi::FIDO_ERR_USER_PRESENCE_REQUIRED
        | ffi::FIDO_ERR_UV_BLOCKED
        | ffi::FIDO_ERR_UV_INVALID => Error::UserAction,
        ffi::FIDO_ERR_UNSUPPORTED_EXTENSION
        | ffi::FIDO_ERR_UNSUPPORTED_ALGORITHM
        | ffi::FIDO_ERR_UNSUPPORTED_OPTION => Error::Unsupported,
        ffi::FIDO_ERR_NO_CREDENTIALS => Error::CredentialNotFound,
        ffi::FIDO_ERR_INVALID_SIG => Error::VerificationFailed,
        code => Error::Native { operation, code },
    }
}

fn translate_open_status(status: i32) -> Error {
    if status == ffi::FIDO_ERR_INTERNAL {
        Error::Transport
    } else {
        translate_status(status, "open authenticator")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNED_EXTENSION_CLIENT_DATA_HASH: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const SIGNED_EXTENSION_AUTHDATA: [u8; 84] = [
        0x98, 0x3b, 0x29, 0x53, 0xb3, 0xa8, 0x56, 0x7d, 0x53, 0x9f, 0xd2, 0xbf, 0x8d, 0x8c, 0xf3,
        0x5e, 0xfe, 0xdc, 0x2d, 0x04, 0xf6, 0x7a, 0xc0, 0x86, 0xca, 0x59, 0x48, 0x77, 0x85, 0x72,
        0x2d, 0xf8, 0x81, 0x00, 0x00, 0x00, 0x07, 0xa1, 0x6b, 0x68, 0x6d, 0x61, 0x63, 0x2d, 0x73,
        0x65, 0x63, 0x72, 0x65, 0x74, 0x58, 0x20, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6,
        0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    ];
    const SIGNED_EXTENSION_PUBLIC_KEY: [u8; ES256_PUBLIC_KEY_BYTES] = [
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c,
        0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
        0x37, 0xbf, 0x51, 0xf5,
    ];
    const ALTERED_VALID_PUBLIC_KEY: [u8; ES256_PUBLIC_KEY_BYTES] = [
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96, 0xb0, 0x1c, 0xbd, 0x1c, 0x01, 0xe5, 0x80, 0x65, 0x71, 0x18, 0x14, 0xb5, 0x83,
        0xf0, 0x61, 0xe9, 0xd4, 0x31, 0xcc, 0xa9, 0x94, 0xce, 0xa1, 0x31, 0x34, 0x49, 0xbf, 0x97,
        0xc8, 0x40, 0xae, 0x0a,
    ];
    const SIGNED_EXTENSION_SIGNATURE: [u8; 70] = [
        0x30, 0x44, 0x02, 0x20, 0x0f, 0xab, 0x53, 0x30, 0x2b, 0xa4, 0x6c, 0x61, 0x28, 0x4f, 0xc2,
        0xc1, 0xe0, 0xd8, 0x45, 0xda, 0xff, 0x04, 0xb0, 0x26, 0x8f, 0x37, 0xbc, 0x5d, 0x70, 0xc6,
        0x19, 0xf1, 0x28, 0x18, 0xfe, 0x96, 0x02, 0x20, 0x79, 0xb3, 0x9f, 0x4a, 0x1d, 0x70, 0xd4,
        0x3a, 0x1b, 0x69, 0xba, 0xe3, 0x10, 0x3f, 0xbc, 0x2a, 0x43, 0x11, 0x9d, 0x45, 0x1c, 0xe5,
        0x60, 0xe3, 0xc8, 0x13, 0x50, 0x91, 0xa7, 0x5a, 0xf8, 0x87,
    ];

    fn signed_extension_assertion(
        authdata: &[u8],
        client_data_hash: &[u8; SECRET_BYTES],
    ) -> Assertion {
        let relying_party = CString::new("fixture.example").unwrap();
        let mut assertion = Assertion::new().unwrap();
        assertion
            .call("fixture count", |raw| unsafe {
                ffi::fido_assert_set_count(raw, 1)
            })
            .unwrap();
        assertion
            .call("fixture relying party", |raw| unsafe {
                ffi::fido_assert_set_rp(raw, relying_party.as_ptr())
            })
            .unwrap();
        assertion
            .call("fixture client-data hash", |raw| unsafe {
                ffi::fido_assert_set_clientdata_hash(
                    raw,
                    client_data_hash.as_ptr(),
                    client_data_hash.len(),
                )
            })
            .unwrap();
        assertion
            .call("fixture authdata", |raw| unsafe {
                ffi::fido_assert_set_authdata_raw(raw, 0, authdata.as_ptr(), authdata.len())
            })
            .unwrap();
        assertion
            .call("fixture extensions", |raw| unsafe {
                ffi::fido_assert_set_extensions(raw, ffi::FIDO_EXT_HMAC_SECRET)
            })
            .unwrap();
        assertion
            .call("fixture presence", |raw| unsafe {
                ffi::fido_assert_set_up(raw, ffi::FIDO_OPT_TRUE)
            })
            .unwrap();
        assertion
            .call("fixture signature", |raw| unsafe {
                ffi::fido_assert_set_sig(
                    raw,
                    0,
                    SIGNED_EXTENSION_SIGNATURE.as_ptr(),
                    SIGNED_EXTENSION_SIGNATURE.len(),
                )
            })
            .unwrap();
        assertion
    }

    #[test]
    fn pin_is_redacted_and_validated() {
        let pin = Pin::new("123456").unwrap();
        assert_eq!(format!("{pin:?}"), "Pin([REDACTED])");
        assert!(matches!(
            Pin::new(""),
            Err(Error::InvalidInput("PIN must not be empty"))
        ));
        assert!(matches!(
            Pin::new("a\0b"),
            Err(Error::InvalidInput("PIN contains a NUL byte"))
        ));
    }

    #[test]
    fn exact_flags_distinguish_hidden_prf_branches() {
        assert!(flags_match(ffi::AUTHDATA_UP, ExactPolicy::Presence));
        assert!(!flags_match(
            ffi::AUTHDATA_UP | ffi::AUTHDATA_UV,
            ExactPolicy::Presence
        ));
        assert!(flags_match(
            ffi::AUTHDATA_UP | ffi::AUTHDATA_UV,
            ExactPolicy::UserVerified
        ));
        assert!(!flags_match(ffi::AUTHDATA_UP, ExactPolicy::UserVerified));
        assert!(!flags_match(ffi::AUTHDATA_UV, ExactPolicy::UserVerified));

        for backup_flag in [ffi::AUTHDATA_BE, ffi::AUTHDATA_BS] {
            assert!(!flags_match(
                ffi::AUTHDATA_UP | backup_flag,
                ExactPolicy::Presence
            ));
            assert!(!flags_match(
                ffi::AUTHDATA_UP | ffi::AUTHDATA_UV | backup_flag,
                ExactPolicy::UserVerified
            ));
        }

        assert!(!flags_match(
            ffi::AUTHDATA_UP | ffi::AUTHDATA_BE | ffi::AUTHDATA_BS,
            ExactPolicy::Presence
        ));
    }

    #[test]
    fn hmac_secret_extension_bytes_are_covered_by_the_assertion_signature() {
        initialize_thread();
        let public_key = Es256PublicKey::from_bytes(&SIGNED_EXTENSION_PUBLIC_KEY).unwrap();
        let assertion = signed_extension_assertion(
            &SIGNED_EXTENSION_AUTHDATA,
            &SIGNED_EXTENSION_CLIENT_DATA_HASH,
        );
        assert_eq!(
            unsafe {
                ffi::fido_assert_verify(
                    assertion.0.as_ptr(),
                    0,
                    ffi::COSE_ES256,
                    public_key.as_ptr().cast(),
                )
            },
            ffi::FIDO_OK
        );

        // Flip only the final encrypted hmac-secret byte, retaining the
        // original signature. Verification must reject the altered authdata.
        let mut altered_authdata = SIGNED_EXTENSION_AUTHDATA;
        *altered_authdata.last_mut().unwrap() ^= 1;
        let altered_assertion =
            signed_extension_assertion(&altered_authdata, &SIGNED_EXTENSION_CLIENT_DATA_HASH);
        assert_eq!(
            unsafe {
                ffi::fido_assert_verify(
                    altered_assertion.0.as_ptr(),
                    0,
                    ffi::COSE_ES256,
                    public_key.as_ptr().cast(),
                )
            },
            ffi::FIDO_ERR_INVALID_SIG
        );
    }

    #[test]
    fn signed_assertion_replay_and_altered_valid_public_key_are_rejected() {
        initialize_thread();
        let public_key = Es256PublicKey::from_bytes(&SIGNED_EXTENSION_PUBLIC_KEY).unwrap();
        let mut fresh_challenge = SIGNED_EXTENSION_CLIENT_DATA_HASH;
        fresh_challenge[0] ^= 1;
        let replayed = signed_extension_assertion(&SIGNED_EXTENSION_AUTHDATA, &fresh_challenge);
        assert_eq!(
            unsafe {
                ffi::fido_assert_verify(
                    replayed.0.as_ptr(),
                    0,
                    ffi::COSE_ES256,
                    public_key.as_ptr().cast(),
                )
            },
            ffi::FIDO_ERR_INVALID_SIG
        );

        let altered_public_key = Es256PublicKey::from_bytes(&ALTERED_VALID_PUBLIC_KEY)
            .expect("the negated generator is a valid P-256 public key");
        let assertion = signed_extension_assertion(
            &SIGNED_EXTENSION_AUTHDATA,
            &SIGNED_EXTENSION_CLIENT_DATA_HASH,
        );
        assert_eq!(
            unsafe {
                ffi::fido_assert_verify(
                    assertion.0.as_ptr(),
                    0,
                    ffi::COSE_ES256,
                    altered_public_key.as_ptr().cast(),
                )
            },
            ffi::FIDO_ERR_INVALID_SIG
        );
    }

    #[test]
    fn prf_result_shape_rejects_missing_and_wrong_lengths() {
        let mut secret = [0x5a; SECRET_BYTES];
        for len in [0, SECRET_BYTES - 1, SECRET_BYTES + 1, SECRET_BYTES * 2] {
            assert!(matches!(
                exact_secret_pointer(secret.as_ptr(), len),
                Err(Error::VerificationFailed)
            ));
        }
        assert!(matches!(
            exact_secret_pointer(ptr::null(), SECRET_BYTES),
            Err(Error::VerificationFailed)
        ));
        assert_eq!(
            exact_secret_pointer(secret.as_ptr(), SECRET_BYTES).unwrap(),
            NonNull::from(&mut secret[0])
        );
    }

    #[test]
    fn compatibility_is_strict() {
        let capabilities = Capabilities {
            fido2: true,
            hmac_secret: true,
            credential_protection: true,
            es256: true,
            client_pin_supported: true,
            client_pin_configured: true,
            internal_uv_supported: false,
            internal_uv_configured: false,
            always_uv: false,
        };
        assert!(capabilities.compatible());
        assert!(capabilities.supports_presence_policy());
        assert!(capabilities.supports_policy(ExactPolicy::Presence));
        assert!(capabilities.supports_policy(ExactPolicy::UserVerified));

        let mut always_uv = capabilities.clone();
        always_uv.always_uv = true;
        assert!(!always_uv.supports_policy(ExactPolicy::Presence));
        assert!(always_uv.supports_policy(ExactPolicy::UserVerified));

        let candidates = [&capabilities, &always_uv];
        assert_eq!(
            candidates
                .iter()
                .filter(|candidate| candidate.supports_policy(ExactPolicy::Presence))
                .count(),
            1
        );
        assert_eq!(
            candidates
                .iter()
                .filter(|candidate| candidate.supports_policy(ExactPolicy::UserVerified))
                .count(),
            2
        );

        let mut missing_es256 = capabilities;
        missing_es256.es256 = false;
        assert!(!missing_es256.compatible());
    }

    #[test]
    fn configuration_is_finite_and_bounded() {
        assert!(Config::new(Duration::ZERO, Duration::from_secs(1), 1).is_err());
        assert!(Config::new(Duration::from_nanos(1), Duration::from_secs(1), 1).is_err());
        assert!(Config::new(Duration::from_secs(1), Duration::from_secs(1), 0).is_err());
        assert!(Config::new(Duration::from_secs(1), Duration::from_secs(1), 33).is_err());
        assert!(Config::new(Duration::from_secs(1), Duration::from_secs(1), 32).is_ok());
    }

    #[test]
    fn errors_do_not_include_native_strings_or_secrets() {
        let error = translate_status(ffi::FIDO_ERR_PIN_INVALID, "get assertion");
        assert_eq!(error.to_string(), "the PIN was incorrect");
        assert!(!error.to_string().contains("get assertion"));
    }

    #[test]
    fn device_open_maps_internal_io_failure_without_global_reclassification() {
        assert!(matches!(
            translate_open_status(ffi::FIDO_ERR_INTERNAL),
            Error::Transport
        ));
        assert!(matches!(
            translate_open_status(ffi::FIDO_ERR_RX),
            Error::TimedOut
        ));
        assert!(matches!(
            translate_status(ffi::FIDO_ERR_INTERNAL, "other operation"),
            Error::Native { .. }
        ));
    }

    #[test]
    fn empty_native_string_array_may_have_a_null_pointer() {
        let values = unsafe { copy_string_array(ptr::null_mut(), 0) }.unwrap();
        assert!(values.is_empty());
    }

    #[test]
    fn serialized_es256_key_uses_the_native_opaque_type() {
        initialize_thread();
        let bytes: [u8; ES256_PUBLIC_KEY_BYTES] = [
            0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
            0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
            0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7,
            0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
            0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
        ];
        let public_key = Es256PublicKey::from_bytes(&bytes).unwrap();
        assert!(!public_key.as_ptr().is_null());
    }
}
