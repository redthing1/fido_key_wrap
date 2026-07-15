//! protocol operations backed by `libfido2`.
//!
//! the api covers capability discovery, authenticator selection,
//! exact es256 credential enrollment, verified `hmac-secret` evaluation, and
//! selective retirement of managed discoverable credentials.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
#[path = "../build_policy.rs"]
mod build_policy;
mod error;
mod ffi;
mod native;

pub use error::{Error, Result};
pub use native::{
    Authenticator, Backend, Capabilities, Config, CredentialProtection, CredentialStorage,
    DeviceReport, DeviceStatus, Enrollment, EnrollmentRequest, ExactPolicy, Incompatibility,
    ManagedCapability, ManagedCredential, Pin, PreparedSelection, PrfRequest,
};
