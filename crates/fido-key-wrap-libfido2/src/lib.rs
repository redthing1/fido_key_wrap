//! protocol operations backed by `libfido2`.
//!
//! the api covers capability discovery, authenticator selection,
//! non-discoverable es256 credential enrollment, and verified `hmac-secret`
//! evaluation.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
#[path = "../build_policy.rs"]
mod build_policy;
mod error;
mod ffi;
mod native;

pub use error::{Error, Result};
pub use native::{
    Authenticator, Backend, Capabilities, Config, CredentialProtection, DeviceReport, DeviceStatus,
    Enrollment, EnrollmentRequest, ExactPolicy, Incompatibility, Pin, PreparedSelection,
    PrfRequest,
};
