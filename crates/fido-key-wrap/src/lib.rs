//! protect one random 32-byte application root with a passphrase, a security
//! key, or both.
//!
//! the crate owns factor-specific wrapping and a strict authenticated key
//! envelope. applications own their data encryption, persistence, trusted
//! application identity, unlocked-session lifetime, and root rotation.
//!
//! # application boundary
//!
//! construct [`ApplicationId`] from trusted configuration. after decoding an
//! envelope, compare its application id and enforce the application's policy
//! allowlist before asking the user for a factor. pass the selected
//! [`RecipientId`] to [`KeyProtector::unlock`]; the library never falls back to
//! another route.
//!
//! the application derives its own data key from the recovered root with a
//! domain unique to that application and format. its authenticated container
//! binds the exact bytes returned by [`KeyEnvelope::encode`] as associated
//! data:
//!
//! ```no_run
//! use fido_key_wrap::{
//!     ApplicationId, Enrollment, Error, Interaction, KeyEnvelope,
//!     KeyProtector, RecipientPolicy,
//! };
//!
//! # fn example(interaction: &mut dyn Interaction) -> fido_key_wrap::Result<()> {
//!     let trusted_id = ApplicationId::new("vault.example")?;
//!     let mut protector = KeyProtector::new(trusted_id.clone());
//!     let enrollment = Enrollment::passphrase("primary")?;
//!     let (_root, envelope, recipient) =
//!         protector.create_root(enrollment, interaction)?;
//!     let envelope_bytes = envelope.encode();
//!
//!     let envelope = KeyEnvelope::decode(&envelope_bytes)?;
//!     if envelope.application_id() != &trusted_id {
//!         return Err(Error::ApplicationMismatch);
//!     }
//!     if envelope
//!         .recipients()
//!         .iter()
//!         .any(|recipient| recipient.policy() != RecipientPolicy::Passphrase)
//!     {
//!         return Err(Error::InvalidEnvelope);
//!     }
//!     let _root = protector.unlock(&envelope, recipient, interaction)?;
//! # Ok(())
//! # }
//! ```
//!
//! # optional security-key support
//!
//! a consuming application can forward the native capability without making
//! it part of passphrase-only builds:
//!
//! ```toml
//! [features]
//! fido = ["fido-key-wrap/fido"]
//!
//! [dependencies]
//! fido-key-wrap = { path = "path/to/fido-key-wrap", default-features = false }
//! ```
//!
//! the application chooses the constructor at compile time. both branches use
//! the same public facade:
//!
//! ```no_run
//! use fido_key_wrap::{ApplicationId, KeyProtector};
//!
//! fn protector(application: ApplicationId) -> KeyProtector {
//!     #[cfg(feature = "fido")]
//!     {
//!         KeyProtector::system(application)
//!     }
//!
//!     #[cfg(not(feature = "fido"))]
//!     {
//!         KeyProtector::new(application)
//!     }
//! }
//! ```
//!
//! with the capability enabled, enrollment selects one exact ceremony:
//!
//! ```no_run
//! # #[cfg(feature = "fido")]
//! # fn example(interaction: &mut dyn fido_key_wrap::Interaction)
//! #     -> fido_key_wrap::Result<()> {
//! use fido_key_wrap::{ApplicationId, Enrollment, FidoPolicy, KeyProtector};
//!
//! let trusted_id = ApplicationId::new("vault.example")?;
//! let mut protector = KeyProtector::system(trusted_id);
//! let enrollment = Enrollment::fido_and_passphrase(
//!     "primary",
//!     FidoPolicy::UserVerification,
//! )?;
//! let (_root, _envelope, _recipient) =
//!     protector.create_root(enrollment, interaction)?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

mod backend;
mod crypto;
#[cfg(feature = "fido")]
mod diagnostic;
mod envelope;
mod error;
mod id;
mod interaction;
mod policy;
mod protector;
mod secret;
mod transcript;

#[cfg(feature = "fido")]
pub use diagnostic::{AuthenticatorIssue, AuthenticatorReport, inspect_authenticators};
pub use envelope::{KeyEnvelope, RecipientSummary};
pub use error::{Error, Result};
pub use id::{ApplicationId, RecipientId};
pub use interaction::{
    FidoCeremony, Interaction, InteractionError, Operation, Passphrase, PassphrasePrompt,
    PassphrasePurpose, Pin, PinPrompt, SelectionPrompt, TouchPrompt,
};
pub use policy::{Enrollment, FidoPolicy, PassphraseLimits, PassphraseParameters, RecipientPolicy};
pub use protector::KeyProtector;
pub use secret::RootKey;
