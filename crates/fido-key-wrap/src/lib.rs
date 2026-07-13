//! protect one random 32-byte application root key with dedicated fido2
//! credentials.
//!
//! raw fido prf output is never exposed. applications own their data format,
//! persistence, and unlocked-session lifetime.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod backend;
mod crypto;
mod diagnostic;
mod envelope;
mod error;
mod id;
mod interaction;
/// recipient-policy constructors.
pub mod policy;
mod protector;
mod secret;
mod transcript;

pub use diagnostic::{AuthenticatorIssue, AuthenticatorReport};
pub use envelope::{KeyEnvelope, RecipientSummary};
pub use error::{Error, Result};
pub use id::{ApplicationId, RecipientId};
pub use interaction::{
    Interaction, InteractionError, Operation, Passphrase, PassphrasePrompt, Pin, PinPrompt,
    SelectionPrompt, TouchPrompt,
};
pub use policy::{Enrollment, RecipientPolicy, TokenPolicy};
pub use protector::KeyProtector;
pub use secret::RootKey;
