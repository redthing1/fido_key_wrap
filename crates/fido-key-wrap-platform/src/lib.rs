//! store typed application factors in native user secret stores.
//!
//! this companion crate keeps platform i/o separate from the cryptographic
//! core. applications still publish envelopes and remove recipients in their
//! own durable transaction.

#![warn(missing_docs)]
#![allow(clippy::missing_errors_doc)]

mod error;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
mod macos_user_presence;
#[cfg(feature = "testing")]
pub mod testing;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod unsupported;

use fido_key_wrap::{ApplicationId, LocalSecret, RecipientId, RecoverySecret};
use subtle::ConstantTimeEq;

pub use error::{Result, StoreError};

const SECRET_BYTES: usize = 32;

/// confirmed result of an idempotent removal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Removal {
    /// the exact entry was deleted and is now absent.
    Removed,
    /// the exact entry was already absent.
    Absent,
}

/// exact storage operations for paired-machine local factors.
pub trait LocalSecretStore: Send + Sync {
    /// creates the exact entry without replacing different material.
    ///
    /// retrying with the same recipient and secret is successful.
    fn create(&self, recipient: RecipientId, secret: &LocalSecret) -> Result<()>;

    /// loads one exact local secret.
    fn load(&self, recipient: RecipientId) -> Result<LocalSecret>;

    /// removes one exact entry and confirms that it is absent.
    fn remove(&self, recipient: RecipientId) -> Result<Removal>;
}

/// exact storage operations for generated recovery secrets.
///
/// implementations protect only uniformly random [`RecoverySecret`] values;
/// root keys, passphrases, and arbitrary application secrets are outside this
/// boundary.
pub trait RecoverySecretStore: Send + Sync {
    /// creates the exact entry without replacing different material.
    ///
    /// retrying with the same recipient and secret is successful.
    fn create(&self, recipient: RecipientId, secret: &RecoverySecret) -> Result<()>;

    /// loads one exact recovery secret.
    fn load(&self, recipient: RecipientId) -> Result<RecoverySecret>;

    /// removes one exact entry containing the expected secret and confirms
    /// that it is absent.
    ///
    /// callers normally pass the value returned by [`Self::load`] after using
    /// it to authenticate the selected envelope.
    fn remove(&self, recipient: RecipientId, expected: &RecoverySecret) -> Result<Removal>;
}

/// native local-secret storage bound to one trusted application identity.
#[derive(Debug)]
pub struct NativeLocalSecretStore {
    application: ApplicationId,
    #[cfg(target_os = "macos")]
    kind: macos::StoreKind,
}

impl NativeLocalSecretStore {
    /// uses the native user secret store for the current session.
    ///
    /// on macos this selects the non-synchronizing data-protection keychain and
    /// requires an appropriately signed application. on linux this selects the
    /// default Secret Service collection.
    #[must_use]
    pub const fn new(application: ApplicationId) -> Self {
        Self {
            application,
            #[cfg(target_os = "macos")]
            kind: macos::StoreKind::DataProtection,
        }
    }

    /// uses the default macos login keychain for an unsigned command-line program.
    ///
    /// this backend has the login keychain's access-control and backup behavior;
    /// it is never selected as a fallback from the data-protection keychain.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub const fn macos_login_keychain(application: ApplicationId) -> Self {
        Self {
            application,
            kind: macos::StoreKind::LoginKeychain,
        }
    }

    /// returns the trusted application identity used for every entry.
    #[must_use]
    pub const fn application_id(&self) -> &ApplicationId {
        &self.application
    }
}

impl LocalSecretStore for NativeLocalSecretStore {
    fn create(&self, recipient: RecipientId, secret: &LocalSecret) -> Result<()> {
        platform_create(self, recipient, secret)
    }

    fn load(&self, recipient: RecipientId) -> Result<LocalSecret> {
        platform_load(self, recipient)
    }

    fn remove(&self, recipient: RecipientId) -> Result<Removal> {
        platform_remove(self, recipient)
    }
}

/// recovery-secret storage protected by macos user presence.
///
/// each load requires local user authentication accepted by macos. entries use
/// the non-synchronizing data-protection keychain and never fall back to a file
/// keychain.
#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct MacosUserPresenceStore {
    application: ApplicationId,
}

#[cfg(target_os = "macos")]
impl MacosUserPresenceStore {
    /// creates a store for one trusted application identity.
    #[must_use]
    pub const fn new(application: ApplicationId) -> Self {
        Self { application }
    }

    /// returns the trusted application identity used for every entry.
    #[must_use]
    pub const fn application_id(&self) -> &ApplicationId {
        &self.application
    }
}

#[cfg(target_os = "macos")]
impl RecoverySecretStore for MacosUserPresenceStore {
    fn create(&self, recipient: RecipientId, secret: &RecoverySecret) -> Result<()> {
        macos_user_presence::create(self, recipient, secret)
    }

    fn load(&self, recipient: RecipientId) -> Result<RecoverySecret> {
        macos_user_presence::load(self, recipient)
    }

    fn remove(&self, recipient: RecipientId, expected: &RecoverySecret) -> Result<Removal> {
        macos_user_presence::remove(self, recipient, expected)
    }
}

#[cfg(target_os = "linux")]
use linux::{create as platform_create, load as platform_load, remove as platform_remove};
#[cfg(target_os = "macos")]
use macos::{create as platform_create, load as platform_load, remove as platform_remove};
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use unsupported::{create as platform_create, load as platform_load, remove as platform_remove};

#[cfg(any(test, target_os = "macos"))]
fn service_name(application: &ApplicationId) -> String {
    format!("fido-key-wrap.local-secret:{}", application.as_str())
}

#[cfg(any(test, target_os = "macos"))]
fn recovery_service_name(application: &ApplicationId) -> String {
    format!("fido-key-wrap.recovery-secret:{}", application.as_str())
}

fn recipient_name(recipient: RecipientId) -> String {
    recipient.to_string()
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
fn import_binary(bytes: &[u8]) -> Result<LocalSecret> {
    if bytes.len() != SECRET_BYTES {
        return Err(StoreError::Corrupt);
    }
    let mut exact = [0u8; SECRET_BYTES];
    exact.copy_from_slice(bytes);
    Ok(LocalSecret::import(&mut exact))
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
fn binary_matches(bytes: &[u8], secret: &LocalSecret) -> bool {
    bytes.len() == SECRET_BYTES
        && secret.expose(|expected| bool::from(expected.as_slice().ct_eq(bytes)))
}

#[cfg(any(test, target_os = "macos"))]
fn import_recovery_secret(bytes: &[u8]) -> Result<RecoverySecret> {
    if bytes.len() != SECRET_BYTES {
        return Err(StoreError::Corrupt);
    }
    let mut exact = [0u8; SECRET_BYTES];
    exact.copy_from_slice(bytes);
    Ok(RecoverySecret::import(&mut exact))
}

#[cfg(any(test, target_os = "macos"))]
fn recovery_secret_matches(bytes: &[u8], secret: &RecoverySecret) -> bool {
    bytes.len() == SECRET_BYTES
        && secret.expose(|expected| bool::from(expected.as_slice().ct_eq(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_and_recipient_are_canonical_public_keys() {
        let application = ApplicationId::new("vault.example").unwrap();
        let recipient: RecipientId = "ab".repeat(32).parse().unwrap();
        assert_eq!(
            service_name(&application),
            "fido-key-wrap.local-secret:vault.example"
        );
        assert_eq!(recipient_name(recipient), "ab".repeat(32));
        assert_eq!(
            recovery_service_name(&application),
            "fido-key-wrap.recovery-secret:vault.example"
        );
    }

    #[test]
    fn binary_import_is_exact() {
        let mut source = [0x5au8; SECRET_BYTES];
        let secret = LocalSecret::import(&mut source);
        assert!(binary_matches(&[0x5a; SECRET_BYTES], &secret));

        let binary = import_binary(&[0x5a; SECRET_BYTES]).unwrap();
        assert!(binary_matches(&[0x5a; SECRET_BYTES], &binary));

        assert!(matches!(import_binary(&[0; 31]), Err(StoreError::Corrupt)));

        let mut recovery_source = [0x6bu8; SECRET_BYTES];
        let recovery = RecoverySecret::import(&mut recovery_source);
        assert!(recovery_secret_matches(&[0x6b; SECRET_BYTES], &recovery));
        let imported = import_recovery_secret(&[0x6b; SECRET_BYTES]).unwrap();
        assert!(recovery_secret_matches(&[0x6b; SECRET_BYTES], &imported));
        assert!(matches!(
            import_recovery_secret(&[0; 31]),
            Err(StoreError::Corrupt)
        ));
    }
}
