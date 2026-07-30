//! in-memory factor storage for downstream tests.

use std::{collections::HashMap, fmt, sync::Mutex};

use fido_key_wrap::{ApplicationId, LocalSecret, RecipientId, RecoverySecret};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{LocalSecretStore, RecoverySecretStore, Removal, Result, StoreError};

struct MemoryStore {
    application: ApplicationId,
    entries: Mutex<HashMap<RecipientId, Zeroizing<[u8; 32]>>>,
}

impl MemoryStore {
    fn new(application: ApplicationId) -> Self {
        Self {
            application,
            entries: Mutex::new(HashMap::new()),
        }
    }

    const fn application_id(&self) -> &ApplicationId {
        &self.application
    }

    fn create(&self, recipient: RecipientId, secret: &[u8; 32]) -> Result<()> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| StoreError::OperationFailed)?;
        if let Some(existing) = entries.get(&recipient) {
            return if bool::from(existing.as_slice().ct_eq(secret)) {
                Ok(())
            } else {
                Err(StoreError::AlreadyExists)
            };
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(secret);
        entries.insert(recipient, bytes);
        Ok(())
    }

    fn load(&self, recipient: RecipientId) -> Result<Zeroizing<[u8; 32]>> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| StoreError::OperationFailed)?;
        let stored = entries.get(&recipient).ok_or(StoreError::Missing)?;
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(stored.as_slice());
        Ok(bytes)
    }

    fn remove(&self, recipient: RecipientId) -> Result<Removal> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| StoreError::OperationFailed)?;
        Ok(if entries.remove(&recipient).is_some() {
            Removal::Removed
        } else {
            Removal::Absent
        })
    }

    fn debug(&self, name: &str, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries = self.entries.lock().map(|entries| entries.len()).ok();
        formatter
            .debug_struct(name)
            .field("application", &self.application)
            .field("entries", &entries)
            .finish()
    }
}

/// process-local local-secret store with create-only semantics.
pub struct MemoryLocalSecretStore {
    inner: MemoryStore,
}

impl fmt::Debug for MemoryLocalSecretStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.debug("MemoryLocalSecretStore", formatter)
    }
}

impl MemoryLocalSecretStore {
    /// creates an empty store for one trusted application identity.
    #[must_use]
    pub fn new(application: ApplicationId) -> Self {
        Self {
            inner: MemoryStore::new(application),
        }
    }

    /// returns the trusted application identity used by this store.
    #[must_use]
    pub const fn application_id(&self) -> &ApplicationId {
        self.inner.application_id()
    }
}

impl LocalSecretStore for MemoryLocalSecretStore {
    fn create(&self, recipient: RecipientId, secret: &LocalSecret) -> Result<()> {
        secret.expose(|bytes| self.inner.create(recipient, bytes))
    }

    fn load(&self, recipient: RecipientId) -> Result<LocalSecret> {
        let mut bytes = self.inner.load(recipient)?;
        Ok(LocalSecret::import(&mut bytes))
    }

    fn remove(&self, recipient: RecipientId) -> Result<Removal> {
        self.inner.remove(recipient)
    }
}

/// process-local recovery-secret store with create-only semantics.
pub struct MemoryRecoverySecretStore {
    inner: MemoryStore,
}

impl fmt::Debug for MemoryRecoverySecretStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.debug("MemoryRecoverySecretStore", formatter)
    }
}

impl MemoryRecoverySecretStore {
    /// creates an empty store for one trusted application identity.
    #[must_use]
    pub fn new(application: ApplicationId) -> Self {
        Self {
            inner: MemoryStore::new(application),
        }
    }

    /// returns the trusted application identity used by this store.
    #[must_use]
    pub const fn application_id(&self) -> &ApplicationId {
        self.inner.application_id()
    }
}

impl RecoverySecretStore for MemoryRecoverySecretStore {
    fn create(&self, recipient: RecipientId, secret: &RecoverySecret) -> Result<()> {
        secret.expose(|bytes| self.inner.create(recipient, bytes))
    }

    fn load(&self, recipient: RecipientId) -> Result<RecoverySecret> {
        let mut bytes = self.inner.load(recipient)?;
        Ok(RecoverySecret::import(&mut bytes))
    }

    fn remove(&self, recipient: RecipientId, expected: &RecoverySecret) -> Result<Removal> {
        let mut entries = self
            .inner
            .entries
            .lock()
            .map_err(|_| StoreError::OperationFailed)?;
        let Some(stored) = entries.get(&recipient) else {
            return Ok(Removal::Absent);
        };
        let matches = expected.expose(|bytes| bool::from(stored.as_slice().ct_eq(bytes)));
        if !matches {
            return Err(StoreError::AlreadyExists);
        }
        entries.remove(&recipient);
        Ok(Removal::Removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exercise_store<S, Secret>(
        store: &S,
        recipient: RecipientId,
        first: &Secret,
        second: &Secret,
        create: impl Fn(&S, RecipientId, &Secret) -> Result<()>,
        load_matches: impl Fn(&S, RecipientId) -> Result<bool>,
        remove: impl Fn(&S, RecipientId) -> Result<Removal>,
    ) {
        assert_eq!(
            load_matches(store, recipient).unwrap_err(),
            StoreError::Missing
        );
        create(store, recipient, first).unwrap();
        create(store, recipient, first).unwrap();
        assert_eq!(
            create(store, recipient, second).unwrap_err(),
            StoreError::AlreadyExists
        );
        assert!(load_matches(store, recipient).unwrap());
        assert_eq!(remove(store, recipient).unwrap(), Removal::Removed);
        assert_eq!(remove(store, recipient).unwrap(), Removal::Absent);
    }

    #[test]
    fn local_secret_lifecycle_is_create_only_and_idempotent() {
        let store = MemoryLocalSecretStore::new(ApplicationId::new("vault.example").unwrap());
        let recipient: RecipientId = "12".repeat(32).parse().unwrap();
        let mut first_bytes = [1u8; 32];
        let first = LocalSecret::import(&mut first_bytes);
        let mut second_bytes = [2u8; 32];
        let second = LocalSecret::import(&mut second_bytes);

        exercise_store(
            &store,
            recipient,
            &first,
            &second,
            LocalSecretStore::create,
            |store, recipient| {
                store
                    .load(recipient)
                    .map(|secret| secret.expose(|bytes| bool::from(bytes.ct_eq(&[1u8; 32]))))
            },
            LocalSecretStore::remove,
        );
    }

    #[test]
    fn recovery_secret_lifecycle_is_create_only_and_idempotent() {
        let store = MemoryRecoverySecretStore::new(ApplicationId::new("vault.example").unwrap());
        let recipient: RecipientId = "34".repeat(32).parse().unwrap();
        let mut first_bytes = [3u8; 32];
        let first = RecoverySecret::import(&mut first_bytes);
        let mut second_bytes = [4u8; 32];
        let second = RecoverySecret::import(&mut second_bytes);

        exercise_store(
            &store,
            recipient,
            &first,
            &second,
            RecoverySecretStore::create,
            |store, recipient| {
                store
                    .load(recipient)
                    .map(|secret| secret.expose(|bytes| bool::from(bytes.ct_eq(&[3u8; 32]))))
            },
            |store, recipient| RecoverySecretStore::remove(store, recipient, &first),
        );
    }

    #[test]
    fn recovery_secret_removal_requires_expected_material() {
        let store = MemoryRecoverySecretStore::new(ApplicationId::new("vault.example").unwrap());
        let recipient: RecipientId = "56".repeat(32).parse().unwrap();
        let mut expected_bytes = [5u8; 32];
        let expected = RecoverySecret::import(&mut expected_bytes);
        let mut wrong_bytes = [6u8; 32];
        let wrong = RecoverySecret::import(&mut wrong_bytes);

        store.create(recipient, &expected).unwrap();
        assert_eq!(
            store.remove(recipient, &wrong).unwrap_err(),
            StoreError::AlreadyExists
        );
        assert!(store.load(recipient).is_ok());
        assert_eq!(
            store.remove(recipient, &expected).unwrap(),
            Removal::Removed
        );
    }

    #[test]
    fn debug_output_never_contains_secret_material() {
        let store = MemoryRecoverySecretStore::new(ApplicationId::new("vault.example").unwrap());
        let recipient: RecipientId = "12".repeat(32).parse().unwrap();
        let mut bytes = [0xabu8; 32];
        let secret = RecoverySecret::import(&mut bytes);
        store.create(recipient, &secret).unwrap();

        let rendered = format!("{store:?}");
        assert!(!rendered.contains("171"));
        assert!(!rendered.contains(&"ab".repeat(32)));
        assert!(rendered.contains("entries: Some(1)"));
    }
}
