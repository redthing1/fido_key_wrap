//! in-memory local-secret storage for downstream tests.

use std::{collections::HashMap, fmt, sync::Mutex};

use fido_key_wrap::{ApplicationId, LocalSecret, RecipientId};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{LocalSecretStore, Removal, Result, StoreError};

/// process-local implementation with the same create-only semantics.
pub struct MemoryLocalSecretStore {
    application: ApplicationId,
    entries: Mutex<HashMap<RecipientId, Zeroizing<[u8; 32]>>>,
}

impl fmt::Debug for MemoryLocalSecretStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries = self.entries.lock().map(|entries| entries.len()).ok();
        formatter
            .debug_struct("MemoryLocalSecretStore")
            .field("application", &self.application)
            .field("entries", &entries)
            .finish()
    }
}

impl MemoryLocalSecretStore {
    /// creates an empty store for one trusted application identity.
    #[must_use]
    pub fn new(application: ApplicationId) -> Self {
        Self {
            application,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// returns the trusted application identity used by this store.
    #[must_use]
    pub const fn application_id(&self) -> &ApplicationId {
        &self.application
    }
}

impl LocalSecretStore for MemoryLocalSecretStore {
    fn create(&self, recipient: RecipientId, secret: &LocalSecret) -> Result<()> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| StoreError::OperationFailed)?;
        if let Some(existing) = entries.get(&recipient) {
            return secret.expose(|bytes| {
                if bool::from(existing.as_slice().ct_eq(bytes)) {
                    Ok(())
                } else {
                    Err(StoreError::AlreadyExists)
                }
            });
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        secret.expose(|secret| bytes.copy_from_slice(secret));
        entries.insert(recipient, bytes);
        Ok(())
    }

    fn load(&self, recipient: RecipientId) -> Result<LocalSecret> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| StoreError::OperationFailed)?;
        let stored = entries.get(&recipient).ok_or(StoreError::Missing)?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(stored.as_slice());
        Ok(LocalSecret::import(&mut bytes))
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_is_create_only_and_idempotent() {
        let store = MemoryLocalSecretStore::new(ApplicationId::new("vault.example").unwrap());
        let recipient: RecipientId = "12".repeat(32).parse().unwrap();
        let mut first_bytes = [1u8; 32];
        let first = LocalSecret::import(&mut first_bytes);
        let mut second_bytes = [2u8; 32];
        let second = LocalSecret::import(&mut second_bytes);

        assert_eq!(store.load(recipient).unwrap_err(), StoreError::Missing);
        store.create(recipient, &first).unwrap();
        store.create(recipient, &first).unwrap();
        assert_eq!(
            store.create(recipient, &second).unwrap_err(),
            StoreError::AlreadyExists
        );
        let loaded = store.load(recipient).unwrap();
        assert!(loaded.expose(|bytes| bool::from(bytes.ct_eq(&[1u8; 32]))));
        assert_eq!(store.remove(recipient).unwrap(), Removal::Removed);
        assert_eq!(store.remove(recipient).unwrap(), Removal::Absent);
    }

    #[test]
    fn debug_output_never_contains_secret_material() {
        let store = MemoryLocalSecretStore::new(ApplicationId::new("vault.example").unwrap());
        let recipient: RecipientId = "12".repeat(32).parse().unwrap();
        let mut bytes = [0xabu8; 32];
        let secret = LocalSecret::import(&mut bytes);
        store.create(recipient, &secret).unwrap();

        let rendered = format!("{store:?}");
        assert!(!rendered.contains("171"));
        assert!(!rendered.contains(&"ab".repeat(32)));
        assert!(rendered.contains("entries: Some(1)"));
    }
}
