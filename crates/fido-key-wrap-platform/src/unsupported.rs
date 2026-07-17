use fido_key_wrap::{LocalSecret, RecipientId};

use crate::{NativeLocalSecretStore, Removal, Result, StoreError};

pub(crate) fn create(
    _store: &NativeLocalSecretStore,
    _recipient: RecipientId,
    _secret: &LocalSecret,
) -> Result<()> {
    Err(StoreError::Unsupported)
}

pub(crate) fn load(
    _store: &NativeLocalSecretStore,
    _recipient: RecipientId,
) -> Result<LocalSecret> {
    Err(StoreError::Unsupported)
}

pub(crate) fn remove(_store: &NativeLocalSecretStore, _recipient: RecipientId) -> Result<Removal> {
    Err(StoreError::Unsupported)
}
