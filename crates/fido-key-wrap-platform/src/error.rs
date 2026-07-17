/// result returned by a local-secret store.
pub type Result<T> = std::result::Result<T, StoreError>;

/// bounded failure from native local-secret storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// this target has no native backend.
    #[error("platform local-secret storage is unsupported")]
    Unsupported,
    /// the native store or its user session is unavailable.
    #[error("platform local-secret storage is unavailable")]
    Unavailable,
    /// the native store is locked.
    #[error("platform local-secret storage is locked")]
    Locked,
    /// the process is not permitted to access the entry.
    #[error("platform local-secret storage denied access")]
    AccessDenied,
    /// the user cancelled a native storage prompt.
    #[error("platform local-secret storage was cancelled")]
    Cancelled,
    /// the exact entry already contains different secret material.
    #[error("the local-secret entry already exists")]
    AlreadyExists,
    /// the exact entry does not exist.
    #[error("the local-secret entry is missing")]
    Missing,
    /// more than one entry matched the exact public identity.
    #[error("the local-secret entry is ambiguous")]
    Ambiguous,
    /// the stored value is not one canonical local secret.
    #[error("the local-secret entry is corrupt")]
    Corrupt,
    /// a native mutation may have changed the exact entry.
    #[error("the local-secret entry state is uncertain")]
    StateUncertain,
    /// the native operation failed without a safer useful category.
    #[error("platform local-secret storage failed")]
    OperationFailed,
}
