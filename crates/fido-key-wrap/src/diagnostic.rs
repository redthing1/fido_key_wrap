/// read-only authenticator capability report.
///
/// manufacturer and product strings are presentation hints, never stable
/// identity and never credential selectors. they are untrusted device metadata
/// and must be escaped for the output context.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct AuthenticatorReport {
    pub(crate) manufacturer: Option<String>,
    pub(crate) product: Option<String>,
    pub(crate) available: bool,
    pub(crate) compatible: bool,
    pub(crate) fido2: bool,
    pub(crate) hmac_secret: bool,
    pub(crate) credential_protection: bool,
    pub(crate) es256: bool,
    pub(crate) pin_supported: bool,
    pub(crate) pin_configured: bool,
    pub(crate) always_uv: bool,
    pub(crate) issue: Option<AuthenticatorIssue>,
}

/// reason a discovered authenticator could not be inspected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AuthenticatorIssue {
    /// another process or operation is using the authenticator.
    Busy,
    /// an operation reached its deadline.
    TimedOut,
    /// the device disappeared or operating-system access was denied.
    Inaccessible,
    /// another native failure occurred.
    Backend,
}

impl AuthenticatorReport {
    /// returns the untrusted manufacturer string reported during discovery.
    #[must_use]
    pub fn manufacturer(&self) -> Option<&str> {
        self.manufacturer.as_deref()
    }

    /// returns the untrusted product string reported during discovery.
    #[must_use]
    pub fn product(&self) -> Option<&str> {
        self.product.as_deref()
    }

    /// reports whether the authenticator could be opened and inspected.
    #[must_use]
    pub const fn available(&self) -> bool {
        self.available
    }

    /// reports whether all features required by this crate are available.
    #[must_use]
    pub const fn compatible(&self) -> bool {
        self.compatible
    }

    /// reports whether the authenticator supports fido2.
    #[must_use]
    pub const fn fido2(&self) -> bool {
        self.fido2
    }

    /// reports support for the ctap2 `hmac-secret` extension.
    #[must_use]
    pub const fn hmac_secret(&self) -> bool {
        self.hmac_secret
    }

    /// reports support for the credential-protection extension.
    #[must_use]
    pub const fn credential_protection(&self) -> bool {
        self.credential_protection
    }

    /// reports support for es256 credentials.
    #[must_use]
    pub const fn es256(&self) -> bool {
        self.es256
    }

    /// reports whether the authenticator supports a client pin.
    #[must_use]
    pub const fn pin_supported(&self) -> bool {
        self.pin_supported
    }

    /// reports whether a client pin is configured.
    #[must_use]
    pub const fn pin_configured(&self) -> bool {
        self.pin_configured
    }

    /// reports whether the authenticator forces user verification.
    #[must_use]
    pub const fn always_uv(&self) -> bool {
        self.always_uv
    }

    /// explains why an unavailable device could not be inspected.
    #[must_use]
    pub const fn issue(&self) -> Option<AuthenticatorIssue> {
        self.issue
    }
}
