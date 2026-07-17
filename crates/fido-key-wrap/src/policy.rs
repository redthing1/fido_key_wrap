use crate::{Error, Result};

pub(crate) const MIN_MEMORY_KIB: u32 = 65_536;
pub(crate) const MAX_MEMORY_KIB: u32 = 262_144;
pub(crate) const MIN_PASSES: u32 = 3;
pub(crate) const MAX_PASSES: u32 = 6;
pub(crate) const MIN_LANES: u8 = 1;
pub(crate) const MAX_LANES: u8 = 4;

const MIN_WORK_KIB_PASSES: u64 = 196_608;
const DESKTOP_WORK_KIB_PASSES: u64 = 786_432;
const MAX_WORK_KIB_PASSES: u64 = 1_572_864;
const MAX_LABEL_BYTES: usize = 64;

/// exact security-key ceremony required by a recipient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FidoPolicy {
    /// require a signed touch without user verification.
    Presence,
    /// require signed user presence and user verification.
    UserVerification,
}

impl FidoPolicy {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Presence => 1,
            Self::UserVerification => 2,
        }
    }

    pub(crate) fn from_code(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Presence),
            2 => Ok(Self::UserVerification),
            _ => Err(Error::InvalidEnvelope),
        }
    }
}

/// factors required by one route to a root key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecipientPolicy {
    /// an application passphrase.
    Passphrase,
    /// one uniformly random recovery secret.
    RecoverySecret,
    /// one exact security-key ceremony.
    Fido(FidoPolicy),
    /// one exact security-key ceremony backed by managed credential storage.
    ManagedFido(FidoPolicy),
    /// one exact security-key ceremony followed by an application passphrase.
    FidoAndPassphrase(FidoPolicy),
    /// security-key presence and a separately stored local secret.
    FidoPresenceAndLocalSecret,
}

impl RecipientPolicy {
    pub(crate) const fn uses_passphrase(self) -> bool {
        matches!(self, Self::Passphrase | Self::FidoAndPassphrase(_))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FidoStorage {
    NonDiscoverable,
    Managed,
}

/// argon2id work recorded for one passphrase-bearing recipient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PassphraseParameters {
    memory_kib: u32,
    passes: u32,
    lanes: u8,
}

impl PassphraseParameters {
    /// default interactive parameters for a modern desktop system.
    pub const DESKTOP: Self = Self {
        memory_kib: MAX_MEMORY_KIB,
        passes: MIN_PASSES,
        lanes: MAX_LANES,
    };

    /// constructs a format-1 argon2id parameter set.
    ///
    /// # errors
    ///
    /// returns [`Error::InvalidPassphraseParameters`] when a value is outside
    /// format 1 or cannot be represented safely on this target.
    pub fn new(memory_kib: u32, passes: u32, lanes: u8) -> Result<Self> {
        validate_parameters(memory_kib, passes, lanes)
            .map_err(|()| Error::InvalidPassphraseParameters)?;
        Ok(Self {
            memory_kib,
            passes,
            lanes,
        })
    }

    /// returns the argon2 memory cost in kibibytes.
    #[must_use]
    pub const fn memory_kib(self) -> u32 {
        self.memory_kib
    }

    /// returns the argon2 pass count.
    #[must_use]
    pub const fn passes(self) -> u32 {
        self.passes
    }

    /// returns the argon2 lane count.
    #[must_use]
    pub const fn lanes(self) -> u8 {
        self.lanes
    }

    pub(crate) fn decode(memory_kib: u32, passes: u32, lanes: u8) -> Result<Self> {
        Self::new(memory_kib, passes, lanes).map_err(|_| Error::InvalidEnvelope)
    }

    pub(crate) const fn work_kib_passes(self) -> u64 {
        self.memory_kib as u64 * self.passes as u64
    }
}

/// local resource ceilings for passphrase derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PassphraseLimits {
    max_memory_kib: u32,
    max_work_kib_passes: u64,
}

impl PassphraseLimits {
    /// admits the named desktop profile and lighter format-1 profiles.
    pub const DESKTOP: Self = Self {
        max_memory_kib: MAX_MEMORY_KIB,
        max_work_kib_passes: DESKTOP_WORK_KIB_PASSES,
    };

    /// admits every passphrase profile allowed by format 1.
    pub const PROTOCOL_MAX: Self = Self {
        max_memory_kib: MAX_MEMORY_KIB,
        max_work_kib_passes: MAX_WORK_KIB_PASSES,
    };

    /// constructs immutable local resource ceilings.
    ///
    /// # errors
    ///
    /// returns [`Error::InvalidPassphraseLimits`] when either ceiling is below
    /// the lightest format-1 profile or above the format maximum.
    pub fn new(max_memory_kib: u32, max_work_kib_passes: u64) -> Result<Self> {
        if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&max_memory_kib)
            || !(MIN_WORK_KIB_PASSES..=MAX_WORK_KIB_PASSES).contains(&max_work_kib_passes)
        {
            return Err(Error::InvalidPassphraseLimits);
        }
        Ok(Self {
            max_memory_kib,
            max_work_kib_passes,
        })
    }

    /// returns the maximum admitted argon2 memory cost in kibibytes.
    #[must_use]
    pub const fn max_memory_kib(self) -> u32 {
        self.max_memory_kib
    }

    /// returns the maximum admitted memory-times-passes work value.
    #[must_use]
    pub const fn max_work_kib_passes(self) -> u64 {
        self.max_work_kib_passes
    }

    /// reports whether this process admits the supplied protocol parameters.
    #[must_use]
    pub const fn accepts(self, parameters: PassphraseParameters) -> bool {
        parameters.memory_kib <= self.max_memory_kib
            && parameters.work_kib_passes() <= self.max_work_kib_passes
    }
}

/// request to add one root-recovery route.
#[derive(Clone, Debug)]
pub struct Enrollment {
    pub(crate) label: String,
    pub(crate) policy: RecipientPolicy,
    pub(crate) parameters: Option<PassphraseParameters>,
}

impl Enrollment {
    /// requests a passphrase route using [`PassphraseParameters::DESKTOP`].
    pub fn passphrase(label: impl Into<String>) -> Result<Self> {
        Self::passphrase_with_parameters(label, PassphraseParameters::DESKTOP)
    }

    /// requests a passphrase route using explicit parameters.
    pub fn passphrase_with_parameters(
        label: impl Into<String>,
        parameters: PassphraseParameters,
    ) -> Result<Self> {
        Self::build(label, RecipientPolicy::Passphrase, Some(parameters))
    }

    /// requests a security-key route.
    pub fn fido(label: impl Into<String>, policy: FidoPolicy) -> Result<Self> {
        Self::build(label, RecipientPolicy::Fido(policy), None)
    }

    /// requests a security-key route whose discoverable credential can later
    /// be retired. recovery uses `policy`; enrollment, verification, and
    /// retirement require pin-backed user verification.
    pub fn managed_fido(label: impl Into<String>, policy: FidoPolicy) -> Result<Self> {
        Self::build(label, RecipientPolicy::ManagedFido(policy), None)
    }

    /// requests a security-key plus passphrase route using the desktop profile.
    pub fn fido_and_passphrase(label: impl Into<String>, policy: FidoPolicy) -> Result<Self> {
        Self::fido_and_passphrase_with_parameters(label, policy, PassphraseParameters::DESKTOP)
    }

    /// requests a security-key plus passphrase route with explicit parameters.
    pub fn fido_and_passphrase_with_parameters(
        label: impl Into<String>,
        policy: FidoPolicy,
        parameters: PassphraseParameters,
    ) -> Result<Self> {
        Self::build(
            label,
            RecipientPolicy::FidoAndPassphrase(policy),
            Some(parameters),
        )
    }

    fn build(
        label: impl Into<String>,
        policy: RecipientPolicy,
        parameters: Option<PassphraseParameters>,
    ) -> Result<Self> {
        let label = label.into();
        validate_label(&label).map_err(|()| Error::InvalidLabel)?;
        Ok(Self {
            label,
            policy,
            parameters,
        })
    }

    /// returns the untrusted presentation label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// returns the exact factors requested by this enrollment.
    #[must_use]
    pub const fn policy(&self) -> RecipientPolicy {
        self.policy
    }
}

pub(crate) fn validate_label(label: &str) -> std::result::Result<(), ()> {
    let bytes = label.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_LABEL_BYTES
        || bytes[0] == b' '
        || bytes[bytes.len() - 1] == b' '
        || !bytes.iter().all(|byte| (0x20..=0x7e).contains(byte))
    {
        return Err(());
    }
    Ok(())
}

fn validate_parameters(memory_kib: u32, passes: u32, lanes: u8) -> std::result::Result<(), ()> {
    if !(MIN_LANES..=MAX_LANES).contains(&lanes)
        || !(MIN_PASSES..=MAX_PASSES).contains(&passes)
        || !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&memory_kib)
    {
        return Err(());
    }
    let lanes = u32::from(lanes);
    if memory_kib < 8 * lanes || memory_kib % (4 * lanes) != 0 {
        return Err(());
    }
    let _work = u64::from(memory_kib)
        .checked_mul(u64::from(passes))
        .ok_or(())?;
    let bytes = u64::from(memory_kib).checked_mul(1024).ok_or(())?;
    let _block_count = usize::try_from(memory_kib).map_err(|_| ())?;
    let _byte_count = usize::try_from(bytes).map_err(|_| ())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_interactive_enrollments_and_separate_recovery_policy() {
        let policies = [
            Enrollment::passphrase("passphrase").unwrap().policy(),
            Enrollment::fido("presence", FidoPolicy::Presence)
                .unwrap()
                .policy(),
            Enrollment::fido("verified", FidoPolicy::UserVerification)
                .unwrap()
                .policy(),
            Enrollment::managed_fido("managed", FidoPolicy::UserVerification)
                .unwrap()
                .policy(),
            Enrollment::fido_and_passphrase("both", FidoPolicy::Presence)
                .unwrap()
                .policy(),
            Enrollment::fido_and_passphrase("both uv", FidoPolicy::UserVerification)
                .unwrap()
                .policy(),
        ];
        assert_eq!(policies.len(), 6);
        assert!(!policies.contains(&RecipientPolicy::RecoverySecret));
        assert!(!RecipientPolicy::RecoverySecret.uses_passphrase());
        assert!(!policies.contains(&RecipientPolicy::FidoPresenceAndLocalSecret));
        assert!(!RecipientPolicy::FidoPresenceAndLocalSecret.uses_passphrase());
        assert!(policies[0].uses_passphrase());
        assert_eq!(policies[1], RecipientPolicy::Fido(FidoPolicy::Presence));
        assert_eq!(
            policies[3],
            RecipientPolicy::ManagedFido(FidoPolicy::UserVerification)
        );
    }

    #[test]
    fn validates_parameters_and_local_limits_separately() {
        let expensive = PassphraseParameters::new(262_144, 6, 4).unwrap();
        assert!(!PassphraseLimits::DESKTOP.accepts(expensive));
        assert!(PassphraseLimits::PROTOCOL_MAX.accepts(expensive));

        for (memory_kib, passes, lanes) in [
            (MIN_MEMORY_KIB, MIN_PASSES, MIN_LANES),
            (MIN_MEMORY_KIB, MAX_PASSES, MAX_LANES),
            (MAX_MEMORY_KIB, MIN_PASSES, MIN_LANES),
            (MAX_MEMORY_KIB, MAX_PASSES, MAX_LANES),
            (65_544, MIN_PASSES, 3),
        ] {
            assert!(
                PassphraseParameters::new(memory_kib, passes, lanes).is_ok(),
                "{memory_kib}, {passes}, {lanes}"
            );
        }

        for (memory_kib, passes, lanes) in [
            (MIN_MEMORY_KIB - 1, MIN_PASSES, MIN_LANES),
            (MAX_MEMORY_KIB + 1, MIN_PASSES, MIN_LANES),
            (MIN_MEMORY_KIB, MIN_PASSES - 1, MIN_LANES),
            (MIN_MEMORY_KIB, MAX_PASSES + 1, MIN_LANES),
            (MIN_MEMORY_KIB, MIN_PASSES, MIN_LANES - 1),
            (MIN_MEMORY_KIB, MIN_PASSES, MAX_LANES + 1),
            (MIN_MEMORY_KIB + 1, MIN_PASSES, MIN_LANES),
            (MIN_MEMORY_KIB + 4, MIN_PASSES, 3),
        ] {
            assert!(
                PassphraseParameters::new(memory_kib, passes, lanes).is_err(),
                "{memory_kib}, {passes}, {lanes}"
            );
        }

        let minimum = PassphraseLimits::new(MIN_MEMORY_KIB, MIN_WORK_KIB_PASSES).unwrap();
        let maximum = PassphraseLimits::new(MAX_MEMORY_KIB, MAX_WORK_KIB_PASSES).unwrap();
        assert!(minimum.accepts(PassphraseParameters::new(65_536, 3, 1).unwrap()));
        assert!(maximum.accepts(expensive));
        assert!(PassphraseLimits::new(MIN_MEMORY_KIB - 1, MIN_WORK_KIB_PASSES).is_err());
        assert!(PassphraseLimits::new(MAX_MEMORY_KIB + 1, MAX_WORK_KIB_PASSES).is_err());
        assert!(PassphraseLimits::new(MIN_MEMORY_KIB, MIN_WORK_KIB_PASSES - 1).is_err());
        assert!(PassphraseLimits::new(MAX_MEMORY_KIB, MAX_WORK_KIB_PASSES + 1).is_err());
    }

    #[test]
    fn labels_are_small_printable_ascii() {
        assert!(Enrollment::passphrase("primary key").is_ok());
        assert!(Enrollment::passphrase(" primary").is_err());
        assert!(Enrollment::passphrase("primary ").is_err());
        assert!(Enrollment::passphrase("line\nbreak").is_err());
        assert!(Enrollment::passphrase("é").is_err());
        assert!(Enrollment::passphrase("x".repeat(65)).is_err());
    }
}
