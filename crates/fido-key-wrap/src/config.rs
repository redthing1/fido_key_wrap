use std::time::Duration;

use crate::{Error, Result};

const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_SELECTION_TIMEOUT: Duration = Duration::from_secs(20);
const DEFAULT_MAX_DEVICES: usize = 16;
const HARD_MAX_DEVICES: usize = 32;
const NANOS_PER_MILLISECOND: u128 = 1_000_000;

/// trusted, immutable limits for native security-key operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FidoConfig {
    operation_timeout: Duration,
    selection_timeout: Duration,
    max_devices: usize,
}

impl FidoConfig {
    /// constructs validated native-operation limits.
    ///
    /// timeouts must be positive, exact whole milliseconds representable by
    /// libfido2. the device bound must be between one and 32.
    pub fn new(
        operation_timeout: Duration,
        selection_timeout: Duration,
        max_devices: usize,
    ) -> Result<Self> {
        validate_timeout(operation_timeout)?;
        validate_timeout(selection_timeout)?;
        if !(1..=HARD_MAX_DEVICES).contains(&max_devices) {
            return Err(Error::InvalidFidoConfig);
        }
        Ok(Self {
            operation_timeout,
            selection_timeout,
            max_devices,
        })
    }

    /// returns the timeout for one native authenticator operation.
    #[must_use]
    pub const fn operation_timeout(self) -> Duration {
        self.operation_timeout
    }

    /// returns the timeout for touch-based authenticator selection.
    #[must_use]
    pub const fn selection_timeout(self) -> Duration {
        self.selection_timeout
    }

    /// returns the maximum number of endpoints inspected during discovery.
    #[must_use]
    pub const fn max_devices(self) -> usize {
        self.max_devices
    }
}

impl Default for FidoConfig {
    fn default() -> Self {
        Self {
            operation_timeout: DEFAULT_OPERATION_TIMEOUT,
            selection_timeout: DEFAULT_SELECTION_TIMEOUT,
            max_devices: DEFAULT_MAX_DEVICES,
        }
    }
}

fn validate_timeout(timeout: Duration) -> Result<()> {
    let nanoseconds = timeout.as_nanos();
    if nanoseconds < NANOS_PER_MILLISECOND
        || nanoseconds % NANOS_PER_MILLISECOND != 0
        || timeout.as_millis() > i32::MAX as u128
    {
        return Err(Error::InvalidFidoConfig);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_exact_native_boundaries() {
        let maximum = Duration::from_millis(i32::MAX as u64);
        for (operation, selection, devices) in [
            (Duration::from_millis(1), Duration::from_millis(1), 1),
            (maximum, maximum, HARD_MAX_DEVICES),
        ] {
            let config = FidoConfig::new(operation, selection, devices).unwrap();
            assert_eq!(config.operation_timeout(), operation);
            assert_eq!(config.selection_timeout(), selection);
            assert_eq!(config.max_devices(), devices);
        }

        for (operation, selection, devices) in [
            (Duration::ZERO, Duration::from_millis(1), 1),
            (Duration::from_millis(1), Duration::ZERO, 1),
            (Duration::from_micros(1_500), Duration::from_millis(1), 1),
            (Duration::from_millis(1), Duration::from_micros(1_500), 1),
            (maximum + Duration::from_millis(1), maximum, 1),
            (maximum, maximum + Duration::from_millis(1), 1),
            (Duration::from_millis(1), Duration::from_millis(1), 0),
            (
                Duration::from_millis(1),
                Duration::from_millis(1),
                HARD_MAX_DEVICES + 1,
            ),
        ] {
            assert!(FidoConfig::new(operation, selection, devices).is_err());
        }
    }

    #[test]
    fn defaults_match_the_native_operational_profile() {
        let config = FidoConfig::default();
        assert_eq!(config.operation_timeout(), Duration::from_secs(30));
        assert_eq!(config.selection_timeout(), Duration::from_secs(20));
        assert_eq!(config.max_devices(), 16);
    }
}
