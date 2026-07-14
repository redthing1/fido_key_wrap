pub const LIBFIDO2_VERSION: &str = "1.17.0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnsupportedTarget,
    UnsupportedVersion,
}

pub fn validate(target: &str, version: &str) -> Result<(), Error> {
    if !matches!(target, "linux" | "macos") {
        return Err(Error::UnsupportedTarget);
    }
    if version != LIBFIDO2_VERSION {
        return Err(Error::UnsupportedVersion);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_the_supported_targets_and_exact_version() {
        assert_eq!(LIBFIDO2_VERSION, "1.17.0");
        assert_eq!(validate("linux", LIBFIDO2_VERSION), Ok(()));
        assert_eq!(validate("macos", LIBFIDO2_VERSION), Ok(()));
        assert_eq!(validate("linux", "1.17.1"), Err(Error::UnsupportedVersion));
        assert_eq!(
            validate("windows", LIBFIDO2_VERSION),
            Err(Error::UnsupportedTarget)
        );
        assert_eq!(validate("windows", "1.17.1"), Err(Error::UnsupportedTarget));
    }
}
