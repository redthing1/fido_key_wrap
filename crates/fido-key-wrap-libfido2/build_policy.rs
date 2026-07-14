pub const LIBFIDO2_MIN_VERSION: &str = "1.14.0";
pub const LIBFIDO2_NEXT_MAJOR: &str = "2.0.0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    UnsupportedTarget,
}

pub fn validate_target(target: &str) -> Result<(), Error> {
    if !matches!(target, "linux" | "macos") {
        return Err(Error::UnsupportedTarget);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_the_supported_targets() {
        assert_eq!(LIBFIDO2_MIN_VERSION, "1.14.0");
        assert_eq!(LIBFIDO2_NEXT_MAJOR, "2.0.0");
        assert_eq!(validate_target("linux"), Ok(()));
        assert_eq!(validate_target("macos"), Ok(()));
        assert_eq!(validate_target("windows"), Err(Error::UnsupportedTarget));
    }
}
