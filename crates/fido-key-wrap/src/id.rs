use std::{fmt, str::FromStr};

use crate::{Error, Result};

const MAX_APPLICATION_ID_LEN: usize = 253;

/// stable dns-shaped namespace used as the fido relying-party id.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ApplicationId(String);

impl ApplicationId {
    /// validates and constructs a lowercase dns-shaped application namespace.
    ///
    /// # Errors
    ///
    /// returns [`Error::InvalidApplicationId`] unless the value contains at
    /// least two valid lowercase dns labels and is at most 253 bytes.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_APPLICATION_ID_LEN || !value.is_ascii() {
            return Err(Error::InvalidApplicationId);
        }
        let labels = value.split('.');
        let mut count = 0usize;
        for label in labels {
            count += 1;
            if label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                || !label.as_bytes()[0].is_ascii_alphanumeric()
                || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            {
                return Err(Error::InvalidApplicationId);
            }
        }
        if count < 2 {
            return Err(Error::InvalidApplicationId);
        }
        Ok(Self(value))
    }

    /// returns the namespace as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ApplicationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// stable public identity of one fido recipient.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecipientId(pub(crate) [u8; 32]);

impl RecipientId {
    /// returns the raw public identifier.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for RecipientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for RecipientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecipientId({self})")
    }
}

impl FromStr for RecipientId {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        if value.len() != 64 || !value.is_ascii() {
            return Err(Error::InvalidRecipientId);
        }
        let mut bytes = [0u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let hi = decode_hex(pair[0]).ok_or(Error::InvalidRecipientId)?;
            let lo = decode_hex(pair[1]).ok_or(Error::InvalidRecipientId)?;
            bytes[index] = (hi << 4) | lo;
        }
        Ok(Self(bytes))
    }
}

fn decode_hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_id_is_strict_and_canonical() {
        assert!(ApplicationId::new("org.example.vault").is_ok());
        assert!(ApplicationId::new("org.example.research-vault").is_ok());
        assert!(ApplicationId::new("localhost").is_err());
        assert!(ApplicationId::new("Org.example.vault").is_err());
        assert!(ApplicationId::new("org..vault").is_err());
        assert!(ApplicationId::new("org.example._vault").is_err());
    }

    #[test]
    fn recipient_id_round_trips_hex() {
        let id = RecipientId([0xabu8; 32]);
        let text = id.to_string();
        assert_eq!(text.len(), 64);
        assert_eq!(text.parse::<RecipientId>().unwrap(), id);
        assert_eq!(text.to_uppercase().parse::<RecipientId>().unwrap(), id);
    }
}
