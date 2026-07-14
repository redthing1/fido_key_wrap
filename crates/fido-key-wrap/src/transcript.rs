//! byte transcripts for cryptographic domain separation.

use crate::{Error, Result};

const MAX_FIELDS: usize = 32;

pub(crate) fn encode(fields: &[&[u8]]) -> Result<Vec<u8>> {
    if fields.len() > MAX_FIELDS {
        return Err(Error::InvalidEnvelope);
    }
    let capacity = fields
        .iter()
        .try_fold(4usize, |total, field| -> Result<usize> {
            let _ = u32::try_from(field.len()).map_err(|_| Error::InvalidEnvelope)?;
            total
                .checked_add(4)
                .and_then(|value| value.checked_add(field.len()))
                .ok_or(Error::InvalidEnvelope)
        })?;
    let mut output = Vec::with_capacity(capacity);
    let field_count = u32::try_from(fields.len()).map_err(|_| Error::InvalidEnvelope)?;
    output.extend_from_slice(&field_count.to_be_bytes());
    for field in fields {
        let length = u32::try_from(field.len()).expect("validated transcript field length");
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(field);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_is_unambiguous() {
        let first = encode(&[b"ab", b"c"]).unwrap();
        let second = encode(&[b"a", b"bc"]).unwrap();
        assert_ne!(first, second);
        assert_eq!(&first[..4], &2u32.to_be_bytes());
    }
}
