use std::io::Cursor;

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead, aead::Payload};
use anyhow::{Context, Result, bail};
use fido_key_wrap::{ApplicationId, RootKey};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"FKD\0";
const FORMAT: u8 = 1;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const MAX_ENVELOPE_BYTES: usize = 65_536;
pub(crate) const MAX_NOTE_BYTES: usize = 1024 * 1024;
const MAX_CONTAINER_BYTES: usize =
    MAGIC.len() + 1 + 4 + MAX_ENVELOPE_BYTES + NONCE_BYTES + 4 + MAX_NOTE_BYTES + TAG_BYTES;

const NOTE_KEY_DOMAIN: &[u8] = b"fkw-demo/format_1/note_encryption_key";
const NOTE_AAD_DOMAIN: &[u8] = b"fkw-demo/format_1/note_aad";

#[derive(Debug)]
pub(crate) struct EncryptedNote {
    nonce: [u8; NONCE_BYTES],
    ciphertext: Vec<u8>,
}

impl EncryptedNote {
    pub(crate) fn encrypt(
        root: &RootKey,
        application_id: &ApplicationId,
        envelope: &[u8],
        plaintext: &[u8],
    ) -> Result<Self> {
        if plaintext.is_empty() || plaintext.len() > MAX_NOTE_BYTES {
            bail!("the note must contain between 1 byte and 1 MiB");
        }
        let mut nonce = [0u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).context("secure randomness is unavailable")?;
        Self::encrypt_with_nonce(root, application_id, envelope, plaintext, nonce)
    }

    fn encrypt_with_nonce(
        root: &RootKey,
        application_id: &ApplicationId,
        envelope: &[u8],
        plaintext: &[u8],
        nonce: [u8; NONCE_BYTES],
    ) -> Result<Self> {
        validate_envelope_len(envelope)?;
        if plaintext.is_empty() || plaintext.len() > MAX_NOTE_BYTES {
            bail!("the note must contain between 1 byte and 1 MiB");
        }
        let key = derive_note_key(root, application_id)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|_| anyhow::anyhow!("failed to initialize note encryption"))?;
        let aad = note_aad(envelope)?;
        let ciphertext = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("failed to encrypt the note"))?;
        Ok(Self { nonce, ciphertext })
    }

    pub(crate) fn decrypt(
        &self,
        root: &RootKey,
        application_id: &ApplicationId,
        envelope: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        validate_envelope_len(envelope)?;
        validate_ciphertext_len(self.ciphertext.len())?;
        let key = derive_note_key(root, application_id)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|_| anyhow::anyhow!("failed to initialize note decryption"))?;
        let aad = note_aad(envelope)?;
        let plaintext = cipher
            .decrypt(
                &Nonce::from(self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("the encrypted note failed authentication"))?;
        if plaintext.is_empty() || plaintext.len() > MAX_NOTE_BYTES {
            bail!("the encrypted note is invalid");
        }
        Ok(Zeroizing::new(plaintext))
    }

    #[must_use]
    pub(crate) const fn nonce(&self) -> [u8; NONCE_BYTES] {
        self.nonce
    }
}

#[derive(Debug)]
pub(crate) struct NoteFile {
    envelope: Vec<u8>,
    note: EncryptedNote,
}

impl NoteFile {
    pub(crate) fn new(envelope: Vec<u8>, note: EncryptedNote) -> Result<Self> {
        validate_envelope_len(&envelope)?;
        validate_ciphertext_len(note.ciphertext.len())?;
        Ok(Self { envelope, note })
    }

    pub(crate) fn decode(input: &[u8]) -> Result<Self> {
        if input.len() > MAX_CONTAINER_BYTES {
            bail!("the encrypted note file is too large");
        }
        let mut cursor = ByteCursor::new(input);
        if cursor.take(MAGIC.len())? != MAGIC || cursor.take_u8()? != FORMAT {
            bail!("this is not a supported fkw note file");
        }
        let envelope_len =
            usize::try_from(cursor.take_u32()?).context("invalid key-envelope length")?;
        validate_length(envelope_len, 1, MAX_ENVELOPE_BYTES)?;
        let envelope = cursor.take(envelope_len)?.to_vec();
        let nonce = cursor
            .take(NONCE_BYTES)?
            .try_into()
            .expect("the cursor returned exactly one nonce");
        let ciphertext_len =
            usize::try_from(cursor.take_u32()?).context("invalid encrypted-note length")?;
        validate_ciphertext_len(ciphertext_len)?;
        let ciphertext = cursor.take(ciphertext_len)?.to_vec();
        if !cursor.is_empty() {
            bail!("the encrypted note has trailing data");
        }
        Ok(Self {
            envelope,
            note: EncryptedNote { nonce, ciphertext },
        })
    }

    #[must_use]
    pub(crate) fn encode(&self) -> Vec<u8> {
        let capacity = MAGIC.len()
            + 1
            + 4
            + self.envelope.len()
            + NONCE_BYTES
            + 4
            + self.note.ciphertext.len();
        let mut output = Vec::with_capacity(capacity);
        output.extend_from_slice(MAGIC);
        output.push(FORMAT);
        output.extend_from_slice(&length_u32(self.envelope.len()).to_be_bytes());
        output.extend_from_slice(&self.envelope);
        output.extend_from_slice(&self.note.nonce);
        output.extend_from_slice(&length_u32(self.note.ciphertext.len()).to_be_bytes());
        output.extend_from_slice(&self.note.ciphertext);
        output
    }

    #[must_use]
    pub(crate) fn envelope_bytes(&self) -> &[u8] {
        &self.envelope
    }

    #[must_use]
    pub(crate) const fn note(&self) -> &EncryptedNote {
        &self.note
    }
}

fn derive_note_key(root: &RootKey, application_id: &ApplicationId) -> Result<Zeroizing<[u8; 32]>> {
    root.expose(|bytes| {
        let (prk, hkdf) = Hkdf::<Sha256>::extract(None, bytes);
        let prk = Zeroizing::new(prk);
        let info = transcript(&[NOTE_KEY_DOMAIN, application_id.as_str().as_bytes()])?;
        let mut key = Zeroizing::new([0u8; 32]);
        hkdf.expand(&info, key.as_mut())
            .map_err(|_| anyhow::anyhow!("failed to derive the note-encryption key"))?;
        drop(hkdf);
        drop(prk);
        Ok(key)
    })
}

fn note_aad(envelope: &[u8]) -> Result<Vec<u8>> {
    transcript(&[NOTE_AAD_DOMAIN, envelope])
}

fn transcript(fields: &[&[u8]]) -> Result<Vec<u8>> {
    let count = u32::try_from(fields.len()).context("too many transcript fields")?;
    let mut length = 4usize;
    for field in fields {
        let _ = u32::try_from(field.len()).context("transcript field is too large")?;
        length = length
            .checked_add(4)
            .and_then(|value| value.checked_add(field.len()))
            .context("transcript is too large")?;
    }
    let mut output = Vec::with_capacity(length);
    output.extend_from_slice(&count.to_be_bytes());
    for field in fields {
        output.extend_from_slice(
            &u32::try_from(field.len())
                .expect("validated transcript field length")
                .to_be_bytes(),
        );
        output.extend_from_slice(field);
    }
    Ok(output)
}

fn validate_envelope_len(envelope: &[u8]) -> Result<()> {
    validate_length(envelope.len(), 1, MAX_ENVELOPE_BYTES)
}

fn validate_ciphertext_len(len: usize) -> Result<()> {
    validate_length(len, TAG_BYTES + 1, MAX_NOTE_BYTES + TAG_BYTES)
}

fn validate_length(len: usize, min: usize, max: usize) -> Result<()> {
    if !(min..=max).contains(&len) {
        bail!("the encrypted note is invalid");
    }
    Ok(())
}

fn length_u32(len: usize) -> u32 {
    u32::try_from(len).expect("validated demo lengths fit in u32")
}

struct ByteCursor<'a> {
    inner: Cursor<&'a [u8]>,
}

impl<'a> ByteCursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            inner: Cursor::new(input),
        }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let position = usize::try_from(self.inner.position()).context("invalid cursor position")?;
        let input = self.inner.get_ref();
        let end = position
            .checked_add(len)
            .context("invalid container length")?;
        let value = input
            .get(position..end)
            .context("the encrypted note file is truncated")?;
        self.inner
            .set_position(u64::try_from(end).expect("bounded container position"));
        Ok(value)
    }

    fn take_u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn take_u32(&mut self) -> Result<u32> {
        let bytes = self
            .take(4)?
            .try_into()
            .expect("the cursor returned exactly four bytes");
        Ok(u32::from_be_bytes(bytes))
    }

    fn is_empty(&self) -> bool {
        usize::try_from(self.inner.position()).ok() == Some(self.inner.get_ref().len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn application() -> ApplicationId {
        ApplicationId::new("demo.fido-key-wrap.example").unwrap()
    }

    #[test]
    fn note_crypto_authenticates_exact_envelope_and_uses_fresh_nonces() {
        let root = RootKey::import([0x42; 32]);
        let first =
            EncryptedNote::encrypt(&root, &application(), b"envelope-a", b"secret note").unwrap();
        let second =
            EncryptedNote::encrypt(&root, &application(), b"envelope-b", b"secret note").unwrap();
        assert_ne!(first.nonce(), second.nonce());
        assert_eq!(
            first
                .decrypt(&root, &application(), b"envelope-a")
                .unwrap()
                .as_slice(),
            b"secret note"
        );
        assert!(first.decrypt(&root, &application(), b"envelope-b").is_err());
        assert!(
            first
                .decrypt(&RootKey::import([0x24; 32]), &application(), b"envelope-a")
                .is_err()
        );
    }

    #[test]
    fn container_is_strict_fkd_nul_format_one() {
        let root = RootKey::import([0x42; 32]);
        let encrypted =
            EncryptedNote::encrypt(&root, &application(), b"opaque envelope", b"note").unwrap();
        let encoded = NoteFile::new(b"opaque envelope".to_vec(), encrypted)
            .unwrap()
            .encode();
        assert_eq!(&encoded[..5], b"FKD\0\x01");
        assert_eq!(NoteFile::decode(&encoded).unwrap().encode(), encoded);
        for end in 0..encoded.len() {
            assert!(NoteFile::decode(&encoded[..end]).is_err());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(NoteFile::decode(&trailing).is_err());
    }

    #[test]
    fn independent_demo_vector_matches_every_application_layer() {
        let vector = include_str!("../../../test-vectors/format-1-demo-container.txt");
        let get = |name: &str| {
            let prefix = format!("{name}=");
            vector
                .lines()
                .find_map(|line| line.strip_prefix(&prefix))
                .unwrap_or_else(|| panic!("missing vector field {name}"))
        };
        let root_bytes: [u8; 32] = decode_hex(get("root_key")).try_into().unwrap();
        let root = RootKey::import(root_bytes);
        let application = ApplicationId::new(get("application_id").to_owned()).unwrap();
        let envelope = decode_hex(get("envelope"));
        let plaintext = decode_hex(get("note_plaintext"));
        let nonce: [u8; 12] = decode_hex(get("note_nonce")).try_into().unwrap();
        let encrypted =
            EncryptedNote::encrypt_with_nonce(&root, &application, &envelope, &plaintext, nonce)
                .unwrap();
        assert_eq!(encrypted.ciphertext, decode_hex(get("note_ciphertext")));
        assert_eq!(
            derive_note_key(&root, &application).unwrap().as_slice(),
            decode_hex(get("note_key"))
        );
        assert_eq!(note_aad(&envelope).unwrap(), decode_hex(get("note_aad")));
        let container = NoteFile::new(envelope, encrypted).unwrap();
        assert_eq!(container.encode(), decode_hex(get("container")));
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }
}
