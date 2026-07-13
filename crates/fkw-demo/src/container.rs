use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use anyhow::{Context, Result, bail};
use fido_key_wrap::{ApplicationId, RootKey};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"FKD1";
const MAX_ENVELOPE_BYTES: usize = 64 * 1024;
const MAX_NOTE_BYTES: usize = 1024 * 1024;
const TAG_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;
const MAX_CONTAINER_BYTES: usize =
    MAGIC.len() + 4 + MAX_ENVELOPE_BYTES + NONCE_BYTES + 4 + MAX_NOTE_BYTES + TAG_BYTES;

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
        if plaintext.len() > MAX_NOTE_BYTES {
            bail!("the note is larger than 1 mib");
        }
        validate_envelope_len(envelope)?;
        let key = derive_note_key(root, application_id)?;
        let mut nonce = [0u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).context("secure randomness is unavailable")?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|_| anyhow::anyhow!("failed to initialize note encryption"))?;
        let aad = note_aad(envelope);
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
        let aad = note_aad(envelope);
        let plaintext = cipher
            .decrypt(
                &Nonce::from(self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("the encrypted note failed authentication"))?;
        if plaintext.len() > MAX_NOTE_BYTES {
            bail!("the encrypted note is invalid");
        }
        Ok(Zeroizing::new(plaintext))
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
        let mut cursor = Cursor::new(input);
        if cursor.take(MAGIC.len())? != MAGIC {
            bail!("this is not an fkw note file");
        }
        let envelope_len = cursor.take_u32()?;
        let envelope_len = usize::try_from(envelope_len).context("invalid key-envelope length")?;
        validate_length(envelope_len, 1, MAX_ENVELOPE_BYTES)?;
        let envelope = cursor.take(envelope_len)?.to_vec();
        let nonce: [u8; NONCE_BYTES] = cursor
            .take(NONCE_BYTES)?
            .try_into()
            .expect("the cursor returned exactly one nonce");
        let ciphertext_len = cursor.take_u32()?;
        let ciphertext_len =
            usize::try_from(ciphertext_len).context("invalid encrypted-note length")?;
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

    pub(crate) fn encode(&self) -> Vec<u8> {
        let capacity =
            MAGIC.len() + 4 + self.envelope.len() + NONCE_BYTES + 4 + self.note.ciphertext.len();
        let mut output = Vec::with_capacity(capacity);
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&length_u32(self.envelope.len()).to_be_bytes());
        output.extend_from_slice(&self.envelope);
        output.extend_from_slice(&self.note.nonce);
        output.extend_from_slice(&length_u32(self.note.ciphertext.len()).to_be_bytes());
        output.extend_from_slice(&self.note.ciphertext);
        output
    }

    pub(crate) fn envelope_bytes(&self) -> &[u8] {
        &self.envelope
    }

    pub(crate) const fn note(&self) -> &EncryptedNote {
        &self.note
    }
}

fn derive_note_key(root: &RootKey, application_id: &ApplicationId) -> Result<Zeroizing<[u8; 32]>> {
    root.expose(|bytes| {
        let hkdf = Hkdf::<Sha256>::new(None, bytes);
        let application = application_id.as_str().as_bytes();
        let mut info = Vec::with_capacity(34 + application.len());
        info.extend_from_slice(b"fkw-demo/note-encryption-key/v1");
        info.extend_from_slice(&length_u32(application.len()).to_be_bytes());
        info.extend_from_slice(application);
        let mut key = Zeroizing::new([0u8; 32]);
        hkdf.expand(&info, key.as_mut())
            .map_err(|_| anyhow::anyhow!("failed to derive the note-encryption key"))?;
        Ok(key)
    })
}

fn note_aad(envelope: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(29 + 4 + envelope.len());
    aad.extend_from_slice(b"fkw-demo/note-encryption/v1");
    aad.extend_from_slice(&length_u32(envelope.len()).to_be_bytes());
    aad.extend_from_slice(envelope);
    aad
}

fn validate_envelope_len(envelope: &[u8]) -> Result<()> {
    validate_length(envelope.len(), 1, MAX_ENVELOPE_BYTES)
}

fn validate_ciphertext_len(len: usize) -> Result<()> {
    validate_length(len, TAG_BYTES, MAX_NOTE_BYTES + TAG_BYTES)
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

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { remaining: input }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let (value, remaining) = self
            .remaining
            .split_at_checked(len)
            .context("the encrypted note file is truncated")?;
        self.remaining = remaining;
        Ok(value)
    }

    fn take_u32(&mut self) -> Result<u32> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .expect("the cursor returned exactly four bytes");
        Ok(u32::from_be_bytes(bytes))
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn application() -> ApplicationId {
        ApplicationId::new("org.example.fkw-demo-test").unwrap()
    }

    #[test]
    fn note_crypto_authenticates_envelope_and_key() {
        let root = RootKey::import([0x42; 32]);
        let note =
            EncryptedNote::encrypt(&root, &application(), b"envelope-a", b"secret note").unwrap();
        assert_eq!(
            note.decrypt(&root, &application(), b"envelope-a")
                .unwrap()
                .as_slice(),
            b"secret note"
        );
        assert!(note.decrypt(&root, &application(), b"envelope-b").is_err());
        assert!(
            note.decrypt(&RootKey::import([0x24; 32]), &application(), b"envelope-a")
                .is_err()
        );

        let mut altered_nonce =
            EncryptedNote::encrypt(&root, &application(), b"envelope-a", b"secret note").unwrap();
        altered_nonce.nonce[0] ^= 1;
        assert!(
            altered_nonce
                .decrypt(&root, &application(), b"envelope-a")
                .is_err()
        );

        let mut altered_ciphertext =
            EncryptedNote::encrypt(&root, &application(), b"envelope-a", b"secret note").unwrap();
        altered_ciphertext.ciphertext[0] ^= 1;
        assert!(
            altered_ciphertext
                .decrypt(&root, &application(), b"envelope-a")
                .is_err()
        );
    }

    #[test]
    fn container_round_trips_exactly() {
        let root = RootKey::import([0x42; 32]);
        let encrypted =
            EncryptedNote::encrypt(&root, &application(), b"opaque envelope", b"note").unwrap();
        let container = NoteFile::new(b"opaque envelope".to_vec(), encrypted).unwrap();
        let encoded = container.encode();
        let decoded = NoteFile::decode(&encoded).unwrap();
        assert_eq!(decoded.encode(), encoded);
        assert_eq!(decoded.envelope_bytes(), b"opaque envelope");
    }

    #[test]
    fn parser_rejects_truncation_trailing_data_and_oversize() {
        let root = RootKey::import([0x42; 32]);
        let encrypted =
            EncryptedNote::encrypt(&root, &application(), b"envelope", b"note").unwrap();
        let encoded = NoteFile::new(b"envelope".to_vec(), encrypted)
            .unwrap()
            .encode();
        for end in 0..encoded.len() {
            assert!(NoteFile::decode(&encoded[..end]).is_err());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(NoteFile::decode(&trailing).is_err());
        assert!(NoteFile::decode(&vec![0; MAX_CONTAINER_BYTES + 1]).is_err());
    }
}
