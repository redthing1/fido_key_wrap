use std::cmp::Ordering;

use minicbor::{Decoder, Encoder};
use p256::PublicKey;

use crate::{
    ApplicationId, Error, RecipientId, RecipientPolicy, Result, TokenPolicy, policy, transcript,
};

pub(crate) const MAGIC: &[u8; 4] = b"FKW1";
pub(crate) const FORMAT_VERSION: u8 = 1;
pub(crate) const SUITE_ID: u8 = 1;
pub(crate) const MAX_ENVELOPE_SIZE: usize = 64 * 1024;
pub(crate) const MAX_RECIPIENTS: usize = 32;
pub(crate) const MAX_CREDENTIAL_ID: usize = 1024;
pub(crate) const MAX_LABEL: usize = 128;

const CRED_PROTECT_PRESENCE: u8 = 2;
const CRED_PROTECT_VERIFIED: u8 = 3;
const TOKEN_ONLY_CIPHERTEXT: usize = 48;
const PASSPHRASE_CIPHERTEXT: usize = 64;

#[derive(Clone)]
pub(crate) struct PublicKey64(pub(crate) [u8; 64]);

impl PublicKey64 {
    pub(crate) fn new(bytes: [u8; 64]) -> Result<Self> {
        let mut sec1 = [0u8; 65];
        sec1[0] = 4;
        sec1[1..].copy_from_slice(&bytes);
        PublicKey::from_sec1_bytes(&sec1).map_err(|_| Error::InvalidEnvelope)?;
        Ok(Self(bytes))
    }
}

#[derive(Clone)]
pub(crate) struct PassphraseHeader {
    pub(crate) salt: [u8; 16],
    pub(crate) nonce: [u8; 12],
}

#[derive(Clone)]
pub(crate) struct RecipientRecord {
    pub(crate) id: RecipientId,
    pub(crate) label: String,
    pub(crate) credential_id: Vec<u8>,
    pub(crate) public_key: PublicKey64,
    pub(crate) policy: RecipientPolicy,
    pub(crate) credential_protection: u8,
    pub(crate) prf_nonce: [u8; 32],
    pub(crate) token_nonce: [u8; 12],
    pub(crate) passphrase: Option<PassphraseHeader>,
    pub(crate) wrapped_key: Vec<u8>,
}

impl RecipientRecord {
    pub(crate) fn crypto_header(
        &self,
        application: &ApplicationId,
        envelope_id: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let token = [self.policy.token.code()];
        let factor = [self.policy.factor_code()];
        let protection = [self.credential_protection];
        let version = [FORMAT_VERSION];
        let suite = [SUITE_ID];
        let empty = [];
        let (salt, passphrase_nonce) = self
            .passphrase
            .as_ref()
            .map_or((&empty[..], &empty[..]), |header| {
                (&header.salt[..], &header.nonce[..])
            });
        transcript::encode(&[
            b"fido_key_wrap/recipient_header/v1",
            &version,
            &suite,
            application.as_str().as_bytes(),
            envelope_id,
            &self.id.0,
            &self.credential_id,
            &self.public_key.0,
            &token,
            &protection,
            &factor,
            &self.prf_nonce,
            &self.token_nonce,
            salt,
            passphrase_nonce,
        ])
    }

    pub(crate) fn expected_credential_protection(policy: TokenPolicy) -> u8 {
        match policy {
            TokenPolicy::Presence => CRED_PROTECT_PRESENCE,
            TokenPolicy::UserVerified => CRED_PROTECT_VERIFIED,
        }
    }
}

/// encrypted root and fido recipient data.
#[derive(Clone)]
pub struct KeyEnvelope {
    pub(crate) application_id: ApplicationId,
    pub(crate) envelope_id: [u8; 32],
    pub(crate) recipients: Vec<RecipientRecord>,
    pub(crate) mac: [u8; 32],
}

impl KeyEnvelope {
    /// decodes a canonical version 1 envelope.
    ///
    /// # Errors
    ///
    /// returns an error for malformed, noncanonical, unsupported, or
    /// resource-exhausting input.
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() > MAX_ENVELOPE_SIZE {
            return Err(Error::ResourceLimitExceeded);
        }
        if input.len() < MAGIC.len() || &input[..MAGIC.len()] != MAGIC {
            return Err(Error::InvalidEnvelope);
        }
        let mut decoder = Decoder::new(&input[MAGIC.len()..]);
        require_array(&mut decoder, 5)?;
        if decoder.u8().map_err(invalid)? != FORMAT_VERSION {
            return Err(Error::InvalidEnvelope);
        }
        let application_text = decoder.str().map_err(invalid)?;
        if application_text.len() > 253 {
            return Err(Error::ResourceLimitExceeded);
        }
        let application_id =
            ApplicationId::new(application_text.to_owned()).map_err(|_| Error::InvalidEnvelope)?;
        let envelope_id = exact_bytes::<32>(&mut decoder)?;
        let recipient_count = decoder
            .array()
            .map_err(invalid)?
            .ok_or(Error::InvalidEnvelope)?;
        let recipient_count =
            usize::try_from(recipient_count).map_err(|_| Error::ResourceLimitExceeded)?;
        if recipient_count == 0 {
            return Err(Error::InvalidEnvelope);
        }
        if recipient_count > MAX_RECIPIENTS {
            return Err(Error::ResourceLimitExceeded);
        }
        let mut recipients = Vec::with_capacity(recipient_count);
        for _ in 0..recipient_count {
            recipients.push(decode_recipient(
                &mut decoder,
                &application_id,
                &envelope_id,
            )?);
        }
        let mac = exact_bytes::<32>(&mut decoder)?;
        if decoder.position() != input.len() - MAGIC.len() {
            return Err(Error::InvalidEnvelope);
        }
        validate_recipient_order(&recipients)?;
        let envelope = Self {
            application_id,
            envelope_id,
            recipients,
            mac,
        };
        if envelope.encode().as_slice() != input {
            return Err(Error::InvalidEnvelope);
        }
        Ok(envelope)
    }

    /// encodes the envelope canonically.
    ///
    /// # Panics
    ///
    /// panics only if the in-memory `Vec` encoder rejects values
    /// that were already validated at construction or decode time.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(Vec::new());
        encode_full(&mut encoder, self).expect("encoding validated in-memory values cannot fail");
        let mut output = Vec::with_capacity(MAGIC.len() + encoder.writer().len());
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(encoder.writer());
        output
    }

    /// returns the application namespace embedded in this envelope.
    #[must_use]
    pub fn application_id(&self) -> &ApplicationId {
        &self.application_id
    }

    /// returns recipient summaries in recipient-id order.
    #[must_use]
    pub fn recipients(&self) -> Vec<RecipientSummary<'_>> {
        self.recipients
            .iter()
            .map(|recipient| RecipientSummary {
                id: recipient.id,
                label: &recipient.label,
                policy: recipient.policy,
            })
            .collect()
    }

    pub(crate) fn canonical_body(&self) -> Result<Vec<u8>> {
        let mut encoder = Encoder::new(Vec::new());
        encode_body(&mut encoder, self).map_err(|_| Error::InvalidEnvelope)?;
        Ok(encoder.into_writer())
    }

    pub(crate) fn find(&self, id: RecipientId) -> Result<&RecipientRecord> {
        self.recipients
            .binary_search_by_key(&id, |recipient| recipient.id)
            .map(|index| &self.recipients[index])
            .map_err(|_| Error::RecipientNotFound)
    }
}

/// public recipient metadata.
#[derive(Clone, Copy, Debug)]
pub struct RecipientSummary<'a> {
    id: RecipientId,
    label: &'a str,
    policy: RecipientPolicy,
}

impl RecipientSummary<'_> {
    /// returns the recipient id.
    #[must_use]
    pub const fn id(self) -> RecipientId {
        self.id
    }

    /// returns the recorded recipient policy.
    #[must_use]
    pub const fn policy(self) -> RecipientPolicy {
        self.policy
    }
}

impl<'a> RecipientSummary<'a> {
    /// returns the untrusted display label.
    ///
    /// the label is authenticated only after successful unlock.
    #[must_use]
    pub const fn label(self) -> &'a str {
        self.label
    }
}

pub(crate) fn compute_recipient_id(
    application: &ApplicationId,
    credential_id: &[u8],
    public_key: &PublicKey64,
    policy: RecipientPolicy,
) -> Result<RecipientId> {
    use sha2::{Digest, Sha256};
    let token = [policy.token.code()];
    let factor = [policy.factor_code()];
    let encoded = transcript::encode(&[
        b"fido_key_wrap/recipient_id/v1",
        application.as_str().as_bytes(),
        credential_id,
        &public_key.0,
        &token,
        &factor,
    ])?;
    Ok(RecipientId::from_bytes(Sha256::digest(encoded).into()))
}

fn encode_full<W: minicbor::encode::Write>(
    encoder: &mut Encoder<W>,
    envelope: &KeyEnvelope,
) -> std::result::Result<(), minicbor::encode::Error<W::Error>> {
    encoder.array(5)?;
    encode_body_fields(encoder, envelope)?;
    encoder.bytes(&envelope.mac)?;
    Ok(())
}

fn encode_body<W: minicbor::encode::Write>(
    encoder: &mut Encoder<W>,
    envelope: &KeyEnvelope,
) -> std::result::Result<(), minicbor::encode::Error<W::Error>> {
    encoder.array(4)?;
    encode_body_fields(encoder, envelope)
}

fn encode_body_fields<W: minicbor::encode::Write>(
    encoder: &mut Encoder<W>,
    envelope: &KeyEnvelope,
) -> std::result::Result<(), minicbor::encode::Error<W::Error>> {
    encoder.u8(FORMAT_VERSION)?;
    encoder.str(envelope.application_id.as_str())?;
    encoder.bytes(&envelope.envelope_id)?;
    encoder.array(envelope.recipients.len() as u64)?;
    for recipient in &envelope.recipients {
        encode_recipient(encoder, recipient)?;
    }
    Ok(())
}

fn encode_recipient<W: minicbor::encode::Write>(
    encoder: &mut Encoder<W>,
    recipient: &RecipientRecord,
) -> std::result::Result<(), minicbor::encode::Error<W::Error>> {
    encoder.array(12)?;
    encoder.u8(SUITE_ID)?;
    encoder.bytes(&recipient.id.0)?;
    encoder.str(&recipient.label)?;
    encoder.bytes(&recipient.credential_id)?;
    encoder.bytes(&recipient.public_key.0)?;
    encoder.u8(recipient.policy.token.code())?;
    encoder.u8(recipient.policy.factor_code())?;
    encoder.u8(recipient.credential_protection)?;
    encoder.bytes(&recipient.prf_nonce)?;
    encoder.bytes(&recipient.token_nonce)?;
    match &recipient.passphrase {
        Some(header) => {
            encoder
                .array(3)?
                .u8(1)?
                .bytes(&header.salt)?
                .bytes(&header.nonce)?;
        }
        None => {
            encoder.null()?;
        }
    }
    encoder.bytes(&recipient.wrapped_key)?;
    Ok(())
}

fn decode_recipient(
    decoder: &mut Decoder<'_>,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
) -> Result<RecipientRecord> {
    require_array(decoder, 12)?;
    if decoder.u8().map_err(invalid)? != SUITE_ID {
        return Err(Error::InvalidEnvelope);
    }
    let id = RecipientId::from_bytes(exact_bytes::<32>(decoder)?);
    let label = decoder.str().map_err(invalid)?.to_owned();
    if label.is_empty() || label.len() > MAX_LABEL || label.chars().any(char::is_control) {
        return Err(Error::InvalidEnvelope);
    }
    let credential_id = decoder.bytes().map_err(invalid)?.to_vec();
    if credential_id.is_empty() {
        return Err(Error::InvalidEnvelope);
    }
    if credential_id.len() > MAX_CREDENTIAL_ID {
        return Err(Error::ResourceLimitExceeded);
    }
    let public_key = PublicKey64::new(exact_bytes::<64>(decoder)?)?;
    let token = TokenPolicy::from_code(decoder.u8().map_err(invalid)?)?;
    let factor = decoder.u8().map_err(invalid)?;
    let policy = match (token, factor) {
        (TokenPolicy::Presence, 0) => policy::presence(),
        (TokenPolicy::Presence, 1) => policy::presence().and_passphrase(),
        (TokenPolicy::UserVerified, 0) => policy::user_verified(),
        (TokenPolicy::UserVerified, 1) => policy::user_verified().and_passphrase(),
        _ => return Err(Error::InvalidEnvelope),
    };
    let credential_protection = decoder.u8().map_err(invalid)?;
    if credential_protection != RecipientRecord::expected_credential_protection(token) {
        return Err(Error::InvalidEnvelope);
    }
    let prf_nonce = exact_bytes::<32>(decoder)?;
    let token_nonce = exact_bytes::<12>(decoder)?;
    let passphrase = if decoder.datatype().map_err(invalid)? == minicbor::data::Type::Null {
        decoder.null().map_err(invalid)?;
        None
    } else {
        require_array(decoder, 3)?;
        if decoder.u8().map_err(invalid)? != 1 {
            return Err(Error::InvalidEnvelope);
        }
        Some(PassphraseHeader {
            salt: exact_bytes::<16>(decoder)?,
            nonce: exact_bytes::<12>(decoder)?,
        })
    };
    if passphrase.is_some() != policy.passphrase {
        return Err(Error::InvalidEnvelope);
    }
    let wrapped_key = decoder.bytes().map_err(invalid)?.to_vec();
    let expected_ciphertext = if policy.passphrase {
        PASSPHRASE_CIPHERTEXT
    } else {
        TOKEN_ONLY_CIPHERTEXT
    };
    if wrapped_key.len() != expected_ciphertext {
        return Err(Error::InvalidEnvelope);
    }
    let record = RecipientRecord {
        id,
        label,
        credential_id,
        public_key,
        policy,
        credential_protection,
        prf_nonce,
        token_nonce,
        passphrase,
        wrapped_key,
    };
    let expected_id = compute_recipient_id(
        application,
        &record.credential_id,
        &record.public_key,
        record.policy,
    )?;
    if expected_id != record.id {
        return Err(Error::InvalidEnvelope);
    }
    let _ = record.crypto_header(application, envelope_id)?;
    Ok(record)
}

fn validate_recipient_order(recipients: &[RecipientRecord]) -> Result<()> {
    for pair in recipients.windows(2) {
        if pair[0].id.cmp(&pair[1].id) != Ordering::Less {
            return Err(Error::InvalidEnvelope);
        }
    }
    for (index, recipient) in recipients.iter().enumerate() {
        if recipients[index + 1..]
            .iter()
            .any(|other| recipient.credential_id == other.credential_id)
        {
            return Err(Error::InvalidEnvelope);
        }
    }
    Ok(())
}

fn require_array(decoder: &mut Decoder<'_>, expected: u64) -> Result<()> {
    match decoder.array().map_err(invalid)? {
        Some(actual) if actual == expected => Ok(()),
        _ => Err(Error::InvalidEnvelope),
    }
}

fn exact_bytes<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N]> {
    let value = decoder.bytes().map_err(invalid)?;
    value.try_into().map_err(|_| Error::InvalidEnvelope)
}

fn invalid<T>(_error: T) -> Error {
    Error::InvalidEnvelope
}

#[cfg(test)]
mod tests {
    use crate::{Enrollment, KeyProtector, backend::fake::TestInteraction, policy};

    use super::*;

    fn envelope_with_two_recipients() -> KeyEnvelope {
        let application = ApplicationId::new("org.example.format-test").unwrap();
        let mut protector = KeyProtector::fake(application);
        let mut interaction = TestInteraction::new(b"unused");
        let (root, mut envelope, _primary) = protector
            .provision(
                Enrollment::new("primary", policy::user_verified()).unwrap(),
                &mut interaction,
            )
            .unwrap();
        protector
            .add_recipient(
                &mut envelope,
                &root,
                Enrollment::new("backup", policy::presence()).unwrap(),
                &mut interaction,
            )
            .unwrap();
        envelope
    }

    #[test]
    fn rejects_trailing_bytes() {
        let envelope = envelope_with_two_recipients();
        let mut encoded = envelope.encode();
        encoded.push(0);
        assert!(matches!(
            KeyEnvelope::decode(&encoded),
            Err(Error::InvalidEnvelope)
        ));
    }

    #[test]
    fn rejects_non_shortest_integer_encoding() {
        let envelope = envelope_with_two_recipients();
        let encoded = envelope.encode();
        assert_eq!(encoded[4], 0x85);
        assert_eq!(encoded[5], FORMAT_VERSION);
        let mut noncanonical = Vec::with_capacity(encoded.len() + 1);
        noncanonical.extend_from_slice(&encoded[..5]);
        noncanonical.extend_from_slice(&[0x18, FORMAT_VERSION]);
        noncanonical.extend_from_slice(&encoded[6..]);
        assert!(matches!(
            KeyEnvelope::decode(&noncanonical),
            Err(Error::InvalidEnvelope)
        ));
    }

    #[test]
    fn rejects_unsorted_and_duplicate_recipients() {
        let envelope = envelope_with_two_recipients();
        let mut unsorted = envelope.clone();
        unsorted.recipients.swap(0, 1);
        assert!(matches!(
            KeyEnvelope::decode(&unsorted.encode()),
            Err(Error::InvalidEnvelope)
        ));

        let mut duplicate = envelope;
        duplicate.recipients[1] = duplicate.recipients[0].clone();
        assert!(matches!(
            KeyEnvelope::decode(&duplicate.encode()),
            Err(Error::InvalidEnvelope)
        ));
    }

    #[test]
    fn rejects_nonadjacent_duplicate_credentials() {
        let envelope = envelope_with_two_recipients();
        let mut recipients = vec![
            envelope.recipients[0].clone(),
            envelope.recipients[1].clone(),
            envelope.recipients[0].clone(),
        ];
        recipients[0].id = RecipientId::from_bytes([0x10; 32]);
        recipients[1].id = RecipientId::from_bytes([0x20; 32]);
        recipients[2].id = RecipientId::from_bytes([0x30; 32]);
        assert!(matches!(
            validate_recipient_order(&recipients),
            Err(Error::InvalidEnvelope)
        ));
    }

    #[test]
    fn enforces_size_bound_before_parsing() {
        let oversized = vec![0u8; MAX_ENVELOPE_SIZE + 1];
        assert!(matches!(
            KeyEnvelope::decode(&oversized),
            Err(Error::ResourceLimitExceeded)
        ));
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut state = 0x4d59_5df4_d0f3_3173u64;
        for length in 0..=1024usize {
            let mut input = vec![0u8; length];
            for byte in &mut input {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state.to_le_bytes()[0];
            }
            let _ = KeyEnvelope::decode(&input);
        }
    }

    #[test]
    fn rejects_indefinite_and_tagged_top_level_values() {
        let indefinite = [MAGIC.as_slice(), &[0x9f, 0xff]].concat();
        assert!(matches!(
            KeyEnvelope::decode(&indefinite),
            Err(Error::InvalidEnvelope)
        ));
        let tagged = [MAGIC.as_slice(), &[0xc0, 0x85]].concat();
        assert!(matches!(
            KeyEnvelope::decode(&tagged),
            Err(Error::InvalidEnvelope)
        ));
    }
}
