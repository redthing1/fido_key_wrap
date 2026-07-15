use minicbor::{Decoder, Encoder};
use p256::PublicKey;

use crate::{
    ApplicationId, Error, RecipientId, Result,
    policy::{FidoPolicy, FidoStorage, PassphraseParameters, RecipientPolicy, validate_label},
};

pub(crate) const MAGIC: &[u8; 4] = b"FKW\0";
pub(crate) const FORMAT_VERSION: u8 = 1;
pub(crate) const MAX_ENVELOPE_SIZE: usize = 65_536;
pub(crate) const MAX_RECIPIENTS: usize = 32;
pub(crate) const MAX_CREDENTIAL_ID: usize = 1_024;

const PASSPHRASE_SUITE: u8 = 1;
const FIDO_SUITE: u8 = 2;
const FIDO_AND_PASSPHRASE_SUITE: u8 = 3;
const RECOVERY_SECRET_SUITE: u8 = 4;
const MANAGED_FIDO_SUITE: u8 = 5;
const ARGON2ID_KDF: u8 = 1;

const ROOT_BYTES: usize = 32;
const ENVELOPE_ID_BYTES: usize = 32;
const RECIPIENT_ID_BYTES: usize = 32;
const PUBLIC_KEY_BYTES: usize = 64;
const PRF_NONCE_BYTES: usize = 32;
const GCM_NONCE_BYTES: usize = 12;
const ARGON2_SALT_BYTES: usize = 16;
const AEAD_TAG_BYTES: usize = 16;
const WRAPPED_ROOT_BYTES: usize = ROOT_BYTES + AEAD_TAG_BYTES;
const COMBINED_WRAPPED_ROOT_BYTES: usize = WRAPPED_ROOT_BYTES + AEAD_TAG_BYTES;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PublicKey64(pub(crate) [u8; PUBLIC_KEY_BYTES]);

impl PublicKey64 {
    pub(crate) fn new(bytes: [u8; PUBLIC_KEY_BYTES]) -> Result<Self> {
        let mut sec1 = [0_u8; PUBLIC_KEY_BYTES + 1];
        sec1[0] = 4;
        sec1[1..].copy_from_slice(&bytes);
        PublicKey::from_sec1_bytes(&sec1).map_err(|_| Error::InvalidEnvelope)?;
        Ok(Self(bytes))
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KdfDescriptor {
    pub(crate) parameters: PassphraseParameters,
    pub(crate) salt: [u8; ARGON2_SALT_BYTES],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PassphraseRecipient {
    pub(crate) id: RecipientId,
    pub(crate) label: String,
    pub(crate) kdf: KdfDescriptor,
    pub(crate) passphrase_nonce: [u8; GCM_NONCE_BYTES],
    pub(crate) wrapped_root: [u8; WRAPPED_ROOT_BYTES],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoverySecretRecord {
    pub(crate) id: RecipientId,
    pub(crate) label: String,
    pub(crate) recovery_nonce: [u8; GCM_NONCE_BYTES],
    pub(crate) wrapped_root: [u8; WRAPPED_ROOT_BYTES],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FidoRecipient {
    pub(crate) id: RecipientId,
    pub(crate) label: String,
    pub(crate) credential_id: Vec<u8>,
    pub(crate) public_key: PublicKey64,
    pub(crate) policy: FidoPolicy,
    pub(crate) storage: FidoStorage,
    pub(crate) prf_nonce: [u8; PRF_NONCE_BYTES],
    pub(crate) fido_nonce: [u8; GCM_NONCE_BYTES],
    pub(crate) wrapped_root: [u8; WRAPPED_ROOT_BYTES],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FidoAndPassphraseRecipient {
    pub(crate) id: RecipientId,
    pub(crate) label: String,
    pub(crate) credential_id: Vec<u8>,
    pub(crate) public_key: PublicKey64,
    pub(crate) policy: FidoPolicy,
    pub(crate) prf_nonce: [u8; PRF_NONCE_BYTES],
    pub(crate) fido_nonce: [u8; GCM_NONCE_BYTES],
    pub(crate) kdf: KdfDescriptor,
    pub(crate) passphrase_nonce: [u8; GCM_NONCE_BYTES],
    pub(crate) wrapped_root: [u8; COMBINED_WRAPPED_ROOT_BYTES],
}

/// one structurally valid route to the envelope root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RecipientRecord {
    Passphrase(PassphraseRecipient),
    RecoverySecret(RecoverySecretRecord),
    Fido(FidoRecipient),
    FidoAndPassphrase(FidoAndPassphraseRecipient),
}

impl RecipientRecord {
    pub(crate) const fn id(&self) -> RecipientId {
        match self {
            Self::Passphrase(record) => record.id,
            Self::RecoverySecret(record) => record.id,
            Self::Fido(record) => record.id,
            Self::FidoAndPassphrase(record) => record.id,
        }
    }

    pub(crate) fn label(&self) -> &str {
        match self {
            Self::Passphrase(record) => &record.label,
            Self::RecoverySecret(record) => &record.label,
            Self::Fido(record) => &record.label,
            Self::FidoAndPassphrase(record) => &record.label,
        }
    }

    pub(crate) const fn policy(&self) -> RecipientPolicy {
        match self {
            Self::Passphrase(_) => RecipientPolicy::Passphrase,
            Self::RecoverySecret(_) => RecipientPolicy::RecoverySecret,
            Self::Fido(record) => match record.storage {
                FidoStorage::NonDiscoverable => RecipientPolicy::Fido(record.policy),
                FidoStorage::Managed => RecipientPolicy::ManagedFido(record.policy),
            },
            Self::FidoAndPassphrase(record) => RecipientPolicy::FidoAndPassphrase(record.policy),
        }
    }

    pub(crate) const fn passphrase_parameters(&self) -> Option<PassphraseParameters> {
        match self {
            Self::Passphrase(record) => Some(record.kdf.parameters),
            Self::RecoverySecret(_) | Self::Fido(_) => None,
            Self::FidoAndPassphrase(record) => Some(record.kdf.parameters),
        }
    }

    fn credential_id(&self) -> Option<&[u8]> {
        match self {
            Self::Passphrase(_) | Self::RecoverySecret(_) => None,
            Self::Fido(record) => Some(&record.credential_id),
            Self::FidoAndPassphrase(record) => Some(&record.credential_id),
        }
    }

    fn passphrase_salt(&self) -> Option<&[u8; ARGON2_SALT_BYTES]> {
        match self {
            Self::Passphrase(record) => Some(&record.kdf.salt),
            Self::RecoverySecret(_) | Self::Fido(_) => None,
            Self::FidoAndPassphrase(record) => Some(&record.kdf.salt),
        }
    }
}

/// an opaque, canonical set of encrypted routes to one application root key.
///
/// every decoded field is untrusted until a selected recipient recovers the
/// root and the whole-envelope mac verifies.
#[derive(Clone)]
pub struct KeyEnvelope {
    pub(crate) application_id: ApplicationId,
    pub(crate) envelope_id: [u8; ENVELOPE_ID_BYTES],
    pub(crate) recipients: Vec<RecipientRecord>,
    pub(crate) mac: [u8; ROOT_BYTES],
}

impl KeyEnvelope {
    /// decodes one strict format-1 envelope without authenticating it.
    ///
    /// the application identity and recipient summaries remain untrusted. an
    /// application must compare the identity with trusted configuration before
    /// factor interaction.
    ///
    /// # errors
    ///
    /// returns [`Error::InvalidEnvelope`] for oversized, malformed,
    /// noncanonical, unsupported, or structurally contradictory input.
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() > MAX_ENVELOPE_SIZE
            || input.len() < MAGIC.len()
            || &input[..MAGIC.len()] != MAGIC
        {
            return Err(Error::InvalidEnvelope);
        }

        let encoded = &input[MAGIC.len()..];
        let mut decoder = Decoder::new(encoded);
        require_array(&mut decoder, 5)?;
        if decoder.u8().map_err(invalid)? != FORMAT_VERSION {
            return Err(Error::InvalidEnvelope);
        }

        let application = decoder.str().map_err(invalid)?;
        let application_id =
            ApplicationId::new(application.to_owned()).map_err(|_| Error::InvalidEnvelope)?;
        let envelope_id = exact_bytes::<ENVELOPE_ID_BYTES>(&mut decoder)?;

        let recipient_count = definite_array_len(&mut decoder)?;
        if !(1..=MAX_RECIPIENTS).contains(&recipient_count) {
            return Err(Error::InvalidEnvelope);
        }
        let mut recipients = Vec::with_capacity(recipient_count);
        for _ in 0..recipient_count {
            recipients.push(decode_recipient(&mut decoder)?);
        }

        let mac = exact_bytes::<ROOT_BYTES>(&mut decoder)?;
        if decoder.position() != encoded.len() {
            return Err(Error::InvalidEnvelope);
        }

        validate_recipient_set(&recipients)?;
        let envelope = Self {
            application_id,
            envelope_id,
            recipients,
            mac,
        };

        // Decoder methods accept some representable non-shortest integers.
        // Exact canonical re-encoding also rejects noncanonical CBOR choices.
        if envelope.encode().as_slice() != input {
            return Err(Error::InvalidEnvelope);
        }
        Ok(envelope)
    }

    /// encodes this envelope as `FKW\0` followed by core deterministic cbor.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(Vec::new());
        encode_full(&mut encoder, self).expect("validated envelope values must encode into memory");
        let cbor = encoder.into_writer();
        let mut output = Vec::with_capacity(MAGIC.len() + cbor.len());
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&cbor);
        output
    }

    /// returns the unauthenticated application namespace carried by this envelope.
    ///
    /// this value must be compared with trusted application configuration. it
    /// must never be adopted as the identity used to construct a protector.
    #[must_use]
    pub const fn application_id(&self) -> &ApplicationId {
        &self.application_id
    }

    /// returns bounded, unauthenticated recipient presentation metadata.
    #[must_use]
    pub fn recipients(&self) -> Vec<RecipientSummary<'_>> {
        self.recipients
            .iter()
            .map(|record| RecipientSummary {
                id: record.id(),
                label: record.label(),
                policy: record.policy(),
                passphrase_parameters: record.passphrase_parameters(),
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
            .binary_search_by_key(&id, RecipientRecord::id)
            .map(|index| &self.recipients[index])
            .map_err(|_| Error::RecipientNotFound)
    }
}

/// bounded, unauthenticated presentation metadata for one recipient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecipientSummary<'a> {
    id: RecipientId,
    label: &'a str,
    policy: RecipientPolicy,
    passphrase_parameters: Option<PassphraseParameters>,
}

impl<'a> RecipientSummary<'a> {
    /// returns the recipient identity.
    #[must_use]
    pub const fn id(self) -> RecipientId {
        self.id
    }

    /// returns the untrusted presentation label.
    #[must_use]
    pub const fn label(self) -> &'a str {
        self.label
    }

    /// returns the structural factor policy.
    #[must_use]
    pub const fn policy(self) -> RecipientPolicy {
        self.policy
    }

    /// returns recorded argon2id work for a passphrase-bearing recipient.
    #[must_use]
    pub const fn passphrase_parameters(self) -> Option<PassphraseParameters> {
        self.passphrase_parameters
    }
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
    match recipient {
        RecipientRecord::Passphrase(record) => {
            encoder.array(6)?.u8(PASSPHRASE_SUITE)?;
            encoder.bytes(record.id.as_bytes())?;
            encoder.str(&record.label)?;
            encode_kdf(encoder, record.kdf)?;
            encoder.bytes(&record.passphrase_nonce)?;
            encoder.bytes(&record.wrapped_root)?;
        }
        RecipientRecord::RecoverySecret(record) => {
            encoder.array(5)?.u8(RECOVERY_SECRET_SUITE)?;
            encoder.bytes(record.id.as_bytes())?;
            encoder.str(&record.label)?;
            encoder.bytes(&record.recovery_nonce)?;
            encoder.bytes(&record.wrapped_root)?;
        }
        RecipientRecord::Fido(record) => {
            let suite = match record.storage {
                FidoStorage::NonDiscoverable => FIDO_SUITE,
                FidoStorage::Managed => MANAGED_FIDO_SUITE,
            };
            encoder.array(9)?.u8(suite)?;
            encoder.bytes(record.id.as_bytes())?;
            encoder.str(&record.label)?;
            encoder.bytes(&record.credential_id)?;
            encoder.bytes(record.public_key.as_bytes())?;
            encoder.u8(record.policy.code())?;
            encoder.bytes(&record.prf_nonce)?;
            encoder.bytes(&record.fido_nonce)?;
            encoder.bytes(&record.wrapped_root)?;
        }
        RecipientRecord::FidoAndPassphrase(record) => {
            encoder.array(11)?.u8(FIDO_AND_PASSPHRASE_SUITE)?;
            encoder.bytes(record.id.as_bytes())?;
            encoder.str(&record.label)?;
            encoder.bytes(&record.credential_id)?;
            encoder.bytes(record.public_key.as_bytes())?;
            encoder.u8(record.policy.code())?;
            encoder.bytes(&record.prf_nonce)?;
            encoder.bytes(&record.fido_nonce)?;
            encode_kdf(encoder, record.kdf)?;
            encoder.bytes(&record.passphrase_nonce)?;
            encoder.bytes(&record.wrapped_root)?;
        }
    }
    Ok(())
}

fn encode_kdf<W: minicbor::encode::Write>(
    encoder: &mut Encoder<W>,
    kdf: KdfDescriptor,
) -> std::result::Result<(), minicbor::encode::Error<W::Error>> {
    encoder
        .array(5)?
        .u8(ARGON2ID_KDF)?
        .u32(kdf.parameters.memory_kib())?
        .u32(kdf.parameters.passes())?
        .u8(kdf.parameters.lanes())?
        .bytes(&kdf.salt)?;
    Ok(())
}

fn decode_recipient(decoder: &mut Decoder<'_>) -> Result<RecipientRecord> {
    let length = definite_array_len(decoder)?;
    let suite = decoder.u8().map_err(invalid)?;
    match suite {
        PASSPHRASE_SUITE if length == 6 => decode_passphrase_recipient(decoder),
        RECOVERY_SECRET_SUITE if length == 5 => decode_recovery_secret_recipient(decoder),
        FIDO_SUITE if length == 9 => decode_fido_recipient(decoder, FidoStorage::NonDiscoverable),
        MANAGED_FIDO_SUITE if length == 9 => decode_fido_recipient(decoder, FidoStorage::Managed),
        FIDO_AND_PASSPHRASE_SUITE if length == 11 => decode_fido_and_passphrase_recipient(decoder),
        _ => Err(Error::InvalidEnvelope),
    }
}

fn decode_recovery_secret_recipient(decoder: &mut Decoder<'_>) -> Result<RecipientRecord> {
    let id = RecipientId::from_bytes(exact_bytes::<RECIPIENT_ID_BYTES>(decoder)?);
    let label = decode_label(decoder)?;
    let recovery_nonce = exact_bytes::<GCM_NONCE_BYTES>(decoder)?;
    let wrapped_root = exact_bytes::<WRAPPED_ROOT_BYTES>(decoder)?;
    Ok(RecipientRecord::RecoverySecret(RecoverySecretRecord {
        id,
        label,
        recovery_nonce,
        wrapped_root,
    }))
}

fn decode_passphrase_recipient(decoder: &mut Decoder<'_>) -> Result<RecipientRecord> {
    let id = RecipientId::from_bytes(exact_bytes::<RECIPIENT_ID_BYTES>(decoder)?);
    let label = decode_label(decoder)?;
    let kdf = decode_kdf(decoder)?;
    let passphrase_nonce = exact_bytes::<GCM_NONCE_BYTES>(decoder)?;
    let wrapped_root = exact_bytes::<WRAPPED_ROOT_BYTES>(decoder)?;
    Ok(RecipientRecord::Passphrase(PassphraseRecipient {
        id,
        label,
        kdf,
        passphrase_nonce,
        wrapped_root,
    }))
}

fn decode_fido_recipient(
    decoder: &mut Decoder<'_>,
    storage: FidoStorage,
) -> Result<RecipientRecord> {
    let id = RecipientId::from_bytes(exact_bytes::<RECIPIENT_ID_BYTES>(decoder)?);
    let label = decode_label(decoder)?;
    let credential_id = decode_credential_id(decoder)?;
    let public_key = PublicKey64::new(exact_bytes::<PUBLIC_KEY_BYTES>(decoder)?)?;
    let policy = FidoPolicy::from_code(decoder.u8().map_err(invalid)?)?;
    let prf_nonce = exact_bytes::<PRF_NONCE_BYTES>(decoder)?;
    let fido_nonce = exact_bytes::<GCM_NONCE_BYTES>(decoder)?;
    let wrapped_root = exact_bytes::<WRAPPED_ROOT_BYTES>(decoder)?;
    Ok(RecipientRecord::Fido(FidoRecipient {
        id,
        label,
        credential_id,
        public_key,
        policy,
        storage,
        prf_nonce,
        fido_nonce,
        wrapped_root,
    }))
}

fn decode_fido_and_passphrase_recipient(decoder: &mut Decoder<'_>) -> Result<RecipientRecord> {
    let id = RecipientId::from_bytes(exact_bytes::<RECIPIENT_ID_BYTES>(decoder)?);
    let label = decode_label(decoder)?;
    let credential_id = decode_credential_id(decoder)?;
    let public_key = PublicKey64::new(exact_bytes::<PUBLIC_KEY_BYTES>(decoder)?)?;
    let policy = FidoPolicy::from_code(decoder.u8().map_err(invalid)?)?;
    let prf_nonce = exact_bytes::<PRF_NONCE_BYTES>(decoder)?;
    let fido_nonce = exact_bytes::<GCM_NONCE_BYTES>(decoder)?;
    let kdf = decode_kdf(decoder)?;
    let passphrase_nonce = exact_bytes::<GCM_NONCE_BYTES>(decoder)?;
    let wrapped_root = exact_bytes::<COMBINED_WRAPPED_ROOT_BYTES>(decoder)?;
    Ok(RecipientRecord::FidoAndPassphrase(
        FidoAndPassphraseRecipient {
            id,
            label,
            credential_id,
            public_key,
            policy,
            prf_nonce,
            fido_nonce,
            kdf,
            passphrase_nonce,
            wrapped_root,
        },
    ))
}

fn decode_kdf(decoder: &mut Decoder<'_>) -> Result<KdfDescriptor> {
    require_array(decoder, 5)?;
    if decoder.u8().map_err(invalid)? != ARGON2ID_KDF {
        return Err(Error::InvalidEnvelope);
    }
    let memory_kib = decoder.u32().map_err(invalid)?;
    let passes = decoder.u32().map_err(invalid)?;
    let lanes = decoder.u8().map_err(invalid)?;
    let parameters = PassphraseParameters::decode(memory_kib, passes, lanes)?;
    let salt = exact_bytes::<ARGON2_SALT_BYTES>(decoder)?;
    Ok(KdfDescriptor { parameters, salt })
}

fn decode_label(decoder: &mut Decoder<'_>) -> Result<String> {
    let label = decoder.str().map_err(invalid)?;
    validate_label(label).map_err(|()| Error::InvalidEnvelope)?;
    Ok(label.to_owned())
}

fn decode_credential_id(decoder: &mut Decoder<'_>) -> Result<Vec<u8>> {
    let credential_id = decoder.bytes().map_err(invalid)?;
    if credential_id.is_empty() || credential_id.len() > MAX_CREDENTIAL_ID {
        return Err(Error::InvalidEnvelope);
    }
    Ok(credential_id.to_vec())
}

fn validate_recipient_set(recipients: &[RecipientRecord]) -> Result<()> {
    for pair in recipients.windows(2) {
        if pair[0].id() >= pair[1].id() {
            return Err(Error::InvalidEnvelope);
        }
    }

    for (index, recipient) in recipients.iter().enumerate() {
        for other in &recipients[index + 1..] {
            if recipient.credential_id().is_some()
                && recipient.credential_id() == other.credential_id()
            {
                return Err(Error::InvalidEnvelope);
            }
            if recipient.passphrase_salt().is_some()
                && recipient.passphrase_salt() == other.passphrase_salt()
            {
                return Err(Error::InvalidEnvelope);
            }
        }
    }
    Ok(())
}

fn require_array(decoder: &mut Decoder<'_>, expected: usize) -> Result<()> {
    if definite_array_len(decoder)? == expected {
        Ok(())
    } else {
        Err(Error::InvalidEnvelope)
    }
}

fn definite_array_len(decoder: &mut Decoder<'_>) -> Result<usize> {
    let length = decoder
        .array()
        .map_err(invalid)?
        .ok_or(Error::InvalidEnvelope)?;
    usize::try_from(length).map_err(|_| Error::InvalidEnvelope)
}

fn exact_bytes<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N]> {
    decoder
        .bytes()
        .map_err(invalid)?
        .try_into()
        .map_err(|_| Error::InvalidEnvelope)
}

fn invalid<T>(_error: T) -> Error {
    Error::InvalidEnvelope
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use super::*;

    const MAX_TEST_LABEL_BYTES: usize = 64;

    const GENERATOR_PUBLIC_KEY: [u8; PUBLIC_KEY_BYTES] = [
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c,
        0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
        0x37, 0xbf, 0x51, 0xf5,
    ];

    fn kdf(salt_byte: u8) -> KdfDescriptor {
        KdfDescriptor {
            parameters: PassphraseParameters::DESKTOP,
            salt: [salt_byte; ARGON2_SALT_BYTES],
        }
    }

    fn sample_envelope() -> KeyEnvelope {
        let public_key = PublicKey64::new(GENERATOR_PUBLIC_KEY).unwrap();
        KeyEnvelope {
            application_id: ApplicationId::new("org.example.format-test").unwrap(),
            envelope_id: [0x44; ENVELOPE_ID_BYTES],
            recipients: vec![
                RecipientRecord::Passphrase(PassphraseRecipient {
                    id: RecipientId::from_bytes([0x10; RECIPIENT_ID_BYTES]),
                    label: "passphrase".to_owned(),
                    kdf: kdf(0x11),
                    passphrase_nonce: [0x12; GCM_NONCE_BYTES],
                    wrapped_root: [0x13; WRAPPED_ROOT_BYTES],
                }),
                RecipientRecord::RecoverySecret(RecoverySecretRecord {
                    id: RecipientId::from_bytes([0x18; RECIPIENT_ID_BYTES]),
                    label: "recovery secret".to_owned(),
                    recovery_nonce: [0x19; GCM_NONCE_BYTES],
                    wrapped_root: [0x1a; WRAPPED_ROOT_BYTES],
                }),
                RecipientRecord::Fido(FidoRecipient {
                    id: RecipientId::from_bytes([0x20; RECIPIENT_ID_BYTES]),
                    label: "security key".to_owned(),
                    credential_id: vec![0x21; 64],
                    public_key: public_key.clone(),
                    policy: FidoPolicy::Presence,
                    storage: FidoStorage::NonDiscoverable,
                    prf_nonce: [0x22; PRF_NONCE_BYTES],
                    fido_nonce: [0x23; GCM_NONCE_BYTES],
                    wrapped_root: [0x24; WRAPPED_ROOT_BYTES],
                }),
                RecipientRecord::FidoAndPassphrase(FidoAndPassphraseRecipient {
                    id: RecipientId::from_bytes([0x30; RECIPIENT_ID_BYTES]),
                    label: "verified plus passphrase".to_owned(),
                    credential_id: vec![0x31; 96],
                    public_key,
                    policy: FidoPolicy::UserVerification,
                    prf_nonce: [0x32; PRF_NONCE_BYTES],
                    fido_nonce: [0x33; GCM_NONCE_BYTES],
                    kdf: kdf(0x34),
                    passphrase_nonce: [0x35; GCM_NONCE_BYTES],
                    wrapped_root: [0x36; COMBINED_WRAPPED_ROOT_BYTES],
                }),
            ],
            mac: [0x55; ROOT_BYTES],
        }
    }

    fn single_passphrase_envelope() -> KeyEnvelope {
        let mut envelope = sample_envelope();
        envelope.recipients.truncate(1);
        envelope
    }

    fn single_fido_envelope() -> KeyEnvelope {
        let mut envelope = sample_envelope();
        envelope.recipients = vec![envelope.recipients[2].clone()];
        envelope
    }

    fn decoder_at_first_record(encoded: &[u8], record_length: u64) -> Decoder<'_> {
        let mut decoder = Decoder::new(&encoded[MAGIC.len()..]);
        assert_eq!(decoder.array().unwrap(), Some(5));
        assert_eq!(decoder.u8().unwrap(), FORMAT_VERSION);
        decoder.str().unwrap();
        decoder.bytes().unwrap();
        assert_eq!(decoder.array().unwrap(), Some(1));
        assert_eq!(decoder.array().unwrap(), Some(record_length));
        decoder
    }

    fn vector_envelope(source: &str) -> Vec<u8> {
        let value = source
            .lines()
            .find_map(|line| line.strip_prefix("envelope="))
            .expect("vector contains envelope bytes");
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16)
                    .expect("vector contains lowercase hexadecimal")
            })
            .collect()
    }

    struct EncodingSpans {
        fields: Vec<Range<usize>>,
        arrays: Vec<(Range<usize>, usize)>,
        fixed_bytes: Vec<(Range<usize>, Vec<u8>)>,
    }

    #[allow(clippy::too_many_lines)]
    fn encoding_spans(encoded: &[u8]) -> EncodingSpans {
        let mut decoder = Decoder::new(&encoded[MAGIC.len()..]);
        let mut spans = EncodingSpans {
            fields: Vec::new(),
            arrays: Vec::new(),
            fixed_bytes: Vec::new(),
        };

        macro_rules! scalar {
            ($read:expr) => {{
                let start = decoder.position();
                let value = $read.unwrap();
                spans.fields.push(start..decoder.position());
                value
            }};
        }
        macro_rules! array {
            () => {{
                let start = decoder.position();
                let length = decoder.array().unwrap().unwrap();
                let length = usize::try_from(length).unwrap();
                let range = start..decoder.position();
                spans.fields.push(range.clone());
                spans.arrays.push((range, length));
                length
            }};
        }
        macro_rules! fixed_bytes {
            () => {{
                let start = decoder.position();
                let value = decoder.bytes().unwrap().to_vec();
                let range = start..decoder.position();
                spans.fields.push(range.clone());
                spans.fixed_bytes.push((range, value));
            }};
        }
        macro_rules! dynamic_bytes {
            () => {{
                let start = decoder.position();
                decoder.bytes().unwrap();
                spans.fields.push(start..decoder.position());
            }};
        }
        macro_rules! text {
            () => {{
                let start = decoder.position();
                decoder.str().unwrap();
                spans.fields.push(start..decoder.position());
            }};
        }
        macro_rules! kdf {
            () => {{
                assert_eq!(array!(), 5);
                scalar!(decoder.u8());
                scalar!(decoder.u32());
                scalar!(decoder.u32());
                scalar!(decoder.u8());
                fixed_bytes!();
            }};
        }

        assert_eq!(array!(), 5);
        scalar!(decoder.u8());
        text!();
        fixed_bytes!();
        let recipient_count = array!();
        for _ in 0..recipient_count {
            let record_length = array!();
            let suite = scalar!(decoder.u8());
            match suite {
                PASSPHRASE_SUITE => {
                    assert_eq!(record_length, 6);
                    fixed_bytes!();
                    text!();
                    kdf!();
                    fixed_bytes!();
                    fixed_bytes!();
                }
                RECOVERY_SECRET_SUITE => {
                    assert_eq!(record_length, 5);
                    fixed_bytes!();
                    text!();
                    fixed_bytes!();
                    fixed_bytes!();
                }
                FIDO_SUITE => {
                    assert_eq!(record_length, 9);
                    fixed_bytes!();
                    text!();
                    dynamic_bytes!();
                    fixed_bytes!();
                    scalar!(decoder.u8());
                    fixed_bytes!();
                    fixed_bytes!();
                    fixed_bytes!();
                }
                FIDO_AND_PASSPHRASE_SUITE => {
                    assert_eq!(record_length, 11);
                    fixed_bytes!();
                    text!();
                    dynamic_bytes!();
                    fixed_bytes!();
                    scalar!(decoder.u8());
                    fixed_bytes!();
                    fixed_bytes!();
                    kdf!();
                    fixed_bytes!();
                    fixed_bytes!();
                }
                _ => unreachable!(),
            }
        }
        fixed_bytes!();
        assert_eq!(decoder.position(), encoded.len() - MAGIC.len());
        spans
    }

    fn replace_value(encoded: &[u8], range: &Range<usize>, replacement: &[u8]) -> Vec<u8> {
        let range = MAGIC.len() + range.start..MAGIC.len() + range.end;
        let mut result = Vec::with_capacity(encoded.len() - range.len() + replacement.len());
        result.extend_from_slice(&encoded[..range.start]);
        result.extend_from_slice(replacement);
        result.extend_from_slice(&encoded[range.end..]);
        result
    }

    #[test]
    fn structural_suites_round_trip_canonically() {
        let envelope = sample_envelope();
        let encoded = envelope.encode();
        assert!(encoded.starts_with(MAGIC));
        let decoded = KeyEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded.encode(), envelope.encode());
        assert_eq!(decoded.encode(), encoded);

        let summaries = decoded.recipients();
        assert_eq!(summaries.len(), 4);
        assert_eq!(summaries[0].policy(), RecipientPolicy::Passphrase);
        assert_eq!(summaries[1].policy(), RecipientPolicy::RecoverySecret);
        assert_eq!(
            summaries[2].policy(),
            RecipientPolicy::Fido(FidoPolicy::Presence)
        );
        assert_eq!(
            summaries[3].policy(),
            RecipientPolicy::FidoAndPassphrase(FidoPolicy::UserVerification)
        );
        assert_eq!(
            summaries[0].passphrase_parameters(),
            Some(PassphraseParameters::DESKTOP)
        );
        assert_eq!(summaries[1].passphrase_parameters(), None);
        assert_eq!(summaries[2].passphrase_parameters(), None);
    }

    #[test]
    fn independent_format_1_envelopes_decode_and_reencode_exactly() {
        let vectors = [
            include_str!("../../../test-vectors/format-1-passphrase.txt"),
            include_str!("../../../test-vectors/format-1-recovery-secret.txt"),
            include_str!("../../../test-vectors/format-1-fido-presence.txt"),
            include_str!("../../../test-vectors/format-1-fido-user-verification.txt"),
            include_str!("../../../test-vectors/format-1-managed-fido-presence.txt"),
            include_str!("../../../test-vectors/format-1-managed-fido-user-verification.txt"),
            include_str!("../../../test-vectors/format-1-fido-presence-plus-passphrase.txt"),
            include_str!(
                "../../../test-vectors/format-1-fido-user-verification-plus-passphrase.txt"
            ),
            include_str!("../../../test-vectors/format-1-mixed.txt"),
        ];
        for source in vectors {
            let encoded = vector_envelope(source);
            let envelope = KeyEnvelope::decode(&encoded).unwrap();
            assert_eq!(envelope.encode(), encoded);
        }
    }

    #[test]
    fn managed_fido_accepts_both_exact_policies() {
        let encoded = vector_envelope(include_str!(
            "../../../test-vectors/format-1-managed-fido-user-verification.txt"
        ));
        let mut envelope = KeyEnvelope::decode(&encoded).unwrap();
        let RecipientRecord::Fido(record) = &mut envelope.recipients[0] else {
            panic!("fixture has the wrong suite");
        };
        record.policy = FidoPolicy::Presence;
        let decoded = KeyEnvelope::decode(&envelope.encode()).unwrap();
        assert_eq!(
            decoded.recipients[0].policy(),
            RecipientPolicy::ManagedFido(FidoPolicy::Presence)
        );
    }

    #[test]
    fn rejects_every_truncation_and_trailing_data() {
        let encoded = sample_envelope().encode();
        for end in 0..encoded.len() {
            assert!(KeyEnvelope::decode(&encoded[..end]).is_err(), "end={end}");
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            KeyEnvelope::decode(&trailing),
            Err(Error::InvalidEnvelope)
        ));
    }

    #[test]
    fn rejects_noncanonical_and_unsupported_cbor() {
        let encoded = sample_envelope().encode();
        assert_eq!(encoded[MAGIC.len()], 0x85);
        assert_eq!(encoded[MAGIC.len() + 1], FORMAT_VERSION);
        let mut non_shortest = Vec::with_capacity(encoded.len() + 1);
        non_shortest.extend_from_slice(&encoded[..=MAGIC.len()]);
        non_shortest.extend_from_slice(&[0x18, FORMAT_VERSION]);
        non_shortest.extend_from_slice(&encoded[MAGIC.len() + 2..]);
        assert!(KeyEnvelope::decode(&non_shortest).is_err());

        assert!(KeyEnvelope::decode(b"FKW\0\x9f\xff").is_err());
        assert!(KeyEnvelope::decode(b"FKW\0\xc0\x80").is_err());
        assert!(KeyEnvelope::decode(b"FKW1\x80").is_err());
    }

    #[test]
    fn rejects_wrong_types_and_adjacent_lengths_for_every_structural_field() {
        let encoded = sample_envelope().encode();
        let spans = encoding_spans(&encoded);

        for (index, range) in spans.fields.iter().enumerate() {
            let mut wrong_type = encoded.clone();
            wrong_type[MAGIC.len() + range.start] = 0xf6;
            assert!(
                KeyEnvelope::decode(&wrong_type).is_err(),
                "field type {index}"
            );
        }

        for (index, (range, length)) in spans.arrays.iter().enumerate() {
            assert!((1..=23).contains(length));
            for adjacent in [length - 1, length + 1] {
                let header = [0x80 | u8::try_from(adjacent).unwrap()];
                let candidate = replace_value(&encoded, range, &header);
                assert!(
                    KeyEnvelope::decode(&candidate).is_err(),
                    "array {index}, length {adjacent}"
                );
            }
        }

        for (index, (range, bytes)) in spans.fixed_bytes.iter().enumerate() {
            for adjacent in [bytes.len() - 1, bytes.len() + 1] {
                let mut value = vec![0x5a; adjacent];
                let copied = bytes.len().min(adjacent);
                value[..copied].copy_from_slice(&bytes[..copied]);
                let mut replacement = Vec::new();
                Encoder::new(&mut replacement).bytes(&value).unwrap();
                let candidate = replace_value(&encoded, range, &replacement);
                assert!(
                    KeyEnvelope::decode(&candidate).is_err(),
                    "fixed bytes {index}, length {adjacent}"
                );
            }
        }
    }

    #[test]
    fn rejects_unknown_format_suite_policy_and_kdf_codes() {
        let mut unknown_format = single_passphrase_envelope().encode();
        unknown_format[MAGIC.len() + 1] = FORMAT_VERSION + 1;
        assert!(matches!(
            KeyEnvelope::decode(&unknown_format),
            Err(Error::InvalidEnvelope)
        ));

        let mut unknown_suite = single_passphrase_envelope().encode();
        let suite_offset = {
            let decoder = decoder_at_first_record(&unknown_suite, 6);
            MAGIC.len() + decoder.position()
        };
        assert_eq!(unknown_suite[suite_offset], PASSPHRASE_SUITE);
        unknown_suite[suite_offset] = u8::MAX;
        assert!(matches!(
            KeyEnvelope::decode(&unknown_suite),
            Err(Error::InvalidEnvelope)
        ));

        let mut unknown_policy = single_fido_envelope().encode();
        let policy_offset = {
            let mut decoder = decoder_at_first_record(&unknown_policy, 9);
            assert_eq!(decoder.u8().unwrap(), FIDO_SUITE);
            decoder.bytes().unwrap();
            decoder.str().unwrap();
            decoder.bytes().unwrap();
            decoder.bytes().unwrap();
            MAGIC.len() + decoder.position()
        };
        assert_eq!(unknown_policy[policy_offset], FidoPolicy::Presence.code());
        unknown_policy[policy_offset] = 3;
        assert!(matches!(
            KeyEnvelope::decode(&unknown_policy),
            Err(Error::InvalidEnvelope)
        ));

        let mut unknown_kdf = single_passphrase_envelope().encode();
        let kdf_offset = {
            let mut decoder = decoder_at_first_record(&unknown_kdf, 6);
            assert_eq!(decoder.u8().unwrap(), PASSPHRASE_SUITE);
            decoder.bytes().unwrap();
            decoder.str().unwrap();
            assert_eq!(decoder.array().unwrap(), Some(5));
            MAGIC.len() + decoder.position()
        };
        assert_eq!(unknown_kdf[kdf_offset], ARGON2ID_KDF);
        unknown_kdf[kdf_offset] = 2;
        assert!(matches!(
            KeyEnvelope::decode(&unknown_kdf),
            Err(Error::InvalidEnvelope)
        ));
    }

    #[test]
    fn enforces_adjacent_label_and_credential_length_boundaries() {
        for length in [1, MAX_TEST_LABEL_BYTES] {
            let mut envelope = single_passphrase_envelope();
            let RecipientRecord::Passphrase(record) = &mut envelope.recipients[0] else {
                unreachable!();
            };
            record.label = "x".repeat(length);
            assert!(
                KeyEnvelope::decode(&envelope.encode()).is_ok(),
                "label={length}"
            );
        }
        for length in [0, MAX_TEST_LABEL_BYTES + 1] {
            let mut envelope = single_passphrase_envelope();
            let RecipientRecord::Passphrase(record) = &mut envelope.recipients[0] else {
                unreachable!();
            };
            record.label = "x".repeat(length);
            assert!(
                KeyEnvelope::decode(&envelope.encode()).is_err(),
                "label={length}"
            );
        }

        for length in [1, MAX_CREDENTIAL_ID] {
            let mut envelope = single_fido_envelope();
            let RecipientRecord::Fido(record) = &mut envelope.recipients[0] else {
                unreachable!();
            };
            record.credential_id = vec![0x42; length];
            assert!(
                KeyEnvelope::decode(&envelope.encode()).is_ok(),
                "credential={length}"
            );
        }
        for length in [0, MAX_CREDENTIAL_ID + 1] {
            let mut envelope = single_fido_envelope();
            let RecipientRecord::Fido(record) = &mut envelope.recipients[0] else {
                unreachable!();
            };
            record.credential_id = vec![0x42; length];
            assert!(
                KeyEnvelope::decode(&envelope.encode()).is_err(),
                "credential={length}"
            );
        }
    }

    #[test]
    fn rejects_unsorted_and_duplicate_recipient_properties() {
        let mut unsorted = sample_envelope();
        unsorted.recipients.swap(0, 1);
        assert!(KeyEnvelope::decode(&unsorted.encode()).is_err());

        let mut duplicate_id = sample_envelope();
        if let RecipientRecord::Fido(record) = &mut duplicate_id.recipients[2] {
            record.id = RecipientId::from_bytes([0x10; RECIPIENT_ID_BYTES]);
        }
        assert!(KeyEnvelope::decode(&duplicate_id.encode()).is_err());

        let mut duplicate_salt = sample_envelope();
        let first_salt = *duplicate_salt.recipients[0].passphrase_salt().unwrap();
        if let RecipientRecord::FidoAndPassphrase(record) = &mut duplicate_salt.recipients[3] {
            record.kdf.salt = first_salt;
        }
        assert!(KeyEnvelope::decode(&duplicate_salt.encode()).is_err());

        let mut duplicate_credential = sample_envelope();
        let first_credential = duplicate_credential.recipients[2]
            .credential_id()
            .unwrap()
            .to_vec();
        if let RecipientRecord::FidoAndPassphrase(record) = &mut duplicate_credential.recipients[3]
        {
            record.credential_id = first_credential;
        }
        assert!(KeyEnvelope::decode(&duplicate_credential.encode()).is_err());
    }

    #[test]
    fn rejects_invalid_labels_credentials_points_and_parameters() {
        let mut invalid_label = sample_envelope();
        if let RecipientRecord::Passphrase(record) = &mut invalid_label.recipients[0] {
            record.label = " leading".to_owned();
        }
        assert!(KeyEnvelope::decode(&invalid_label.encode()).is_err());

        let mut empty_credential = sample_envelope();
        if let RecipientRecord::Fido(record) = &mut empty_credential.recipients[2] {
            record.credential_id.clear();
        }
        assert!(KeyEnvelope::decode(&empty_credential.encode()).is_err());

        let mut oversized_credential = sample_envelope();
        if let RecipientRecord::Fido(record) = &mut oversized_credential.recipients[2] {
            record.credential_id = vec![0; MAX_CREDENTIAL_ID + 1];
        }
        assert!(KeyEnvelope::decode(&oversized_credential.encode()).is_err());

        let mut invalid_point = sample_envelope();
        if let RecipientRecord::Fido(record) = &mut invalid_point.recipients[2] {
            record.public_key = PublicKey64([0; PUBLIC_KEY_BYTES]);
        }
        assert!(KeyEnvelope::decode(&invalid_point.encode()).is_err());

        let mut invalid_kdf = sample_envelope().encode();
        let memory = PassphraseParameters::DESKTOP.memory_kib().to_be_bytes();
        let position = invalid_kdf
            .windows(memory.len())
            .position(|window| window == memory)
            .unwrap();
        invalid_kdf[position + memory.len() - 1] ^= 1;
        assert!(KeyEnvelope::decode(&invalid_kdf).is_err());
    }

    #[test]
    fn enforces_global_and_collection_bounds() {
        let mut exact_maximum = sample_envelope().encode();
        exact_maximum.resize(MAX_ENVELOPE_SIZE, 0);
        assert!(KeyEnvelope::decode(&exact_maximum).is_err());
        assert!(KeyEnvelope::decode(&vec![0; MAX_ENVELOPE_SIZE + 1]).is_err());

        let mut empty = sample_envelope();
        empty.recipients.clear();
        assert!(KeyEnvelope::decode(&empty.encode()).is_err());

        let recipients = |count: usize| {
            (0..count)
                .map(|index| {
                    let byte = u8::try_from(index).expect("recipient test index fits in u8");
                    RecipientRecord::Passphrase(PassphraseRecipient {
                        id: RecipientId::from_bytes([byte; RECIPIENT_ID_BYTES]),
                        label: "route".to_owned(),
                        kdf: KdfDescriptor {
                            parameters: PassphraseParameters::DESKTOP,
                            salt: [byte; ARGON2_SALT_BYTES],
                        },
                        passphrase_nonce: [byte; GCM_NONCE_BYTES],
                        wrapped_root: [byte; WRAPPED_ROOT_BYTES],
                    })
                })
                .collect::<Vec<_>>()
        };

        let mut maximum = sample_envelope();
        maximum.recipients = recipients(MAX_RECIPIENTS);
        let maximum_bytes = maximum.encode();
        assert!(maximum_bytes.len() <= MAX_ENVELOPE_SIZE);
        assert_eq!(
            KeyEnvelope::decode(&maximum_bytes)
                .unwrap()
                .recipients
                .len(),
            MAX_RECIPIENTS
        );

        let mut too_many = sample_envelope();
        too_many.recipients = recipients(MAX_RECIPIENTS + 1);
        assert!(KeyEnvelope::decode(&too_many.encode()).is_err());
    }

    #[test]
    fn structured_and_mutated_bounded_input_never_panics() {
        let template = sample_envelope().encode();
        let mut state = 0x4d59_5df4_d0f3_3173_u64;
        for length in 0..=1_024 {
            let mut input = vec![0_u8; length];
            for byte in &mut input {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state.to_le_bytes()[0];
            }
            let prefix = length.min(template.len());
            input[..prefix].copy_from_slice(&template[..prefix]);
            let _ = KeyEnvelope::decode(&input);

            if length > MAGIC.len() {
                let mut mutated = template.clone();
                let index = MAGIC.len()
                    + usize::try_from(state).unwrap_or(0) % (mutated.len() - MAGIC.len());
                mutated[index] ^= 1;
                mutated.truncate(length.min(mutated.len()));
                let _ = KeyEnvelope::decode(&mutated);
            }
        }

        let mut arbitrary = vec![0_u8; MAX_ENVELOPE_SIZE];
        let mut structured = vec![0_u8; MAX_ENVELOPE_SIZE];
        structured[..template.len()].copy_from_slice(&template);
        for length in 0..=MAX_ENVELOPE_SIZE {
            let _ = KeyEnvelope::decode(&arbitrary[..length]);
            let _ = KeyEnvelope::decode(&structured[..length]);
        }
        arbitrary.push(0);
        structured.push(0);
        assert!(KeyEnvelope::decode(&arbitrary).is_err());
        assert!(KeyEnvelope::decode(&structured).is_err());
    }
}
