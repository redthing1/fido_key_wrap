use aes_gcm::{
    Aes256Gcm, Nonce, Tag,
    aead::{AeadInPlace, KeyInit},
};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[cfg(test)]
use std::cell::Cell;

use crate::{
    ApplicationId, Error, KeyEnvelope, Passphrase, RecoverySecret, Result, RootKey,
    envelope::{
        FidoAndPassphraseRecipient, FidoRecipient, KdfDescriptor, PassphraseRecipient,
        RecipientRecord, RecoverySecretRecord,
    },
    transcript,
};

const FORMAT: [u8; 1] = [1];
const PASSPHRASE_SUITE: [u8; 1] = [1];
const FIDO_SUITE: [u8; 1] = [2];
const COMBINED_SUITE: [u8; 1] = [3];
const RECOVERY_SECRET_SUITE: [u8; 1] = [4];
const ARGON2ID_KDF: [u8; 1] = [1];
const ROOT_BYTES: usize = 32;
const TAG_BYTES: usize = 16;
const WRAPPED_ROOT_BYTES: usize = ROOT_BYTES + TAG_BYTES;
const COMBINED_WRAPPED_ROOT_BYTES: usize = WRAPPED_ROOT_BYTES + TAG_BYTES;

const RECIPIENT_CONTEXT_DOMAIN: &[u8] = b"fido_key_wrap/format_1/recipient_context";
const PRF_INPUT_DOMAIN: &[u8] = b"fido_key_wrap/format_1/prf_input";
const PASSPHRASE_KEY_DOMAIN: &[u8] = b"fido_key_wrap/format_1/passphrase_key";
const FIDO_KEY_DOMAIN: &[u8] = b"fido_key_wrap/format_1/fido_key";
const RECOVERY_SECRET_KEY_DOMAIN: &[u8] = b"fido_key_wrap/format_1/recovery_secret_key";
const PASSPHRASE_AAD_DOMAIN: &[u8] = b"fido_key_wrap/format_1/passphrase_aad";
const FIDO_AAD_DOMAIN: &[u8] = b"fido_key_wrap/format_1/fido_aad";
const RECOVERY_SECRET_AAD_DOMAIN: &[u8] = b"fido_key_wrap/format_1/recovery_secret_aad";
const COMBINED_PASSPHRASE_AAD_DOMAIN: &[u8] = b"fido_key_wrap/format_1/combined_passphrase_aad";
const COMBINED_FIDO_AAD_DOMAIN: &[u8] = b"fido_key_wrap/format_1/combined_fido_aad";
const ENVELOPE_MAC_KEY_DOMAIN: &[u8] = b"fido_key_wrap/format_1/envelope_mac_key";
const ENVELOPE_MAC_DOMAIN: &[u8] = b"fido_key_wrap/format_1/envelope_mac";

#[cfg(test)]
thread_local! {
    static PASSPHRASE_DERIVATIONS: Cell<usize> = const { Cell::new(0) };
    static FAIL_NEXT_ARGON2_ALLOCATION: Cell<bool> = const { Cell::new(false) };
}

/// a short-lived key derived for one exact recipient layer.
///
/// the type is opaque, non-cloneable, and non-debuggable. its owned bytes are
/// cleared when it leaves scope.
pub(crate) struct DerivedKey(Zeroizing<[u8; ROOT_BYTES]>);

impl DerivedKey {
    fn as_bytes(&self) -> &[u8; ROOT_BYTES] {
        &self.0
    }
}

pub(crate) fn recipient_context(
    recipient: &RecipientRecord,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
) -> Result<[u8; 32]> {
    let encoded = recipient_context_transcript(recipient, application, envelope_id)?;
    Ok(Sha256::digest(encoded).into())
}

pub(crate) fn prf_input(
    recipient: &RecipientRecord,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
) -> Result<[u8; 32]> {
    if matches!(
        recipient,
        RecipientRecord::Passphrase(_) | RecipientRecord::RecoverySecret(_)
    ) {
        return Err(Error::InvalidEnvelope);
    }
    let context = recipient_context(recipient, application, envelope_id)?;
    let encoded = prf_input_transcript(&context)?;
    Ok(Sha256::digest(encoded).into())
}

pub(crate) fn derive_passphrase_key(
    recipient: &RecipientRecord,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
    passphrase: &Passphrase,
) -> Result<DerivedKey> {
    // The protector must apply its immutable local limits before requesting a
    // passphrase and reaching this admitted, allocating operation.
    derive_passphrase_key_inner(recipient, application, envelope_id, passphrase, |_| {})
}

pub(crate) fn derive_fido_key(
    recipient: &RecipientRecord,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
    verified_prf_result: &[u8; 32],
) -> Result<DerivedKey> {
    if matches!(
        recipient,
        RecipientRecord::Passphrase(_) | RecipientRecord::RecoverySecret(_)
    ) {
        return Err(Error::InvalidEnvelope);
    }
    let context = recipient_context(recipient, application, envelope_id)?;
    let info = transcript::encode(&[FIDO_KEY_DOMAIN, &context])?;
    derive_key(verified_prf_result, envelope_id, &info)
}

pub(crate) fn derive_recovery_secret_key(
    recipient: &RecoverySecretRecord,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
    secret: &RecoverySecret,
) -> Result<DerivedKey> {
    let context = recovery_secret_context(recipient, application, envelope_id)?;
    let info = transcript::encode(&[RECOVERY_SECRET_KEY_DOMAIN, &context])?;
    derive_key(secret.bytes(), envelope_id, &info)
}

pub(crate) fn wrap_passphrase_root(
    recipient: &PassphraseRecipient,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
    root: &RootKey,
    key: &DerivedKey,
) -> Result<[u8; WRAPPED_ROOT_BYTES]> {
    let context = passphrase_context(recipient, application, envelope_id)?;
    let aad = transcript::encode(&[PASSPHRASE_AAD_DOMAIN, &context])?;
    encrypt_fixed(key, &recipient.passphrase_nonce, root.bytes(), &aad)
}

pub(crate) fn unwrap_passphrase_root(
    recipient: &PassphraseRecipient,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
    key: &DerivedKey,
) -> Result<RootKey> {
    let context = passphrase_context(recipient, application, envelope_id)?;
    let aad = transcript::encode(&[PASSPHRASE_AAD_DOMAIN, &context])?;
    let root = decrypt_fixed(
        key,
        &recipient.passphrase_nonce,
        &recipient.wrapped_root,
        &aad,
    )?;
    Ok(RootKey::from_zeroizing(root))
}

pub(crate) fn wrap_recovery_secret_root(
    recipient: &RecoverySecretRecord,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
    root: &RootKey,
    key: &DerivedKey,
) -> Result<[u8; WRAPPED_ROOT_BYTES]> {
    let context = recovery_secret_context(recipient, application, envelope_id)?;
    let aad = transcript::encode(&[RECOVERY_SECRET_AAD_DOMAIN, &context])?;
    encrypt_fixed(key, &recipient.recovery_nonce, root.bytes(), &aad)
}

pub(crate) fn unwrap_recovery_secret_root(
    recipient: &RecoverySecretRecord,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
    key: &DerivedKey,
) -> Result<RootKey> {
    let context = recovery_secret_context(recipient, application, envelope_id)?;
    let aad = transcript::encode(&[RECOVERY_SECRET_AAD_DOMAIN, &context])?;
    let root = decrypt_fixed(
        key,
        &recipient.recovery_nonce,
        &recipient.wrapped_root,
        &aad,
    )?;
    Ok(RootKey::from_zeroizing(root))
}

pub(crate) fn wrap_fido_root(
    recipient: &FidoRecipient,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
    root: &RootKey,
    key: &DerivedKey,
) -> Result<[u8; WRAPPED_ROOT_BYTES]> {
    let context = fido_context(recipient, application, envelope_id)?;
    let aad = transcript::encode(&[FIDO_AAD_DOMAIN, &context])?;
    encrypt_fixed(key, &recipient.fido_nonce, root.bytes(), &aad)
}

pub(crate) fn unwrap_fido_root(
    recipient: &FidoRecipient,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
    key: &DerivedKey,
) -> Result<RootKey> {
    let context = fido_context(recipient, application, envelope_id)?;
    let aad = transcript::encode(&[FIDO_AAD_DOMAIN, &context])?;
    let root = decrypt_fixed(key, &recipient.fido_nonce, &recipient.wrapped_root, &aad)?;
    Ok(RootKey::from_zeroizing(root))
}

pub(crate) fn wrap_combined_inner(
    recipient: &FidoAndPassphraseRecipient,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
    root: &RootKey,
    passphrase_key: &DerivedKey,
) -> Result<Zeroizing<[u8; WRAPPED_ROOT_BYTES]>> {
    let context = combined_context(recipient, application, envelope_id)?;
    let aad = transcript::encode(&[COMBINED_PASSPHRASE_AAD_DOMAIN, &context])?;
    Ok(Zeroizing::new(encrypt_fixed(
        passphrase_key,
        &recipient.passphrase_nonce,
        root.bytes(),
        &aad,
    )?))
}

pub(crate) fn wrap_combined_outer(
    recipient: &FidoAndPassphraseRecipient,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
    inner: &[u8; WRAPPED_ROOT_BYTES],
    fido_key: &DerivedKey,
) -> Result<[u8; COMBINED_WRAPPED_ROOT_BYTES]> {
    let context = combined_context(recipient, application, envelope_id)?;
    let aad = transcript::encode(&[COMBINED_FIDO_AAD_DOMAIN, &context])?;
    encrypt_fixed(fido_key, &recipient.fido_nonce, inner, &aad)
}

pub(crate) fn wrap_combined_root(
    recipient: &FidoAndPassphraseRecipient,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
    root: &RootKey,
    passphrase_key: &DerivedKey,
    fido_key: &DerivedKey,
) -> Result<[u8; COMBINED_WRAPPED_ROOT_BYTES]> {
    let inner = wrap_combined_inner(recipient, application, envelope_id, root, passphrase_key)?;
    wrap_combined_outer(recipient, application, envelope_id, &inner, fido_key)
}

/// authenticates and decrypts only the fido layer of a combined recipient.
///
/// the caller can drop its fido-derived key after this returns and before it
/// requests or derives the passphrase layer.
pub(crate) fn unwrap_combined_outer(
    recipient: &FidoAndPassphraseRecipient,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
    fido_key: &DerivedKey,
) -> Result<Zeroizing<[u8; WRAPPED_ROOT_BYTES]>> {
    let context = combined_context(recipient, application, envelope_id)?;
    let aad = transcript::encode(&[COMBINED_FIDO_AAD_DOMAIN, &context])?;
    decrypt_fixed(
        fido_key,
        &recipient.fido_nonce,
        &recipient.wrapped_root,
        &aad,
    )
}

pub(crate) fn unwrap_combined_inner(
    recipient: &FidoAndPassphraseRecipient,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
    inner: &[u8; WRAPPED_ROOT_BYTES],
    passphrase_key: &DerivedKey,
) -> Result<RootKey> {
    let context = combined_context(recipient, application, envelope_id)?;
    let aad = transcript::encode(&[COMBINED_PASSPHRASE_AAD_DOMAIN, &context])?;
    let root = decrypt_fixed(passphrase_key, &recipient.passphrase_nonce, inner, &aad)?;
    Ok(RootKey::from_zeroizing(root))
}

pub(crate) fn compute_envelope_mac(envelope: &KeyEnvelope, root: &RootKey) -> Result<[u8; 32]> {
    let key_info = transcript::encode(&[
        ENVELOPE_MAC_KEY_DOMAIN,
        &FORMAT,
        envelope.application_id.as_str().as_bytes(),
    ])?;
    let key = derive_key(root.bytes(), &envelope.envelope_id, &key_info)?;
    let canonical_body = envelope.canonical_body()?;
    let message = transcript::encode(&[ENVELOPE_MAC_DOMAIN, &FORMAT, &canonical_body])?;
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key.as_bytes())
        .map_err(|_| Error::InvalidEnvelope)?;
    mac.update(&message);
    Ok(mac.finalize().into_bytes().into())
}

pub(crate) fn envelope_mac_matches(envelope: &KeyEnvelope, root: &RootKey) -> Result<bool> {
    let expected = compute_envelope_mac(envelope, root)?;
    Ok(bool::from(expected.ct_eq(&envelope.mac)))
}

pub(crate) fn verify_envelope_mac(envelope: &KeyEnvelope, root: &RootKey) -> Result<()> {
    if envelope_mac_matches(envelope, root)? {
        Ok(())
    } else {
        Err(Error::EnvelopeAuthenticationFailed)
    }
}

fn recipient_context_transcript(
    recipient: &RecipientRecord,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
) -> Result<Vec<u8>> {
    match recipient {
        RecipientRecord::Passphrase(record) => {
            passphrase_context_transcript(record, application, envelope_id)
        }
        RecipientRecord::RecoverySecret(record) => {
            recovery_secret_context_transcript(record, application, envelope_id)
        }
        RecipientRecord::Fido(record) => fido_context_transcript(record, application, envelope_id),
        RecipientRecord::FidoAndPassphrase(record) => {
            combined_context_transcript(record, application, envelope_id)
        }
    }
}

fn recovery_secret_context_transcript(
    recipient: &RecoverySecretRecord,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
) -> Result<Vec<u8>> {
    transcript::encode(&[
        RECIPIENT_CONTEXT_DOMAIN,
        &FORMAT,
        &RECOVERY_SECRET_SUITE,
        application.as_str().as_bytes(),
        envelope_id,
        recipient.id.as_bytes(),
        recipient.label.as_bytes(),
        &recipient.recovery_nonce,
    ])
}

fn passphrase_context_transcript(
    recipient: &PassphraseRecipient,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
) -> Result<Vec<u8>> {
    let memory = recipient.kdf.parameters.memory_kib().to_be_bytes();
    let passes = recipient.kdf.parameters.passes().to_be_bytes();
    let lanes = [recipient.kdf.parameters.lanes()];
    transcript::encode(&[
        RECIPIENT_CONTEXT_DOMAIN,
        &FORMAT,
        &PASSPHRASE_SUITE,
        application.as_str().as_bytes(),
        envelope_id,
        recipient.id.as_bytes(),
        &ARGON2ID_KDF,
        &memory,
        &passes,
        &lanes,
        &recipient.kdf.salt,
        &recipient.passphrase_nonce,
    ])
}

fn fido_context_transcript(
    recipient: &FidoRecipient,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
) -> Result<Vec<u8>> {
    let policy = [recipient.policy.code()];
    transcript::encode(&[
        RECIPIENT_CONTEXT_DOMAIN,
        &FORMAT,
        &FIDO_SUITE,
        application.as_str().as_bytes(),
        envelope_id,
        recipient.id.as_bytes(),
        &recipient.credential_id,
        recipient.public_key.as_bytes(),
        &policy,
        &recipient.prf_nonce,
        &recipient.fido_nonce,
    ])
}

fn combined_context_transcript(
    recipient: &FidoAndPassphraseRecipient,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
) -> Result<Vec<u8>> {
    let policy = [recipient.policy.code()];
    let memory = recipient.kdf.parameters.memory_kib().to_be_bytes();
    let passes = recipient.kdf.parameters.passes().to_be_bytes();
    let lanes = [recipient.kdf.parameters.lanes()];
    transcript::encode(&[
        RECIPIENT_CONTEXT_DOMAIN,
        &FORMAT,
        &COMBINED_SUITE,
        application.as_str().as_bytes(),
        envelope_id,
        recipient.id.as_bytes(),
        &recipient.credential_id,
        recipient.public_key.as_bytes(),
        &policy,
        &recipient.prf_nonce,
        &recipient.fido_nonce,
        &ARGON2ID_KDF,
        &memory,
        &passes,
        &lanes,
        &recipient.kdf.salt,
        &recipient.passphrase_nonce,
    ])
}

fn passphrase_context(
    recipient: &PassphraseRecipient,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
) -> Result<[u8; 32]> {
    Ok(Sha256::digest(passphrase_context_transcript(
        recipient,
        application,
        envelope_id,
    )?)
    .into())
}

fn fido_context(
    recipient: &FidoRecipient,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
) -> Result<[u8; 32]> {
    Ok(Sha256::digest(fido_context_transcript(
        recipient,
        application,
        envelope_id,
    )?)
    .into())
}

fn recovery_secret_context(
    recipient: &RecoverySecretRecord,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
) -> Result<[u8; 32]> {
    Ok(Sha256::digest(recovery_secret_context_transcript(
        recipient,
        application,
        envelope_id,
    )?)
    .into())
}

fn combined_context(
    recipient: &FidoAndPassphraseRecipient,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
) -> Result<[u8; 32]> {
    Ok(Sha256::digest(combined_context_transcript(
        recipient,
        application,
        envelope_id,
    )?)
    .into())
}

fn prf_input_transcript(context: &[u8; 32]) -> Result<Vec<u8>> {
    transcript::encode(&[PRF_INPUT_DOMAIN, context])
}

fn derive_passphrase_key_inner(
    recipient: &RecipientRecord,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
    passphrase: &Passphrase,
    inspect_intermediate: impl FnOnce(&[u8; 32]),
) -> Result<DerivedKey> {
    let kdf = match recipient {
        RecipientRecord::Passphrase(record) => record.kdf,
        RecipientRecord::RecoverySecret(_) | RecipientRecord::Fido(_) => {
            return Err(Error::InvalidEnvelope);
        }
        RecipientRecord::FidoAndPassphrase(record) => record.kdf,
    };
    let context = recipient_context(recipient, application, envelope_id)?;
    let intermediate = argon2_output(passphrase, kdf)?;
    inspect_intermediate(&intermediate);
    let info = transcript::encode(&[PASSPHRASE_KEY_DOMAIN, &context])?;
    derive_key(intermediate.as_ref(), envelope_id, &info)
}

fn argon2_output(passphrase: &Passphrase, kdf: KdfDescriptor) -> Result<Zeroizing<[u8; 32]>> {
    #[cfg(test)]
    PASSPHRASE_DERIVATIONS.set(PASSPHRASE_DERIVATIONS.get() + 1);
    let params = Params::new(
        kdf.parameters.memory_kib(),
        kdf.parameters.passes(),
        u32::from(kdf.parameters.lanes()),
        Some(32),
    )
    .map_err(|_| Error::InvalidEnvelope)?;
    let block_count = params.block_count();
    let encoded_block_count =
        usize::try_from(kdf.parameters.memory_kib()).map_err(|_| Error::InvalidEnvelope)?;
    if block_count != encoded_block_count {
        return Err(Error::InvalidEnvelope);
    }
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    #[cfg(test)]
    if FAIL_NEXT_ARGON2_ALLOCATION.replace(false) {
        return Err(Error::KdfResourceUnavailable);
    }
    let mut memory = Vec::new();
    memory
        .try_reserve_exact(block_count)
        .map_err(|_| Error::KdfResourceUnavailable)?;
    memory.resize(block_count, Block::default());
    let mut memory = Zeroizing::new(memory);
    let mut output = Zeroizing::new([0_u8; 32]);
    argon2
        .hash_password_into_with_memory(
            passphrase.as_bytes(),
            &kdf.salt,
            output.as_mut(),
            memory.as_mut_slice(),
        )
        .map_err(|_| Error::UnlockFailed)?;
    Ok(output)
}

#[cfg(test)]
pub(crate) fn reset_passphrase_derivations() {
    PASSPHRASE_DERIVATIONS.set(0);
}

#[cfg(test)]
pub(crate) fn passphrase_derivations() -> usize {
    PASSPHRASE_DERIVATIONS.get()
}

#[cfg(test)]
pub(crate) fn fail_next_argon2_allocation() {
    FAIL_NEXT_ARGON2_ALLOCATION.set(true);
}

fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<DerivedKey> {
    let (prk, hkdf) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let prk = Zeroizing::new(prk);
    let mut output = Zeroizing::new([0_u8; ROOT_BYTES]);
    hkdf.expand(info, output.as_mut())
        .map_err(|_| Error::InvalidEnvelope)?;
    drop(hkdf);
    drop(prk);
    Ok(DerivedKey(output))
}

fn encrypt_fixed<const PLAINTEXT: usize, const CIPHERTEXT: usize>(
    key: &DerivedKey,
    nonce: &[u8; 12],
    plaintext: &[u8; PLAINTEXT],
    aad: &[u8],
) -> Result<[u8; CIPHERTEXT]> {
    if CIPHERTEXT != PLAINTEXT + TAG_BYTES {
        return Err(Error::InvalidEnvelope);
    }
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| Error::InvalidEnvelope)?;
    let mut output = Zeroizing::new([0_u8; CIPHERTEXT]);
    output[..PLAINTEXT].copy_from_slice(plaintext);
    let tag = cipher
        .encrypt_in_place_detached(&Nonce::from(*nonce), aad, &mut output[..PLAINTEXT])
        .map_err(|_| Error::InvalidEnvelope)?;
    output[PLAINTEXT..].copy_from_slice(&tag);
    Ok(*output)
}

fn decrypt_fixed<const PLAINTEXT: usize, const CIPHERTEXT: usize>(
    key: &DerivedKey,
    nonce: &[u8; 12],
    ciphertext: &[u8; CIPHERTEXT],
    aad: &[u8],
) -> Result<Zeroizing<[u8; PLAINTEXT]>> {
    if CIPHERTEXT != PLAINTEXT + TAG_BYTES {
        return Err(Error::InvalidEnvelope);
    }
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| Error::InvalidEnvelope)?;
    let mut plaintext = Zeroizing::new([0_u8; PLAINTEXT]);
    plaintext.copy_from_slice(&ciphertext[..PLAINTEXT]);
    let tag_bytes: [u8; TAG_BYTES] = ciphertext[PLAINTEXT..]
        .try_into()
        .map_err(|_| Error::InvalidEnvelope)?;
    let tag = Tag::from(tag_bytes);
    cipher
        .decrypt_in_place_detached(&Nonce::from(*nonce), aad, plaintext.as_mut(), &tag)
        .map_err(|_| Error::UnlockFailed)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSPHRASE_VECTOR: &str = include_str!("../../../test-vectors/format-1-passphrase.txt");
    const RECOVERY_SECRET_VECTOR: &str =
        include_str!("../../../test-vectors/format-1-recovery-secret.txt");
    const FIDO_PRESENCE_VECTOR: &str =
        include_str!("../../../test-vectors/format-1-fido-presence.txt");
    const FIDO_UV_VECTOR: &str =
        include_str!("../../../test-vectors/format-1-fido-user-verification.txt");
    const COMBINED_PRESENCE_VECTOR: &str =
        include_str!("../../../test-vectors/format-1-fido-presence-plus-passphrase.txt");
    const COMBINED_UV_VECTOR: &str =
        include_str!("../../../test-vectors/format-1-fido-user-verification-plus-passphrase.txt");
    const MIXED_VECTOR: &str = include_str!("../../../test-vectors/format-1-mixed.txt");

    fn field<'a>(vector: &'a str, name: &str) -> &'a str {
        vector
            .lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
            .unwrap_or_else(|| panic!("missing vector field: {name}"))
    }

    fn hex(vector: &str, name: &str) -> Vec<u8> {
        let value = field(vector, name).as_bytes();
        assert_eq!(value.len() % 2, 0, "odd vector hex field: {name}");
        value
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("invalid vector hex field: {name}"),
                };
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect()
    }

    fn array<const N: usize>(vector: &str, name: &str) -> [u8; N] {
        hex(vector, name)
            .try_into()
            .unwrap_or_else(|_| panic!("wrong vector field length: {name}"))
    }

    fn envelope(vector: &str) -> KeyEnvelope {
        KeyEnvelope::decode(&hex(vector, "envelope")).unwrap()
    }

    fn root(vector: &str) -> RootKey {
        let mut bytes = array(vector, "root_key");
        RootKey::import(&mut bytes)
    }

    fn same_root(left: &RootKey, right: &RootKey) -> bool {
        left.expose(|left| right.expose(|right| left == right))
    }

    fn check_envelope_mac_intermediates(vector: &str, envelope: &KeyEnvelope, root: &RootKey) {
        let canonical_body = envelope.canonical_body().unwrap();
        assert_eq!(canonical_body, hex(vector, "canonical_body"));
        let key_info = transcript::encode(&[
            ENVELOPE_MAC_KEY_DOMAIN,
            &FORMAT,
            envelope.application_id.as_str().as_bytes(),
        ])
        .unwrap();
        assert_eq!(key_info, hex(vector, "envelope_mac_key_info"));
        let key = derive_key(root.bytes(), &envelope.envelope_id, &key_info).unwrap();
        assert_eq!(key.as_bytes(), &array(vector, "envelope_mac_key"));
        let message = transcript::encode(&[ENVELOPE_MAC_DOMAIN, &FORMAT, &canonical_body]).unwrap();
        assert_eq!(message, hex(vector, "envelope_mac_transcript"));
        assert_eq!(
            compute_envelope_mac(envelope, root).unwrap(),
            array(vector, "envelope_mac")
        );
        assert_eq!(envelope.encode(), hex(vector, "envelope"));
    }

    #[test]
    fn passphrase_vector_matches_every_intermediate_with_one_desktop_derivation() {
        let envelope = envelope(PASSPHRASE_VECTOR);
        let recipient = &envelope.recipients[0];
        let RecipientRecord::Passphrase(record) = recipient else {
            panic!("fixture has the wrong suite");
        };
        assert_eq!(
            recipient_context_transcript(
                recipient,
                &envelope.application_id,
                &envelope.envelope_id,
            )
            .unwrap(),
            hex(PASSPHRASE_VECTOR, "recipient_context_transcript")
        );
        assert_eq!(
            recipient_context(recipient, &envelope.application_id, &envelope.envelope_id).unwrap(),
            array(PASSPHRASE_VECTOR, "recipient_context")
        );

        let passphrase = Passphrase::new(hex(PASSPHRASE_VECTOR, "passphrase")).unwrap();
        let key = derive_passphrase_key_inner(
            recipient,
            &envelope.application_id,
            &envelope.envelope_id,
            &passphrase,
            |intermediate| {
                assert_eq!(intermediate, &array(PASSPHRASE_VECTOR, "argon2_output"));
            },
        )
        .unwrap();
        assert_eq!(key.as_bytes(), &array(PASSPHRASE_VECTOR, "passphrase_key"));
        let context =
            passphrase_context(record, &envelope.application_id, &envelope.envelope_id).unwrap();
        assert_eq!(
            transcript::encode(&[PASSPHRASE_KEY_DOMAIN, &context]).unwrap(),
            hex(PASSPHRASE_VECTOR, "passphrase_key_info")
        );
        assert_eq!(
            transcript::encode(&[PASSPHRASE_AAD_DOMAIN, &context]).unwrap(),
            hex(PASSPHRASE_VECTOR, "passphrase_aad")
        );

        let expected_root = root(PASSPHRASE_VECTOR);
        check_envelope_mac_intermediates(PASSPHRASE_VECTOR, &envelope, &expected_root);
        assert_eq!(
            wrap_passphrase_root(
                record,
                &envelope.application_id,
                &envelope.envelope_id,
                &expected_root,
                &key,
            )
            .unwrap(),
            array(PASSPHRASE_VECTOR, "wrapped_root")
        );
        let recovered = unwrap_passphrase_root(
            record,
            &envelope.application_id,
            &envelope.envelope_id,
            &key,
        )
        .unwrap();
        assert!(same_root(&expected_root, &recovered));

        let mut tampered = record.clone();
        tampered.wrapped_root[0] ^= 1;
        assert!(matches!(
            unwrap_passphrase_root(
                &tampered,
                &envelope.application_id,
                &envelope.envelope_id,
                &key,
            ),
            Err(Error::UnlockFailed)
        ));
    }

    #[test]
    fn recovery_secret_vector_matches_every_intermediate() {
        let envelope = envelope(RECOVERY_SECRET_VECTOR);
        let recipient = &envelope.recipients[0];
        let RecipientRecord::RecoverySecret(record) = recipient else {
            panic!("vector must contain a recovery-secret recipient");
        };

        let context_transcript = recovery_secret_context_transcript(
            record,
            &envelope.application_id,
            &envelope.envelope_id,
        )
        .unwrap();
        assert_eq!(
            context_transcript,
            hex(RECOVERY_SECRET_VECTOR, "recipient_context_transcript")
        );
        let context =
            recipient_context(recipient, &envelope.application_id, &envelope.envelope_id).unwrap();
        assert_eq!(context, array(RECOVERY_SECRET_VECTOR, "recipient_context"));

        let mut secret_bytes = array(RECOVERY_SECRET_VECTOR, "recovery_secret");
        let secret = RecoverySecret::import(&mut secret_bytes);
        assert_eq!(secret_bytes, [0; 32]);
        let key = derive_recovery_secret_key(
            record,
            &envelope.application_id,
            &envelope.envelope_id,
            &secret,
        )
        .unwrap();
        assert_eq!(
            key.as_bytes(),
            &array(RECOVERY_SECRET_VECTOR, "recovery_key")
        );
        assert_eq!(
            transcript::encode(&[RECOVERY_SECRET_KEY_DOMAIN, &context]).unwrap(),
            hex(RECOVERY_SECRET_VECTOR, "recovery_key_info")
        );
        assert_eq!(
            transcript::encode(&[RECOVERY_SECRET_AAD_DOMAIN, &context]).unwrap(),
            hex(RECOVERY_SECRET_VECTOR, "recovery_aad")
        );

        let expected_root = root(RECOVERY_SECRET_VECTOR);
        check_envelope_mac_intermediates(RECOVERY_SECRET_VECTOR, &envelope, &expected_root);
        let wrapped = wrap_recovery_secret_root(
            record,
            &envelope.application_id,
            &envelope.envelope_id,
            &expected_root,
            &key,
        )
        .unwrap();
        assert_eq!(wrapped, array(RECOVERY_SECRET_VECTOR, "wrapped_root"));
        let recovered = unwrap_recovery_secret_root(
            record,
            &envelope.application_id,
            &envelope.envelope_id,
            &key,
        )
        .unwrap();
        assert_eq!(recovered.bytes(), expected_root.bytes());
    }

    #[test]
    fn passphrase_wrapping_rejects_context_transplants() {
        let envelope = envelope(PASSPHRASE_VECTOR);
        let RecipientRecord::Passphrase(record) = &envelope.recipients[0] else {
            panic!("fixture has the wrong suite");
        };
        let passphrase = Passphrase::new(hex(PASSPHRASE_VECTOR, "passphrase")).unwrap();
        let key = derive_passphrase_key(
            &envelope.recipients[0],
            &envelope.application_id,
            &envelope.envelope_id,
            &passphrase,
        )
        .unwrap();

        let rejects = |candidate: &PassphraseRecipient,
                       application: &ApplicationId,
                       envelope_id: &[u8; 32]| {
            assert!(matches!(
                unwrap_passphrase_root(candidate, application, envelope_id, &key),
                Err(Error::UnlockFailed)
            ));
        };

        let other_application = ApplicationId::new("other.example").unwrap();
        rejects(record, &other_application, &envelope.envelope_id);

        let mut other_envelope_id = envelope.envelope_id;
        other_envelope_id[0] ^= 1;
        rejects(record, &envelope.application_id, &other_envelope_id);

        let mut candidate = record.clone();
        candidate.id.0[0] ^= 1;
        rejects(&candidate, &envelope.application_id, &envelope.envelope_id);

        let mut candidate = record.clone();
        candidate.kdf.parameters = crate::PassphraseParameters::new(64 * 1024, 4, 2).unwrap();
        rejects(&candidate, &envelope.application_id, &envelope.envelope_id);

        let mut candidate = record.clone();
        candidate.kdf.salt[0] ^= 1;
        rejects(&candidate, &envelope.application_id, &envelope.envelope_id);

        let mut candidate = record.clone();
        candidate.passphrase_nonce[0] ^= 1;
        rejects(&candidate, &envelope.application_id, &envelope.envelope_id);
    }

    #[test]
    fn fido_wrapping_rejects_every_context_transplant() {
        let envelope = envelope(FIDO_PRESENCE_VECTOR);
        let RecipientRecord::Fido(record) = &envelope.recipients[0] else {
            panic!("fixture has the wrong suite");
        };
        let key = derive_fido_key(
            &envelope.recipients[0],
            &envelope.application_id,
            &envelope.envelope_id,
            &array(FIDO_PRESENCE_VECTOR, "verified_prf_result"),
        )
        .unwrap();
        let rejects =
            |candidate: &FidoRecipient, application: &ApplicationId, envelope_id: &[u8; 32]| {
                assert!(matches!(
                    unwrap_fido_root(candidate, application, envelope_id, &key),
                    Err(Error::UnlockFailed)
                ));
            };

        let other_application = ApplicationId::new("other.example").unwrap();
        rejects(record, &other_application, &envelope.envelope_id);

        let mut other_envelope_id = envelope.envelope_id;
        other_envelope_id[0] ^= 1;
        rejects(record, &envelope.application_id, &other_envelope_id);

        let mut candidate = record.clone();
        candidate.id.0[0] ^= 1;
        rejects(&candidate, &envelope.application_id, &envelope.envelope_id);

        let mut candidate = record.clone();
        candidate.credential_id[0] ^= 1;
        rejects(&candidate, &envelope.application_id, &envelope.envelope_id);

        let mut candidate = record.clone();
        candidate.public_key =
            crate::envelope::PublicKey64::new(array(FIDO_UV_VECTOR, "public_key")).unwrap();
        rejects(&candidate, &envelope.application_id, &envelope.envelope_id);

        let mut candidate = record.clone();
        candidate.policy = crate::FidoPolicy::UserVerification;
        rejects(&candidate, &envelope.application_id, &envelope.envelope_id);

        let mut candidate = record.clone();
        candidate.prf_nonce[0] ^= 1;
        rejects(&candidate, &envelope.application_id, &envelope.envelope_id);

        let mut candidate = record.clone();
        candidate.fido_nonce[0] ^= 1;
        rejects(&candidate, &envelope.application_id, &envelope.envelope_id);

        let mut candidate = record.clone();
        candidate.wrapped_root[0] ^= 1;
        rejects(&candidate, &envelope.application_id, &envelope.envelope_id);
    }

    #[test]
    fn combined_outer_wrapping_binds_both_factor_contexts_and_suite() {
        let envelope = envelope(COMBINED_UV_VECTOR);
        let RecipientRecord::FidoAndPassphrase(record) = &envelope.recipients[0] else {
            panic!("fixture has the wrong suite");
        };
        let key = derive_fido_key(
            &envelope.recipients[0],
            &envelope.application_id,
            &envelope.envelope_id,
            &array(COMBINED_UV_VECTOR, "verified_prf_result"),
        )
        .unwrap();
        let rejects = |candidate: &FidoAndPassphraseRecipient| {
            assert!(matches!(
                unwrap_combined_outer(
                    candidate,
                    &envelope.application_id,
                    &envelope.envelope_id,
                    &key,
                ),
                Err(Error::UnlockFailed)
            ));
        };

        let mut candidate = record.clone();
        candidate.id.0[0] ^= 1;
        rejects(&candidate);

        let mut candidate = record.clone();
        candidate.credential_id[0] ^= 1;
        rejects(&candidate);

        let mut candidate = record.clone();
        candidate.public_key =
            crate::envelope::PublicKey64::new(array(FIDO_PRESENCE_VECTOR, "public_key")).unwrap();
        rejects(&candidate);

        let mut candidate = record.clone();
        candidate.policy = crate::FidoPolicy::Presence;
        rejects(&candidate);

        let mut candidate = record.clone();
        candidate.prf_nonce[0] ^= 1;
        rejects(&candidate);

        let mut candidate = record.clone();
        candidate.fido_nonce[0] ^= 1;
        rejects(&candidate);

        let mut candidate = record.clone();
        candidate.kdf.parameters = crate::PassphraseParameters::DESKTOP;
        rejects(&candidate);

        let mut candidate = record.clone();
        candidate.kdf.salt[0] ^= 1;
        rejects(&candidate);

        let mut candidate = record.clone();
        candidate.passphrase_nonce[0] ^= 1;
        rejects(&candidate);

        let mut candidate = record.clone();
        candidate.wrapped_root[0] ^= 1;
        rejects(&candidate);

        let fido_shape = RecipientRecord::Fido(FidoRecipient {
            id: record.id,
            label: record.label.clone(),
            credential_id: record.credential_id.clone(),
            public_key: record.public_key.clone(),
            policy: record.policy,
            prf_nonce: record.prf_nonce,
            fido_nonce: record.fido_nonce,
            wrapped_root: record.wrapped_root[..WRAPPED_ROOT_BYTES]
                .try_into()
                .unwrap(),
        });
        assert_ne!(
            recipient_context(&fido_shape, &envelope.application_id, &envelope.envelope_id,)
                .unwrap(),
            recipient_context(
                &envelope.recipients[0],
                &envelope.application_id,
                &envelope.envelope_id,
            )
            .unwrap()
        );
    }

    #[test]
    fn all_fido_contexts_prf_inputs_keys_and_envelope_macs_match_vectors() {
        for vector in [
            FIDO_PRESENCE_VECTOR,
            FIDO_UV_VECTOR,
            COMBINED_PRESENCE_VECTOR,
            COMBINED_UV_VECTOR,
        ] {
            let envelope = envelope(vector);
            let recipient = &envelope.recipients[0];
            assert_eq!(
                recipient_context_transcript(
                    recipient,
                    &envelope.application_id,
                    &envelope.envelope_id,
                )
                .unwrap(),
                hex(vector, "recipient_context_transcript")
            );
            assert_eq!(
                recipient_context(recipient, &envelope.application_id, &envelope.envelope_id)
                    .unwrap(),
                array(vector, "recipient_context")
            );
            let input =
                prf_input(recipient, &envelope.application_id, &envelope.envelope_id).unwrap();
            assert_eq!(input, array(vector, "prf_input"));
            assert_eq!(
                prf_input_transcript(
                    &recipient_context(recipient, &envelope.application_id, &envelope.envelope_id,)
                        .unwrap()
                )
                .unwrap(),
                hex(vector, "prf_input_transcript")
            );
            let key = derive_fido_key(
                recipient,
                &envelope.application_id,
                &envelope.envelope_id,
                &array(vector, "verified_prf_result"),
            )
            .unwrap();
            assert_eq!(key.as_bytes(), &array(vector, "fido_key"));
            let context =
                recipient_context(recipient, &envelope.application_id, &envelope.envelope_id)
                    .unwrap();
            assert_eq!(
                transcript::encode(&[FIDO_KEY_DOMAIN, &context]).unwrap(),
                hex(vector, "fido_key_info")
            );

            let expected_root = root(vector);
            check_envelope_mac_intermediates(vector, &envelope, &expected_root);
            assert!(envelope_mac_matches(&envelope, &expected_root).unwrap());
            verify_envelope_mac(&envelope, &expected_root).unwrap();
        }
    }

    #[test]
    fn fido_only_vectors_wrap_and_unwrap_exactly() {
        for vector in [FIDO_PRESENCE_VECTOR, FIDO_UV_VECTOR] {
            let envelope = envelope(vector);
            let recipient = &envelope.recipients[0];
            let RecipientRecord::Fido(record) = recipient else {
                panic!("fixture has the wrong suite");
            };
            let key = derive_fido_key(
                recipient,
                &envelope.application_id,
                &envelope.envelope_id,
                &array(vector, "verified_prf_result"),
            )
            .unwrap();
            let context =
                fido_context(record, &envelope.application_id, &envelope.envelope_id).unwrap();
            assert_eq!(
                transcript::encode(&[FIDO_AAD_DOMAIN, &context]).unwrap(),
                hex(vector, "fido_aad")
            );
            let expected_root = root(vector);
            assert_eq!(
                wrap_fido_root(
                    record,
                    &envelope.application_id,
                    &envelope.envelope_id,
                    &expected_root,
                    &key,
                )
                .unwrap(),
                array(vector, "wrapped_root")
            );
            let recovered = unwrap_fido_root(
                record,
                &envelope.application_id,
                &envelope.envelope_id,
                &key,
            )
            .unwrap();
            assert!(same_root(&expected_root, &recovered));
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn non_default_combined_vector_matches_both_layers_and_split_unwrap() {
        let envelope = envelope(COMBINED_UV_VECTOR);
        let recipient = &envelope.recipients[0];
        let RecipientRecord::FidoAndPassphrase(record) = recipient else {
            panic!("fixture has the wrong suite");
        };
        let passphrase = Passphrase::new(hex(COMBINED_UV_VECTOR, "passphrase")).unwrap();
        let passphrase_key = derive_passphrase_key(
            recipient,
            &envelope.application_id,
            &envelope.envelope_id,
            &passphrase,
        )
        .unwrap();
        assert_eq!(
            passphrase_key.as_bytes(),
            &array(COMBINED_UV_VECTOR, "passphrase_key")
        );
        let fido_key = derive_fido_key(
            recipient,
            &envelope.application_id,
            &envelope.envelope_id,
            &array(COMBINED_UV_VECTOR, "verified_prf_result"),
        )
        .unwrap();
        let context =
            combined_context(record, &envelope.application_id, &envelope.envelope_id).unwrap();
        assert_eq!(
            transcript::encode(&[PASSPHRASE_KEY_DOMAIN, &context]).unwrap(),
            hex(COMBINED_UV_VECTOR, "passphrase_key_info")
        );
        assert_eq!(
            transcript::encode(&[COMBINED_PASSPHRASE_AAD_DOMAIN, &context]).unwrap(),
            hex(COMBINED_UV_VECTOR, "combined_passphrase_aad")
        );
        assert_eq!(
            transcript::encode(&[COMBINED_FIDO_AAD_DOMAIN, &context]).unwrap(),
            hex(COMBINED_UV_VECTOR, "combined_fido_aad")
        );

        let expected_root = root(COMBINED_UV_VECTOR);
        let inner = wrap_combined_inner(
            record,
            &envelope.application_id,
            &envelope.envelope_id,
            &expected_root,
            &passphrase_key,
        )
        .unwrap();
        assert_eq!(
            inner.as_slice(),
            hex(COMBINED_UV_VECTOR, "inner_ciphertext")
        );
        let outer = wrap_combined_outer(
            record,
            &envelope.application_id,
            &envelope.envelope_id,
            &inner,
            &fido_key,
        )
        .unwrap();
        assert_eq!(outer, array(COMBINED_UV_VECTOR, "wrapped_root"));
        assert_eq!(
            wrap_combined_root(
                record,
                &envelope.application_id,
                &envelope.envelope_id,
                &expected_root,
                &passphrase_key,
                &fido_key,
            )
            .unwrap(),
            outer
        );

        let recovered_inner = unwrap_combined_outer(
            record,
            &envelope.application_id,
            &envelope.envelope_id,
            &fido_key,
        )
        .unwrap();
        drop(fido_key);
        assert_eq!(recovered_inner.as_slice(), inner.as_slice());
        let recovered = unwrap_combined_inner(
            record,
            &envelope.application_id,
            &envelope.envelope_id,
            &recovered_inner,
            &passphrase_key,
        )
        .unwrap();
        assert!(same_root(&expected_root, &recovered));

        let mut outer_tampered = record.clone();
        outer_tampered.wrapped_root[0] ^= 1;
        assert!(matches!(
            unwrap_combined_outer(
                &outer_tampered,
                &envelope.application_id,
                &envelope.envelope_id,
                // The original key was dropped above to exercise caller ordering.
                &derive_fido_key(
                    recipient,
                    &envelope.application_id,
                    &envelope.envelope_id,
                    &array(COMBINED_UV_VECTOR, "verified_prf_result"),
                )
                .unwrap(),
            ),
            Err(Error::UnlockFailed)
        ));
        let mut inner_tampered = Zeroizing::new([0_u8; WRAPPED_ROOT_BYTES]);
        inner_tampered.copy_from_slice(recovered_inner.as_ref());
        inner_tampered[0] ^= 1;
        assert!(matches!(
            unwrap_combined_inner(
                record,
                &envelope.application_id,
                &envelope.envelope_id,
                &inner_tampered,
                &passphrase_key,
            ),
            Err(Error::UnlockFailed)
        ));
    }

    #[test]
    fn envelope_mac_mismatch_maps_to_authentication_failure() {
        let envelope = envelope(FIDO_PRESENCE_VECTOR);
        let wrong = RootKey::import(&mut [0xA5; 32]);
        assert!(!envelope_mac_matches(&envelope, &wrong).unwrap());
        assert!(matches!(
            verify_envelope_mac(&envelope, &wrong),
            Err(Error::EnvelopeAuthenticationFailed)
        ));
    }

    #[test]
    fn envelope_mac_rejects_global_metadata_and_recipient_set_changes() {
        let envelope = envelope(MIXED_VECTOR);
        let root = root(MIXED_VECTOR);

        let rejects = |candidate: &KeyEnvelope| {
            assert!(!envelope_mac_matches(candidate, &root).unwrap());
            assert!(matches!(
                verify_envelope_mac(candidate, &root),
                Err(Error::EnvelopeAuthenticationFailed)
            ));
        };

        let mut candidate = envelope.clone();
        candidate.application_id = ApplicationId::new("other.example").unwrap();
        rejects(&candidate);

        let mut candidate = envelope.clone();
        candidate.envelope_id[0] ^= 1;
        rejects(&candidate);

        for index in 0..envelope.recipients.len() {
            let mut candidate = envelope.clone();
            match &mut candidate.recipients[index] {
                RecipientRecord::Passphrase(record) => record.label.push('x'),
                RecipientRecord::RecoverySecret(record) => record.label.push('x'),
                RecipientRecord::Fido(record) => record.label.push('x'),
                RecipientRecord::FidoAndPassphrase(record) => record.label.push('x'),
            }
            rejects(&candidate);
        }

        let mut candidate = envelope.clone();
        candidate.recipients.remove(0);
        rejects(&candidate);

        let mut candidate = envelope.clone();
        candidate.recipients.swap(0, 1);
        rejects(&candidate);

        let mut candidate = envelope;
        candidate.mac[0] ^= 1;
        rejects(&candidate);
    }

    #[test]
    fn mixed_recipient_body_and_whole_envelope_mac_match_vector() {
        let envelope = envelope(MIXED_VECTOR);
        assert_eq!(envelope.recipients.len(), 6);
        let root = root(MIXED_VECTOR);
        check_envelope_mac_intermediates(MIXED_VECTOR, &envelope, &root);
        verify_envelope_mac(&envelope, &root).unwrap();
    }
}
