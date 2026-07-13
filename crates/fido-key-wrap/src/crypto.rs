use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    ApplicationId, Error, KeyEnvelope, Passphrase, Result, RootKey, envelope::RecipientRecord,
    transcript,
};

const ARGON2_MEMORY_KIB: u32 = 65_536;
const ARGON2_PASSES: u32 = 3;
const ARGON2_LANES: u32 = 4;

pub(crate) fn recipient_context(
    recipient: &RecipientRecord,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
) -> Result<[u8; 32]> {
    let header = recipient.crypto_header(application, envelope_id)?;
    let encoded = transcript::encode(&[b"fido_key_wrap/recipient_context/v1", &header])?;
    Ok(Sha256::digest(encoded).into())
}

pub(crate) fn prf_input(
    recipient: &RecipientRecord,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
) -> Result<[u8; 32]> {
    let context = recipient_context(recipient, application, envelope_id)?;
    let encoded = transcript::encode(&[b"fido_key_wrap/prf_input/v1", &context])?;
    Ok(Sha256::digest(encoded).into())
}

pub(crate) fn wrap_root(
    recipient: &RecipientRecord,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
    root: &RootKey,
    prf_result: &[u8; 32],
    passphrase: Option<&Passphrase>,
) -> Result<Vec<u8>> {
    let header = recipient.crypto_header(application, envelope_id)?;
    let context = recipient_context(recipient, application, envelope_id)?;
    let token_key = derive_key(
        prf_result,
        envelope_id,
        &transcript::encode(&[b"fido_key_wrap/token_key/v1", &context])?,
    )?;
    let token_aad = transcript::encode(&[b"fido_key_wrap/token_aad/v1", &header])?;

    if let Some(passphrase_header) = &recipient.passphrase {
        let passphrase = passphrase.ok_or(Error::InvalidPassphrase)?;
        let passphrase_key =
            derive_passphrase_key(passphrase, &passphrase_header.salt, envelope_id, &context)?;
        let passphrase_aad = transcript::encode(&[b"fido_key_wrap/passphrase_aad/v1", &header])?;
        let inner = encrypt(
            &passphrase_key,
            &passphrase_header.nonce,
            root.bytes(),
            &passphrase_aad,
        )?;
        encrypt(&token_key, &recipient.token_nonce, &inner, &token_aad)
    } else {
        if passphrase.is_some() {
            return Err(Error::InvalidPassphrase);
        }
        encrypt(&token_key, &recipient.token_nonce, root.bytes(), &token_aad)
    }
}

pub(crate) fn unwrap_token_layer(
    recipient: &RecipientRecord,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
    prf_result: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>> {
    let header = recipient.crypto_header(application, envelope_id)?;
    let context = recipient_context(recipient, application, envelope_id)?;
    let token_key = derive_key(
        prf_result,
        envelope_id,
        &transcript::encode(&[b"fido_key_wrap/token_key/v1", &context])?,
    )?;
    let token_aad = transcript::encode(&[b"fido_key_wrap/token_aad/v1", &header])?;
    let outer = decrypt(
        &token_key,
        &recipient.token_nonce,
        &recipient.wrapped_key,
        &token_aad,
    )?;
    Ok(Zeroizing::new(outer))
}

pub(crate) fn finish_unwrap(
    recipient: &RecipientRecord,
    application: &ApplicationId,
    envelope_id: &[u8; 32],
    outer_plaintext: &[u8],
    passphrase: Option<&Passphrase>,
) -> Result<RootKey> {
    let header = recipient.crypto_header(application, envelope_id)?;
    let context = recipient_context(recipient, application, envelope_id)?;
    let mut plaintext = if let Some(passphrase_header) = &recipient.passphrase {
        if outer_plaintext.len() != 48 {
            return Err(Error::UnlockFailed);
        }
        let passphrase = passphrase.ok_or(Error::UnlockFailed)?;
        let passphrase_key =
            derive_passphrase_key(passphrase, &passphrase_header.salt, envelope_id, &context)?;
        let passphrase_aad = transcript::encode(&[b"fido_key_wrap/passphrase_aad/v1", &header])?;
        decrypt(
            &passphrase_key,
            &passphrase_header.nonce,
            outer_plaintext,
            &passphrase_aad,
        )?
    } else {
        if outer_plaintext.len() != 32 || passphrase.is_some() {
            return Err(Error::UnlockFailed);
        }
        outer_plaintext.to_vec()
    };
    if plaintext.len() != 32 {
        plaintext.zeroize();
        return Err(Error::UnlockFailed);
    }
    let root = RootKey::copy_from(&plaintext)?;
    plaintext.zeroize();
    Ok(root)
}

pub(crate) fn compute_envelope_mac(envelope: &KeyEnvelope, root: &RootKey) -> Result<[u8; 32]> {
    let key_info = transcript::encode(&[
        b"fido_key_wrap/envelope_mac_key/v1",
        envelope.application_id.as_str().as_bytes(),
    ])?;
    let key = derive_key(root.bytes(), &envelope.envelope_id, &key_info)?;
    let body = envelope.canonical_body()?;
    let message = transcript::encode(&[b"fido_key_wrap/envelope_mac/v1", &body])?;
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key.as_ref())
        .map_err(|_| Error::InvalidEnvelope)?;
    mac.update(&message);
    Ok(mac.finalize().into_bytes().into())
}

pub(crate) fn verify_envelope_mac(envelope: &KeyEnvelope, root: &RootKey) -> Result<()> {
    let expected = compute_envelope_mac(envelope, root)?;
    if bool::from(expected.ct_eq(&envelope.mac)) {
        Ok(())
    } else {
        Err(Error::WrongRootKey)
    }
}

fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut output = Zeroizing::new([0u8; 32]);
    hkdf.expand(info, output.as_mut())
        .map_err(|_| Error::InvalidEnvelope)?;
    Ok(output)
}

fn derive_passphrase_key(
    passphrase: &Passphrase,
    salt: &[u8; 16],
    envelope_id: &[u8; 32],
    context: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_PASSES, ARGON2_LANES, Some(32))
        .map_err(|_| Error::InvalidEnvelope)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut intermediate = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, intermediate.as_mut())
        .map_err(|_| Error::UnlockFailed)?;
    let info = transcript::encode(&[b"fido_key_wrap/passphrase_key/v1", context])?;
    derive_key(intermediate.as_ref(), envelope_id, &info)
}

fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::InvalidEnvelope)?;
    cipher
        .encrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::UnlockFailed)
}

fn decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::InvalidEnvelope)?;
    cipher
        .decrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::UnlockFailed)
}

#[cfg(test)]
mod tests {
    use crate::{
        KeyEnvelope, RecipientId,
        envelope::{PassphraseHeader, PublicKey64, RecipientRecord, compute_recipient_id},
        policy,
    };

    use super::*;

    const TOKEN_VECTOR: &str = include_str!("../../../test-vectors/v1-token-only.txt");
    const PASSPHRASE_VECTOR: &str = include_str!("../../../test-vectors/v1-passphrase.txt");

    fn field<'a>(vector: &'a str, name: &str) -> &'a str {
        vector
            .lines()
            .find_map(|line| {
                line.strip_prefix(name)
                    .and_then(|rest| rest.strip_prefix('='))
            })
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

    #[allow(clippy::too_many_lines)]
    fn check_vector(vector: &str, policy: crate::RecipientPolicy) {
        let application = ApplicationId::new(field(vector, "application_id")).unwrap();
        let envelope_id = array(vector, "envelope_id");
        let public_key = PublicKey64::new(array(vector, "public_key")).unwrap();
        let credential_id = hex(vector, "credential_id");
        let id = compute_recipient_id(&application, &credential_id, &public_key, policy).unwrap();
        assert_eq!(id.to_bytes(), array(vector, "recipient_id"));

        let passphrase_header = policy.has_passphrase().then(|| PassphraseHeader {
            salt: array(vector, "passphrase_salt"),
            nonce: array(vector, "passphrase_nonce"),
        });

        let mut recipient = RecipientRecord {
            id,
            label: field(vector, "label").to_owned(),
            credential_id,
            public_key,
            policy,
            credential_protection: RecipientRecord::expected_credential_protection(policy.token),
            prf_nonce: array(vector, "prf_nonce"),
            token_nonce: array(vector, "token_nonce"),
            passphrase: passphrase_header,
            wrapped_key: Vec::new(),
        };
        assert_eq!(
            recipient.crypto_header(&application, &envelope_id).unwrap(),
            hex(vector, "recipient_header")
        );
        assert_eq!(
            recipient_context(&recipient, &application, &envelope_id).unwrap(),
            array(vector, "recipient_context")
        );
        assert_eq!(
            prf_input(&recipient, &application, &envelope_id).unwrap(),
            array(vector, "prf_input")
        );

        let context = recipient_context(&recipient, &application, &envelope_id).unwrap();
        let token_info = transcript::encode(&[b"fido_key_wrap/token_key/v1", &context]).unwrap();
        assert_eq!(
            *derive_key(
                &array::<32>(vector, "prf_result"),
                &envelope_id,
                &token_info
            )
            .unwrap(),
            array(vector, "token_key")
        );

        let passphrase = policy
            .has_passphrase()
            .then(|| Passphrase::new(hex(vector, "passphrase")).unwrap());
        if let (Some(header), Some(passphrase)) = (&recipient.passphrase, &passphrase) {
            let params =
                Params::new(ARGON2_MEMORY_KIB, ARGON2_PASSES, ARGON2_LANES, Some(32)).unwrap();
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let mut intermediate = Zeroizing::new([0; 32]);
            argon2
                .hash_password_into(passphrase.as_bytes(), &header.salt, intermediate.as_mut())
                .unwrap();
            assert_eq!(*intermediate, array(vector, "argon2_intermediate"));
            assert_eq!(
                *derive_passphrase_key(passphrase, &header.salt, &envelope_id, &context).unwrap(),
                array(vector, "passphrase_key")
            );
        }

        let root = RootKey::import(array(vector, "root_key"));
        recipient.wrapped_key = wrap_root(
            &recipient,
            &application,
            &envelope_id,
            &root,
            &array(vector, "prf_result"),
            passphrase.as_ref(),
        )
        .unwrap();
        assert_eq!(recipient.wrapped_key, hex(vector, "wrapped_key"));

        let outer = unwrap_token_layer(
            &recipient,
            &application,
            &envelope_id,
            &array(vector, "prf_result"),
        )
        .unwrap();
        if policy.has_passphrase() {
            assert_eq!(outer.as_slice(), hex(vector, "inner_wrapped_key"));
        }
        let unwrapped = finish_unwrap(
            &recipient,
            &application,
            &envelope_id,
            &outer,
            passphrase.as_ref(),
        )
        .unwrap();
        assert!(root.expose(|root| unwrapped.expose(|unwrapped| root == unwrapped)));

        let mut envelope = KeyEnvelope {
            application_id: application,
            envelope_id,
            recipients: vec![recipient],
            mac: [0; 32],
        };
        assert_eq!(
            envelope.canonical_body().unwrap(),
            hex(vector, "canonical_body")
        );
        envelope.mac = compute_envelope_mac(&envelope, &root).unwrap();
        assert_eq!(envelope.mac, array(vector, "envelope_mac"));
        assert_eq!(envelope.encode(), hex(vector, "envelope"));

        let decoded = KeyEnvelope::decode(&envelope.encode()).unwrap();
        verify_envelope_mac(&decoded, &root).unwrap();
        assert_eq!(
            decoded.recipients[0].id,
            RecipientId(array(vector, "recipient_id"))
        );
    }

    #[test]
    fn matches_independent_token_only_vector() {
        check_vector(TOKEN_VECTOR, policy::presence());
    }

    #[test]
    fn matches_independent_passphrase_vector() {
        check_vector(PASSPHRASE_VECTOR, policy::user_verified().and_passphrase());
    }
}
