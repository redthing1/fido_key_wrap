#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "argon2-cffi==25.1.0",
#     "cryptography==47.0.0",
# ]
# ///
"""Independent version-1 vector generator; writes key=value lines to stdout."""

import argparse
import hashlib
import hmac

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def transcript(*fields: bytes) -> bytes:
    return len(fields).to_bytes(4, "big") + b"".join(
        len(field).to_bytes(4, "big") + field for field in fields
    )


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    output = b""
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(
            prk, previous + info + bytes([counter]), hashlib.sha256
        ).digest()
        output += previous
        counter += 1
    return output[:length]


def cbor_head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 256:
        return bytes([(major << 5) | 24, value])
    if value < 65536:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value < 2**32:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")


def cbor_uint(value: int) -> bytes:
    return cbor_head(0, value)


def cbor_bytes(value: bytes) -> bytes:
    return cbor_head(2, len(value)) + value


def cbor_text(value: str) -> bytes:
    encoded = value.encode()
    return cbor_head(3, len(encoded)) + encoded


def cbor_array(*values: bytes) -> bytes:
    return cbor_head(4, len(values)) + b"".join(values)


def calculate(with_passphrase: bool) -> dict[str, str | bytes]:
    application = (
        b"org.example.fkw-pass-vector"
        if with_passphrase
        else b"org.example.fkw-vector"
    )
    label = "primary"
    envelope_id = bytes(range(0x00, 0x20))
    credential_id = bytes.fromhex(
        "102132435465768798a9bacbdcedfe0f"
        if with_passphrase
        else "00112233445566778899aabbccddeeff"
    )
    public_key = bytes.fromhex(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    )
    token = b"\x02" if with_passphrase else b"\x01"
    factor = b"\x01" if with_passphrase else b"\x00"
    protection = b"\x03" if with_passphrase else b"\x02"
    prf_nonce = bytes(range(0x20, 0x40))
    token_nonce = bytes(range(0xA0, 0xAC))
    prf_result = bytes(range(0x40, 0x60))
    root_key = bytes(range(0x60, 0x80))
    passphrase = b"correct horse battery staple"
    passphrase_salt = bytes(range(0xB0, 0xC0)) if with_passphrase else b""
    passphrase_nonce = bytes(range(0xC0, 0xCC)) if with_passphrase else b""

    recipient_id = hashlib.sha256(
        transcript(
            b"fido_key_wrap/recipient_id/v1",
            application,
            credential_id,
            public_key,
            token,
            factor,
        )
    ).digest()
    recipient_header = transcript(
        b"fido_key_wrap/recipient_header/v1",
        b"\x01",
        b"\x01",
        application,
        envelope_id,
        recipient_id,
        credential_id,
        public_key,
        token,
        protection,
        factor,
        prf_nonce,
        token_nonce,
        passphrase_salt,
        passphrase_nonce,
    )
    context = hashlib.sha256(
        transcript(b"fido_key_wrap/recipient_context/v1", recipient_header)
    ).digest()
    prf_input = hashlib.sha256(
        transcript(b"fido_key_wrap/prf_input/v1", context)
    ).digest()
    token_key = hkdf(
        prf_result,
        envelope_id,
        transcript(b"fido_key_wrap/token_key/v1", context),
    )
    token_aad = transcript(b"fido_key_wrap/token_aad/v1", recipient_header)

    if with_passphrase:
        intermediate = hash_secret_raw(
            passphrase,
            passphrase_salt,
            time_cost=3,
            memory_cost=65_536,
            parallelism=4,
            hash_len=32,
            type=Type.ID,
            version=19,
        )
        passphrase_key = hkdf(
            intermediate,
            envelope_id,
            transcript(b"fido_key_wrap/passphrase_key/v1", context),
        )
        passphrase_aad = transcript(
            b"fido_key_wrap/passphrase_aad/v1", recipient_header
        )
        inner = AESGCM(passphrase_key).encrypt(
            passphrase_nonce, root_key, passphrase_aad
        )
        wrapped_key = AESGCM(token_key).encrypt(token_nonce, inner, token_aad)
        passphrase_field = cbor_array(
            cbor_uint(1), cbor_bytes(passphrase_salt), cbor_bytes(passphrase_nonce)
        )
    else:
        intermediate = b""
        passphrase_key = b""
        inner = b""
        wrapped_key = AESGCM(token_key).encrypt(token_nonce, root_key, token_aad)
        passphrase_field = b"\xf6"

    recipient = cbor_array(
        cbor_uint(1),
        cbor_bytes(recipient_id),
        cbor_text(label),
        cbor_bytes(credential_id),
        cbor_bytes(public_key),
        cbor_uint(token[0]),
        cbor_uint(factor[0]),
        cbor_uint(protection[0]),
        cbor_bytes(prf_nonce),
        cbor_bytes(token_nonce),
        passphrase_field,
        cbor_bytes(wrapped_key),
    )
    body = cbor_array(
        cbor_uint(1),
        cbor_text(application.decode()),
        cbor_bytes(envelope_id),
        cbor_array(recipient),
    )
    envelope_mac_key = hkdf(
        root_key,
        envelope_id,
        transcript(b"fido_key_wrap/envelope_mac_key/v1", application),
    )
    envelope_mac = hmac.new(
        envelope_mac_key,
        transcript(b"fido_key_wrap/envelope_mac/v1", body),
        hashlib.sha256,
    ).digest()
    envelope = b"FKW1" + cbor_array(
        cbor_uint(1),
        cbor_text(application.decode()),
        cbor_bytes(envelope_id),
        cbor_array(recipient),
        cbor_bytes(envelope_mac),
    )
    return {
        "application_id": application.decode(),
        "label": label,
        "envelope_id": envelope_id,
        "credential_id": credential_id,
        "public_key": public_key,
        "prf_nonce": prf_nonce,
        "token_nonce": token_nonce,
        "prf_result": prf_result,
        "root_key": root_key,
        "passphrase": passphrase if with_passphrase else b"",
        "passphrase_salt": passphrase_salt,
        "passphrase_nonce": passphrase_nonce,
        "recipient_id": recipient_id,
        "recipient_header": recipient_header,
        "recipient_context": context,
        "prf_input": prf_input,
        "argon2_intermediate": intermediate,
        "passphrase_key": passphrase_key,
        "inner_wrapped_key": inner,
        "token_key": token_key,
        "wrapped_key": wrapped_key,
        "canonical_body": body,
        "envelope_mac": envelope_mac,
        "envelope": envelope,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("kind", choices=("token", "passphrase"))
    args = parser.parse_args()
    for name, value in calculate(args.kind == "passphrase").items():
        if value != b"":
            print(f"{name}={value.hex() if isinstance(value, bytes) else value}")


if __name__ == "__main__":
    main()
