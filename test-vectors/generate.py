#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "argon2-cffi==25.1.0",
#     "cryptography==47.0.0",
# ]
# ///
"""Generate deterministic, independent format-1 interoperability vectors."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


FORMAT = 1
SUITE_PASSPHRASE = 1
SUITE_FIDO = 2
SUITE_COMBINED = 3
SUITE_RECOVERY_SECRET = 4
SUITE_MANAGED_FIDO = 5
SUITE_FIDO_LOCAL_SECRET = 6
FIDO_SUITES = (
    SUITE_FIDO,
    SUITE_COMBINED,
    SUITE_MANAGED_FIDO,
    SUITE_FIDO_LOCAL_SECRET,
)
POLICY_PRESENCE = 1
POLICY_USER_VERIFICATION = 2
KDF_ARGON2ID = 1

APPLICATION_ID = "vectors.fido-key-wrap.example"
ROOT_KEY = hashlib.sha256(b"fido-key-wrap independent vector root").digest()
PASSPHRASE = b"correct horse battery staple"
RECOVERY_SECRET = hashlib.sha256(
    b"fido-key-wrap independent vector recovery secret"
).digest()
LOCAL_SECRET = hashlib.sha256(
    b"fido-key-wrap independent vector local secret"
).digest()
FIDO_LOCAL_SECRET_ENVELOPE_ID = hashlib.sha256(
    b"fido-key-wrap independent vector fido local secret envelope"
).digest()
DESKTOP_KDF = (262_144, 3, 4)
NON_DEFAULT_KDF = (65_536, 4, 2)

DOMAIN_RECIPIENT_CONTEXT = b"fido_key_wrap/format_1/recipient_context"
DOMAIN_PASSPHRASE_KEY = b"fido_key_wrap/format_1/passphrase_key"
DOMAIN_FIDO_KEY = b"fido_key_wrap/format_1/fido_key"
DOMAIN_RECOVERY_SECRET_KEY = (
    b"fido_key_wrap/format_1/recovery_secret_key"
)
DOMAIN_PRF_INPUT = b"fido_key_wrap/format_1/prf_input"
DOMAIN_PASSPHRASE_AAD = b"fido_key_wrap/format_1/passphrase_aad"
DOMAIN_FIDO_AAD = b"fido_key_wrap/format_1/fido_aad"
DOMAIN_RECOVERY_SECRET_AAD = (
    b"fido_key_wrap/format_1/recovery_secret_aad"
)
DOMAIN_COMBINED_PASSPHRASE_AAD = (
    b"fido_key_wrap/format_1/combined_passphrase_aad"
)
DOMAIN_COMBINED_FIDO_AAD = b"fido_key_wrap/format_1/combined_fido_aad"
DOMAIN_FIDO_LOCAL_FIDO_KEY = (
    b"fido_key_wrap/format_1/fido_local_fido_key"
)
DOMAIN_FIDO_LOCAL_SECRET_KEY = (
    b"fido_key_wrap/format_1/fido_local_secret_key"
)
DOMAIN_FIDO_LOCAL_COMBINED_KEY = (
    b"fido_key_wrap/format_1/fido_local_combined_key"
)
DOMAIN_FIDO_LOCAL_AAD = b"fido_key_wrap/format_1/fido_local_aad"
DOMAIN_ENVELOPE_MAC_KEY = b"fido_key_wrap/format_1/envelope_mac_key"
DOMAIN_ENVELOPE_MAC = b"fido_key_wrap/format_1/envelope_mac"
DOMAIN_SECRET_KEY = b"fkw-tool/format_1/secret_encryption_key"
DOMAIN_SECRET_AAD = b"fkw-tool/format_1/secret_aad"

Value: TypeAlias = bytes | str | int


@dataclass(frozen=True)
class RecordSpec:
    name: str
    suite: int
    recipient_id: bytes
    label: str
    credential_id: bytes | None = None
    public_key: bytes | None = None
    policy: int | None = None
    prf_nonce: bytes | None = None
    fido_nonce: bytes | None = None
    prf_result: bytes | None = None
    kdf: tuple[int, int, int] | None = None
    salt: bytes | None = None
    passphrase_nonce: bytes | None = None
    recovery_secret: bytes | None = None
    recovery_nonce: bytes | None = None
    local_secret: bytes | None = None
    wrap_nonce: bytes | None = None


@dataclass(frozen=True)
class BuiltRecord:
    spec: RecordSpec
    fields: tuple[tuple[str, Value], ...]
    encoded: bytes


def sequence(start: int, length: int) -> bytes:
    return bytes((start + offset) & 0xFF for offset in range(length))


def p256_public_key(private_scalar: int) -> bytes:
    public_numbers = ec.derive_private_key(
        private_scalar, ec.SECP256R1()
    ).public_key().public_numbers()
    return public_numbers.x.to_bytes(32, "big") + public_numbers.y.to_bytes(
        32, "big"
    )


def transcript(*fields: bytes) -> bytes:
    assert len(fields) <= 32
    return len(fields).to_bytes(4, "big") + b"".join(
        len(field).to_bytes(4, "big") + field for field in fields
    )


def hkdf_sha256(
    ikm: bytes, salt: bytes | None, info: bytes, length: int = 32
) -> bytes:
    effective_salt = bytes(hashlib.sha256().digest_size) if salt is None else salt
    pseudorandom_key = hmac.new(effective_salt, ikm, hashlib.sha256).digest()
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(
            pseudorandom_key,
            previous + info + bytes([counter]),
            hashlib.sha256,
        ).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def cbor_head(major: int, value: int) -> bytes:
    assert 0 <= major <= 7
    assert value >= 0
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 2**8:
        return bytes([(major << 5) | 24, value])
    if value < 2**16:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value < 2**32:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    if value < 2**64:
        return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")
    raise ValueError("CBOR integer exceeds the supported deterministic subset")


def cbor_uint(value: int) -> bytes:
    return cbor_head(0, value)


def cbor_bytes(value: bytes) -> bytes:
    return cbor_head(2, len(value)) + value


def cbor_text(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return cbor_head(3, len(encoded)) + encoded


def cbor_array(values: tuple[bytes, ...] | list[bytes]) -> bytes:
    return cbor_head(4, len(values)) + b"".join(values)


def require(value: Value | None) -> Value:
    assert value is not None
    return value


def build_record(
    spec: RecordSpec,
    application_id: str,
    envelope_id: bytes,
    root_key: bytes,
) -> BuiltRecord:
    application = application_id.encode("ascii")
    fields: list[tuple[str, Value]] = [
        ("suite", spec.suite),
        ("recipient_id", spec.recipient_id),
        ("label", spec.label),
    ]

    if spec.suite == SUITE_PASSPHRASE:
        assert spec.kdf is not None
        assert spec.salt is not None
        assert spec.passphrase_nonce is not None
        memory_kib, passes, lanes = spec.kdf
        context_transcript = transcript(
            DOMAIN_RECIPIENT_CONTEXT,
            bytes([FORMAT]),
            bytes([spec.suite]),
            application,
            envelope_id,
            spec.recipient_id,
            bytes([KDF_ARGON2ID]),
            memory_kib.to_bytes(4, "big"),
            passes.to_bytes(4, "big"),
            bytes([lanes]),
            spec.salt,
            spec.passphrase_nonce,
        )
    elif spec.suite == SUITE_RECOVERY_SECRET:
        assert spec.recovery_secret is not None
        assert spec.recovery_nonce is not None
        context_transcript = transcript(
            DOMAIN_RECIPIENT_CONTEXT,
            bytes([FORMAT]),
            bytes([spec.suite]),
            application,
            envelope_id,
            spec.recipient_id,
            spec.label.encode("utf-8"),
            spec.recovery_nonce,
        )
    elif spec.suite == SUITE_FIDO_LOCAL_SECRET:
        credential_id = require(spec.credential_id)
        public_key = require(spec.public_key)
        prf_nonce = require(spec.prf_nonce)
        wrap_nonce = require(spec.wrap_nonce)
        assert isinstance(credential_id, bytes)
        assert isinstance(public_key, bytes)
        assert isinstance(prf_nonce, bytes)
        assert isinstance(wrap_nonce, bytes)
        context_transcript = transcript(
            DOMAIN_RECIPIENT_CONTEXT,
            bytes([FORMAT]),
            bytes([spec.suite]),
            application,
            envelope_id,
            spec.recipient_id,
            spec.label.encode("utf-8"),
            credential_id,
            public_key,
            prf_nonce,
            wrap_nonce,
        )
    elif spec.suite in FIDO_SUITES:
        credential_id = require(spec.credential_id)
        public_key = require(spec.public_key)
        policy = require(spec.policy)
        prf_nonce = require(spec.prf_nonce)
        fido_nonce = require(spec.fido_nonce)
        assert isinstance(credential_id, bytes)
        assert isinstance(public_key, bytes)
        assert isinstance(policy, int)
        assert isinstance(prf_nonce, bytes)
        assert isinstance(fido_nonce, bytes)
        context_fields = [
            DOMAIN_RECIPIENT_CONTEXT,
            bytes([FORMAT]),
            bytes([spec.suite]),
            application,
            envelope_id,
            spec.recipient_id,
            credential_id,
            public_key,
            bytes([policy]),
            prf_nonce,
            fido_nonce,
        ]
        if spec.suite == SUITE_COMBINED:
            assert spec.kdf is not None
            assert spec.salt is not None
            assert spec.passphrase_nonce is not None
            memory_kib, passes, lanes = spec.kdf
            context_fields.extend(
                (
                    bytes([KDF_ARGON2ID]),
                    memory_kib.to_bytes(4, "big"),
                    passes.to_bytes(4, "big"),
                    bytes([lanes]),
                    spec.salt,
                    spec.passphrase_nonce,
                )
            )
        context_transcript = transcript(*context_fields)
    else:
        raise AssertionError("unknown record suite")

    context = hashlib.sha256(context_transcript).digest()
    fields.extend(
        (
            ("recipient_context_transcript", context_transcript),
            ("recipient_context", context),
        )
    )

    passphrase_key: bytes | None = None
    if spec.suite in (SUITE_PASSPHRASE, SUITE_COMBINED):
        assert spec.kdf is not None
        assert spec.salt is not None
        memory_kib, passes, lanes = spec.kdf
        argon2_output = hash_secret_raw(
            PASSPHRASE,
            spec.salt,
            time_cost=passes,
            memory_cost=memory_kib,
            parallelism=lanes,
            hash_len=32,
            type=Type.ID,
            version=19,
        )
        passphrase_key_info = transcript(DOMAIN_PASSPHRASE_KEY, context)
        passphrase_key = hkdf_sha256(
            argon2_output, envelope_id, passphrase_key_info
        )
        fields.extend(
            (
                ("passphrase", PASSPHRASE),
                ("kdf_code", KDF_ARGON2ID),
                ("memory_kib", memory_kib),
                ("passes", passes),
                ("lanes", lanes),
                ("salt", spec.salt),
                ("passphrase_nonce", require(spec.passphrase_nonce)),
                ("argon2_output", argon2_output),
                ("passphrase_key_info", passphrase_key_info),
                ("passphrase_key", passphrase_key),
            )
        )

    recovery_key: bytes | None = None
    if spec.suite == SUITE_RECOVERY_SECRET:
        assert spec.recovery_secret is not None
        assert spec.recovery_nonce is not None
        recovery_key_info = transcript(DOMAIN_RECOVERY_SECRET_KEY, context)
        recovery_key = hkdf_sha256(
            spec.recovery_secret, envelope_id, recovery_key_info
        )
        fields.extend(
            (
                ("recovery_secret", spec.recovery_secret),
                ("recovery_nonce", spec.recovery_nonce),
                ("recovery_key_info", recovery_key_info),
                ("recovery_key", recovery_key),
            )
        )

    fido_key: bytes | None = None
    if spec.suite in FIDO_SUITES:
        credential_id = require(spec.credential_id)
        public_key = require(spec.public_key)
        prf_nonce = require(spec.prf_nonce)
        prf_result = require(spec.prf_result)
        assert isinstance(credential_id, bytes)
        assert isinstance(public_key, bytes)
        assert isinstance(prf_nonce, bytes)
        assert isinstance(prf_result, bytes)
        prf_input_transcript = transcript(DOMAIN_PRF_INPUT, context)
        prf_input = hashlib.sha256(prf_input_transcript).digest()
        fido_key_domain = (
            DOMAIN_FIDO_LOCAL_FIDO_KEY
            if spec.suite == SUITE_FIDO_LOCAL_SECRET
            else DOMAIN_FIDO_KEY
        )
        fido_key_info = transcript(fido_key_domain, context)
        fido_key = hkdf_sha256(prf_result, envelope_id, fido_key_info)
        fido_fields: list[tuple[str, Value]] = [
            ("credential_id", credential_id),
            ("public_key", public_key),
        ]
        if spec.suite == SUITE_FIDO_LOCAL_SECRET:
            fido_fields.append(("prf_nonce", prf_nonce))
            fido_fields.append(("wrap_nonce", require(spec.wrap_nonce)))
        else:
            policy = require(spec.policy)
            fido_nonce = require(spec.fido_nonce)
            assert isinstance(policy, int)
            assert isinstance(fido_nonce, bytes)
            fido_fields.append(("fido_policy", policy))
            fido_fields.append(("prf_nonce", prf_nonce))
            fido_fields.append(("fido_nonce", fido_nonce))
        fido_fields.extend(
            (
                ("verified_prf_result", prf_result),
                ("prf_input_transcript", prf_input_transcript),
                ("prf_input", prf_input),
                ("fido_key_info", fido_key_info),
                ("fido_key", fido_key),
            )
        )
        fields.extend(fido_fields)

    local_key: bytes | None = None
    combined_key: bytes | None = None
    if spec.suite == SUITE_FIDO_LOCAL_SECRET:
        assert fido_key is not None
        local_secret = require(spec.local_secret)
        assert isinstance(local_secret, bytes)
        local_key_info = transcript(DOMAIN_FIDO_LOCAL_SECRET_KEY, context)
        local_key = hkdf_sha256(
            local_secret, envelope_id, local_key_info
        )
        combined_key_info = transcript(DOMAIN_FIDO_LOCAL_COMBINED_KEY, context)
        combined_key = hkdf_sha256(
            fido_key, local_key, combined_key_info
        )
        fields.extend(
            (
                ("local_secret", local_secret),
                ("local_key_info", local_key_info),
                ("local_key", local_key),
                ("combined_key_info", combined_key_info),
                ("combined_key", combined_key),
            )
        )

    if spec.suite == SUITE_PASSPHRASE:
        assert passphrase_key is not None
        assert spec.kdf is not None
        assert spec.salt is not None
        assert spec.passphrase_nonce is not None
        aad = transcript(DOMAIN_PASSPHRASE_AAD, context)
        wrapped_root = AESGCM(passphrase_key).encrypt(
            spec.passphrase_nonce, root_key, aad
        )
        assert (
            AESGCM(passphrase_key).decrypt(spec.passphrase_nonce, wrapped_root, aad)
            == root_key
        )
        memory_kib, passes, lanes = spec.kdf
        kdf = cbor_array(
            [
                cbor_uint(KDF_ARGON2ID),
                cbor_uint(memory_kib),
                cbor_uint(passes),
                cbor_uint(lanes),
                cbor_bytes(spec.salt),
            ]
        )
        encoded = cbor_array(
            [
                cbor_uint(spec.suite),
                cbor_bytes(spec.recipient_id),
                cbor_text(spec.label),
                kdf,
                cbor_bytes(spec.passphrase_nonce),
                cbor_bytes(wrapped_root),
            ]
        )
        fields.extend(
            (
                ("passphrase_aad", aad),
                ("wrapped_root", wrapped_root),
            )
        )
    elif spec.suite == SUITE_RECOVERY_SECRET:
        assert recovery_key is not None
        assert spec.recovery_nonce is not None
        aad = transcript(DOMAIN_RECOVERY_SECRET_AAD, context)
        wrapped_root = AESGCM(recovery_key).encrypt(
            spec.recovery_nonce, root_key, aad
        )
        assert (
            AESGCM(recovery_key).decrypt(
                spec.recovery_nonce, wrapped_root, aad
            )
            == root_key
        )
        encoded = cbor_array(
            [
                cbor_uint(spec.suite),
                cbor_bytes(spec.recipient_id),
                cbor_text(spec.label),
                cbor_bytes(spec.recovery_nonce),
                cbor_bytes(wrapped_root),
            ]
        )
        fields.extend(
            (("recovery_aad", aad), ("wrapped_root", wrapped_root))
        )
    elif spec.suite in (SUITE_FIDO, SUITE_MANAGED_FIDO):
        assert fido_key is not None
        credential_id = require(spec.credential_id)
        public_key = require(spec.public_key)
        policy = require(spec.policy)
        prf_nonce = require(spec.prf_nonce)
        fido_nonce = require(spec.fido_nonce)
        assert isinstance(credential_id, bytes)
        assert isinstance(public_key, bytes)
        assert isinstance(policy, int)
        assert isinstance(prf_nonce, bytes)
        assert isinstance(fido_nonce, bytes)
        aad = transcript(DOMAIN_FIDO_AAD, context)
        wrapped_root = AESGCM(fido_key).encrypt(fido_nonce, root_key, aad)
        assert AESGCM(fido_key).decrypt(fido_nonce, wrapped_root, aad) == root_key
        encoded = cbor_array(
            [
                cbor_uint(spec.suite),
                cbor_bytes(spec.recipient_id),
                cbor_text(spec.label),
                cbor_bytes(credential_id),
                cbor_bytes(public_key),
                cbor_uint(policy),
                cbor_bytes(prf_nonce),
                cbor_bytes(fido_nonce),
                cbor_bytes(wrapped_root),
            ]
        )
        fields.extend((("fido_aad", aad), ("wrapped_root", wrapped_root)))
    elif spec.suite == SUITE_COMBINED:
        assert passphrase_key is not None
        assert fido_key is not None
        assert spec.kdf is not None
        assert spec.salt is not None
        assert spec.passphrase_nonce is not None
        credential_id = require(spec.credential_id)
        public_key = require(spec.public_key)
        policy = require(spec.policy)
        prf_nonce = require(spec.prf_nonce)
        fido_nonce = require(spec.fido_nonce)
        assert isinstance(credential_id, bytes)
        assert isinstance(public_key, bytes)
        assert isinstance(policy, int)
        assert isinstance(prf_nonce, bytes)
        assert isinstance(fido_nonce, bytes)
        inner_aad = transcript(DOMAIN_COMBINED_PASSPHRASE_AAD, context)
        inner = AESGCM(passphrase_key).encrypt(
            spec.passphrase_nonce, root_key, inner_aad
        )
        outer_aad = transcript(DOMAIN_COMBINED_FIDO_AAD, context)
        wrapped_root = AESGCM(fido_key).encrypt(fido_nonce, inner, outer_aad)
        recovered_inner = AESGCM(fido_key).decrypt(
            fido_nonce, wrapped_root, outer_aad
        )
        assert (
            AESGCM(passphrase_key).decrypt(
                spec.passphrase_nonce, recovered_inner, inner_aad
            )
            == root_key
        )
        memory_kib, passes, lanes = spec.kdf
        kdf = cbor_array(
            [
                cbor_uint(KDF_ARGON2ID),
                cbor_uint(memory_kib),
                cbor_uint(passes),
                cbor_uint(lanes),
                cbor_bytes(spec.salt),
            ]
        )
        encoded = cbor_array(
            [
                cbor_uint(spec.suite),
                cbor_bytes(spec.recipient_id),
                cbor_text(spec.label),
                cbor_bytes(credential_id),
                cbor_bytes(public_key),
                cbor_uint(policy),
                cbor_bytes(prf_nonce),
                cbor_bytes(fido_nonce),
                kdf,
                cbor_bytes(spec.passphrase_nonce),
                cbor_bytes(wrapped_root),
            ]
        )
        fields.extend(
            (
                ("combined_passphrase_aad", inner_aad),
                ("inner_ciphertext", inner),
                ("combined_fido_aad", outer_aad),
                ("wrapped_root", wrapped_root),
            )
        )
    else:
        assert spec.suite == SUITE_FIDO_LOCAL_SECRET
        assert combined_key is not None
        credential_id = require(spec.credential_id)
        public_key = require(spec.public_key)
        prf_nonce = require(spec.prf_nonce)
        wrap_nonce = require(spec.wrap_nonce)
        assert isinstance(credential_id, bytes)
        assert isinstance(public_key, bytes)
        assert isinstance(prf_nonce, bytes)
        assert isinstance(wrap_nonce, bytes)
        aad = transcript(DOMAIN_FIDO_LOCAL_AAD, context)
        wrapped_root = AESGCM(combined_key).encrypt(
            wrap_nonce, root_key, aad
        )
        assert (
            AESGCM(combined_key).decrypt(wrap_nonce, wrapped_root, aad)
            == root_key
        )
        encoded = cbor_array(
            [
                cbor_uint(spec.suite),
                cbor_bytes(spec.recipient_id),
                cbor_text(spec.label),
                cbor_bytes(credential_id),
                cbor_bytes(public_key),
                cbor_bytes(prf_nonce),
                cbor_bytes(wrap_nonce),
                cbor_bytes(wrapped_root),
            ]
        )
        fields.extend(
            (("fido_local_aad", aad), ("wrapped_root", wrapped_root))
        )

    expected_length = 64 if spec.suite == SUITE_COMBINED else 48
    assert len(wrapped_root) == expected_length
    fields.append(("record", encoded))
    return BuiltRecord(spec, tuple(fields), encoded)


def envelope_fields(
    application_id: str,
    envelope_id: bytes,
    root_key: bytes,
    records: list[BuiltRecord],
) -> tuple[tuple[str, Value], ...]:
    records.sort(key=lambda record: record.spec.recipient_id)
    assert len({record.spec.recipient_id for record in records}) == len(records)
    passphrase_salts = [
        record.spec.salt for record in records if record.spec.salt is not None
    ]
    credential_ids = [
        record.spec.credential_id
        for record in records
        if record.spec.credential_id is not None
    ]
    assert len(set(passphrase_salts)) == len(passphrase_salts)
    assert len(set(credential_ids)) == len(credential_ids)

    encoded_records = cbor_array([record.encoded for record in records])
    canonical_body = cbor_array(
        [
            cbor_uint(FORMAT),
            cbor_text(application_id),
            cbor_bytes(envelope_id),
            encoded_records,
        ]
    )
    envelope_mac_key_info = transcript(
        DOMAIN_ENVELOPE_MAC_KEY,
        bytes([FORMAT]),
        application_id.encode("ascii"),
    )
    envelope_mac_key = hkdf_sha256(
        root_key, envelope_id, envelope_mac_key_info
    )
    envelope_mac_transcript = transcript(
        DOMAIN_ENVELOPE_MAC, bytes([FORMAT]), canonical_body
    )
    envelope_mac = hmac.new(
        envelope_mac_key, envelope_mac_transcript, hashlib.sha256
    ).digest()
    envelope = b"FKW\0" + cbor_array(
        [
            cbor_uint(FORMAT),
            cbor_text(application_id),
            cbor_bytes(envelope_id),
            encoded_records,
            cbor_bytes(envelope_mac),
        ]
    )
    assert len(envelope) <= 65_536
    return (
        ("format", FORMAT),
        ("application_id", application_id),
        ("envelope_id", envelope_id),
        ("root_key", root_key),
        ("canonical_body", canonical_body),
        ("envelope_mac_key_info", envelope_mac_key_info),
        ("envelope_mac_key", envelope_mac_key),
        ("envelope_mac_transcript", envelope_mac_transcript),
        ("envelope_mac", envelope_mac),
        ("envelope", envelope),
    )


def render_value(value: Value) -> str:
    return value.hex() if isinstance(value, bytes) else str(value)


def render_fixture(
    title: str,
    records: list[BuiltRecord],
    common: tuple[tuple[str, Value], ...],
) -> str:
    lines = [
        f"# {title}",
        "# deterministic correctness vector; byte values are lowercase hexadecimal.",
    ]
    if any(
        record.spec.suite in FIDO_SUITES
        for record in records
    ):
        lines.append(
            "# verified_prf_result values are synthetic fixed inputs, not an authenticator simulation."
        )
    lines.append("")
    multi = len(records) > 1
    for index, record in enumerate(records, start=1):
        prefix = f"recipient_{index}_" if multi else ""
        if multi:
            lines.append(f"# recipient {index}: {record.spec.name}")
        lines.extend(
            f"{prefix}{name}={render_value(value)}" for name, value in record.fields
        )
        lines.append("")
    lines.append("# complete envelope")
    lines.extend(f"{name}={render_value(value)}" for name, value in common)
    lines.append("")
    return "\n".join(lines)


def specs() -> list[RecordSpec]:
    return [
        RecordSpec(
            name="passphrase",
            suite=SUITE_PASSPHRASE,
            recipient_id=sequence(0x10, 32),
            label="passphrase",
            kdf=DESKTOP_KDF,
            salt=sequence(0xA0, 16),
            passphrase_nonce=sequence(0x10, 12),
        ),
        RecordSpec(
            name="fido-presence",
            suite=SUITE_FIDO,
            recipient_id=sequence(0x30, 32),
            label="fido presence",
            credential_id=sequence(0x20, 16),
            public_key=p256_public_key(1),
            policy=POLICY_PRESENCE,
            prf_nonce=sequence(0x40, 32),
            fido_nonce=sequence(0x30, 12),
            prf_result=sequence(0x80, 32),
        ),
        RecordSpec(
            name="fido-user-verification",
            suite=SUITE_FIDO,
            recipient_id=sequence(0x50, 32),
            label="fido user verification",
            credential_id=sequence(0x40, 16),
            public_key=p256_public_key(2),
            policy=POLICY_USER_VERIFICATION,
            prf_nonce=sequence(0x60, 32),
            fido_nonce=sequence(0x50, 12),
            prf_result=sequence(0xC0, 32),
        ),
        RecordSpec(
            name="fido-presence-plus-passphrase",
            suite=SUITE_COMBINED,
            recipient_id=sequence(0x70, 32),
            label="presence plus passphrase",
            credential_id=sequence(0x60, 16),
            public_key=p256_public_key(3),
            policy=POLICY_PRESENCE,
            prf_nonce=sequence(0x80, 32),
            fido_nonce=sequence(0x70, 12),
            prf_result=sequence(0x20, 32),
            kdf=DESKTOP_KDF,
            salt=sequence(0xB0, 16),
            passphrase_nonce=sequence(0x90, 12),
        ),
        RecordSpec(
            name="fido-user-verification-plus-passphrase",
            suite=SUITE_COMBINED,
            recipient_id=sequence(0x90, 32),
            label="uv plus passphrase",
            credential_id=sequence(0x80, 16),
            public_key=p256_public_key(4),
            policy=POLICY_USER_VERIFICATION,
            prf_nonce=sequence(0xA0, 32),
            fido_nonce=sequence(0xB0, 12),
            prf_result=sequence(0x40, 32),
            kdf=NON_DEFAULT_KDF,
            salt=sequence(0xC0, 16),
            passphrase_nonce=sequence(0xD0, 12),
        ),
        RecordSpec(
            name="recovery-secret",
            suite=SUITE_RECOVERY_SECRET,
            recipient_id=sequence(0xB0, 32),
            label="recovery secret",
            recovery_secret=RECOVERY_SECRET,
            recovery_nonce=sequence(0xE0, 12),
        ),
        RecordSpec(
            name="managed-fido-presence",
            suite=SUITE_MANAGED_FIDO,
            recipient_id=sequence(0xA0, 32),
            label="managed presence",
            credential_id=sequence(0xA0, 16),
            public_key=p256_public_key(5),
            policy=POLICY_PRESENCE,
            prf_nonce=sequence(0xC0, 32),
            fido_nonce=sequence(0xF0, 12),
            prf_result=sequence(0x60, 32),
        ),
        RecordSpec(
            name="managed-fido-user-verification",
            suite=SUITE_MANAGED_FIDO,
            recipient_id=sequence(0xA8, 32),
            label="managed user verification",
            credential_id=sequence(0xA8, 16),
            public_key=p256_public_key(6),
            policy=POLICY_USER_VERIFICATION,
            prf_nonce=sequence(0xC8, 32),
            fido_nonce=sequence(0xF8, 12),
            prf_result=sequence(0x68, 32),
        ),
        RecordSpec(
            name="fido-presence-plus-local-secret",
            suite=SUITE_FIDO_LOCAL_SECRET,
            recipient_id=sequence(0xC0, 32),
            label="presence plus local secret",
            credential_id=sequence(0xD0, 16),
            public_key=p256_public_key(7),
            prf_nonce=sequence(0xE0, 32),
            prf_result=sequence(0x70, 32),
            local_secret=LOCAL_SECRET,
            wrap_nonce=sequence(0x20, 12),
        ),
    ]


def generate_envelope(
    selected_specs: list[RecordSpec], envelope_id: bytes
) -> tuple[list[BuiltRecord], tuple[tuple[str, Value], ...]]:
    records = [
        build_record(spec, APPLICATION_ID, envelope_id, ROOT_KEY)
        for spec in selected_specs
    ]
    common = envelope_fields(
        APPLICATION_ID, envelope_id, ROOT_KEY, records
    )
    return records, common


def render_tool_vector(
    passphrase_common: tuple[tuple[str, Value], ...]
) -> str:
    common = dict(passphrase_common)
    envelope = common["envelope"]
    assert isinstance(envelope, bytes)
    secret_plaintext = b"independent format-1 tool secret\n"
    secret_nonce = sequence(0xE0, 12)
    secret_key_info = transcript(
        DOMAIN_SECRET_KEY, APPLICATION_ID.encode("ascii")
    )
    secret_key = hkdf_sha256(ROOT_KEY, None, secret_key_info)
    secret_aad = transcript(DOMAIN_SECRET_AAD, envelope)
    secret_ciphertext = AESGCM(secret_key).encrypt(
        secret_nonce, secret_plaintext, secret_aad
    )
    assert (
        AESGCM(secret_key).decrypt(secret_nonce, secret_ciphertext, secret_aad)
        == secret_plaintext
    )
    container = (
        b"FKW\0"
        + bytes([FORMAT])
        + len(envelope).to_bytes(4, "big")
        + envelope
        + secret_nonce
        + len(secret_ciphertext).to_bytes(4, "big")
        + secret_ciphertext
    )
    values: tuple[tuple[str, Value], ...] = (
        ("format", FORMAT),
        ("application_id", APPLICATION_ID),
        ("root_key", ROOT_KEY),
        ("envelope", envelope),
        ("secret_plaintext", secret_plaintext),
        ("secret_nonce", secret_nonce),
        ("secret_key_info", secret_key_info),
        ("secret_key", secret_key),
        ("secret_aad", secret_aad),
        ("secret_ciphertext", secret_ciphertext),
        ("container", container),
    )
    lines = [
        "# fkw-tool format-1 data-key, aead, and container vector",
        "# deterministic correctness vector; byte values are lowercase hexadecimal.",
        "",
    ]
    lines.extend(f"{name}={render_value(value)}" for name, value in values)
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    output_directory = Path(__file__).resolve().parent
    all_specs = specs()
    single_results: dict[str, tuple[tuple[str, Value], ...]] = {}
    standalone_envelope_ids = [
        *(sequence(index * 0x20, 32) for index in range(8)),
        FIDO_LOCAL_SECRET_ENVELOPE_ID,
    ]
    assert len(standalone_envelope_ids) == len(all_specs)
    assert len(set(standalone_envelope_ids)) == len(standalone_envelope_ids)

    for spec, envelope_id in zip(all_specs, standalone_envelope_ids, strict=True):
        records, common = generate_envelope([spec], envelope_id)
        fixture = render_fixture(
            f"fido-key-wrap format 1, {spec.name} recipient", records, common
        )
        (output_directory / f"format-1-{spec.name}.txt").write_text(
            fixture, encoding="ascii", newline="\n"
        )
        single_results[spec.name] = common

    mixed_records, mixed_common = generate_envelope(
        all_specs, sequence(0xD0, 32)
    )
    (output_directory / "format-1-mixed.txt").write_text(
        render_fixture(
            "fido-key-wrap format 1, nine-recipient mixed envelope",
            mixed_records,
            mixed_common,
        ),
        encoding="ascii",
        newline="\n",
    )

    (output_directory / "format-1-tool-container.txt").write_text(
        render_tool_vector(single_results["passphrase"]),
        encoding="ascii",
        newline="\n",
    )


if __name__ == "__main__":
    main()
