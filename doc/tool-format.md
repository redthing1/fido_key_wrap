# tool format

the tool container is:

```text
"FKW\0" ||
format ||
u32be(envelope_length) || envelope ||
nonce ||
u32be(ciphertext_length) || ciphertext
```

`format` is `1`. `nonce` is 12 random bytes. the envelope is the exact canonical
`KeyEnvelope::encode()` output. the plaintext is 1 byte to 1 mib, and the
envelope is at most 65,536 bytes. the tool's trusted application id is
`tool.fido-key-wrap.local`.

transcripts use length-prefixed framing:

```text
t(a, b, ...) =
  u32be(field_count) ||
  u32be(len(a)) || a ||
  u32be(len(b)) || b ||
  ...
```

the tool derives a 32-byte data key from the random application root:

```text
prk = hkdf-extract-sha-256(salt = none, ikm = root)
key = hkdf-expand-sha-256(
  prk,
  t("fkw-tool/format_1/secret_encryption_key", application_id),
  32
)
```

it encrypts the plaintext with aes-256-gcm and appends the 16-byte tag. the
associated data is:

```text
t("fkw-tool/format_1/secret_aad", envelope)
```

the exact envelope is therefore authenticated both by the root-derived
envelope mac and by the application ciphertext. changing either component
causes unlock to fail.

`test-vectors/format-1-tool-container.txt` records a deterministic independent
vector for the derivation, associated data, ciphertext, and complete container.
