# protocol

this document specifies the version 1 envelope and key-wrapping protocol.

## notation

- `||` is byte concatenation
- `u32be(n)` is an unsigned 32-bit integer in network byte order
- `sha256`, `hmac-sha-256`, and `hkdf-sha-256` follow their standard definitions
- `aes-256-gcm` uses a 12-byte nonce and appends a 16-byte tag to the ciphertext
- `empty` is a zero-length byte string

`t(a, b, ...)` is the following byte encoding:

```text
u32be(field count) ||
u32be(length of a) || a ||
u32be(length of b) || b ||
...
```

transcript framing uses `u32be` for its field count and lengths. protocol codes
supplied as fields are one byte. strings are utf-8 bytes without a terminator.

## codes

| field | name | code |
| --- | --- | --- |
| format | version 1 | `1` |
| suite | version 1 suite | `1` |
| token policy | presence | `1` |
| token policy | user-verified | `2` |
| additional factor | none | `0` |
| additional factor | passphrase | `1` |
| credential protection | uv optional with credential id | `2` |
| credential protection | uv required | `3` |
| passphrase suite | argon2id | `1` |

presence recipients use credential-protection code `2`. user-verified
recipients use code `3`. every unlisted code is rejected.

## values

the following values are independently random:

| name | length | meaning |
| --- | --- | --- |
| `m` | 32 bytes | application root key |
| `e` | 32 bytes | envelope id |
| `n_prf` | 32 bytes | recipient prf nonce |
| `n_token` | 12 bytes | recipient token nonce |
| `s_pass` | 16 bytes | passphrase salt, when present |
| `n_pass` | 12 bytes | passphrase nonce, when present |

`m` must be uniformly random. all generated values come from the
operating-system random number generator.

an es256 public key `pk` is encoded as `x || y`, where each p-256 coordinate is
a 32-byte big-endian integer. the point must be on the p-256 curve.

## application id

the application id `app` is both the fido relying-party id and a protocol
input. its utf-8 representation must be ascii, lowercase, dns-shaped, no more
than 253 bytes, and contain at least two labels. each label is 1 to 63 bytes,
begins and ends with an ascii letter or digit, and otherwise contains only
ascii letters, digits, or `-`.

## credential creation

each recipient uses a non-discoverable es256 credential scoped to `app`. the
creation request contains a fresh random 32-byte client-data hash and random
32-byte user id, sets `rk=false` and `uv=true`, and enables the `hmac-secret`
and credential-protection extensions. user names and display names do not
affect the envelope construction.

creation requires client-pin user verification and uses the
credential-protection code assigned to the recipient policy. the response must
use packed self-attestation or packed basic attestation, es256, the requested
credential-protection value, and signed `up=1, uv=1`. its signature is verified
against the request's client-data hash and relying-party data. `fmt=none` is
rejected.

the returned credential id `cid` must contain 1 to 1,024 bytes. the public key
is normalized to the 64-byte encoding above and validated as a p-256 point.

## recipient id

let `tp` be the one-byte token-policy code and `af` the one-byte
additional-factor code:

```text
rid = sha256(t(
  "fido_key_wrap/recipient_id/v1",
  app,
  cid,
  pk,
  tp,
  af
))
```

`rid` is 32 bytes. the recipient label is not an input to `rid`.

## recipient header

let `v` be the one-byte format version, `su` the one-byte suite code, and `cp`
the one-byte credential-protection code. for a recipient without a passphrase,
`s_pass` and `n_pass` below are both `empty`.

```text
h = t(
  "fido_key_wrap/recipient_header/v1",
  v,
  su,
  app,
  e,
  rid,
  cid,
  pk,
  tp,
  cp,
  af,
  n_prf,
  n_token,
  s_pass,
  n_pass
)
```

the recipient context and fido extension input are:

```text
c = sha256(t("fido_key_wrap/recipient_context/v1", h))
s = sha256(t("fido_key_wrap/prf_input/v1", c))
```

## fido assertion

the assertion request supplies `app` and a fresh random 32-byte client-data
hash, allows only `cid`, requests `hmac-secret(s)`, and requires user presence.
presence supplies no pin and requests uv false. user-verified supplies one
client pin and requests uv true.

the response is accepted only when:

- the es256 signature verifies under `pk` over authenticator data for `app` and
  the request's client-data hash
- exactly one assertion is returned for `cid`
- `up=1, uv=0` for presence or `up=1, uv=1` for user-verified
- exactly one 32-byte `hmac-secret` result is returned

call the verified extension result `r`.

## token key

```text
k_token = hkdf-sha-256(
  ikm  = r,
  salt = e,
  info = t("fido_key_wrap/token_key/v1", c),
  len  = 32
)

a_token = t("fido_key_wrap/token_aad/v1", h)
```

without a passphrase:

```text
wrapped = aes-256-gcm.encrypt(k_token, n_token, m, a_token)
```

`wrapped` is 48 bytes.

## passphrase key

the passphrase is an unmodified byte string from 1 to 1,024 bytes. no unicode
normalization or whitespace processing is applied.

```text
i_pass = argon2id(
  password = passphrase,
  salt = s_pass,
  version = 0x13,
  memory = 65536 kib,
  passes = 3,
  lanes = 4,
  output = 32 bytes
)

k_pass = hkdf-sha-256(
  ikm  = i_pass,
  salt = e,
  info = t("fido_key_wrap/passphrase_key/v1", c),
  len  = 32
)

a_pass = t("fido_key_wrap/passphrase_aad/v1", h)
inner = aes-256-gcm.encrypt(k_pass, n_pass, m, a_pass)
wrapped = aes-256-gcm.encrypt(k_token, n_token, inner, a_token)
```

`inner` is 48 bytes and `wrapped` is 64 bytes. decryption authenticates the
token layer before processing the passphrase.

## envelope body and mac

the canonical body uses the core deterministic encoding requirements from rfc
8949 section 4.2.1 to encode:

```text
[
  1,
  app,
  e,
  recipients
]
```

the envelope mac is:

```text
k_envelope = hkdf-sha-256(
  ikm  = m,
  salt = e,
  info = t("fido_key_wrap/envelope_mac_key/v1", app),
  len  = 32
)

envelope_mac = hmac-sha-256(
  k_envelope,
  t("fido_key_wrap/envelope_mac/v1", canonical_body)
)
```

mac comparison is constant-time.

## envelope encoding

the serialized envelope is the ascii bytes `FKW1` followed by rfc 8949 core
deterministic cbor encoding of:

```text
[
  1,
  app,
  e,
  recipients,
  envelope_mac
]
```

each recipient is:

```text
[
  1,
  rid,
  label,
  cid,
  pk,
  tp,
  af,
  cp,
  n_prf,
  n_token,
  passphrase_parameters,
  wrapped
]
```

`passphrase_parameters` is `null` when `af=0`. when `af=1`, it is:

```text
[1, s_pass, n_pass]
```

`app` and `label` are cbor text strings. ids, keys, nonces, salts, ciphertexts,
and macs are cbor byte strings. codes are unsigned cbor integers using their
shortest encoding. arrays have definite lengths. tags, floats, indefinite
values, unknown fields, and trailing bytes are not accepted.

recipients are sorted by `rid` in bytewise ascending order. recipient ids and
credential ids are unique within an envelope. labels are valid utf-8, contain
no control characters, and are 1 to 128 bytes.

decoding recomputes `rid` and validates `pk` as a p-256 point. presence requires
`cp=2`; user-verified requires `cp=3`. `af=0` requires null passphrase
parameters and a 48-byte `wrapped` value. `af=1` requires
`[1, s_pass, n_pass]` and a 64-byte `wrapped` value.

an envelope contains 1 to 32 recipients and is no larger than 65,536 bytes.
decoding and re-encoding must produce the same bytes.

## recovery

1. decode the envelope and require `app` to match the expected application id
2. locate `rid`
3. obtain and verify the fido assertion
4. derive `k_token` and authenticate the outer ciphertext
5. when present, derive `k_pass` and authenticate the inner ciphertext
6. require a 32-byte plaintext root
7. verify `envelope_mac`

the recovered root is released only after all seven steps succeed.
