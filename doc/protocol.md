# protocol

format 1 combines fido primitives with project-defined transcripts, wrapping
layers, and an envelope format. it is not a standardized fido key-wrapping
protocol. all algorithms, codes, field order, and limits are fixed.

## notation

- `||` means byte concatenation
- `u32be(n)` is an unsigned 32-bit integer in network byte order
- `sha256`, `hmac-sha-256`, and `hkdf-sha-256` have their standard meanings
- `aead(k, n, p, a)` is aes-256-gcm encryption with key `k`, 12-byte nonce `n`,
  plaintext `p`, associated data `a`, and an appended 16-byte tag
- `argon2id(p, s, m, t, q)` uses version `0x13`, passphrase `p`, salt `s`,
  memory in kibibytes `m`, passes `t`, lanes `q`, and 32 output bytes

transcripts use length-prefixed framing:

```text
t(a, b, ...) =
  u32be(field_count) ||
  u32be(len(a)) || a ||
  u32be(len(b)) || b ||
  ...
```

one-byte protocol codes are encoded as one-byte transcript fields. argon2
memory and pass counts are four-byte big-endian transcript fields. a transcript
contains at most 32 fields, and its field and total lengths are checked before
allocation.

## codes

| value | meaning | code |
| --- | --- | --- |
| format | format 1 | `1` |
| suite | passphrase | `1` |
| suite | fido | `2` |
| suite | fido and passphrase | `3` |
| suite | recovery secret | `4` |
| suite | managed fido | `5` |
| suite | fido presence and local secret | `6` |
| fido policy | presence | `1` |
| fido policy | user verification | `2` |
| kdf | argon2id | `1` |

all other codes are rejected.

## fixed domains

```text
fido_key_wrap/format_1/recipient_context
fido_key_wrap/format_1/prf_input
fido_key_wrap/format_1/passphrase_key
fido_key_wrap/format_1/fido_key
fido_key_wrap/format_1/fido_local_fido_key
fido_key_wrap/format_1/fido_local_secret_key
fido_key_wrap/format_1/fido_local_combined_key
fido_key_wrap/format_1/passphrase_aad
fido_key_wrap/format_1/fido_aad
fido_key_wrap/format_1/fido_local_aad
fido_key_wrap/format_1/combined_passphrase_aad
fido_key_wrap/format_1/combined_fido_aad
fido_key_wrap/format_1/recovery_secret_key
fido_key_wrap/format_1/recovery_secret_aad
fido_key_wrap/format_1/envelope_mac_key
fido_key_wrap/format_1/envelope_mac
```

the ascii bytes of each displayed string are used directly.

## values

| symbol | length | value |
| --- | --- | --- |
| `f` | 1 byte | format code |
| `su` | 1 byte | suite code |
| `app` | 3–253 bytes | application id |
| `eid` | 32 bytes | random envelope id |
| `rid` | 32 bytes | random recipient id |
| `root` | 32 bytes | random application root |
| `rs` | 32 bytes | random recovery secret |
| `ls` | 32 bytes | random local secret |
| `cid` | 1–1,024 bytes | fido credential id |
| `pk` | 64 bytes | es256 public key as `x || y` |
| `fp` | 1 byte | fido policy code |
| `np` | 32 bytes | random prf nonce |
| `nf` | 12 bytes | random fido-layer nonce |
| `s` | 16 bytes | random argon2 salt |
| `npass` | 12 bytes | random passphrase-layer nonce |
| `nr` | 12 bytes | random recovery-secret nonce |
| `nl` | 12 bytes | random local-secret route nonce |

### generation

root-creation methods generate `root` with the operating-system random source.
protection methods instead accept caller-supplied root bytes, which must already
be uniformly random. each new recovery-secret route generates `rs`, and each
new local-secret route generates `ls`, from this source. library-generated ids,
nonces, and salts use the same source.
recipient ids and passphrase salts use bounded collision rejection within an
envelope; rewrap also rejects a repeated prior nonce. recipient ids are public
random identifiers, not credential or physical-device identities.

### validation

the p-256 point encoded by `pk` must be valid. labels are 1–64 printable ascii
bytes, with no leading or trailing space. recovery-secret and local-secret
contexts include their labels. other recipient contexts omit labels. the final
envelope mac authenticates every label.

the application id is ascii lowercase dns-shaped text with at least two
labels. each label contains 1–63 lowercase letters, digits, or `-`, begins and
ends with a letter or digit, and the full value is at most 253 bytes.

## recipient context

each recipient has one context `c`. including random `rid` and `eid` separates
otherwise equal recipients and envelopes.

for a passphrase recipient:

```text
c = sha256(t(
  "fido_key_wrap/format_1/recipient_context",
  f, su, app, eid, rid,
  kdf_code, u32be(memory_kib), u32be(passes), lanes,
  s, npass
))
```

for a recovery-secret recipient:

```text
c = sha256(t(
  "fido_key_wrap/format_1/recipient_context",
  f, su, app, eid, rid, label, nr
))
```

for an ordinary or managed fido recipient:

```text
c = sha256(t(
  "fido_key_wrap/format_1/recipient_context",
  f, su, app, eid, rid,
  cid, pk, fp, np, nf
))
```

for a combined recipient:

```text
c = sha256(t(
  "fido_key_wrap/format_1/recipient_context",
  f, su, app, eid, rid,
  cid, pk, fp, np, nf,
  kdf_code, u32be(memory_kib), u32be(passes), lanes,
  s, npass
))
```

for a fido-presence and local-secret recipient:

```text
c = sha256(t(
  "fido_key_wrap/format_1/recipient_context",
  f, su, app, eid, rid, label,
  cid, pk, np, nl
))
```

## passphrase key

passphrases contain 1–1,024 bytes. bytes are used exactly as supplied; there is
no text normalization, trimming, or case conversion.

format 1 accepts:

- memory from 65,536 through 262,144 kibibytes
- three through six passes
- one through four lanes
- memory at least eight times the lane count
- memory divisible by four times the lane count
- memory, work, byte count, and block count safely representable on the target

the default desktop profile is 262,144 kibibytes, three passes, and four lanes.

```text
i = argon2id(passphrase, s, memory_kib, passes, lanes)

kpass = hkdf-sha-256(
  ikm  = i,
  salt = eid,
  info = t("fido_key_wrap/format_1/passphrase_key", c),
  len  = 32
)
```

## recovery-secret key

```text
krecovery = hkdf-sha-256(
  ikm  = rs,
  salt = eid,
  info = t("fido_key_wrap/format_1/recovery_secret_key", c),
  len  = 32
)
```

## fido credential and prf key

### ordinary enrollment

each ordinary fido, combined, or local-secret recipient creates one dedicated
non-discoverable es256 credential under relying-party id `app`. creation uses
fresh random client-data and user-id values, requests `hmac-secret` and
credential protection, and requires user verification.

presence credentials use protection optional with the credential id. user
verification credentials require user verification. the result is accepted
only after packed attestation, es256, the requested protection, and signed
`up=1`, `uv=1`, `be=0`, `bs=0` have been verified.

the local-secret suite fixes recovery to presence and uses a distinct
non-discoverable credential. a fresh exact-presence assertion must succeed
before the route and local secret are returned.

### managed enrollment

a managed fido recipient creates one discoverable es256 credential with
`rk=true`, user id `rid`, and relying-party id `app`. its authenticator-visible
user name is fixed and contains no recipient label. managed enrollment requires
`hmac-secret`, credential management, discoverable storage, and the credential
protection selected by `fp`: optional with the credential id for presence, or
user verification required for user verification.

the creation response is accepted under the same attestation, key, and signed
flag checks as ordinary enrollment. the new credential is then exercised by an
exact-policy `hmac-secret` assertion on the same open authenticator. presence
uses `uv=0`; user verification uses `uv=1`. before the recipient is returned,
complete relying-party enumeration must find exactly the record with user id
`rid`, credential id `cid`, public key `pk`, and required credential
protection.

### assertion

the prf salt for an assertion is:

```text
prf_input = sha256(t("fido_key_wrap/format_1/prf_input", c))
```

each assertion uses a fresh random 32-byte client-data hash, allows only `cid`,
requests `hmac-secret(prf_input)`, and requests user presence. presence
requests exact `uv=0` without a pin. user verification supplies one pin and
requests exact `uv=1`.

the result is accepted only after the es256 assertion signature, relying-party
binding, fresh client-data hash, exact credential id, exact signed
`up`/`uv`/`be`/`bs` flags, single assertion count, and 32-byte extension result
have been verified. call the verified extension result `r`.

ordinary recovery does not enumerate managed credentials. the signed assertion
already proves the exact credential and recovery policy; enumeration belongs
to managed enrollment, verification, and retirement.

```text
kfido = hkdf-sha-256(
  ikm  = r,
  salt = eid,
  info = t("fido_key_wrap/format_1/fido_key", c),
  len  = 32
)
```

### fido-presence and local-secret key

the local-secret suite uses the same exact presence assertion and verified
extension result `r`, but separate derivation domains:

```text
kfl_fido = hkdf-sha-256(
  ikm  = r,
  salt = eid,
  info = t("fido_key_wrap/format_1/fido_local_fido_key", c),
  len  = 32
)

kfl_local = hkdf-sha-256(
  ikm  = ls,
  salt = eid,
  info = t("fido_key_wrap/format_1/fido_local_secret_key", c),
  len  = 32
)

kfl = hkdf-sha-256(
  ikm  = kfl_fido,
  salt = kfl_local,
  info = t("fido_key_wrap/format_1/fido_local_combined_key", c),
  len  = 32
)
```

`kfl_fido` and `kfl_local` are cleared after combination. `ls` is returned to
the application only after the staged recipient has recovered and
authenticated the complete envelope.

### managed verification and retirement

managed verification first authenticates the complete envelope with `root`.
it then obtains a fresh user-verified signed assertion for `cid` without
requesting `hmac-secret`, and completes exact relying-party enumeration on the
same open authenticator. verification and retirement require pin-backed user
verification even when `fp` selects presence for recovery.

managed retirement performs that verification, deletes exactly `cid`, then
completes another enumeration proving that the exact record is absent. a
complete absence check can confirm retirement after a lost deletion response.
an inconclusive check reports uncertain retirement. a missing or unavailable
authenticator is not successful retirement. no operation resets an
authenticator.

## wrapping

a passphrase recipient stores:

```text
aad = t("fido_key_wrap/format_1/passphrase_aad", c)
wrapped_root = aead(kpass, npass, root, aad)
```

a recovery-secret recipient stores:

```text
aad = t("fido_key_wrap/format_1/recovery_secret_aad", c)
wrapped_root = aead(krecovery, nr, root, aad)
```

a fido recipient stores:

```text
aad = t("fido_key_wrap/format_1/fido_aad", c)
wrapped_root = aead(kfido, nf, root, aad)
```

a fido-presence and local-secret recipient stores:

```text
aad = t("fido_key_wrap/format_1/fido_local_aad", c)
wrapped_root = aead(kfl, nl, root, aad)
```

a combined recipient stores two layers:

```text
inner_aad = t("fido_key_wrap/format_1/combined_passphrase_aad", c)
inner = aead(kpass, npass, root, inner_aad)

outer_aad = t("fido_key_wrap/format_1/combined_fido_aad", c)
wrapped_root = aead(kfido, nf, inner, outer_aad)
```

a wrapped root is 48 bytes for the passphrase, recovery-secret, fido, and
fido-local-secret suites. the combined inner value is 48 bytes and its outer
value is 64 bytes.
combined decryption authenticates the outer fido layer before requesting or
deriving the passphrase.

## envelope authentication

let `body` be the core deterministic cbor encoding of:

```text
[1, app, eid, recipients]
```

the complete recipient records, including their labels and wrapped roots, are
part of `body`.

```text
kmac = hkdf-sha-256(
  ikm  = root,
  salt = eid,
  info = t(
    "fido_key_wrap/format_1/envelope_mac_key",
    f,
    app
  ),
  len  = 32
)

mac = hmac-sha-256(
  kmac,
  t("fido_key_wrap/format_1/envelope_mac", f, body)
)
```

mac comparison is constant-time. unlock returns the root only after the
selected recipient and this whole-envelope mac have both authenticated.

## failure convergence

the parser reports malformed, noncanonical, unsupported, and structurally
contradictory input as an invalid envelope before factor interaction. a trusted
application-id mismatch and a local argon2 resource refusal are also detected
before interaction.

once a passphrase-bearing unlock begins, a wrong passphrase, selected wrapping
ciphertext failure, or candidate-root envelope-mac failure returns the same
unlock failure. the result does not reveal which cryptographic check rejected
the candidate. a passphrase confirmation mismatch remains distinct because it
is new enrollment input, not an unlock verifier.

a wrong recovery secret, absent or changed recipient id, context change,
wrapping failure, or final envelope-mac failure returns the same unlock
failure.

a wrong local secret, a changed authenticated local-recipient field after a
valid assertion, wrapping failure, or final envelope-mac failure returns the
same unlock failure. credential lookup and assertion failures can instead
return a bounded security-key error before local-secret verification. the
general unlock method rejects this suite; its dedicated method always requires
both a verified presence assertion and the local secret.

security-key transport and verified-response failures are bounded public error
classes. native error strings, credential material, prf output, pins,
passphrases, derived keys, candidate roots, and plaintext are not included in
errors. an operation evaluates only the selected recipient and never tries a
different recipient or weaker policy after failure.

## wire format

an encoded envelope is the four bytes `FKW\0` followed by core deterministic
cbor for:

```text
[
  1,
  app,
  eid,
  recipients,
  mac
]
```

recipient arrays are:

```text
passphrase:
[1, rid, label, [1, memory_kib, passes, lanes, s], npass, wrapped_root]

recovery secret:
[4, rid, label, nr, wrapped_root]

fido:
[2, rid, label, cid, pk, fp, np, nf, wrapped_root]

managed fido:
[5, rid, label, cid, pk, fp, np, nf, wrapped_root]

fido and passphrase:
[3, rid, label, cid, pk, fp, np, nf,
 [1, memory_kib, passes, lanes, s], npass, wrapped_root]

fido presence and local secret:
[6, rid, label, cid, pk, np, nl, wrapped_root]
```

suite 5 accepts `fp=1` for presence and `fp=2` for user verification. suite 6
has fixed presence semantics and carries no policy byte.

recipients are ordered by ascending `rid`. ids are unique. fido-bearing
recipients have unique credential ids, and passphrase-bearing recipients have
unique salts. an envelope contains 1–32 recipients and is at most 65,536 bytes,
including the magic.

the decoder requires definite arrays, exact array sizes, shortest integers,
exact byte lengths, valid utf-8 and p-256 points, canonical ordering, no
trailing data, and byte-for-byte canonical re-encoding. malformed or unsupported
input is rejected before factor interaction.

## interoperability vectors

`test-vectors/` contains deterministic format-1 fixtures for every recipient
policy, a nine-recipient mixed envelope, and the command-line tool container.
`test-vectors/generate.py` implements transcript framing, hkdf, cbor, and
envelope construction independently from the rust code.
