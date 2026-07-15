# python integration

the python package is a thin binding to `fido-key-wrap`. rust performs envelope
validation, cryptography, passphrase derivation, and security-key operations.
python supplies trusted application configuration, user interaction, storage,
and application data encryption.

## installation

source installation requires python 3.11 or later and rust 1.85 or later:

```console
uv add "fido-key-wrap @ git+https://github.com/redthing1/fido_key_wrap.git"
```

security-key support is a native build feature. add this setting to the
consuming project's `pyproject.toml` before running the same `uv add` command:

```toml
[tool.uv]
config-settings-package = { fido-key-wrap = { "maturin.build-args" = "--features fido" } }
```

the fido build supports macos and linux with pkg-config and the libfido2
development files for version 1.14 or later in the 1.x series. both builds
expose the same python module. `FIDO_SUPPORT` reports which capability was
compiled, without discovering a device.

## basic use

one protector belongs to one trusted application identity. enrollment selects
one recovery policy. the application stores the encoded envelope and chooses
one recipient explicitly when it unlocks the root.

```python
import fido_key_wrap as fkw


class UserInteraction:
    def request_passphrase(self, prompt: fkw.PassphrasePrompt) -> bytearray:
        return read_application_passphrase(prompt)


interaction = UserInteraction()
protector = fkw.KeyProtector("vault.example")
enrollment = fkw.Enrollment("primary", fkw.Policy.PASSPHRASE)

root, envelope, recipient = protector.create_root(enrollment, interaction)
encoded = envelope.encode()

material = root.export()
try:
    data_key = derive_application_key(material, domain=b"vault.example/data/v1")
    try:
        ciphertext = encrypt(plaintext, data_key, associated_data=encoded)
    finally:
        data_key[:] = b"\0" * len(data_key)
finally:
    material[:] = b"\0" * len(material)

envelope = fkw.KeyEnvelope.decode(encoded)
root = protector.unlock(envelope, recipient, interaction)
```

when a random root already exists, `protect_root` enrolls it without generating
a replacement:

```python
envelope, recipient = protector.protect_root(root, enrollment, interaction)
```

`read_application_passphrase` represents the application's input layer. it must
return an exact built-in `bytearray`. the binding transfers the contents into
zeroizing rust storage and clears that bytearray before the enclosing library
operation returns to python.

## recovery policies

`Policy` contains the complete eight-route model:

- `PASSPHRASE`
- `RECOVERY_SECRET`
- `FIDO_PRESENCE`
- `FIDO_USER_VERIFICATION`
- `MANAGED_FIDO_PRESENCE`
- `MANAGED_FIDO_USER_VERIFICATION`
- `FIDO_PRESENCE_AND_PASSPHRASE`
- `FIDO_USER_VERIFICATION_AND_PASSPHRASE`

passphrase-bearing enrollments use `PassphraseParameters.desktop()` unless
explicit parameters are supplied. the desktop profile uses 256 mib, three
passes, and four lanes. `PassphraseLimits` controls the maximum work this
process will accept from an envelope.

fido policies use the system backend in a fido-capable build. they fail with
`ErrorCode.FIDO_SUPPORT_UNAVAILABLE` before interaction in a passphrase-only
build. `inspect_authenticators()` returns bounded capability reports without
device identity.

each managed policy uses one discoverable credential slot. presence recovery
requires a touch; user-verification recovery requires the authenticator pin and
a touch. enrollment, verification, and retirement require the pin under either
policy. verify or retire the exact credential with the authenticated envelope
and root:

```python
protector.verify_managed_recipient(envelope, root, recipient, interaction)
protector.retire_managed_recipient(envelope, root, recipient, interaction)
```

retirement deletes and confirms absence of the credential but leaves the
immutable envelope unchanged. prepare the application state without that route,
retire against the original envelope, then publish the prepared state. any
other recipient remains an independent route to the root.

recovery-secret routes use explicit methods instead of `Enrollment`:

```python
root, envelope, recovery = protector.create_root_with_recovery_secret("recovery")

stored_secret = recovery.secret.export()
try:
    store_secret_separately(stored_secret)
finally:
    stored_secret[:] = b"\0" * len(stored_secret)

secret_bytes = load_stored_secret_as_bytearray()
secret = fkw.RecoverySecret.from_bytearray(secret_bytes)
root = protector.unlock_with_recovery_secret(
    envelope, recovery.recipient_id, secret
)
```

`from_bytearray` requires exactly 32 bytes and clears its input. the application
stores the secret separately from the envelope. it is generated binary key
material, not a passphrase or a human recovery code.

`FidoConfig` supplies trusted operation timeout, selection timeout, and device
count limits. pass it as the `fido_config` keyword when constructing a
fido-capable protector. supplying it to a passphrase-only build fails before
any interaction.

## interaction

an interaction object implements only the callbacks its policies require:

```python
class UserInteraction:
    def select_authenticator_by_touch(
        self, prompt: fkw.SelectionPrompt
    ) -> None:
        show_selection_request(prompt)

    def request_pin(self, prompt: fkw.PinPrompt) -> bytearray:
        return read_security_key_pin(prompt)

    def request_passphrase(self, prompt: fkw.PassphrasePrompt) -> bytearray:
        return read_application_passphrase(prompt)

    def touch_required(self, prompt: fkw.TouchPrompt) -> None:
        show_touch_request(prompt)
```

passphrases and pins must be exact built-in `bytearray` values. strings,
immutable bytes, subclasses, and general buffer objects are rejected.
passphrases contain 1–1,024 arbitrary bytes. pins contain 1–63 bytes of utf-8
without nul. the binding clears every exact bytearray received as secret input,
including values with invalid lengths. selection and touch callbacks must
return `None`.

raising `Cancelled` cancels an operation. other callback exceptions are
normally propagated unchanged. a later managed-credential state error takes
precedence when cleanup cannot be confirmed.

prompt objects contain the operation, recipient label, and the exact purpose or
fido ceremony needed by the interface. labels decoded from envelopes are
untrusted presentation text.

## roots and envelopes

`RootKey` is opaque and represented as redacted text. explicit copying,
pickling, hashing, and implicit byte access are blocked. python assignment may
alias the same root object. `export()` returns one writable copy for application
cryptography; clear it after use as shown above.

`RootKey.from_bytearray(material)` imports a uniformly random 32-byte root and
clears the supplied bytearray. passwords and other guessable values are not root
keys.

`KeyEnvelope` is immutable. `add_recipient`, `remove_recipient`, and
`rewrap_passphrase` return a new envelope and leave the input object unchanged.
the application re-encrypts its data with the new encoded envelope as associated
data, then publishes both atomically. it keeps any backup needed for recovery.

```python
expanded, added_recipient = protector.add_recipient(
    envelope, root, new_enrollment, interaction
)
changed = protector.rewrap_passphrase(
    expanded, root, added_recipient, interaction
)
reduced = protector.remove_recipient(changed, root, added_recipient)
```

the application derives its data-encryption key from the recovered root with a
domain unique to its own protocol. its authenticated container binds the exact
bytes returned by `KeyEnvelope.encode()` as associated data.

the application identity carried by a decoded envelope is untrusted. construct
`KeyProtector` from trusted configuration, enforce the application's allowed
policies, and select a recipient explicitly. the library never tries another
route after a failed unlock.

## errors and concurrency

library failures raise `Error`. its `code` is an `ErrorCode` value with no
native device text or secret input. `pin_retries` is an integer only when an
incorrect-pin response supplies a count and is otherwise `None`. blocked pin
states, timeout, authenticator busy, unavailable credential, and transport
failure have distinct codes. managed capacity exhaustion and uncertain
retirement are also distinct. ambiguous managed enrollment or cleanup reports
`ErrorCode.FIDO_CREDENTIAL_MAY_REMAIN`. wrong passphrases, recovery secrets,
and candidate roots that do not authenticate the envelope remain one generic
`ErrorCode.UNLOCK_FAILED` result.

operations are synchronous and release the python interpreter while rust runs
argon2 or fido work. different protectors may run concurrently. overlapping or
callback-reentrant use of one protector fails with `ErrorCode.BUSY`.
