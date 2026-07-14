# security model

## protected value

the library protects one uniformly random 32-byte application root. the root
is not stored on the security key. a key envelope contains one or more
encrypted copies of the root, plus the public material needed to attempt each
recovery route.

the envelope is public. store it beside application ciphertext only when the
exact envelope bytes are authenticated with that ciphertext.

## construction in brief

a passphrase recipient derives a wrapping key with argon2id followed by
hkdf-sha-256. a recovery-secret recipient derives its wrapping key from a
library-generated 256-bit secret with hkdf-sha-256. a fido recipient obtains a
signed and verified `hmac-secret` result from its dedicated non-discoverable
credential, then derives a wrapping key with hkdf-sha-256.

a combined recipient encrypts the root under the passphrase key and encrypts
that result under the fido key. unlock verifies and removes the fido layer
before requesting the passphrase.

aes-256-gcm authenticates each encrypted layer. recipient identity, policy,
parameters, credential material, application id, and envelope id are bound into
domain-separated contexts. a root-derived hmac-sha-256 authenticates the
canonical envelope body and complete recipient set before a recovered root is
returned.

the exact construction and wire format are in [protocol.md](protocol.md).

## recovery policies

`recovery secret` requires the exact 32-byte secret returned when the recipient
was created. the envelope contains no copy or verifier of that secret. the
application must store it separately and treat it as sufficient to recover the
root through this route. it is generated binary key material, not a passphrase
or a human recovery code.

`fido presence` requires the recorded credential and a signed assertion with
user presence set and user verification clear. in ordinary use this means the
key and a touch.

`fido user verification` requires user presence and user verification set. the
application supplies the authenticator pin through `Interaction`; the library
passes it to the native operation once and accepts no automatic fallback.

the policy code is bound into the recipient context and therefore into the prf
input and wrapping key. an assertion with user verification set does not
satisfy a presence recipient. backup-eligible and backed-up credentials are
rejected for both policies.

credential creation always requires user verification. enrollment verifies the
packed attestation signature, the es256 key, the requested credential
protection, and exact signed flags. the new credential is then exercised by a
fresh assertion before the recipient is returned.

## credential storage

the library requests a non-discoverable credential with `rk=false`. the
credential id is stored in the envelope and supplied to the authenticator for
each assertion. it does not consume a discoverable credential slot.

credential-management tools enumerate and delete discoverable credentials;
they do not manage this envelope-held credential id. removing a recipient
therefore removes the route from the current envelope without contacting the
security key. old envelope copies still contain the route. resetting the fido
function on the authenticator invalidates its non-discoverable credentials,
along with the device's other fido credentials.

## several recipients

several recipients are alternative recovery routes to the same root. they are
joined by **or**.

the least demanding available route determines the minimum protection of the
root. for example, a passphrase-only recovery recipient permits offline
guessing even when another recipient requires both a security key and a
passphrase. a recovery-secret recipient permits recovery by anyone who obtains
that secret and the envelope.

the library evaluates exactly the selected `RecipientId`. it does not search
for a working recipient or fall back after failure.

each fido-bearing recipient has its own credential. primary and backup keys are
represented by separate recipients enrolled while the corresponding key is
selected. when several compatible authenticators are attached, the
`Interaction` implementation asks the user to choose one by touch.

## copied-envelope attacks

### passphrase recipient

a copied envelope provides an offline passphrase verifier. each guess requires
the recorded, locally admitted argon2id work and an authenticated decryption
attempt. application rate limits cannot stop guessing after the envelope has
been copied.

argon2 increases the cost of each guess but does not add entropy. a strong,
unique application passphrase remains necessary.

### recovery-secret recipient

a copied envelope does not permit practical guessing of a uniformly random
256-bit recovery secret. disclosure of the separately stored secret permits
immediate recovery through that recipient. the library does not define its
storage, encoding, export, or transfer policy.

### fido recipient

a copied envelope alone is insufficient. recovery requires the dedicated
credential and the exact signed ceremony recorded by its policy.

a valid unlock places the prf result, derived wrapping key, and root in host
memory. malware present during that unlock can capture them.

### combined recipient

an envelope-only attacker cannot reach the inner passphrase ciphertext without
first completing the fido layer. this removes the standalone passphrase
verifier from the copied envelope.

after a successful fido ceremony, anyone who captures the inner ciphertext or
derived fido material can test passphrase guesses offline. protection against
envelope-only guessing therefore assumes that no valid unlock has been
captured.

## host and native trust

the process is trusted while creating or opening a recipient. it briefly owns
the passphrase or pin, verified prf result, derived keys, root, and any
application plaintext. code running in that process can obtain them.

fido ceremonies also trust the operating-system transport, the native fido
library, its loader, and the selected ctap endpoint to execute the verified
protocol correctly. the adapter applies the host-side verification described
above before copying prf output into the safe crate.

the construction uses direct ctap. the `ApplicationId` is the relying-party id
and a cryptographic namespace, but it does not prove which local executable is
calling the authenticator.

## authenticator identity and attestation

packed attestation authenticates the credential-creation response and its
embedded credential public key. a fresh assertion proves control of the
corresponding private key before the recipient is returned. attestation is not
evaluated against
a manufacturer trust chain and establishes no vendor, model, serial number,
physical origin, or unclonability.

credential ids and discovery metadata are not physical-device identities. an
application or user that wants separate primary and backup keys must arrange
and verify that separation operationally.

changing an authenticator pin normally leaves its credentials usable under the
new pin. resetting the authenticator destroys the credential secrets needed by
existing recipients.

## envelope integrity and application binding

the envelope mac detects changes to the application id, envelope id,
recipients, policies, labels, and wrapped roots after a candidate root is
recovered. wrong factors, malformed or corrupted records, and invalid final
authentication are rejected without exposing partial cryptographic results.

the mac does not bind application ciphertext by itself. the application must
authenticate the exact encoded envelope with its ciphertext. otherwise a valid
envelope and valid ciphertext can be spliced across application objects.

recipient summaries are untrusted display data before unlock. the application
must supply its own trusted application id and policy allowlist rather than
adopting values from the envelope.

## rollback, removal, and rotation

an old complete envelope contains a valid old mac and remains usable. removing
a recipient or changing a passphrase affects only the updated copy.

the envelope has no clock, trusted counter, or monotonic state. applications
that need rollback detection must keep freshness state elsewhere.

root rotation is the revocation boundary. replacing the root and re-encrypting
application data prevents an old envelope from opening future data. the
application owns this operation because it alone can decrypt, verify,
re-encrypt, and atomically replace its data.

## resource limits

the format accepts argon2id memory from 64 to 256 mib, three to six passes, and
one to four lanes. these are protocol bounds, not permission to spend arbitrary
resources.

`PassphraseLimits` provides a separate immutable local ceiling. the protector
checks the selected recipient against it before requesting a passphrase or
allocating argon2 memory. one operation evaluates one recipient.

an application still controls concurrency. untrusted clients can otherwise
turn individually valid derivations into memory exhaustion. servers should use
a bounded blocking pool and limit simultaneous work.

## secret lifetime

`RootKey`, `RecoverySecret`, `Passphrase`, and `Pin` have no `Clone` or
`Display`, redact `Debug`, and use zeroizing storage. their explicit exposure
methods can still let application code copy or print secrets. owned argon2
memory, kdf output, prf result, derived keys, decrypted layers, and transient
root buffers are cleared when dropped.

zeroization reduces ordinary secret lifetime; it is not forensic erasure. it
cannot guarantee removal from registers, compiler temporaries, allocator
history, swap, crash dumps, terminal input buffers, or copies made by the
application. it also cannot protect a compromised process.

## limits

the security model excludes:

- application data encryption or storage
- protection from malware during a valid unlock
- availability, backup, deletion, and rollback protection
- a trusted user interface for passphrase, pin, or touch prompts
- protection from weak passphrases or observed input
- non-exportable host-side wrapping keys
