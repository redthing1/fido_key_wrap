# integration guide

## the boundary

the application has one uniformly random 32-byte root. it derives its data
keys from that root and uses authenticated encryption for its own data.

`fido-key-wrap` protects encrypted copies of the root. each copy is a
recipient, and each recipient names the factors needed to recover it. the
resulting `KeyEnvelope` is public storage and can be backed up beside the
application ciphertext.

the library is responsible for:

- generating or importing the random root
- passphrase derivation and security-key ceremonies
- encrypting the root for each recipient
- strict envelope encoding, decoding, and authentication
- transactional recipient addition, removal, and passphrase rewrap
- clearing secret buffers that it owns

the application is responsible for:

- choosing which policies users may create and open
- supplying a stable, trusted `ApplicationId`
- selecting one exact recipient for each unlock
- implementing the `Interaction` user interface
- deriving and using its data-encryption keys
- authenticating the exact encoded envelope with its ciphertext
- atomic storage, concurrency limits, unlocked-session lifetime, and backups
- re-encrypting application data when the root is rotated

assertion output, prf results, and derived wrapping keys never cross into the
application.

## choosing a recovery model

the five policies are building blocks. an application may expose one, several,
or all of them.

| policy | recovery requirement | main consequence |
| --- | --- | --- |
| application passphrase | passphrase | copied envelopes allow offline guessing |
| fido presence | credential and touch | possession and touch are sufficient |
| fido user verification | credential, authenticator verification, and touch | adds the authenticator's verification check |
| fido presence plus passphrase | credential, touch, and passphrase | the copied envelope alone exposes no passphrase verifier |
| fido user verification plus passphrase | verified security-key ceremony and passphrase | requires both factors and authenticator verification |

recipients in one envelope are joined by **or**, not **and**. adding a
passphrase-only recovery recipient to an envelope with a combined recipient
makes the root recoverable by the passphrase-only route. the application should
present this consequence when it offers recovery choices.

## passphrase-only applications

use `KeyProtector::new` when the build has no fido capability:

```rust,ignore
let application = ApplicationId::new("vault.example")?;
let mut protector = KeyProtector::new(application);
let enrollment = Enrollment::passphrase("primary")?;
let (root, envelope, recipient) =
    protector.create_root(enrollment, &mut interaction)?;
```

passphrase creation, unlock, add, remove, and rewrap are complete in this mode.
selecting a fido policy returns `FidoSupportUnavailable` before user
interaction.

`PassphraseParameters::DESKTOP` uses 256 mib, three passes, and four lanes.
applications can record another permitted profile with the explicit enrollment
constructors. `PassphraseLimits` is a separate local admission ceiling. set it
from trusted application configuration, not from the envelope.

argon2 and native fido ceremonies are synchronous. a server or asynchronous
program should run operations involving either in a bounded blocking context
and limit concurrent derivations.

## applications with optional security-key support

enable the crate's `fido` feature where native security-key support is wanted
and construct `KeyProtector::system`. passphrase routes still work without a
connected device and make no security-key request.

a small compile-time factory keeps both builds on the same application code:

```rust,ignore
fn protector(application: ApplicationId) -> KeyProtector {
    #[cfg(feature = "fido")]
    {
        KeyProtector::system(application)
    }

    #[cfg(not(feature = "fido"))]
    {
        KeyProtector::new(application)
    }
}
```

`inspect_authenticators` is available only with the `fido` feature. it performs
read-only capability inspection and requests neither a pin nor a touch.

## testing without a security key

place root access behind a private application interface. its production
implementation delegates to `KeyProtector`; tests can use deterministic roots
and envelopes for policy, storage, mutation, and rollback behavior.

passphrase flows remain available through the production library without fido
support. security-key integration requires a fido-enabled build and a connected
authenticator.

## trusted application identity

construct `ApplicationId` from trusted application configuration. never read
an envelope's application id and use it to construct the protector.

the application should reject a decoded envelope whose id differs from its
configured id before showing recipient metadata or requesting factors. the id
is a cryptographic namespace and fido relying-party id. it is not proof of
which executable is running.

## selecting and allowing policies

`KeyEnvelope::recipients` returns bounded presentation summaries. their labels,
policies, and argon2 parameters are structurally valid but unauthenticated
until unlock completes.

the application should:

1. compare the envelope application id with its trusted id
2. reject policies outside its configured allowlist
3. ask the user or trusted configuration to select one recipient
4. pass that exact `RecipientId` to `unlock`

the library evaluates one route and never falls back to another. this avoids a
failed strong route silently becoming a weaker recovery attempt.

## binding the envelope to application data

the root-derived envelope mac authenticates the recipient set after root
recovery. it does not authenticate application ciphertext.

derive an application data key from the root with a domain unique to the
application and format. authenticate the exact `KeyEnvelope::encode()` bytes
as associated data, or place both under an equivalent authenticated container.
this prevents an envelope from being spliced onto unrelated ciphertext.

recipient changes alter the envelope. the application must therefore create a
fresh data-encryption nonce, authenticate the new envelope bytes, verify the
staged container, and replace the envelope and ciphertext atomically.

## mutation and root rotation

`add_recipient`, `remove_recipient`, and `rewrap_passphrase` require the current
root and authenticate the current envelope before returning. they stage a
complete replacement and leave the caller's envelope unchanged on failure.

these operations keep the same root. an old complete copy remains valid under
its old recipients and passphrases. strong revocation requires the application
to:

1. unlock and decrypt the current data
2. create a fresh random root and its new recipient set
3. re-encrypt all protected data under keys derived from the new root
4. verify the staged result
5. replace the old state atomically

rollback protection additionally needs trusted freshness state outside the
envelope, such as a server-held generation or monotonic platform state.

## migrating an existing password design

do not import a password-derived key as `RootKey`. instead:

1. authenticate and decrypt the old format
2. call `create_root` to obtain a fresh random root and first recipient
3. derive new application keys from that root
4. re-encrypt and authenticate the data with the exact envelope bytes
5. verify and atomically replace the old format

the old password may become the passphrase for a new recipient, but the new
root remains independent random material. this makes later addition of a
security-key route a recipient change rather than another data migration.
