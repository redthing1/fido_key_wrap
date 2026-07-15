# integration guide

## the boundary

the application has one uniformly random 32-byte root. it derives its data
keys from that root and uses authenticated encryption for its own data.

`fido-key-wrap` protects encrypted copies of the root. each copy is a
recipient, and each recipient names the factors needed to recover it. the
resulting `KeyEnvelope` is public storage and can be backed up beside the
application ciphertext.

the library is responsible for:

- generating or importing the random root and generating recovery secrets
- passphrase derivation and security-key ceremonies
- encrypting the root for each recipient
- strict envelope encoding, decoding, and authentication
- transactional recipient addition, removal, and passphrase rewrap
- exact verification and retirement of managed security-key credentials
- clearing secret buffers that it owns

the application is responsible for:

- choosing which policies users may create and open
- supplying a stable, trusted `ApplicationId`
- selecting one exact recipient for each unlock
- implementing the `Interaction` user interface
- deriving and using its data-encryption keys
- authenticating the exact encoded envelope with its ciphertext
- atomic storage, concurrency limits, unlocked-session lifetime, and backups
- storing each recovery secret separately from its envelope
- publishing managed-recipient changes in a failure-safe order
- re-encrypting application data when the root is rotated

assertion output, prf results, and derived wrapping keys never cross into the
application.

## choosing a recovery model

the eight policies are building blocks. an application may expose one, several,
or all of them.

| policy | recovery requirement | main consequence |
| --- | --- | --- |
| application passphrase | passphrase | copied envelopes allow offline guessing |
| recovery secret | generated 256-bit secret | the separate secret is sufficient to recover this route |
| fido presence | credential and touch | possession and touch are sufficient |
| fido user verification | credential, authenticator verification, and touch | adds the authenticator's verification check |
| managed fido presence | managed credential and touch | uses one discoverable slot and supports exact retirement |
| managed fido user verification | managed credential, authenticator verification, and touch | uses one discoverable slot and supports exact retirement |
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

passphrase and recovery-secret creation, unlock, add, and remove are complete in
this mode. passphrase rewrap is also available. selecting a fido policy returns
`FidoSupportUnavailable` before user interaction.

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

`FidoConfig` sets operation timeout, selection timeout, and the maximum number
of discovered devices from trusted local configuration. pass it to
`KeyProtector::system_with_config`; never derive it from an envelope.

native failures are returned as bounded `AuthenticatorFailure` values. wrong
pin retries, blocked pin states, timeout, busy, unavailable credential, and
transport failure remain distinct. managed capacity exhaustion and an
unconfirmed retirement also have distinct results. an ambiguous managed
creation or failed cleanup reports that a discoverable credential may remain.
applications should not retry a pin automatically.

## managed security-key routes

`Enrollment::managed_fido` creates a discoverable credential under one exact
recovery policy:

```rust,ignore
let enrollment = Enrollment::managed_fido("local key", FidoPolicy::Presence)?;
let (root, envelope, recipient) =
    protector.create_root(enrollment, &mut interaction)?;
```

each managed recipient occupies one discoverable credential slot. enrollment
requires es256, `hmac-secret`, pin-backed user verification, credential
protection, discoverable storage, and credential management. backup-eligible
or backed-up credentials are rejected. labels are not written to authenticator
metadata.

the selected policy governs recovery. presence recovery requires only a touch;
user-verification recovery requires the authenticator pin and a touch.
verification and retirement are credential-management operations and require
the pin for either recovery policy.

verification authenticates the envelope with the supplied root before asking
for a pin or touch, then proves and enumerates the exact credential recorded by
the recipient:

```rust,ignore
protector.verify_managed_recipient(
    &envelope,
    &root,
    recipient,
    &mut interaction,
)?;
```

retirement applies the same checks, deletes that credential on the same open
authenticator, and confirms its absence by complete enumeration. it does not
change the envelope:

```rust,ignore
protector.retire_managed_recipient(
    &envelope,
    &root,
    recipient,
    &mut interaction,
)?;
```

for an envelope with other recipients, prepare the new envelope and
application ciphertext without the managed recipient before retirement. retire
the credential against the authenticated original, then publish the prepared
state. a failure before retirement preserves the original route; a failure
after retirement leaves the other original routes available. retiring the
final recipient leaves an envelope with no working route.

successful retirement disables this managed route in every retained copy of
the envelope. it does not disable another recipient, destroy a passphrase or
recovery secret, or establish that every route to the root is gone. a missing
or unavailable authenticator never counts as successful retirement.

failure or process termination before a managed envelope is durably published
can leave an unpublished discoverable credential on the authenticator. the
library reports known ambiguous creation and cleanup outcomes. applications
should reconcile their durable state and use a trusted authenticator management
tool to remove abandoned entries. no library operation resets an authenticator.

## recovery secrets

recovery-secret creation returns the recipient id and a fresh secret together:

```rust,ignore
let (root, envelope, recovery) =
    protector.create_root_with_recovery_secret("recovery")?;

recovery.secret().expose(|secret| store_secret_separately(secret))?;
```

the encoded envelope does not contain the secret. the application stores the
complete envelope and the exact 32-byte secret in separate protected storage.
to open the route, reconstruct `RecoverySecret` from the stored bytes and call
the explicit method:

```rust,ignore
let root = protector.unlock_with_recovery_secret(
    &envelope,
    recovery.recipient_id(),
    recovery.secret(),
)?;
```

new recovery secrets are generated by the library. they are binary keys, not
passphrases or human recovery codes, and do not use argon2.

## testing without a security key

passphrase and recovery-secret flows remain available through the production
library without fido support or a connected authenticator.

rust tests can enable the non-default `testing` feature and use
`testing::FakeAuthenticator`. it owns an ordinary `KeyProtector` and provides
bounded device counts, managed capacity, exact managed retirement, failure
scheduling, credential removal, and operation counters. it exposes no backend
trait or cryptographic material. keep this feature in development dependencies.

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
4. pass that exact `RecipientId` to `unlock`, or to
   `unlock_with_recovery_secret` for a recovery-secret route

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

`add_recipient`, `add_recovery_secret`, `remove_recipient`, and
`rewrap_passphrase` require the current root and authenticate the current
envelope before returning. they stage a complete replacement and leave the
caller's envelope unchanged on failure.

`remove_recipient` changes only the supplied envelope. it does not delete a
managed credential. applications should use the managed retirement sequence
above when removing that kind of route.

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
