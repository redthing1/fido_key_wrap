# platform factor storage

`fido-key-wrap-platform` stores typed generated factors outside a key envelope.
it is a companion to the cryptographic core, not a general credential store.

## paired-machine factors

`LocalSecretStore` holds the generated local factor used by
`FidoPresenceAndLocalSecret`:

```rust,ignore
use fido_key_wrap_platform::{LocalSecretStore, NativeLocalSecretStore};

let store = NativeLocalSecretStore::new(application_id.clone());
store.create(local.recipient_id(), local.secret())?;
let secret = store.load(local.recipient_id())?;
let removal = store.remove(local.recipient_id())?;
```

on macos, `NativeLocalSecretStore::new` uses the non-synchronizing
data-protection keychain with `WhenUnlockedThisDeviceOnly`. entries use the
caller's keychain access group under code-signing and entitlement controls. an
unsigned command-line program may explicitly choose `macos_login_keychain`; it
is never selected as a fallback.

on linux, the store uses the desktop session's freedesktop Secret Service,
default collection, and encrypted protocol session. it never falls back to a
file or environment variable. a headless system or an inactive user session
may have no available service.

## macos user presence

`MacosUserPresenceStore` implements `RecoverySecretStore` for generated
`RecoverySecret` values:

```rust,ignore
use fido_key_wrap_platform::{MacosUserPresenceStore, RecoverySecretStore};

let store = MacosUserPresenceStore::new(application_id.clone());
store.create(recovery.recipient_id(), recovery.secret())?;
let secret = store.load(recovery.recipient_id())?;
let removal = store.remove(recovery.recipient_id(), &secret)?;
```

each value is stored in the non-synchronizing data-protection keychain with
`WhenPasscodeSetThisDeviceOnly` and the `userPresence` access control. each load
therefore requires local user authentication accepted by macos, typically touch
id or the account password. the entry uses the caller's keychain access group
and is identified by the trusted application id, recipient id, and a public
sha-256 fingerprint of the uniformly random secret.

`create` verifies the stored value through the same protected read and may
prompt before it returns.

processes that share the same keychain access group are trusted not to mutate
these entries concurrently.

this is a recovery-secret route whose storage policy is enforced by macos. it
is not a new envelope policy, does not involve a fido authenticator, and does
not place the root in the secure enclave. after authorization, the recovery
secret and recovered root exist in application memory.

removal accepts the previously loaded secret so it can select the exact entry
without another authorization prompt. callers should first use that secret to
authenticate the selected envelope. a different value cannot delete the entry.

## operation contract

stores are bound to one trusted `ApplicationId`; each operation takes one exact
`RecipientId`. `create` never replaces different material and is safe to retry
with the same material. `load` requires exactly one canonical value. `remove`
confirms absence and distinguishes deletion from an entry that was already
absent.

native mutation failures that cannot be reconciled return `StateUncertain`.
errors are bounded categories and contain no native diagnostic text, account
name, path, or secret. native operations are synchronous and may prompt, so
applications should run them on a bounded blocking worker.

## publication order

the application retains the durable transaction boundary.

when adding a route:

1. create the envelope and generated factor;
2. store the factor;
3. publish the container;
4. remove the factor after a definite publication failure;
5. retain it and reconcile state when publication is uncertain.

process termination after factor creation but before container publication can
leave an orphan native entry. applications that require automatic cleanup
should journal the pending recipient and generated factor in equally protected
storage before creating the entry, then clear that record after publication.

when removing a paired-machine route, publish the container without that route
before removing its local factor.

when removing a macos user-presence route, first load the recovery secret and
authenticate the exact envelope. order deletion and container publication
according to the application's failure model: deleting first can leave an
unusable published route, while publishing first can leave a short-lived old
route. root rotation is required when retained copies must stop opening future
data.

the `testing` feature provides `MemoryLocalSecretStore` and
`MemoryRecoverySecretStore` with the same create-only contracts for downstream
tests. their debug output never contains stored material.
