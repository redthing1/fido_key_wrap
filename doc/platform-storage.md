# platform secret storage

`fido-key-wrap-platform` stores the generated local factor used by the paired-
machine route. it is a companion to the cryptographic core, not a general
credential store.

## surface

one store is bound to a trusted `ApplicationId`. each operation also takes the
exact `RecipientId`:

```rust,ignore
use fido_key_wrap_platform::{LocalSecretStore, NativeLocalSecretStore};

let store = NativeLocalSecretStore::new(application_id.clone());
store.create(local.recipient_id(), local.secret())?;
let secret = store.load(local.recipient_id())?;
```

`create` never replaces different material. retrying it with the same secret
is safe. `load` requires exactly one well-formed entry. `remove` confirms
absence and distinguishes a deletion from an entry that was already absent.
an uncertain native mutation has its own error and requires reconciliation by
retrying `create` or `remove` for the exact entry.

errors are bounded categories and contain no native diagnostic text, account
name, path, or secret. native operations are synchronous and may prompt; run
them on a bounded blocking worker, not directly on an executor or user
interface thread.

## macos

`NativeLocalSecretStore::new` uses the data-protection keychain. entries do not
synchronize and use `WhenUnlockedThisDeviceOnly`. access depends on the host
application's signing and keychain entitlements.

unsigned command-line programs can explicitly select
`NativeLocalSecretStore::macos_login_keychain`. this uses the default login
keychain with its own access-control and backup behavior. failure to access the
data-protection keychain never selects the login keychain automatically.

## linux

the native store uses the desktop session's freedesktop Secret Service, its
default collection, and an encrypted protocol session. the application and
recipient ids are public item attributes; factor material is stored in the
item's secret value.

Secret Service may be absent from a headless system or unavailable before a
user session starts. the crate returns a bounded error and never falls back to
a file, environment variable, or weaker store.

## publication

the store cannot publish the application's encrypted container, so the
application retains the transaction boundary.

when adding a route:

1. create the new envelope and local factor;
2. store the factor;
3. publish the container;
4. remove the factor only after a definite publication failure;
5. retain it and reconcile state when publication is uncertain.

when removing a route, publish the container without that route before calling
`remove` for its local factor. retrying `remove` after a lost response is safe.

## security boundary

the native secret store keeps the factor separate from the envelope and makes a
copied envelope plus a security key insufficient on an unpaired machine. the
selected store's access and at-rest policy determine its local protection. the
user session remains a trusted boundary. a process able to read that user's
native secret store can obtain the local factor, but still needs the bound
security-key credential and a touch.

applications with an existing secret store, a sandbox-specific integration, or
a headless provisioning system can use the typed `LocalSecret` directly. the
core crate performs no platform storage i/o.

the `testing` feature provides `MemoryLocalSecretStore` with the same
create-only lifecycle for downstream tests. it never prints stored material.

## live check

an opt-in example exercises a real security key and native store with a
disposable, non-discoverable recipient:

```console
cargo run -p fido-key-wrap-platform --example live-pairing --features fido --locked
```

the example keeps its envelope in memory and confirms removal of its native
entry before reporting success. the non-discoverable credential consumes no
resident slot. on macos the unsigned example explicitly uses the login
keychain; a signed application can use the data-protection default.
