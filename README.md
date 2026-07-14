# fido-key-wrap

`fido-key-wrap` protects one random 32-byte application root with an application
passphrase, a fido security key, or both.

the crate handles root wrapping, strict envelope parsing, fido ceremonies, and
transactional recipient changes. the application keeps ownership of its data
encryption, storage, policy choices, unlocked sessions, and root rotation.

## recovery routes

one envelope may contain any combination of five routes:

- application passphrase
- security key with presence
- security key with user verification
- security key with presence and an application passphrase
- security key with user verification and an application passphrase

multiple routes are alternatives. any one recipient can recover the same root.
a combined recipient requires both factors in order: the security-key layer is
authenticated before the passphrase is requested.

passphrase support requires no security key or native fido library. the `fido`
crate feature adds security-key support on macos and linux.

## library surface

```rust,ignore
let application = ApplicationId::new("vault.example")?;
let mut protector = KeyProtector::new(application);
let (root, envelope, recipient) =
    protector.create_root(Enrollment::passphrase("primary")?, &mut interaction)?;

let encoded = envelope.encode();
let decoded = KeyEnvelope::decode(&encoded)?;
let recovered = protector.unlock(&decoded, recipient, &mut interaction)?;
```

`Interaction` supplies passphrase, pin, touch, and authenticator-selection user
interface. `RootKey`, `Passphrase`, and `Pin` are opaque, non-cloneable,
zeroizing values with redacted debug output.

with the `fido` feature, `KeyProtector::system` uses the same surface for
security-key routes. applications encrypt their own data and authenticate the
exact encoded envelope with it.

## documentation

- [integration guide](doc/integration.md)
- [security model](doc/security.md)
- [protocol](doc/protocol.md)
- [demo application](doc/demo.md)
- [demo format](doc/demo-format.md)
