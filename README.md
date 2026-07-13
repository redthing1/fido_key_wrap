# fido-key-wrap

`fido-key-wrap` protects a 32-byte application root key with one or more fido2
credentials.

each credential recovers the same root key through one policy:

- `presence` requires the authenticator and a touch
- `user-verified` requires the authenticator, its pin, and a touch
- either policy can also require an application passphrase

the root key must be uniformly random and is not stored on the authenticator.
the key envelope stores the public credential data and encrypted root needed
for recovery.

```rust,ignore
let application = ApplicationId::new("org.example.vault")?;
let mut protector = KeyProtector::system(application);

let enrollment = Enrollment::new("primary", policy::user_verified())?;
let (root, envelope, _recipient) =
    protector.provision(enrollment, &mut interaction)?;

persist(envelope.encode())?;

let envelope = KeyEnvelope::decode(&load()?)?;
let recipient = envelope.recipients()[0].id();
let root = protector.unlock(&envelope, recipient, &mut interaction)?;
```

`interaction`, `persist`, and `load` belong to the application. the application
also owns data encryption, backups, and unlocked-session lifetime.

## demo

the included note application has a short command flow:

```text
fkw new note.fkw
fkw open note.fkw
fkw add-key note.fkw backup
```

see the [demo application](doc/demo.md) for setup and recipient policies.

- [security model](doc/security.md)
- [protocol](doc/protocol.md)
