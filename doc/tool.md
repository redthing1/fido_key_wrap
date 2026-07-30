# command-line tool

`fkw` seals one small secret behind one recovery policy. it accepts arbitrary
bytes on standard input and writes them unchanged to standard output after a
successful unlock.

build it with fido support:

```console
cargo build -p fkw-tool --release --locked
```

seal and unseal a secret:

```console
printf 'secret' | target/release/fkw seal secret.fkw -a fido-presence
target/release/fkw unseal secret.fkw
```

the available access policies are:

- `passphrase`
- `fido-presence`
- `fido-user-verification`
- `fido-presence-plus-passphrase`
- `fido-user-verification-plus-passphrase`
- `mac-user-presence` in macos builds with the `macos-user-presence` feature

`inspect` shows the recorded policy and argon2id parameters. this metadata is
public and remains unauthenticated until the file is successfully unsealed.

```console
target/release/fkw inspect secret.fkw
```

`mac-user-presence` requires a consistently signed executable with access to
the data-protection keychain. enable it when building the packaged macos host:

```console
cargo build -p fkw-tool --release --features macos-user-presence --locked
```

the cargo build produces the executable only. the host package must supply its
app-like bundle, provisioning profile, and authorized keychain access group; a
raw cargo executable cannot use this policy.

the policy stores a generated recovery secret in the non-synchronizing
data-protection keychain. reading it requires local user authentication accepted
by macos, typically touch id or the account password. `forget` authenticates
the sealed file and removes that exact keychain entry:

```console
target/release/fkw forget secret.fkw
```

the sealed file remains after `forget`, but this mac can no longer recover it
through that route. retained copies of the keychain value remain sufficient to
recover retained copies of the file.

the tool never replaces an existing destination. it creates mode-0600 regular
files atomically and rejects links, permissive files, malformed containers,
unexpected application ids, multiple recipients, and policies outside its
allowlist. secrets must contain between 1 byte and 1 mib.

`unseal` writes only the secret bytes to standard output; its prompts and errors
use the terminal streams. do not pipe the secret to a process that is not
trusted to receive it.

the library surface remains the integration point for applications that need
multiple recovery routes, managed credentials, paired-machine recovery,
recipient changes, or their own encrypted-data format.
