# demo application

`fkw` is a small encrypted-note application. it demonstrates the library's
interactive recovery routes, recipient changes, managed-key retirement,
passphrase changes, and root rotation while keeping application encryption
outside the library.

passphrases and pins are read from the terminal with echo disabled.

build the passphrase-only demo in release mode:

```text
cargo build -p fkw-demo --release --no-default-features --locked
target/release/fkw --help
```

the examples below use `fkw` for the resulting executable. this build supports
all passphrase operations and requires no libfido2 installation or security
key.

## first note

create a passphrase-protected note:

```text
printf 'a private note\n' | fkw new note.fkd -a application-passphrase
```

open it:

```text
fkw open note.fkd
```

plaintext travels only through standard input and standard output. redirected
or recorded streams may retain it.

multiline input works through an ordinary pipe:

```text
fkw new note.fkd -a application-passphrase <<'note'
first line
second line
note
```

## access policies

security-key routes require libfido2 1.14 or later in the 1.x series through
`pkg-config` on macos or linux:

```text
pkg-config --atleast-version=1.14.0 libfido2
cargo build -p fkw-demo --release --locked
fkw check
```

`check` inspects authenticator capabilities without requesting a pin or touch
or creating a credential.

`--access` accepts exactly:

```text
application-passphrase
fido-presence
fido-user-verification
fido-managed
fido-presence-plus-passphrase
fido-user-verification-plus-passphrase
```

examples:

```text
printf 'a private note\n' | fkw new note.fkd -a fido-presence
printf 'a private note\n' | fkw new note.fkd -a fido-managed
printf 'a private note\n' | fkw new note.fkd -a fido-user-verification-plus-passphrase
```

fido recipient creation performs two ceremonies: credential enrollment, then a
fresh assertion that verifies the new recovery route before the note is saved.
enrollment requires the security-key pin and a touch. the assertion follows the
recipient policy: presence requires a touch, while user verification requires
the pin and a touch. combined policies authenticate the security-key layer
before asking for the application passphrase.

ordinary fido routes use non-discoverable credentials and take no resident
credential slot. `fido-managed` uses one discoverable slot and requires user
verification. it supports exact verification and deletion of that credential.

the application passphrase and security-key pin are different factors.

## recipients

list recovery routes:

```text
fkw recipients note.fkd
fkw recipients note.fkd --details
```

the detailed form includes canonical recipient ids and recorded argon2 work.
this metadata is structurally valid but unauthenticated until the note is
opened.

when several routes exist, a command asks which one to use. select one directly
with `--recipient` for `open` or `--using` for a mutation:

```text
fkw open note.fkd --recipient primary
fkw open note.fkd --recipient 2f7a3c91
```

a selector may be a unique label, full id, or unambiguous id prefix. labels are
presentation names, not physical-device identities.

## adding a recovery route

add an alternative route after unlocking the current note:

```text
fkw add-recipient note.fkd -a fido-user-verification -l backup -u primary
```

the library verifies the new route before updating the note. adding the first
passphrase-only route to an envelope that does not already contain one requires
confirmation because copied note files then permit offline passphrase guessing
through that alternative route.

## removing a route

```text
fkw remove-recipient note.fkd backup -u primary
```

the last route cannot be removed. an old complete file retains the removed
route and remains usable.

removal does not contact or delete an ordinary fido credential. managed routes
must use `retire-key` instead. the command first unlocks through `--using`,
which may itself be a security-key route.

## managed keys

verify that the exact managed credential is present on the selected key:

```text
fkw verify-key note.fkd primary -u primary
```

retire it and confirm deletion:

```text
fkw retire-key note.fkd primary -u primary
```

retirement requires confirmation unless `--yes` is supplied. it authenticates
the note first, proves the exact credential, deletes it, and confirms that it
is absent. deletion frees its discoverable slot and does not reset the key or
create a permanent blacklist.

when other routes remain, the demo prepares the updated note before deleting
the credential and publishes it only after deletion succeeds. retiring the
final route leaves the file in place with no working recovery route. retained
copies also lose this managed route, but any other recipient in those copies
remains usable.

once deletion succeeds, it cannot be rolled back. if publishing the prepared
note then fails or cannot be confirmed, the command reports that the credential
was retired. the file may still name the dead route or may already contain the
replacement; its other original routes remain usable.

## changing a passphrase

```text
fkw change-passphrase note.fkd primary -u primary
```

this works for passphrase-only and combined recipients. it preserves the root,
recipient id, label, and any fido credential and policy while replacing the
passphrase protection. a combined recipient checks the security key before
requesting the new passphrase. old complete files retain the old passphrase.

the command first unlocks through `--using`. when that authorizer and the
recipient being changed both use fido, each route requires its own assertion.

## argon2 parameters

passphrase-bearing routes use the desktop profile by default. an explicit
profile supplies all three values together:

```text
fkw new note.fkd -a application-passphrase --memory-mib 256 --passes 3 --lanes 4
```

the same options are available when adding a passphrase-bearing recipient,
changing a passphrase, or rotating the root.

the demo accepts the desktop profile and lighter format-1 profiles.

## rotating the root

```text
fkw rotate-root note.fkd -a fido-user-verification-plus-passphrase -u primary
```

root rotation replaces every current route with one new route and re-encrypts
the note under a new random root. it requires confirmation unless `--yes` is
supplied. the library verifies the replacement route, and the staged note is
decrypted and compared before it replaces the current file.

old complete files remain independently usable. rotation prevents them from
opening data encrypted under the new root; it cannot erase or invalidate those
old copies.

## file security

the `.fkd` file contains the key envelope, a random note nonce, and the
authenticated ciphertext. the note key is derived from the root with
hkdf-sha-256. aes-256-gcm authenticates the exact envelope bytes as associated
data, so an envelope cannot be exchanged without invalidating the note.

recipient changes re-encrypt the note and replace the file atomically. note and
lock files must be mode `0600` regular files; symbolic links are rejected. the
[demo format](demo-format.md) specifies the container and update procedure.

the security key alone is not a backup: no security-key credential can recover
the envelope, wrapped root, or note ciphertext without the complete `.fkd`
file. back up that file together with access to at least one working recovery
route.

see the [security model](security.md) for the library guarantees.
