# demo application

`fkw` protects one encrypted note with one or more fido2 credentials.

the build requires `libfido2` and `pkg-config`. a `libfido2` 1.x release at
version 1.17 or newer must be visible to `pkg-config` on macos or linux.

install the demo from the repository:

```text
cargo install --path crates/fkw-demo --locked
```

## first note

inspect the connected authenticators without requesting a pin or touch:

```text
fkw check
```

create a note:

```text
fkw new note.fkw
```

enter one line at the `note (input hidden):` prompt. `fkw` creates a
non-discoverable fido2 credential, verifies a signed assertion carrying its prf
output, and constructs the recipient. the default policy requires the fido pin
and a touch for each operation.

open the note later:

```text
fkw open note.fkw
```

the root key is returned only after the selected recipient and the complete key
envelope have been authenticated. the note ciphertext is then authenticated and
decrypted.

`fkw open` writes the plaintext note to standard output. terminal scrollback,
session recording, logging, or output redirection can retain it. redirecting the
output creates a separate plaintext file whose permissions are controlled by the
shell and operating system.

## input

read a note from a file:

```text
fkw new note.fkw -i note.txt
```

the source file remains plaintext and must be protected or removed separately.

read multiline input from the terminal with `-i -`; this input is visible.
finish with end-of-file (`control-d` on macos and linux):

```text
fkw new note.fkw -i -
first line
second line
<control-d>
```

the note is never accepted as a command-line argument, where it could be
retained in shell history or process listings.

## recipient policies

pin and touch are the default. a recipient can instead require touch with
user verification absent:

```text
fkw new note.fkw --touch-only
```

credential creation still requires the pin. later assertions for this recipient
require signed `up=1, uv=0`. this policy is appropriate only when possession and
a touch are sufficient.

add an application passphrase with `-p`:

```text
fkw new note.fkw -p
```

the application passphrase is separate from the fido pin. both are required to
recover the root key through this recipient.

the options can be combined:

```text
fkw new note.fkw -t -p
```

## backup recipient

add a backup recipient with label `backup`:

```text
fkw add-key note.fkw backup
```

labels contain 1 to 32 lowercase letters, numbers, or hyphens. a label must
begin and end with a letter or number.

the command first unlocks the root key through the current recipient. it then
pauses so that the current authenticator can be unplugged and the backup
connected. the backup credential is created, its signed prf assertion is
verified, and the staged envelope is unlocked through the new recipient before
the file is replaced. under the default policy, these three backup operations
each request its pin and touch.
an application passphrase is entered and confirmed during construction, then
entered once more for the final unlock.

store the backup authenticator separately. `fkw` proves that each credential
works, but cannot prove that two recipients belong to different physical
authenticators.

the same policy options apply to a backup:

```text
fkw add-key note.fkw backup -t
fkw add-key note.fkw backup -p
```

## choosing a recipient

when several recipients can recover the root key, `fkw` presents a numbered
choice. a recipient can also be selected by label:

```text
fkw open note.fkw -k backup
```

this avoids the numbered choice. fido and passphrase interaction is still
required by the selected policy.

list the recipient labels and policies:

```text
fkw keys note.fkw
```

recipient ids are public but hidden from normal output. show them when needed:

```text
fkw keys note.fkw --details
```

`-k` accepts either a recipient label or `id:` followed by a unique recipient-id
prefix of at least eight hexadecimal characters:

```text
fkw open note.fkw -k id:e499e42d
```

a recipient id identifies one envelope record. it is not a physical-device id.
labels and policies are unauthenticated display data until the root key is
recovered and the envelope mac is verified.

## removing a recipient

```text
fkw remove-key note.fkw backup
```

the final recipient cannot be removed. removal updates the current file, but an
older complete copy retains its valid envelope mac and remains recoverable
through the removed recipient.

## the note file

the `.fkw` file contains the encrypted note and its key envelope. each envelope
recipient stores the public credential material, policy, protocol inputs, and
wrapped root key needed for recovery. the authenticator cannot recover the note
without this file, so it must be backed up.

files are created with mode `0600`. updates use an advisory lock and atomic
same-directory replacement. a symbolic link in the final path component is
rejected. use `chmod 600 note.fkw` to correct an overly permissive file before
opening it.

the adjacent lock is named `.<file-name>.fkw-lock`. when no `fkw` process is
using the note, the note and lock can be deleted together.

the non-discoverable credentials created by `fkw` cannot be enumerated and
deleted individually through ordinary authenticator management. deleting the
final copy of the note file loses the credential ids and wrapped root even when
the physical authenticator remains.

see the [security model](security.md) for the guarantees and limitations.
