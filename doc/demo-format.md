# demo format

the demo uses application id `demo.fido-key-wrap.example` and stores each note
in one `.fkd` container.

## container

```text
"FKD\0" ||
0x01 ||
u32be(envelope_length) || envelope ||
note_nonce ||
u32be(ciphertext_length) || ciphertext
```

`note_nonce` is 12 bytes. plaintext contains 1–1,048,576 bytes, ciphertext
contains 17–1,048,592 bytes, and a complete container is at most 1,114,153
bytes. the decoder rejects truncation, trailing data, invalid lengths, and
unknown magic or format.

## encryption

```text
note_key = hkdf-sha-256(
  ikm  = root,
  salt = absent,
  info = t("fkw-demo/format_1/note_encryption_key", application_id),
  len  = 32
)

note_aad = t("fkw-demo/format_1/note_aad", exact_envelope_bytes)
```

an absent hkdf salt is a hash-length string of zero bytes. `t` is the
length-prefixed framing defined in [protocol.md](protocol.md). aes-256-gcm
encrypts the plaintext and authenticates `note_aad`.

## updates

recipient changes alter the envelope. every change uses a fresh note nonce and
re-encrypts the plaintext before replacing the file.

updates use an advisory lock, same-directory temporary file, restrictive
permissions, conflict check, file sync, atomic rename, and directory sync.
failures before replacement leave the original file unchanged. note and lock
files must be mode `0600` regular files; symbolic links in either final path are
rejected.
