# demo

`fkw-demo` performs one create, encode, decode, and unlock round trip in memory.
it does not persist the envelope or root.

run a passphrase round trip without fido support:

```console
cargo run -p fkw-demo --release --no-default-features -- passphrase
```

security-key policies are available in fido builds:

```console
cargo run -p fkw-demo --release -- fido-presence
cargo run -p fkw-demo --release -- fido-user-verification
cargo run -p fkw-demo --release -- fido-presence-plus-passphrase
cargo run -p fkw-demo --release -- fido-user-verification-plus-passphrase
```

the security-key policies create dedicated non-discoverable credentials. they
consume no discoverable credential slot. the program reports success only when
the recovered root exactly matches the generated root.
