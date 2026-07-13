# security model

## protected asset

the protected asset is one uniformly random 32-byte `RootKey`. possession of a
stored envelope alone does not reveal the root.

unlock requires the ceremony recorded for one recipient and, when enabled, its
application passphrase. a root-derived mac authenticates the recipient set and
its policies before the root is returned.

## trust assumptions

- the authenticator protects its credential secrets, enforces its pin and
  presence behavior, and signs correct authenticator data
- the host process is trusted during enrollment and unlock
- the application stores the envelope and its encrypted data correctly

the host briefly sees the pin, passphrase, verified `hmac-secret` result,
derived keys, root, and application plaintext. code executing in the process
during unlock can obtain those values.

the envelope is untrusted until decoding and cryptographic verification
succeed. its credential ids, public keys, labels, and policies are public.

## attacker capabilities

| attacker has | result |
| --- | --- |
| envelope | cannot recover the root |
| authenticator | lacks the credential id, protocol inputs, and encrypted root |
| envelope and authenticator | must complete the fido ceremony and any configured passphrase |
| envelope and application passphrase | still needs the authenticator ceremony |
| older complete envelope | remains valid and still requires its recorded factors |
| control of the host during unlock | can obtain the root and plaintext |

## fido policies

`presence` requests no pin and accepts only a verified assertion with signed
`up=1, uv=0`.

`user-verified` requests one pin and accepts only a verified assertion with
signed `up=1, uv=1`. an incorrect pin is not retried automatically.

presence and user verification select different `hmac-secret` branches. one
cannot substitute for the other, even when user verification might appear
stronger.

credential creation always requires user verification. the new credential is
then used in a second assertion. the envelope is returned only after the final
recipient construction has been proved.

always-uv is incompatible with a presence recipient because the authenticator
cannot produce `uv=0`. changing the authenticator pin does not invalidate a
credential, but later verified operations require the new pin. resetting the
authenticator makes its existing credentials unusable.

## passphrase layer

the passphrase is an application factor, not the authenticator pin.

the root is encrypted under an argon2id-derived key. that ciphertext is then
encrypted under the authenticator-derived key. unlock authenticates the outer
layer before asking for the passphrase.

a copied envelope therefore provides no standalone verifier for passphrase
guessing. an attacker with the envelope who completes the fido ceremony can
obtain the inner ciphertext and test guesses, so passphrase strength still
matters.

passphrases are not normalized or trimmed. their exact bytes are significant.

## envelope integrity and rollback

each recipient ciphertext authenticates the fields that determine its
cryptographic identity. a root-keyed hmac covers the canonical envelope body,
including the application id, recipient set, policies, and labels.

changing, removing, adding, or combining recipient records fails
authentication. an older complete envelope has a valid older mac and remains
usable.

the envelope contains no trusted counter, timestamp, or monotonic state.
applications that need rollback protection must keep freshness state elsewhere.
recipient removal is not strong revocation while older envelope copies remain.

## attestation and device identity

enrollment verifies the attestation signature but does not validate a
manufacturer trust chain. it proves control of the new credential's assertion
key, not a trusted vendor, model, serial number, or physical device identity.

discovery metadata is never used as credential identity. the application and
user must ensure that primary and backup recipients are created on different
authenticators and stored separately.

## secret lifetime

`RootKey`, `Pin`, and `Passphrase` use zeroizing storage, cannot be cloned, and
redact debug output. owned intermediate-secret buffers are cleared when
dropped.

zeroization cannot erase copies made by the compiler, allocator, operating
system, crash reporter, or application. memory is not locked. valuable keys may
require process isolation, disabled core dumps, controlled logging, and short
unlocked sessions.

## not protected

the library does not protect against:

- malware or a deceptive user interface during enrollment or unlock
- physical or firmware compromise of the authenticator
- observation of the pin or passphrase during entry
- deletion, corruption, or rollback of stored data
- accidental enrollment of two recipients on one physical authenticator
- insecure encryption, persistence, logging, backups, or session handling in
  the application

for valuable data:

- keep at least two independently stored authenticators
- prefer user verification when possession and touch are insufficient
- back up the envelope and all key state needed to decrypt application data as
  one consistent set
- verify every backup recipient before relying on it
- rotate the root when strong revocation is required
