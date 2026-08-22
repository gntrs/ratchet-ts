# Security policy

## Status

`ratchet-ts` is a `0.x`, pre-stability library. It has **not** had an
independent security audit and has **not** undergone formal verification. The
cryptographic primitives it builds on (X25519, ML-KEM-768, ML-DSA-65,
HKDF-SHA256, HMAC-SHA512, ChaCha20-Poly1305, XChaCha20-Poly1305) come from the
audited [`@noble`](https://github.com/paulmillr) libraries. The way this library
composes those primitives into a handshake and a Double Ratchet is the part that
has not been reviewed by anyone other than the author.

Do not use this to protect people whose physical safety depends on it. For that,
use [libsignal](https://github.com/signalapp/libsignal) and accept its license,
or fund an audit of this code.

## Known limitations

- The hybrid claim is pinned by test, not by reading the source. Every leg of
  both handshakes is proved load bearing by breaking it: `test/hybrid.test.ts`
  pins the live invite/accept path, and `test/leg-isolation.test.ts` covers the
  two X25519 legs, the conversation id binding, the four secret offline prekey
  handshake, the order they are concatenated in, and the downgrade surface. The
  method is the same throughout. Run the real handshake, take the root key the
  live session actually holds, then re-derive it from outside: the
  reconstruction with every leg present must match byte for byte, and every
  reconstruction with a leg dropped, zeroed or substituted must miss.
  Both files were checked by mutation on 2026-08-21, by editing
  `src/handshake.ts` and `src/prekeys.ts` to drop the ML-KEM secret from the
  ikm. Seven tests went red. Before that date this section said the opposite,
  that nothing isolated the ML-KEM contribution, and it was already out of date
  when it said it.
- What this does NOT prove: that the composition is sound, that the ML-KEM
  parameters are used correctly beyond what `@noble/post-quantum` guarantees,
  or that there is no state machine bug elsewhere. It proves the post-quantum
  arm cannot be removed or ignored without a test failing, which is a smaller
  claim than being secure and is the only one made here.
- The wire format (`OCX3`) and the public API can change within `0.x`.
- This library does not defend against a compromised runtime (malicious or
  tampered JavaScript executing in the same context as the keys).

## Reporting a vulnerability

Please report suspected vulnerabilities privately, not through a public issue.

- Open a private advisory via GitHub Security Advisories on this repository, or
- Email **239629917+gntrs@users.noreply.github.com** with `ratchet-ts security` in the
  subject.

Include enough detail to reproduce: affected version, a description of the
issue, and a proof of concept if you have one. You will get an acknowledgement
within 72 hours. Since this is a solo, unfunded project there is no formal SLA
for a fix, but confirmed issues will be disclosed and patched as fast as is
practical, with credit to the reporter unless you ask otherwise.

## Supported versions

Only the latest `0.x` release receives fixes. Pin an exact version if you depend
on this today.
