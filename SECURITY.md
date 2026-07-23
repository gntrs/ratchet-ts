# Security policy

## Status

`ratchet-ts` is a `0.x`, pre-stability library. It has **not** had an
independent security audit and has **not** undergone formal verification. The
cryptographic primitives it builds on (X25519, ML-KEM-768, HKDF-SHA256,
HMAC-SHA256, XChaCha20-Poly1305) come from the audited
[`@noble`](https://github.com/paulmillr) libraries. The way this library
composes those primitives into a handshake and a Double Ratchet is the part that
has not been reviewed by anyone other than the author.

Do not use this to protect people whose physical safety depends on it. For that,
use [libsignal](https://github.com/signalapp/libsignal) and accept its license,
or fund an audit of this code.

## Known limitations

- No test isolates the ML-KEM-768 contribution to the root key. If the
  post-quantum leg were silently dropped, the current suite would still pass.
  The classical X25519 leg is exercised on every handshake.
- The wire format (`OCX1`) and the public API can change within `0.x`.
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
