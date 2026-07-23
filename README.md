# ratchet-ts

[![npm](https://img.shields.io/npm/v/ratchet-ts.svg)](https://www.npmjs.com/package/ratchet-ts)
[![license](https://img.shields.io/npm/l/ratchet-ts.svg)](./LICENSE)
[![types](https://img.shields.io/npm/types/ratchet-ts.svg)](./src/index.ts)

Hybrid X25519 + ML-KEM-768 Double Ratchet in TypeScript. MIT.

> ### Not audited. Read this before you ship it.
>
> This library has **not** had an independent security audit, and it has **not**
> had formal verification. It is a careful, tested, readable implementation
> written by one person, built on the well reviewed [`@noble`](https://github.com/paulmillr/noble-curves)
> primitives, but the protocol composition on top of those primitives has only
> been reviewed by its author and exercised by its own test suite.
>
> What that means in practice:
>
> - The cryptographic primitives (X25519, ML-KEM-768, HKDF-SHA256, HMAC-SHA256,
>   XChaCha20-Poly1305) come from audited libraries. The way this code wires them
>   into a handshake and a ratchet has not been reviewed by anyone else.
> - There may be protocol-level or state-machine bugs that unit tests do not
>   catch. Absence of a failing test is not proof of correctness.
> - If you are protecting people whose safety depends on this, that is exactly
>   the situation where an unaudited implementation is the wrong tool. Use
>   [libsignal](https://github.com/signalapp/libsignal) and accept its license,
>   or fund an audit of this one.
>
> Good uses today: learning, prototyping, internal tools, projects where MIT
> licensing is a hard requirement and you can accept the audit gap with eyes
> open. Treat 0.x as pre-stability: the wire format and API can change.

## Why this exists

If you want end-to-end encryption in JavaScript today, the practical options are
narrow. `libsignal` is the reference, but it is AGPL/GPL, which is effectively
unusable inside a closed-source product. The remaining path is to roll your own,
which is how most E2EE goes wrong.

`ratchet-ts` is a third option: an MIT-licensed, tested, readable Double Ratchet
with a post-quantum hybrid handshake, small enough to actually read end to end
before you trust it.

| Library | License | Post-quantum | Language |
| --- | --- | --- | --- |
| [libsignal](https://github.com/signalapp/libsignal) (libsignal-client) | AGPL-3.0 | Yes, PQXDH | Rust + bindings |
| [libsignal-protocol-typescript](https://github.com/privacyresearchgroup/libsignal-protocol-typescript) | GPL-3.0 | No | TypeScript |
| [Olm / vodozemac](https://github.com/matrix-org/vodozemac) | Apache-2.0 | No | C++ / Rust |
| **ratchet-ts** | **MIT** | **Yes, ML-KEM-768 hybrid** | **TypeScript** |

Licenses above were confirmed against each project's repository on 2026-07-23
(libsignal AGPL-3.0, libsignal-protocol-typescript GPL-3.0, vodozemac Apache-2.0).
The `ratchet-ts` row is verifiable from this repository: the license is in
[LICENSE](./LICENSE) and the ML-KEM-768 handshake is in
[`src/handshake.ts`](./src/handshake.ts).

## Install

```sh
npm install ratchet-ts
```

Runtime dependencies, all MIT: `@noble/curves`, `@noble/ciphers`, `@noble/hashes`,
`@noble/post-quantum`.

## Quickstart

This is the same code the package's smoke test runs against the published
tarball, so it is proven to work end to end.

```ts
import assert from 'node:assert/strict';
import { engine, formatFingerprint } from 'ratchet-ts';

const alice = await engine.createIdentity();
const bob = await engine.createIdentity();

// Alice invites, Bob accepts. Tokens are plain strings you can paste anywhere.
const { token: inviteToken, pending } = await engine.invite(alice);

const bobOpen = await engine.open(bob, inviteToken, {});
assert.equal(bobOpen.outcome, 'invite');
let bobSession = bobOpen.session;

const aliceOpen = await engine.open(alice, bobOpen.reply, { pending });
assert.equal(aliceOpen.outcome, 'accepted');
let aliceSession = aliceOpen.session;

// Both sides can show the same 6-word fingerprint to verify out of band.
console.log('fingerprint:', formatFingerprint(bobOpen.peerFingerprint));

// Alice -> Bob
const a1 = await engine.seal(aliceSession, 'hello from alice');
aliceSession = a1.session;
const b1 = await engine.open(bob, a1.token, { session: bobSession });
assert.equal(b1.plaintext, 'hello from alice');
bobSession = b1.session;

// Bob -> Alice
const b2 = await engine.seal(bobSession, 'hi back from bob');
bobSession = b2.session;
const a2 = await engine.open(alice, b2.token, { session: aliceSession });
assert.equal(a2.plaintext, 'hi back from bob');
```

`seal` and `open` both return a fresh `session`. The ratchet is immutable at the
API boundary: keep the returned session and drop the old one, and do not reuse a
session object across two `seal` calls.

## What you get

- **Forward secrecy.** Message keys are derived once, used once, and dropped.
  Compromising the device now does not decrypt captured older messages.
- **Post-compromise security.** After a key compromise, one DH ratchet step from
  each side heals the session: the attacker's copied state stops working.
- **Out-of-order delivery.** Messages that arrive late or reordered still
  decrypt. Skipped message keys are parked, up to a bounded limit.
- **Replay rejection.** A ciphertext that was already opened cannot be opened
  again.
- **Tamper fail-closed.** Any single bit flipped in the ciphertext, header,
  nonce, or a truncation fails authentication and decrypts nothing.
- **Hybrid post-quantum.** The handshake mixes an X25519 result and an
  ML-KEM-768 result into the root key, so the session secret holds if **either**
  of the two stands. A future quantum computer that breaks X25519 does not by
  itself break a session, and a flaw in ML-KEM does not by itself break one.

## Protocol

### Handshake

A PQXDH-shaped hybrid handshake establishes the first root key.

- The initiator sends an `invite` carrying its long-term identity (an X25519
  public key and an ML-KEM-768 public key).
- The responder generates an ephemeral ratchet key, encapsulates to the
  initiator's ML-KEM key, and mixes two X25519 Diffie-Hellman results plus the
  ML-KEM shared secret through HKDF-SHA256 into the root key. It replies with an
  `accept` carrying the ML-KEM ciphertext and its ratchet public key.
- The initiator decapsulates, derives the same root key, and takes one DH
  ratchet step to open its send and receive chains.

This is a one-and-a-half round-trip design. The initiator has no forward secrecy
for the handshake secret until the first ratchet step, at which point the Double
Ratchet takes over.

### Double Ratchet

- A **DH ratchet** turns whenever a new peer ratchet public key is seen, deriving
  a new root key and a fresh chain.
- A **symmetric-key ratchet** runs each chain forward with HMAC-SHA256, so each
  message gets a unique key that cannot be walked backward.
- Messages are sealed with **XChaCha20-Poly1305**, with the message header bound
  in as additional authenticated data, so header fields cannot be swapped or
  edited without failing authentication.
- Skipped message keys are retained up to **`MAX_SKIP = 1000`** per chain. A gap
  larger than that is refused rather than allowed to exhaust memory.

### Wire format

Every token is a single ASCII string: `OCX1.<kind>.<base64url>`, where `<kind>`
is `invite`, `accept`, or `message`, and the payload is a compact binary body,
not JSON, so it round-trips byte-exact for the AAD binding. Tokens are safe to
paste into any text channel.

### Message flow

<svg viewBox="0 0 640 300" width="100%" role="img" aria-label="Message flow: invite, accept, then ratcheting messages between Alice and Bob" xmlns="http://www.w3.org/2000/svg" style="max-width:640px;font-family:system-ui,-apple-system,sans-serif">
  <defs>
    <marker id="ah" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0 0 L8 4 L0 8" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
    </marker>
    <marker id="ahg" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <path d="M0 0 L8 4 L0 8" fill="none" stroke="#0f5f44" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
    </marker>
  </defs>
  <text x="120" y="28" text-anchor="middle" font-size="15" font-weight="600" fill="currentColor">Alice</text>
  <text x="520" y="28" text-anchor="middle" font-size="15" font-weight="600" fill="currentColor">Bob</text>
  <line x1="120" y1="44" x2="120" y2="284" stroke="currentColor" stroke-width="2" opacity="0.35"/>
  <line x1="520" y1="44" x2="520" y2="284" stroke="currentColor" stroke-width="2" opacity="0.35"/>
  <line x1="120" y1="80" x2="512" y2="80" stroke="#0f5f44" stroke-width="2" marker-end="url(#ahg)"/>
  <text x="316" y="72" text-anchor="middle" font-size="13" fill="#0f5f44" font-weight="600">invite</text>
  <text x="316" y="96" text-anchor="middle" font-size="11" fill="currentColor" opacity="0.7">identity: X25519 + ML-KEM-768 public</text>
  <line x1="520" y1="140" x2="128" y2="140" stroke="#0f5f44" stroke-width="2" marker-end="url(#ahg)"/>
  <text x="316" y="132" text-anchor="middle" font-size="13" fill="#0f5f44" font-weight="600">accept</text>
  <text x="316" y="156" text-anchor="middle" font-size="11" fill="currentColor" opacity="0.7">ML-KEM ciphertext + ratchet public, root key set</text>
  <line x1="120" y1="204" x2="512" y2="204" stroke="currentColor" stroke-width="2" marker-end="url(#ah)"/>
  <text x="316" y="196" text-anchor="middle" font-size="13" fill="currentColor" font-weight="600">message</text>
  <line x1="520" y1="248" x2="128" y2="248" stroke="currentColor" stroke-width="2" marker-end="url(#ah)"/>
  <text x="316" y="240" text-anchor="middle" font-size="13" fill="currentColor" font-weight="600">message</text>
  <text x="316" y="272" text-anchor="middle" font-size="11" fill="currentColor" opacity="0.7">ratcheting both directions, one key per message</text>
</svg>

## Security properties and limitations

The properties above are real, and the test suite exercises each of them. The
limitations are just as real, and you should read them before trusting this in
anything that matters.

- **No audit, no formal verification.** See the warning at the top. This is the
  single most important limitation.
- **Metadata is not hidden.** The protocol protects message contents and binds
  headers, but it does nothing to hide who is talking to whom, when, or how much.
  Wire tokens reveal length and kind. Anonymity and traffic analysis resistance
  are out of scope.
- **The ML-KEM contribution is not isolated by a test yet.** The hybrid handshake
  mixes the ML-KEM shared secret into the root key, but there is currently no
  test that asserts the ML-KEM half specifically alters the derived root key
  independently of the X25519 half. This is a known gap: the hybrid mix is
  present in code but its post-quantum contribution is not yet pinned down by a
  regression test.
- **Skip bound.** At most `MAX_SKIP = 1000` skipped keys are retained per chain.
  Legitimate use inside that window is fine, larger gaps are refused. A peer that
  deliberately jumps the message counter cannot force unbounded memory use, but
  it can cause its own later messages to be undecryptable past the bound.
- **Long-lived identity keys.** Identity keypairs are long-lived and are the root
  of trust for fingerprint verification. This library generates them and uses
  them, but it does not store them. Your application owns identity storage,
  including secure-at-rest handling and any key rotation policy. Losing or
  leaking an identity secret is a full compromise of that identity.
- **Fingerprints depend on out-of-band comparison.** The 6-word fingerprint (66
  bits) only protects against impersonation if two users actually compare it over
  a channel the attacker does not control. If nobody checks it, there is no
  authentication of the peer identity.

## Test suite

The suite is adversarial, not happy-path. It runs with `tsx --test` and every
test asserts a specific failure reason where a failure is expected, so a wrong
error is a failing test.

- **Forward secrecy snapshot test.** A clone of the session taken at message N is
  shown to be unable to decrypt message N+5 after the live side ratchets forward.
- **Post-compromise recovery.** After a simulated compromise, once the compromised
  side re-ratchets, the copied old state stops decrypting.
- **AAD bit-flip tamper matrix.** Single-bit flips across ciphertext, header
  fields, nonce, and truncation each fail authentication, and malformed or
  wrong-version tokens map to precise error reasons instead of throwing raw.
- **Replay rejection.** An advanced session refuses to reopen a ciphertext it has
  already consumed.
- **Skip-limit DoS bound.** A message that would require skipping past `MAX_SKIP`
  keys is refused with `skip_limit_exceeded` rather than allocating unboundedly.

Plus round-trip envelope encoding across all three token kinds and edge cases,
deterministic fingerprinting, out-of-order delivery across ratchet turns, and
session isolation and identity-mismatch handling.

Run them:

```sh
npm install
npm test
npm run typecheck
npm run build
```

## License

MIT. Copyright (c) 2026 Gintaras. See [LICENSE](./LICENSE).
