# ratchet-ts

[![ci](https://github.com/gntrs/ratchet-ts/actions/workflows/ci.yml/badge.svg)](https://github.com/gntrs/ratchet-ts/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/ratchet-ts.svg)](https://www.npmjs.com/package/ratchet-ts)
[![license](https://img.shields.io/npm/l/ratchet-ts.svg)](./LICENSE)
[![types](https://img.shields.io/npm/types/ratchet-ts.svg)](./src/index.ts)
[![npm downloads](https://img.shields.io/npm/dm/ratchet-ts.svg)](https://www.npmjs.com/package/ratchet-ts)

Hybrid X25519 + ML-KEM-768 Double Ratchet in TypeScript. MIT.

> **Not audited.** No independent audit, no formal verification. The primitives
> (X25519, ML-KEM-768, HKDF-SHA256, HMAC-SHA256, XChaCha20-Poly1305) come from the
> audited [`@noble`](https://github.com/paulmillr) libraries. The protocol on top
> of them was written and reviewed by one person. There can be state-machine bugs
> no test catches. If real people's safety depends on it, use
> [libsignal](https://github.com/signalapp/libsignal) or fund an audit of this.
> Fine for learning, prototyping, internal tools, and anywhere MIT is a hard
> requirement and you can accept the gap. On 0.x the wire format and API can move.

## Why

`libsignal` is the reference, and it is AGPL/GPL, so you cannot use it inside a
closed-source product. The usual next move is to write your own ratchet, which is
how most E2EE breaks.

This is the third option: MIT, post-quantum, and small enough to read before you
trust it.

| Library | License | Post-quantum | Language |
| --- | --- | --- | --- |
| [libsignal](https://github.com/signalapp/libsignal) | AGPL-3.0 | Yes, PQXDH | Rust + bindings |
| [libsignal-protocol-typescript](https://github.com/privacyresearchgroup/libsignal-protocol-typescript) | GPL-3.0 | No | TypeScript |
| [Olm / vodozemac](https://github.com/matrix-org/vodozemac) | Apache-2.0 | No | C++ / Rust |
| **ratchet-ts** | **MIT** | **Yes, ML-KEM-768 hybrid** | **TypeScript** |

Licenses confirmed against each repo on 2026-07-23. The `ratchet-ts` row is
verifiable here: license in [LICENSE](./LICENSE), the ML-KEM-768 handshake in
[`src/handshake.ts`](./src/handshake.ts).

## Install

```sh
npm install ratchet-ts
```

Runtime deps, all MIT: `@noble/curves`, `@noble/ciphers`, `@noble/hashes`,
`@noble/post-quantum`.

## Send a file between two machines

The package ships a `ratchet` command. Two machines, two commands, no account
and no setup. Install it on both:

```sh
npm install -g ratchet-ts
```

Note the `-g`. A plain `npm install ratchet-ts` puts the binary in
`node_modules/.bin` and it never reaches your PATH, so `ratchet` comes back as
command not found.

**On the machine receiving the file**, start the listener first:

```sh
ratchet recv --out . --once
```

`--out` takes a real path and does no expansion of its own, so `~/Downloads` is
fine in bash and zsh, where the shell expands it first, and creates a folder
literally named `~` in PowerShell and cmd, where nothing does. On Windows write
it out: `--out $HOME\Downloads` in PowerShell, `--out %USERPROFILE%\Downloads` in
cmd. The banner prints the directory it resolved to, so read that line before you
go looking for the file.

It prints every address it can be reached on, each one already written out as
the command to run on the other machine, with `FILE` where your filename goes.
**On the machine sending**, run that line with the name filled in:

```sh
ratchet send holiday.jpg --to 192.168.1.24 --stats
```

`--stats` is optional and prints the size, the time and the overhead afterwards.

Text works the same way, and a dash reads stdin so a pipe works:

```sh
ratchet send --text "the wifi password is hunter2" --to 192.168.1.24
echo "same thing from a pipe" | ratchet send - --to 192.168.1.24
```

### Moving a .env

This is the case that probably brought you here. A colleague needs the dev
`.env`, or your other laptop does, and the options are Slack, a ticket, or a
password manager that then keeps a copy of it forever.

```sh
# them, first
ratchet recv --out . --once

# you, with the address it printed
ratchet send .env --to 192.168.1.24
```

The bytes go straight from your machine to theirs over TCP. Nothing is uploaded,
nothing is stored, and when both processes exit there is no copy anywhere except
the two disks that were always going to have one.

`ratchet` notices when a transferred file looks like a secret: `.env`, `*.pem`,
`*.key`, `id_ed25519`, anything with `secret` or `credential` in the name. It
never prompts and never refuses, it just says it saw. The warning prints **on the
receiving machine**, after the file is written, and what it says is that the
transfer was encrypted and the file now sitting on that disk is not. The sending
side prints nothing extra. With `--json` the receiver's object carries
`"secret": true` for the same files.

### Talking instead of transferring

`ratchet chat` is the same handshake with a line-oriented terminal on top.
Nothing is written to disk at either end.

```sh
# one side
ratchet chat --port 4477

# the other, with the address the first one printed
ratchet chat --to 192.168.1.24:4477
```

Type a line, press enter, it arrives. `/quit`, Ctrl-C or Ctrl-D ends it and both
sides print how many messages moved. The same six safety words appear, and the
same rule applies: compare them out loud.

A chat only pairs with another chat. Both ends open with an invite and settle
the tiebreak between themselves, so `ratchet chat` will not talk to
`ratchet recv`, and it does not accept a file.

If you would rather install nothing, `npx ratchet-ts recv` and
`npx ratchet-ts send ...` do the same job. Spell out `ratchet-ts`: `npx ratchet`
is an unrelated package by somebody else.

The file contents and the metadata around them (the filename, the size, the
hash) are all encrypted with the same ratchet the library exposes. It is a
direct TCP connection between the two machines: no relay, no server, no account,
nothing of yours in the middle.

Both ends print two lines of six safety words the moment the handshake lands,
before the bytes finish moving.

```
  compare aloud  scan  fiber  black  abstract  cradle  struggle
  peer identity  derive  remain  trip  noise  bean  fix
```

**Compare the `compare aloud` line out of band**, out loud or over a channel an
attacker on this network does not control. That line belongs to the pair, so it
reads the same on both screens, and matching words mean you are talking to the
machine you think you are. Nobody checks this for you.

The `peer identity` line names the **other** machine, so the two screens show
different words there, and that is correct. It is the same six words that machine
prints for itself under `ratchet id`, and the same words the receiver shows in
the `you` line of its own banner. That is the cross-check: the sender's
`peer identity` should read back the receiver's `you` line. Do not expect it to
match your own words. If it ever does, you have connected to yourself.

Add `--stats` for the full measurement table, `--json` to pipe the numbers into
something else, and `ratchet id` to see this machine's own words.

### A real transfer, end to end

A 763.5 kB file moved between two `ratchet` processes over loopback on one
machine, 0.3.0, Ryzen 5 7530U, Node 25, Windows 11. Both `--stats` tables, side
by side:

| | sender | receiver |
|---|---|---|
| plaintext | 763.5 kB | 763.5 kB |
| on the wire | 765.3 kB | 765.3 kB |
| overhead | 1.8 kB (0.2%) | 1.8 kB (0.2%) |
| chunks | 12 x 65.5 kB | 12 x 65.5 kB |
| handshake | 48 ms | 37 ms |
| crypto | 49 ms | 53 ms |
| AEAD backend | native | native |
| wall time | 62 ms | 70 ms |
| throughput | 12.23 MB/s | 10.98 MB/s |
| SHA-256 | `fdd05cad23edb796` | `fdd05cad23edb796` |

The hashes match, so the bytes that landed are the bytes that left. Loopback
means the transport row is close to free, which is the point of showing it: at
12 MB/s with 49 ms of crypto in a 62 ms wall time, this library is now the thing
you are waiting for, not the wire. On a real network the wall time is the
network's and the crypto row barely moves.

That table is one run. Five repeats of the same transfer on the same machine put
the sender between 12.3 and 14.0 MB/s, median 13.1, and the receiver between
11.7 and 13.3 MB/s, median 11.8, with the crypto row between 46 and 53 ms. The
byte rows are exact and repeat to the byte. Read the wall time and throughput
rows as plus or minus 10%.

The `on the wire` row counts the frames that carry the file, the sealed header
and the twelve chunks. It does not count the handshake. A relay counting every
socket byte in both directions measures the handshake at 2384 bytes out and 1619
bytes back, identical on every transfer whatever the file size, so the socket
actually moved 767.7 kB out and 1.6 kB back for this file: 0.55% overhead
outbound, 0.76% counting both directions. The 0.2.1 figure below leaves the
handshake out in exactly the same way, so the comparison is fair, but a packet
capture will show you the larger number.

The 0.2.1 version of this same table read 1.0 MB on the wire, 257.0 kB of
overhead, 33.7%. Nothing about the encryption changed. See
[the wire](#the-wire) for what did.

The overhead is a fixed cost per chunk rather than a percentage, which is worth
seeing at the other end of the scale. `ratchet send --text` with 20 bytes in it:

```
Plaintext received      20 B
On the wire            415 B
Overhead               395 B (1975.0%)
Chunks              1 x 65.5 kB
```

395 bytes to carry 20, down from 546 on 0.2.1. The floor is the envelope: a 24
byte nonce, a 16 byte Poly1305 tag, a 32 byte ratchet public key, plus the length
prefixes and the sealed header that carries the filename. It is exact, not
approximate, but it moves with the name: `--text` sends `message.txt` and pays
395, while the bench table further down sends `bench.bin` and reports 393. Two
characters of filename, two bytes.

The protocol part of that floor is the same in 0.2.1 and 0.3.0. The wire cost is
not, because 0.2.1 base64url'd the envelope along with everything else, which is
why the same 20 byte message cost 546 bytes of overhead there. It is also why the
interesting numbers here are file sized: a chat line will always be mostly
envelope.

## Quickstart

This is the exact code the smoke test runs against the packed tarball, so it is
proven end to end.

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

// Both sides show the same 6-word fingerprint to verify out of band.
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

`seal` and `open` each return a fresh `session`. The ratchet is immutable at the
API boundary: keep the returned session, drop the old one, never reuse a session
across two `seal` calls.

Binary payloads go through `engine.sealBytes` and `engine.openBytes`: same
sessions, same wire format, `Uint8Array` in and out (files, images, protobuf).

```ts
// A PNG header, deliberately not valid UTF-8.
const bytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0xff, 0xfe, 0x00, 0xc0]);

const sent = await engine.sealBytes(aliceSession, bytes);
aliceSession = sent.session;

// Note the shape: openBytes takes the session directly, not an identity plus
// options. It only ever handles message tokens, so there is no handshake to
// dispatch on, unlike `open`.
const got = await engine.openBytes(bobSession, sent.token);
assert.deepEqual(got.plaintext, bytes);
bobSession = got.session;
```

Tokens interoperate across both APIs, because the string path is a UTF-8 view
over the byte path: a `seal` token opens under `openBytes` as its exact UTF-8
encoding, and a `sealBytes` token that happens to be valid UTF-8 opens under
`open`. One token carries at most 65519 bytes of plaintext; chunk anything
bigger yourself.

Want to watch it work first? Clone the repo and run `node examples/demo.mjs` for
a full handshake, a message each way, and a tamper that fails closed. The
`examples/` directory is in git, not in the npm package, which ships only `dist`,
`bin` and `cli`.

## Persist and restore

Session state has to outlive the process or the conversation dies with it.
Every save function returns one ASCII string in the same `OCX1.` family as the
wire tokens, safe for a DB column or a file.

```ts
import assert from 'node:assert/strict';
import {
  engine,
  serializeSession, deserializeSession,
  serializePending, deserializePending,
  exportIdentity, importIdentity,
} from 'ratchet-ts';

// A live conversation to save. In your app this comes from your own handshake.
const identity = await engine.createIdentity();
const peer = await engine.createIdentity();
const invited = await engine.invite(identity);
const peerOpen = await engine.open(peer, invited.token, {});
const accepted = await engine.open(identity, peerOpen.reply, { pending: invited.pending });
const session = accepted.session;

// Save. Each call returns one ASCII string, safe for a DB column or a file.
// WARNING: these strings contain private keys. Encrypt them at rest.
const savedIdentity = exportIdentity(identity);          // "OCX1.identity...."
const savedSession = serializeSession(session);          // "OCX1.session...."
const savedPending = serializePending(invited.pending);  // "OCX1.pending...."

// Restore after a restart, then carry on exactly where you left off.
const identity2 = importIdentity(savedIdentity);
const session2 = deserializeSession(savedSession);
const pending2 = deserializePending(savedPending);

const sealed = await engine.seal(session2, 'sent after the restart');
const opened = await engine.open(peer, sealed.token, { session: peerOpen.session });
assert.equal(opened.plaintext, 'sent after the restart');

// Persist the LATEST state after every seal/open, overwriting the previous
// snapshot. Treat a saved session as a HANDOFF, not a backup: once you restore
// it, the old session object is dead. Sealing from both is the sharp edge, and
// it is the first entry under Limits.
```

Three honest caveats. The strings contain private keys, so at-rest encryption is
on you. The embedded 8-byte checksum is corruption detection, not
authentication: anyone who can edit your stored state can forge a blob that
loads, so never treat a restored session as proof of anything. Malformed or
future-version state fails closed with a precise reason (`malformed_token`,
`unknown_version`), never a raw throw. And restoring a snapshot rewinds the
ratchet, which has consequences worth reading before you build on this.

## What it does

- **Forward secrecy.** Every message key is derived once, used once, dropped.
  Stealing the device now does not decrypt old captured messages.
- **Post-compromise security.** One ratchet step from each side after a compromise
  locks the attacker's copied state out.
- **Hybrid post-quantum.** The root key mixes an X25519 result and an ML-KEM-768
  result. The session holds if either one holds. A quantum computer that breaks
  X25519 does not break it, and a flaw in ML-KEM does not break it.
- **Out-of-order and replay-safe.** Late or reordered messages still decrypt,
  skipped keys parked up to a bound. A consumed ciphertext cannot be reopened.
- **Tamper fail-closed.** One flipped bit in the ciphertext, header, or nonce
  fails authentication and returns nothing. Headers are bound in as AAD.

## Protocol

**Handshake** (PQXDH-shaped). The initiator sends an `invite` with its identity
(X25519 + ML-KEM-768 public keys). The responder makes an ephemeral ratchet key,
encapsulates to the initiator's ML-KEM key, mixes two X25519 DH results plus the
ML-KEM shared secret through HKDF-SHA256 into the root key, and replies with an
`accept` (ML-KEM ciphertext + ratchet public key). The initiator decapsulates,
derives the same root key, and takes one DH step. One and a half round trips,
after which the Double Ratchet takes over.

**Double Ratchet.** A DH ratchet turns on every new peer ratchet key, deriving a
new root key and chain. A symmetric ratchet runs each chain forward with
HMAC-SHA256, one unique key per message, none walkable backward. Messages are
sealed with XChaCha20-Poly1305, header bound in as AAD. Skipped keys are kept up
to `MAX_SKIP = 1000` per chain; a larger gap is refused, not allocated.

**Where the post-quantum protection actually is.** The ML-KEM-768 contribution
is in the HANDSHAKE. It is mixed into the root key once, when the conversation
opens, and it is what makes recorded traffic safe from harvest-now-decrypt-later.
Every DH ratchet step after that is X25519 and nothing else, so the ongoing
ratchet is classical: an adversary with a quantum computer who breaks X25519
can follow the ratchet forward from a compromise, even though they still cannot
recover the original root key. That is the same scope as Signal's PQXDH, and it
is deliberately narrower than Signal's SPQR, which makes the ratchet itself
post-quantum. This is a post-quantum handshake with a classical ratchet, not a
post-quantum ratchet, and it should not be described as one.

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

### The wire

There are two encodings of the same envelope, and 0.3.0 is the release that
stopped confusing them.

**The token.** `OCX1.<kind>.<base64url>`, `<kind>` in `invite | accept |
message`. One ASCII string, safe to paste into a chat box, an email, a QR code,
a JSON field. The payload underneath is a compact binary body, not JSON, so it
round-trips byte-exact for the AAD binding. This is what `engine.seal`,
`engine.invite` and `engine.open` speak, it is unchanged from 0.2.1 down to the
byte, and the known-answer vectors in `test/vectors.json` still pass untouched.

**The bytes.** `encodeEnvelopeBytes` / `decodeEnvelopeBytes`, new in 0.3.0. A
one byte version, a one byte kind tag, then exactly the bytes the token
base64urls. Self describing, so decoding needs no out-of-band hint about which
kind is arriving. The version byte is `0x01`, chosen because a token starts with
`O` (`0x4f`), so handing a token to the byte decoder is rejected as
`unknown_version` rather than misparsed.

Base64url costs one third. On a socket, where nobody is pasting anything, that
third bought nothing, and it was 33.4 of the 33.7 points of overhead this project
shipped with. The other 0.3 is the envelope itself and is still being paid. The
CLI now sends bytes and the number is 0.2%. The token API is untouched, because
for the paste-anywhere case the text encoding is the whole point.

The framing changed with it. `cli/frame.mjs` was newline delimited text and is
now `[u32 big endian length][payload]`, capped at 8 MiB.

**This is a breaking wire change.** A 0.2.1 CLI cannot talk to a 0.3.0 CLI in
either direction, and there is no version negotiation to soften it. Both
machines upgrade or neither does. Nothing in the library API broke.

## Runs on

No Node APIs in the core, only WebCrypto and the noble libraries, so the same
build runs everywhere:

- Node 20+: `node examples/runtime-smoke.mjs`
- Bun: `bun examples/runtime-smoke.mjs`
- Deno 2: `deno run --allow-read examples/runtime-smoke.mjs`
- Browsers: serve the repo root (`npx serve`) and open `/examples/browser.html`
- Cloudflare Workers: expected to work for the same reason, not yet CI-tested

These run from a clone, not from an install: `examples/` is not in the package.
Clone it, then `npm ci && npm run build` first, because the smoke test exercises
`dist/index.js`, the exact artifact npm installs. CI proves Node, Bun and Deno on
every push.

## Limits

Read these before trusting it with anything real.

- **No audit.** Repeated on purpose. It is the one that matters.
- **Never seal from a stale session snapshot. This is the sharpest edge here.**
  `deserializeSession` rewinds a conversation, it does not clone one. If you save
  a session, keep sealing on the original, and later restore the saved string and
  seal from that, both branches hold the same send chain key at the same message
  number. The chain is a deterministic KDF, so the restored branch derives the
  identical message key and stamps the identical message number onto a different
  plaintext. **Nothing throws.** It is indistinguishable from a normal seal.
  What we measured, so you do not have to guess:
  - It is *not* a two-time pad. Each seal draws a fresh random 24-byte nonce, so
    the two ciphertexts share no keystream and XOR reveals nothing. The AEAD
    carries many messages under one key safely as long as the nonces differ.
  - It *does* break forward secrecy across the rewound span. A chain key derives
    every message key ahead of it until the next DH ratchet step, so an old
    snapshot reads everything sealed after it in that chain. The ratchet deleted
    those keys, the snapshot reconstructs them.
  - It *does* silently lose a message. The receiver keeps whichever colliding
    message number arrives first and rejects the other with `replay_detected`,
    since a repeated number is exactly what a replay looks like. The losing
    plaintext is unreadable forever and the sender is never told.

  The rule: one live copy, always. A serialised session is a handoff. Save it,
  drop the object it came from, and let the restored one be the only writer. The
  library cannot detect a violation for you, so this is your invariant to hold.
- **Metadata is visible.** Contents are encrypted and headers are bound, but who
  talks to whom, when, and how much is not hidden. Tokens leak length and kind.
  No traffic-analysis resistance.
- **One token carries at most 65519 bytes of plaintext.** The envelope length
  prefix is u16, so an oversized `seal` or `sealBytes` input surfaces as a
  `RangeError` from the encoder, not a `CryptoFailure`. Chunk large payloads
  above the engine.
- **You own identity storage.** This library generates, uses, and serialises
  identity keys, it does not store them. At-rest handling (including encrypting
  anything `exportIdentity` or `serializeSession` returns) and rotation are
  yours. Leaking an identity secret is a full compromise of that identity.
- **Fingerprints need out-of-band checking.** The 6-word (66-bit) fingerprint only
  stops impersonation if two people compare it on a channel the attacker does not
  control.

## Tests

Adversarial, not happy-path. Every expected failure asserts a specific reason, so
a wrong error is a failing test.

- **Forward secrecy.** A session snapshot at message N cannot decrypt N+5 once the
  live side ratchets forward.
- **Post-compromise.** Copied old state stops decrypting after the honest side
  re-ratchets.
- **Tamper matrix.** Single-bit flips across ciphertext, header, nonce, and
  truncation all fail closed; malformed and wrong-version tokens map to precise
  reasons instead of throwing raw.
- **Replay.** A consumed ciphertext cannot be reopened.
- **Skip bound.** Skipping past `MAX_SKIP = 1000` is refused with
  `skip_limit_exceeded`, not allocated.
- **Hybrid pin.** The hybrid claim is pinned, not just asserted.
  `test/hybrid.test.ts` proves each half of the handshake moves the root key on
  its own: two different ML-KEM shared secrets under identical X25519 inputs
  yield different roots, and vice versa, and the hybrid root matches neither
  half alone. It then runs the real invite/accept/complete exchange,
  reconstructs the responder's stored root key from first principles (both DH
  values plus the decapsulated ML-KEM secret), and shows the live root matches
  that reconstruction while diverging from a classical-only, a PQ-only, and a
  corrupted-ciphertext counterfactual. If the handshake ever stops mixing the
  KEM secret, this suite fails.
- **Known-answer vectors.** `scripts/gen-vectors.mjs` (run
  `npm run gen:vectors`) replaces every random choice with fixed seeds, which
  the noble APIs accept end to end, ML-KEM encapsulation included, and writes
  `test/vectors.json`: the seeds, both DH values, the KEM ciphertext and shared
  secret, the handshake root, the root evolution across the first two ratchet
  steps, the first three message keys in each direction, and the exact wire
  tokens for the invite, accept, and first message each way.
  `test/vectors.test.ts` re-derives all of it from the seeds alone,
  byte-compares every value, and finally feeds the vector tokens to the real
  ratchet to prove they are genuine protocol traffic. The protocol is
  reproducible by other implementations from the JSON alone.
- **Persistence.** Sessions, pending invites, and identities survive
  serialize/restore byte-exact, parked skipped keys included; truncated,
  corrupted, mislabeled, and future-version state all fail closed with the
  right reason.
- **Binary payloads.** Random payloads round trip byte-exact, non-UTF-8 bytes
  survive the wire untouched, string and byte tokens interoperate in both
  directions, and a one-bit tamper on a bytes token fails closed and leaves the
  session able to open the honest copy.
- **Binary envelope.** The 0.3.0 byte form round trips every kind, and the string
  form is proven unchanged by re-encoding the known-answer vector tokens and
  diffing. Truncation is tested byte by byte at every offset, plus trailing
  bytes, an overrunning length prefix, a token fed to the byte decoder, and
  buffer aliasing. A wrong version byte is refused rather than guessed at.
- **AEAD equivalence.** The native backend is checked byte-for-byte against
  `@noble/ciphers` across random keys, nonces, plaintexts and AAD, empty
  plaintext and 64 KiB included, both backends forced explicitly so a machine
  without native support still tests the path it does not use.
- **Framing.** The length-prefixed wire is tested for prefixes split across TCP
  reads, several frames arriving in one event, the 8 MiB cap, a lying length
  refused before allocation, and clean EOF.

Plus envelope round-trips across all three token kinds, deterministic
fingerprints, out-of-order delivery across ratchet turns, and identity-mismatch
handling. 89 tests, `.ts` and `.mjs`.

```sh
npm install && npm test && npm run typecheck && npm run build
```

## Benchmark

```sh
npm run bench
```

Single thread, no tuning. `--runs N` repeats the whole bench and reports the spread across runs. Seven runs on six machines so far, medians:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="bench/charts/handshake-dark.svg">
  <img src="bench/charts/handshake-light.svg" alt="Full handshake median ms per machine: Apple M1 6.2, i5-12500H 6.5, Ryzen 7 5800X3D 7.3, Ryzen 5 7530U 7.6, EPYC 9354P 8.9, i5-10400F on WSL 10.9, same i5-10400F on Windows 11.5. Lower is better." width="760">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="bench/charts/seal-dark.svg">
  <img src="bench/charts/seal-light.svg" alt="seal of a 256 byte message, median ms per machine: Apple M1 0.019, i5-12500H 0.025, Ryzen 7 5800X3D 0.028, Ryzen 5 7530U 0.031, EPYC 9354P 0.050, i5-10400F on WSL 0.053, same i5-10400F on Windows 0.042. Lower is better." width="760">
</picture>

| Machine | Node | Handshake | `seal` 256 B | `open` 256 B |
|---|---|---|---|---|
| Apple M1 (laptop 2020, macOS) | | 6.2 ms | 0.019 ms | 0.021 ms |
| Core i5-12500H (laptop 2022) | 24 | 6.5 ms | 0.025 ms | 0.026 ms |
| Ryzen 7 5800X3D (desktop) | 24 | 7.3 ms | 0.028 ms | 0.031 ms |
| Ryzen 5 7530U (laptop) | 25 | 7.6 ms | 0.031 ms | 0.033 ms |
| EPYC 9354P 32-core (VPS, Linux) | 22 | 8.9 ms | 0.050 ms | 0.051 ms |
| Core i5-10400F (desktop 2020, WSL) | 22 | 10.9 ms | 0.053 ms | 0.057 ms |
| Core i5-10400F (same box, Windows) | 24 | 11.5 ms | 0.042 ms | 0.044 ms |

The handshake is the expensive step: one ML-KEM-768 encapsulation and decapsulation plus two X25519 exchanges, once per conversation. After that a message is one symmetric ratchet step and one XChaCha20-Poly1305 seal, which is why `seal` and `open` sit under 0.1 ms everywhere. Token overhead for a 256 byte message is **+259 bytes** (ratchet header + AEAD tag + framing) on every machine, because it is protocol math, not hardware. That 259 is not a constant: the body is base64url, so a third of it scales with the plaintext, and a 65519 byte message pays 22013 bytes. The binary envelope overhead **is** constant, 122 bytes at any size, which is where the CLI numbers below come from.

The bench is single-core bound, so a newer core beats a bigger machine. The fastest row is a 2020 ultrabook: the M1 tops every column, and the 2022 laptop chip behind it still outruns the 5800X3D desktop, while a 32-core EPYC server lands mid-table. Core count buys concurrent sessions, not a faster handshake. The M1 run did not record its Node version, and it was measured on 0.1.0, before the byte-first ratchet rewrite in 0.2.0.

The two i5-10400F rows are the same physical box under WSL and under Windows, with different Node versions: the handshake differs by 6 percent, `seal` is 21 percent faster on the Windows run. For scale, three back-to-back runs on the idle VPS varied by 3.3 percent on both handshake and `seal`, so single-digit gaps are run-to-run noise and only the larger one is worth a second look. `keygen` on that same VPS spread 33 percent across the three runs, which is what a noisy neighbour on shared hardware looks like and the reason `--runs` prints the spread at all.

The 7530U row is a correction. It first went in the table at 13.8 ms, measured while that laptop was running a heavy build in the background. Re-measured idle on 0.2.0 it is 7.6 ms with a 0.3 percent spread across three runs, which moved it from last place to fourth. A bench number is only as good as the machine was quiet, so `--runs` exists and the spread is printed. That row has not been reproduced on 0.3.0: three runs on the same laptop with a normal desktop load read 8.9 ms handshake, 0.041 ms `seal`, 0.046 ms `open`, so treat the row as a floor from a quiet machine rather than what you will see.

The test suite has also passed unmodified on hardware I do not own. Charts come from the table via [`bench/charts/generate.mjs`](./bench/charts/generate.mjs); a fixed-iteration CI bench is planned so numbers only move when the code does.

### 0.1.0 to 0.2.0

Both versions installed side by side on one machine, same probe run against each, 200 iterations per op:

| | 0.1.0 | 0.2.0 | Change |
|---|---|---|---|
| `keygen` | 1.315 ms | 1.321 ms | +0.5% |
| Handshake | 10.197 ms | 10.337 ms | +1.4% |
| `seal` 256 B | 0.051 ms | 0.053 ms | +3.9% |
| `open` 256 B | 0.049 ms | 0.053 ms | +8.2% |
| Wire overhead | +259 B | +259 B | none |
| Exports | 12 | 18 | +6 |
| Survives a restart | no | yes | |
| 1 KiB binary payload on the wire | 2227 B | 1539 B | **31% smaller** |

Read the first four rows as flat. They are cold-start numbers with no warmup and a fresh pair of identities per iteration, which is why they sit above the table above; only the deltas are meaningful, and every one of them is inside the run-to-run noise this bench shows on an idle machine. The byte-first rewrite made the string API a UTF-8 shim over the byte path, and it cost nothing measurable.

The last row is the one that moved. 0.1.0 had no bytes API, so the only way to send a file was to smuggle it through the string API with `String.fromCharCode`, and every byte above 0x7f became two bytes of UTF-8 on the way out. `sealBytes` takes the `Uint8Array` straight to the AEAD:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="bench/charts/wire-dark.svg">
  <img src="bench/charts/wire-light.svg" alt="Bytes on the wire for a 1 KiB binary payload: 0.1.0 latin1 workaround 2227 bytes, 0.2.0 sealBytes 1539 bytes, 31 percent fewer." width="760">
</picture>

The other change has no number. On 0.1.0, `JSON.stringify` on a session silently turned every `Uint8Array` key into `{}`, and the next `seal` threw `"key" expected Uint8Array`. A page reload ended the conversation. On 0.2.0 the session is a token you can put in a database and hand back later.

### 0.2.1 to 0.3.0

```sh
npm run bench:wire
```

A second harness, separate from `npm run bench`. It stands the real
`cli/frame.mjs` server up on loopback with a byte-counting relay in front of it,
pushes real transfers through, and reports what the socket actually carried
rather than what the arithmetic predicts. Ryzen 5 7530U, Node 25, Windows 11,
median of 3 runs.

**Bytes on the wire.** Same payload, 0.2.1 base64url token plus newline against
the 0.3.0 binary envelope plus u32 length prefix:

| plaintext | 0.2.1 wire | 0.3.0 wire | 0.3.0 overhead | saved |
|---|---|---|---|---|
| 20 B | 563 B | 413 B | 393 B (1965.0%) | 26.6% |
| 1.0 kB | 1.9 kB | 1.4 kB | 395 B (38.6%) | 25.5% |
| 65.5 kB | 88.1 kB | 66.1 kB | 522 B (0.8%) | 25.0% |
| 1.0 MB | 1.4 MB | 1.1 MB | 2.4 kB (0.2%) | 25.0% |
| 10.5 MB | 14.0 MB | 10.5 MB | 20.6 kB (0.2%) | 25.0% |

The saving converges on 25% because that is exactly what base64url costs. The
small end never gets good in percentage terms, because 393 bytes of envelope
under a 20 byte message is arithmetic nobody can beat.

**AEAD.** `src/aead.ts` prefers Node's native `chacha20-poly1305` through
`crypto.createCipheriv` and falls back to `@noble/ciphers` everywhere else, with
`aeadBackend()` reporting which one is live. Byte-identical output either way,
checked against 200 random tuples on every bench run before any timing is
reported. MB/s, higher is better:

| op | `@noble/ciphers` | `src/aead.ts` (native) | ratio |
|---|---|---|---|
| seal 256 B | 26.7 | 28.8 | 1.08x |
| open 256 B | 24.4 | 29.3 | 1.20x |
| seal 65519 B | 154.6 | 599.9 | 3.88x |
| open 65519 B | 150.3 | 761.1 | 5.06x |

Small messages are dominated by call overhead and the native path buys almost
nothing. At chunk size it is 4x to 5x, which is the case the CLI is in.

Those cells are one run and they move. Nine repeats that alternate the two
backends inside each repeat, so neither one gets the cold cache or the boost
clock to itself, put the chunk sized ratios at 4.8x seal and 5.7x open at the
median, and the worst repeat of the nine still read 3.9x seal and 4.7x open. The
256 B ratios wandered between 1.03x and 1.36x, which is a longer way of saying
there is nothing there.

**Handshake, split.** 3 one-way flights, so 1.5 round trips before a payload byte
moves:

| side | wall | crypto | transport | crypto share |
|---|---|---|---|---|
| sender | 14.66 ms | 7.66 ms | 7.00 ms | 52.3% |
| receiver | 10.84 ms | 5.56 ms | 5.28 ms | 51.3% |

Run to run spread on those cells is about a third, so read them as ten to fifteen
milliseconds, not as four significant figures. Loopback round trip on this
machine is 0.08 ms, so the transport column above is almost entirely process
scheduling, not network. Substitute your own link: at 40 ms RTT the same
handshake costs about 60 ms of transport and the crypto column does not move.

**The honest version of the headline.** The 33.7% overhead this project shipped
with was not the cost of encryption. Encryption costs 0.06%: a 24 byte nonce and
a 16 byte tag on a 65519 byte chunk. Add the rest of the envelope, the ratchet
public key and the sealed header and the length prefixes, and the whole 0.3.0
wire cost on that 763.5 kB file is 0.23%. The remaining 33.4 points were
base64url, which taxes payload and envelope alike at exactly a third, paid on a
socket where nothing was ever going to be pasted anywhere. 0.3.0 stops paying it
on the CLI path and keeps paying it in the token API, where being text is the
entire feature.

One caveat on the throughput numbers anywhere in this README: they are loopback.
The 0.2.1 figure that produced 33.7% was measured once over a Tailscale relay on
different hardware. The byte counts are comparable across those two runs. The
MB/s numbers are not, and `bench/wire.mjs` prints `NOT COMPARABLE` in that cell
rather than a speedup multiple.

## License

MIT. Copyright (c) 2026 Gintaras. See [LICENSE](./LICENSE).
