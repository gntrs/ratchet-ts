# ratchet-ts lab notebook

The long version. [README.md](./README.md) is the short one, and
[SPEC.md](./SPEC.md) is the protocol itself.

This file logs the whole process rather than just the result: the method behind
every number, the numbers that turned out to be wrong, and how each one was
caught. A benchmark that measured a dead base64 path for months, an 11x speedup
that was really 1.4x, a machine chart that overstated one row by 4x, all of it
stays in, because the correction is the more useful half.

Every latency claim carries the machine, the runtime, the backend state, the
payload size and whether it is a p50, a p99 or a median of runs. There is no p50
anywhere without its p99 next to it. **The canonical payload is 256 bytes**,
this project's working estimate of a real chat message. It is a choice rather
than a discovery, and it barely matters: latency is flat below about 1 kB, and
moving the payload from 200 B to 256 B moved the seal by less than the
run-to-run noise.

> **Not audited.** No independent audit, no formal verification. See
> [SECURITY.md](./SECURITY.md) for what that means in practice.

## Where this is, in one screen

Every row measured on the same laptop, AMD Ryzen 5 7530U, Node v25.8.0, Windows
11, all three backends native, 256 byte payload. The two speed columns were taken
in separate sessions and the machine was on mains power for one and on battery
for the other, which is worth roughly 1.8x on its own, so the columns are honest
against their own baseline and not against each other. The ratio inside each
session is the number that means anything.

| | 0.2.1 | 0.3.4 | 0.4.0 / 0.5.0 |
| --- | --- | --- | --- |
| bytes of overhead per message | 122 | 122 | **34** |
| a 20 byte message on the wire | 142 B | 142 B | **54 B** |
| seal, 256 B, p50 | not measured | 24.86 us | **16.36 us** |
| file transfer, loopback, sender | not measured | 79.98 MB/s | 121.90 MB/s |
| classical key exchange | pure JS | native | native |
| chain step | 2x HMAC-SHA256 | 2x HMAC-SHA256 | **1x HMAC-SHA512** |
| identity file on disk | plaintext | plaintext | **sealed** |
| peer list on disk | did not exist | plaintext | **sealed** |
| trust store, changed-key alarm | no | yes | yes |
| full-screen chat client | no | yes | yes |
| tests | 115 | 179 | **255** |

What each release actually did, shortest form. The long version of each is a
section further down, with the method and the mistakes.

- **0.3.0** put the envelope on the wire as binary instead of base64url text.
  The text form still exists, because pasting into a chat box is a real use.
- **0.3.1** stopped the CLI building a base64 token it immediately threw away.
  This is where most of the throughput came from, and the benchmark did not
  notice for two releases.
- **0.3.3** moved X25519 and HMAC onto `node:crypto` where it exists, with the
  pure-JS path kept as the fallback and both compared byte for byte before the
  fast one is trusted. It also added the peer trust store and rewrote the
  benchmark that had been measuring dead code.
- **0.3.4** exported two functions 0.3.3 said it exported and did not.
- **0.4.0** rewrote the message header. 122 bytes of overhead became 34. The
  chain step became one PRF call instead of two. **This breaks the wire**: a
  0.3.x peer and a 0.4.0 peer cannot talk.
- **0.5.0** stopped writing your identity and your peer list to disk in the
  clear. CLI only, the library and the wire are byte for byte 0.4.0.
- **0.5.1** made the line you compare aloud both fingerprints instead of one
  hash of the pair, which is the difference between a 2^66 problem and a 2^33
  one.
- **0.6.0** closed the four gaps this list used to open with. It signs the
  handshake, it can send to somebody who is offline, it can cross the internet
  through a relay, and it can be set up with a pairing code instead of an IP
  address. It moves the wire format and every fingerprint changes.

The four things this section listed for months are done. What replaced them is
shorter and harder:

1. **No audit, no formal model, one author.** This has been the last line here
   since 0.1.0 and it is now the first. Everything below is a detail next to it.
2. **A relay is a metadata observer.** It cannot read a message or impersonate
   anybody, and it does see two addresses meeting at a timestamp and how many
   bytes passed. Run your own, or do not use one: `ratchet relay` is one
   command and there is deliberately no default host.
3. **Offline delivery does not solve replay on its own.** A prekey bundle is a
   static offer, so a recorded intro frame can be delivered twice. The library
   refuses a conversation id it has already opened and makes the caller hold
   that set, which is the honest version rather than the invisible one. Signal
   solves this properly with one time prekeys handed out by a server, and there
   is no server here.
4. **A pairing code pins 64 bits, not 132.** It makes the first identity check
   automatic, which beats a ritual people skip. It does not replace comparing
   the words aloud for a peer you intend to keep.
5. **The handshake got about 29 times more expensive.** 0.88 ms to 25.8 ms on
   the same machine, because it now carries two ML-DSA-65 signatures. Once per
   conversation, and still invisible next to a network round trip, but it is a
   real number and it is not hidden.

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

### Check the package before you trust it

From 0.6.1 every release is published from GitHub Actions with a Sigstore
provenance attestation, so the tarball on npm carries a signed statement naming
the exact commit and workflow that built it, countersigned into a public
transparency log. You do not have to take the author's word that the code you
are reading here is the code npm served you:

```sh
npm audit signatures
```

That is worth more than any assurance in this README, because it does not
involve believing the README.

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
ratchet send holiday.jpg --to 192.168.1.42 --stats
```

`--stats` is optional and prints the size, the time and the overhead afterwards.

Text works the same way, and a dash reads stdin so a pipe works:

```sh
ratchet send --text "the wifi password is hunter2" --to 192.168.1.42
echo "same thing from a pipe" | ratchet send - --to 192.168.1.42
```

### Moving a .env

This is the case that probably brought you here. A colleague needs the dev
`.env`, or your other laptop does, and the options are Slack, a ticket, or a
password manager that then keeps a copy of it forever.

```sh
# them, first
ratchet recv --out . --once

# you, with the address it printed
ratchet send .env --to 192.168.1.42
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
ratchet chat --to 192.168.1.42:4477
```

Type a line, press enter, it arrives. `/quit`, Ctrl-C or Ctrl-D ends it and both
sides print how many messages moved. The same safety words appear, and the same
rule applies: compare them out loud.

A chat only pairs with another chat. Both ends open with an invite and settle
the tiebreak between themselves, so `ratchet chat` will not talk to
`ratchet recv`, and it does not accept a file.

If you would rather install nothing, `npx ratchet-ts recv` and
`npx ratchet-ts send ...` do the same job. Spell out `ratchet-ts`: `npx ratchet`
is an unrelated package by somebody else.

The file contents and the metadata around them (the filename, the size, the
hash) are all encrypted with the same ratchet the library exposes. By default it
is a direct TCP connection between the two machines: no relay, no server, no
account, nothing of yours in the middle. Add `--relay` and the two machines meet
at a host instead, which is what makes it work across the internet; that host
still cannot read anything, and what it does see is spelled out under "A relay,
so two home connections can meet".

Both ends print the safety words the moment the handshake lands, before the
bytes finish moving.

```
  compare aloud  scan  fiber  black  abstract  cradle  struggle
                 goat  window  faint  climb  gossip  process
  peer identity  derive  remain  trip  noise  bean  fix
```

**Compare both `compare aloud` rows out of band**, out loud or over a channel an
attacker on this network does not control. Those two rows are the two identity
fingerprints, six words each, printed in the same order on both screens, and
matching words mean you are talking to the machine you think you are. Nobody
checks this for you.

Twelve words rather than six, and the extra six are the whole point. They used
to be one hash of both identities, which sounds equivalent and is not: a machine
in the middle picks the key it shows to each side, so it is not solving a
preimage, it is grinding both sides until the two six word lines happen to
agree. That is a birthday search over 66 bits, roughly 2^33, which is hours on
rented hardware. Reading the fingerprints separately removes the second degree
of freedom and leaves two independent 2^66 problems. There is no shorter honest
version: any single line you can compare is a space an attacker gets the square
root of, so about 132 bits has to reach the user somehow. Signal shows 60 digits
for the same reason.

The `peer identity` line names the **other** machine, so the two screens show
different words there, and that is correct. It is the same six words that machine
prints for itself under `ratchet id`, and the same words the receiver shows in
the `you` line of its own banner. That is the cross-check: the sender's
`peer identity` should read back the receiver's `you` line. Do not expect it to
match your own words. If it ever does, you have connected to yourself.

Add `--stats` for the full measurement table, `--json` to pipe the numbers into
something else, and `ratchet id` to see this machine's own words.

### What a transfer costs

Two measurements, because they answer different questions. Loopback tells you
what the library costs. A real link tells you what a person waits.

**Loopback**, 10.5 MB file, two real `ratchet send` and `ratchet recv`
processes on one machine, AMD Ryzen 5 7530U, Node v25.8.0, Windows 11, all
three backends native. Published 0.3.2 installed from its tarball against
0.3.4, arms interleaved inside each repeat, wire bytes and payload SHA-256
identical across every run:

| | 0.3.2 | 0.3.4 |
|---|---|---|
| sender throughput | 56.48 MB/s | 79.98 MB/s |
| receiver throughput | 50.31 MB/s | 69.22 MB/s |
| wire overhead, 65519 B chunks | 0.2% | 0.2% |

The gain is roughly 1.4x and it is the native curve and hash backends plus the
copy removal in 0.3.3. It is not the 11x you get by comparing against the
figure this project published for 0.3.1 and 0.3.2, because that figure came
from a benchmark measuring a code path the CLI stopped using in 0.3.1. That is
written up in [bench/README.md](./bench/README.md), which opens by saying so.

**0.4.0 has not been through that same interleaved A/B**, and the table above is
therefore left at 0.3.4 rather than grown a column it did not earn. What has been
run on 0.4.0 is a single real transfer, 3.1 MB, two processes, sender 121.90 MB/s
and receiver 81 MB/s at 0.1% wire overhead with the payload SHA-256 matching.
That is one sample of a different file size against a table of interleaved
medians, so read it as a direction and not as a row.

The byte rows are exact rather than measured. Every chunk pays a constant 122
bytes of envelope whatever it carries, so a 10.5 MB transfer in 65519 byte
chunks pays 0.19% for the envelopes and the rest of the 0.2% is the handshake
and the framing. Both sides print the SHA-256 of what they hashed, and that is
the line worth checking before you trust any of the others.

**A real link**, a 763.5 kB file, a Windows laptop and a Linux box on a mesh VPN
that was relaying through a public relay instead of going direct. Close to the
worst realistic path: every packet crosses the internet twice. Older versions,
and not re-run since:

| | 0.2.1 | 0.3.0 | delta |
|---|---|---|---|
| on the wire | 1.0 MB | 765.3 kB | 25.0% fewer bytes |
| overhead | 257.0 kB (33.7%) | 1.8 kB (0.2%) | the base64 is gone |
| crypto | 52 ms | 47 ms | |
| wall time | 255 ms | 213 ms | 16.5% faster |
| throughput | 3.00 MB/s | 3.58 MB/s | 19.3% faster |

The hash matched on both sides both times, so that is the same file arriving
intact rather than a faster route to a different answer.

Read the two tables differently. The byte rows are exact and reproduce to the
byte against the published tarballs. The loopback rows are medians of
interleaved repeats on an idle machine. The real link rows are one run each, so
16.5% is the right order of magnitude and not a number to quote to three digits.

The prediction for 0.3.1 on that link was that it changes CPU only, so on a
3 MB/s relay it would move the `crypto` row and very little else. That has now
been tried, and the first sample did not behave that way: it came back at
0.60 MB/s against 3.58 for 0.3.0. The handshake column moved 38 percent across
the same set of samples, and that code is identical in both versions, so the
link was moving too and one run each settles nothing. It is written up honestly,
including the second explanation that would be more interesting than noise, in
[the two machine appendix](./bench/README.md#appendix-two-machines-one-relayed-link).
Until that A/B is run properly, treat 0.3.1 and 0.3.2 over a real relay as
unmeasured rather than as fast.

The speed gain is smaller than the byte saving because the handshake is a fixed
round trip that no amount of wire efficiency touches. Over a fast link this
library is the bottleneck. Over a slow one it is a fifth of the wait and the
rest belongs to the network.

### 0.3.0 to 0.3.1

Same bytes on the wire, about three times faster. Both versions installed from
their published tarballs, 763.5 kB file, loopback, AMD Ryzen 5 7530U, Node 25,
Windows 11, medians of 21 transfers. Kept here because it is the release that
moved, not because it is the current number: 0.3.4 on this machine does 79.98
MB/s sending, on a larger file, in the table above.

| | 0.3.0 | 0.3.1 | |
|---|---|---|---|
| sender wall | 56.5 ms | 18.7 ms | 3.0x |
| receiver wall | 60.8 ms | 22.5 ms | 2.7x |
| sender throughput | 13.5 MB/s | 40.9 MB/s | |
| handshake | 45.8 ms | 45.8 ms | untouched |
| bytes on the wire | 765,286 | 765,286 | identical |

0.3.0 base64ed every frame into an `OCX1.` token and parsed it straight back out
before the bytes reached the socket, twice per frame per direction, for a socket
where nothing was ever going to be pasted anywhere. 0.3.1 seals plaintext
directly to envelope bytes. The wire did not move, which is why a 0.3.0 peer and
a 0.3.1 peer still talk to each other: every frame was hashed under a seeded RNG
in both directions and came out identical.

Upgrading one end gets you part of it, 49.9 ms sending to a 0.3.0 peer against
56.9 ms between two of them, because work removed from one process shortens the
other's blocking reads. Upgrading both gets you all of it.

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

If your transport is already binary, skip the token entirely.
`engine.sealToEnvelopeBytes` and `engine.openFromEnvelopeBytes`, new in 0.3.1,
take plaintext bytes to envelope bytes and back with no base64 in between. They
are shortcuts, not a second format: for the same session state and the same
random draw they produce exactly the bytes you would get from `sealBytes`
followed by `encodeEnvelopeBytes(decodeEnvelope(token))`, checked byte for byte
at twelve plaintext lengths from 0 to 65519 with the RNG pinned. Do not expect
two live seals of the same plaintext to match: every message draws a fresh 24
byte nonce, so they differ the way any two seals differ. Either side of a
conversation can use either path in any order.

```ts
const sent = await engine.sealToEnvelopeBytes(aliceSession, bytes);
aliceSession = sent.session;

socket.write(sent.envelope); // a Uint8Array, no base64 anywhere

const got = await engine.openFromEnvelopeBytes(bobSession, sent.envelope);
assert.deepEqual(got.plaintext, bytes);
bobSession = got.session;
```

Message envelopes only, same as `openBytes`. Hand an invite or an accept to
`openFromEnvelopeBytes` and it fails closed with `malformed_token` rather than
guessing. Handshake envelopes go through `engine.open`, which owns that state
machine. The CLI does exactly this: chunks on the bytes path, handshake on the
token path.

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
new root key and chain. A symmetric ratchet runs each chain forward with one
HMAC-SHA512 per step, split 32/32 into the next chain key and this message's key,
one unique key per message, none walkable backward. Messages are sealed with
ChaCha20-Poly1305 and a 12 byte random nonce, header bound in as AAD. Skipped
keys are kept up to `MAX_SKIP = 1000` per chain; a larger gap is refused, not
allocated.

Two of those changed in 0.4.0 and the reasoning is worth stating, because both
look like pure wins and only one is.

The chain step was two HMAC-SHA256 calls, one for the next chain key and one for
the message key. It is now a single HMAC-SHA512 whose 64 byte output is split in
half. That is exactly what HKDF-Expand does internally, so it is not a weakening,
and it measured 1.5 us cheaper per message.

The cipher moved from XChaCha20-Poly1305 with a 24 byte nonce to
ChaCha20-Poly1305 with a 12 byte one. `node:crypto` exposes only the 12 byte
form, so the 24 byte version was paying an HChaCha20 subkey derivation in
TypeScript on every single message. A draft of 0.4.0 went further and derived the
nonce from the message number, which would have removed it from the wire
entirely: 22 bytes of overhead instead of 34, and 3.4 us faster. That draft was
built, measured, and then thrown away. A derived nonce is safe exactly as long as
state never rolls back, and `serializeSession` makes rolling back a supported
operation. Restore an old snapshot, send again, and a counter reproduces the
identical nonce under an identical key, so anyone holding both ciphertexts gets
the XOR of the two plaintexts in the clear. A random nonce turns that same
accident into a forgery risk instead of a plaintext leak. 12 bytes and 3.4
microseconds is the price of that difference and it was paid deliberately.

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

Three names sit close together here and mean different things. `sealBytes` is
about the plaintext being bytes, and it still returns a token. `encodeEnvelopeBytes`
is about the envelope being bytes, and it does no crypto at all. `sealToEnvelopeBytes`,
new in 0.3.1, is both ends at once: plaintext bytes in, envelope bytes out, no
token built in between. That last one is what deleted the CPU cost described in
[0.3.0 to 0.3.1](#030-to-031).

The framing changed with it. `cli/frame.mjs` was newline delimited text and is
now `[u32 big endian length][payload]`, capped at 8 MiB.

### The message header, as of 0.4.0

Everything above describes how the envelope is *encoded*. This is what is
actually in it, and it is where 122 bytes of overhead became 34.

| offset | bytes | field |
| --- | --- | --- |
| 0 | 1 | `[ver:4][kind:2][hasRatchetKey:1][reserved:1]` |
| 1 | 4 | session tag, first 4 bytes of the 16 byte conversation id |
| 5 | 1 to 5 | message number, canonical varint |
| .. | 1 to 5 | previous chain length, varint, **only when hasRatchetKey** |
| .. | 32 | ratchet public key, **only when hasRatchetKey** |
| .. | 12 | nonce, random per seal |
| .. | rest | ciphertext, then the 16 byte Poly1305 tag |

A settled frame is 34 bytes of overhead. A frame that carries a new ratchet key
is 67. Where 0.3.x spent its 122: 34 bytes for the conversation id written as 32
ASCII hex characters, 34 for a ratchet public key repeated on every single
message, 26 for a nonce that did not have to be that wide, 8 for two fixed-width
counters, and 8 more on length prefixes for fields whose length was already
known.

**Four fields left the wire and none of them left the AEAD.** The full 16 byte
conversation id and the full 32 byte ratchet public key are still bound as
associated data, rebuilt on the receiving side out of session state. Binding data
that is not transmitted is exactly what associated data is for. The 4 byte
session tag is a routing hint and nothing else: a collision routes a frame to the
wrong session, where it then fails to open, rather than opening as the wrong
conversation.

**The ratchet key rides the first three messages of a chain, not just the
first.** Sending it once is enough on a lossless transport and it is what a 22
byte header assumes. On a lossy one it is a trap: a receiver cannot step its DH
ratchet until it sees the new key, so if that single message is dropped, every
later message in the chain is undecryptable until the direction changes again.
Three is the compromise. A 20 message chain pays 66 extra bytes rather than 660,
so about 90 percent of the saving survives, and losing all three independently is
not something a non-adversarial transport does.

**This breaks the wire.** In 0.4.0 `ENVELOPE_VERSION` was `OCX2`, the binary
version byte `0x02`, the serialized session version `2`. A 0.3.x peer failed
with `unknown_version`, and so did a 0.3.x session restored from disk.

**0.6.0 moved them again**, to `OCX3` and `0x03`, because the handshake frames
grew signatures and the identity grew a third key. The message envelope is byte
identical to OCX2 apart from the version nibble, still 34 bytes of overhead: a
conversation pays for authentication once rather than per message. The version
still had to move, because an OCX2 peer would meet two unexpected length
prefixed blobs and call the frame malformed, and a peer that cannot check a
signature must not proceed as though there were none to check.

Both ends and any persisted state move together, either way. The failure is
loud and named, not a silent misparse.

### What the CLI keeps on disk, as of 0.5.0

Until 0.5.0 the identity file was 4902 bytes of plaintext holding both secret
keys, and `peers.json` was a timestamped list of who this machine had talked to,
sitting next to a chat client that printed "nothing was written to disk". Forward
secrecy does not cover either of those. A copied folder is a permanent
impersonation of you, to everyone who has not compared words with you.

Both are now sealed under one vault key, and the key is resolved in this order:

1. **The OS keychain.** DPAPI on Windows, `security` on macOS, `secret-tool` on
   Linux. No passphrase, no prompt, `ratchet chat` still works with zero typing.
   A backend is trusted only after it stores 32 random bytes and hands the same
   32 bytes back, so one that is present but broken degrades instead of sealing
   under a store that cannot return the key.
2. **A passphrase**, if you run `ratchet lock`. scrypt at N=2^18, r=8, p=1, so
   256 MiB and about 1.2 seconds per guess on this laptop. Memory is what hurts
   an offline GPU attack: a 24 GB card holds roughly 90 concurrent instances at
   that size.
3. **Nothing**, if neither is reachable. The file then says so in English on its
   first line and `ratchet id` reports it.

An existing plaintext identity is sealed in place on the next run and the
fingerprint does not change. `ratchet id` prints which of the three is in force.

What someone who copies the whole directory and does not have the key learns:
that ratchet is installed, the exact number of peers, which protection mode is in
force, the KDF parameters, and the file modification times. That last one is a
real residual leak and it is not fixed. What they do not learn: any public key,
any safety words, any label, any address, any date, or which peers are verified.
Peer rows are named by a keyed MAC rather than a salted hash, so "did this
machine ever talk to this specific key" is not a question that can be asked
without the vault key, and the salt is fresh on every write, so two stolen copies
of the same store do not correlate row by row.

The honest limit: on every platform the keychain hands the key to any code
running as you. That defends a copied folder, a backup, a synced directory,
another user on the box, and a disk pulled from a machine whose account password
is unknown. It does not defend against something already running as you. Only
`ratchet lock` does that, and only while ratchet itself is not running.

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
  - It is *not* a two-time pad. Each seal draws a fresh random nonce, so the two
    ciphertexts share no keystream and XOR reveals nothing. The AEAD carries many
    messages under one key safely as long as the nonces differ. **This is exactly
    the property a derived nonce would have thrown away**, and it is why 0.4.0
    rejected one. The nonce is 24 bytes through 0.3.4 and 12 from 0.4.0; the
    argument does not depend on the width, only on the randomness.
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
- **One frame is one message.** Through 0.3.4 the ciphertext carried a u16 length
  prefix, so plaintext was hard capped at 65519 bytes and an oversized input
  surfaced as a `RangeError` from the encoder rather than a `CryptoFailure`.
  0.4.0 removed that prefix, so the envelope itself no longer imposes a ceiling,
  but the CLI still chunks at 65519 and you should still chunk: a single frame is
  read into memory whole on the far side, and 8 MiB is the framing cap in
  [`cli/frame.mjs`](./cli/frame.mjs).
- **You own identity storage, if you use the library directly.** The library
  generates, uses and serialises identity keys, it does not store them. At-rest
  handling of anything `exportIdentity` or `serializeSession` returns, and
  rotation, are yours. Leaking an identity secret is a full compromise of that
  identity. **The CLI does this for you from 0.5.0** and the details are under
  "What the CLI keeps on disk" above; if you want the same behaviour in your own
  app, that code is worth reading before writing your own.
- **Fingerprints need out-of-band checking.** Each identity fingerprint is six
  words (66 bits), and the line the CLI asks you to compare is both of them,
  twelve words, on a channel the attacker does not control. A pairing code
  automates the first 64 bits of that check and does not replace it.

## What comes next, and why in that order

Four of the five items that used to be here shipped in 0.6.0. They are described
under "What 0.6.0 added" below rather than deleted, because a roadmap that
quietly loses its entries teaches you nothing about whether the plan was any
good. What is left:

**1. Attachments, and voice notes on top of them.** A `#path` grammar in the chat
input, which needs one new message kind on the wire and is therefore a breaking
change, so it lands with something else that breaks. Voice becomes almost free
once files work: record, attach, done. Received files are shown as a name, a
size and a hash, and are never rendered inline, because rendering bytes a stranger
chose is the wrong instinct for a tool whose whole promise is about who those
bytes came from.

**2. One time prekeys, so offline delivery stops being replayable.** 0.6.0 ships
the bundle and states plainly that a recorded intro frame can be delivered
twice, with the caller holding a set of conversation ids to refuse the second.
That is honest and it is not good enough for anything at scale. Doing it
properly means one time prekeys consumed on use, which means something that
hands each one out exactly once, which means the relay would have to hold state
it currently refuses to hold. That trade is the actual design question and it
has not been answered yet.

**3. Prekey rotation that a user does not have to think about.**
`publishPrekeys` is cheap and is meant to be called on a schedule. Nothing calls
it on a schedule. The bundle carries a signed timestamp so that a client which
enforces a maximum age cannot be lied to, and no client enforces one yet.

**4. A second pair of eyes on the 0.6.0 handshake.** It is new, it is the part
most worth getting wrong quietly, and one author reviewed it. The transcripts
are length prefixed and domain separated, the accept binds the initiator's whole
identity, and test/handshake-auth.test.ts walks a full machine-in-the-middle
scenario. None of that is the same as somebody else having looked.

**Not on this list, deliberately.** Group chat, which is a different protocol
(MLS) and not a feature of this one. A nickname directory, which requires a server
that knows who everyone is and is exactly the thing this tool exists to avoid. A
GUI, which is a product question rather than a protocol one and should wait until
the protocol stops changing. And an audit, which is not a task on a roadmap, it is
something you buy, and it should be bought after the wire format stops moving and
not before.

## What 0.6.0 added

Four changes, and the first two move the wire format, so a 0.6.0 peer and a
0.5.x peer cannot talk to each other. Every fingerprint changes too, because the
identity grew a third key and the digest has to cover it.

### The handshake is signed

Confidentiality was hybrid and authenticity was X25519 alone. The gap was
specific: the responder proves who it is with DH1, computed from its long term
X25519 key, and its ML-KEM key was never used in the handshake at all. An
adversary who can solve discrete log on Curve25519 recovers that secret from a
public key and can produce a valid accept as anybody. ML-KEM protects a recorded
session and does nothing about that.

Both handshake frames now carry an **ML-DSA-65** signature over a length
prefixed, domain separated transcript. No third flight was needed, because each
side already sends exactly one frame that can carry one.

The part worth reading twice is that the accept signs the **initiator's whole
identity as the responder received it**, and the initiator verifies against the
snapshot it took when it sent the invite. That is what catches a rewritten
invite: a machine in the middle can substitute its identity to the responder,
and the responder will sign an accept over that identity, but the initiator
rebuilds the transcript with its own and the signature does not verify.

What it costs, measured on the M4 rather than estimated:

| | 0.4.0 | 0.6.0 |
|---|---|---|
| `createIdentity` | 0.26 ms | **10.7 ms**, once ever |
| full handshake | 0.88 ms | **14.6 ms** |
| `invite` | 0.1 ms | **0.01 ms** |
| `seal` (256 B) | 0.0046 ms | 0.0048 ms |
| `open` (256 B) | 0.0042 ms | 0.0044 ms |
| invite token | 1687 chars | **8707** |
| accept token | 3186 chars | **10206** |
| message envelope | 34 bytes | 34 bytes |

That is about 16x on the handshake and nothing at all per message. An earlier
draft of this README guessed "roughly 2 kB of identity and a fraction of a
millisecond to verify". Both halves were wrong: the verifying key is 1952 bytes,
each signature is 3309, signing is 8.0 ms and verifying is 1.5 ms.

**It was 25.8 ms before the identity certificate.** The first version signed the
conversation id together with the sender's identity on every invite, which is
8 ms of the most expensive operation in the library, repeated forever, to
re-state a fact that never changes. It is now signed once when the identity is
created and carried on every invite after that, which is why `invite` is a
hundredth of a millisecond and `createIdentity` went up instead. See "The
certificate, and what it does not prove" below for why that is not a weakening.

Fifteen milliseconds once per conversation is still invisible next to a network
round trip, which is the reason this is acceptable rather than the reason it is
cheap.

### The certificate, and what it does not prove

The invite carries an **identity certificate**: ML-DSA-65 over the identity's
own three public keys, signed once at creation.

It is worth being precise about what that buys, because the per invite version
it replaced did not buy more. Both are signed by the identity's OWN signing key,
so both prove possession of `sigSecret` and say nothing about `classicalSecret`
or `pqSecret`. Anyone can pair somebody else's X25519 and ML-KEM keys with a
signing keypair of their own and sign either shape. What catches that is the
**fingerprint**, which covers all three keys and therefore changes, and the
**accept transcript**, which binds the initiator identity the responder actually
saw so the real initiator refuses. Neither of those moved.

What the old shape did have was the conversation id inside the signature. That
bound an invite to one conversation while invites stayed replayable verbatim
anyway, so it was never freshness. Dropping it means an attacker can point a
recorded identity at a different conversation id, which gets them a session with
somebody who is not listening: a way to waste a responder's CPU, which they
already had. `test/handshake-auth.test.ts` asserts that re-stamping is accepted,
rather than leaving it implied.

Signing is hedged, per FIPS 204, so two invites from one identity are not byte
identical. Only the vector generator pins deterministic mode, and a test asserts
the live signer stays hedged.

### You can send to somebody who is offline

`publishPrekeys` mints a bundle to publish anywhere and the secrets that open
messages sent to it. `sealIntro` writes to a bundle in one frame with no round
trip. This is X3DH with a post-quantum arm, which is what Signal ships as PQXDH.

Four secrets go into the root, each doing a different job:

| | |
|---|---|
| DH1 | sender ephemeral to recipient identity, binds who it is for |
| DH2 | sender identity to recipient prekey, binds who it is from |
| DH3 | sender ephemeral to recipient prekey, forward secrecy |
| SS | ML-KEM-768 to the recipient's PQ prekey, the post-quantum arm |

**The ephemeral is why this path is stronger than the live handshake, not
weaker.** This README has said since 0.1.0 that the live handshake gives the
initiator no forward secrecy before the first ratchet step, because the
initiator contributes only a long term key: record the wire today, steal the
identity file later, recover the root. DH1 and DH3 both use an ephemeral whose
secret is wiped before the token is built, so the value a future thief would
need stopped existing before the bytes went out.

What it does not solve is replay, and the API says so out loud rather than in a
comment. A bundle is a static offer, so a recorded intro can be delivered twice.
`openIntro` refuses a conversation id it has already opened, and the set of
those ids is a **required argument** rather than an option with an empty
default, because the version with a default is one where everybody who did not
read the docs has no replay protection and no way to find out.

### A relay, so two home connections can meet

```
ratchet relay                                 # on any box with a public address
ratchet recv --relay relay.example.com        # prints a pairing code
ratchet send FILE --code THE-CODE --relay relay.example.com
```

`relay/server.mjs` introduces two sockets and then gets out of the way. After
the pairing byte it is a pipe: no parsing, no framing, no inspection. That is
why adding it needed no change to the envelope and cannot weaken it.

**What it learns:** ciphertext, byte counts, timing, and two IP addresses. It is
trusted for availability and nothing else. It cannot read a message, cannot
change one without the AEAD noticing, and cannot impersonate either party. A
hostile relay's whole power is to refuse service, to log who talked to whom and
when, and to see how much was said. If two addresses meeting at a timestamp is
the thing you need to hide, a relay you do not run is the wrong answer.

It never sees the pairing secret: both clients meet on SHA-256 of it, so an
operator who logs everything still cannot join a rendezvous it is carrying.

**There is no default relay host and that is deliberate.** A default would route
everybody through one machine chosen by me and paid for by me, and it would keep
doing that after I stopped paying. Running one is one command.

### Pairing codes, so nobody types an IP address

A code is 16 bytes of rendezvous secret plus the first 64 bits of the receiver's
fingerprint, in Crockford base32:

```
DG752N-30KF11-XQ5N5X-9C5W4C-D9RFYC-56RAHE-MY0
```

Crockford because a code gets read aloud, and somebody hearing "one" for I or
"zero" for O has to still get in. The decoder folds the lookalikes back.

The secret keeps strangers out of the socket. **The fingerprint prefix is for
when the code leaks**, which is the case that actually happens, because codes
travel over WhatsApp: an attacker who wins the race to the rendezvous still
arrives holding their own identity, and the sender refuses before one byte of
payload leaves the disk. 64 bits is a second preimage at 2^64 keypairs with no
birthday shortcut, because the target is fixed before the attacker sees the code.

That check turns the weakest link in the whole design, a verification ritual
people skip, into something the machine does every time. It does not replace
comparing the words aloud for a peer you intend to keep: 64 bits pinned by a
code you may have pasted somewhere is a different claim from 132 bits two people
read to each other.

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
handling. 179 tests, `.ts` and `.mjs`: 178 pass and 1 is skipped.

```sh
npm install && npm test && npm run typecheck && npm run build
```

## What can and cannot be claimed against Signal and Telegram

This project is fast and the numbers below are real, and there are three
comparisons people reach for that the numbers do not support. Getting these wrong
is how a crypto project loses the only thing it has.

**"Faster than Telegram." No, and the comparison is not meaningful.** A message
takes 20 to 200 milliseconds to cross a network. This library spends 16 to 30
*microseconds* of CPU sealing it. The crypto is three to four orders of magnitude
below the network term, so it is not what anyone is waiting for, and halving it
changes nothing a user can perceive. What is true and is worth saying: Telegram's
MTProto has no post-quantum handshake at all, and secret chats are opt-in and
one-device. That is a protocol difference, not a speed one.

**"More post-quantum than Signal." No. Signal is ahead, in two distinct ways.**
Signal shipped PQXDH in production before this existed, on a larger ML-KEM
parameter set. Signal then shipped SPQR, which makes the *ratchet itself*
post-quantum. This library has a post-quantum handshake and a classical ratchet.
The ML-KEM-768 contribution is mixed into the root key once, when the
conversation opens, and every DH step after that is X25519 and nothing else. That
defeats harvest-now-decrypt-later, which is the threat that actually exists
today, and it is the same scope PQXDH had. It is narrower than where Signal is
now.

**"More secure than Signal." No.** Signal has years of independent audits, formal
models, and adversarial attention. This has none of those, one author, and a
README that says so at the top. Security is not a property of a construction, it
is a property of a construction that people have failed to break.

Here is what is measured and defensible, with the qualifiers that have to travel
with it:

- **About 2x less CPU per message than the Signal Double Ratchet construction**,
  measured on one machine, in one runtime, at 256 bytes. 2.0x when this laptop is
  boosting and 3.0x at base clock, which tells you the ratio moves with the
  machine and neither end of that range is the number. Construction against
  construction: the Signal shape is HKDF-SHA256 to key, IV and MAC key, then
  AES-256-CBC, then HMAC-SHA256 truncated to 8 bytes, and its second HKDF alone
  costs more than this library's entire seal. It is *not* implementation against
  implementation. `libsignal` is Rust and would beat this at the same
  construction.
- **34 bytes of overhead per message against Signal's roughly 82.** That one is
  structural rather than a tuning win, and it does not move with the machine.
- **MIT.** `libsignal` is AGPL. For a closed-source product that is the whole
  reason this exists.

The one-line version that survives a knowledgeable reader: *a hybrid
post-quantum handshake and a Double Ratchet, in TypeScript, under MIT, with a
smaller and cheaper message than the reference construction, and none of the
audit history.*

## Benchmark

```sh
npm run bench
```

Single thread, no tuning. `--runs N` repeats the whole bench and reports the
spread across runs.

### Per message, 0.4.0

All of the following is one machine: AMD Ryzen 5 7530U laptop, Node v25.8.0,
Windows 11, single thread, all three backends confirmed `native` before the
first timer starts. The harness prints `aeadBackend()`, `curveBackend()` and
`hashBackend()` and refuses to measure unless all three say `native`. 2000
iterations after 500 warmup, nine rounds, so every median below is a median of
nine round medians. A number measured anywhere else is a different number, which
is why the machine is written next to it.

**The laptop's power state moves these numbers more than any code change in this
repo did, and that is worth putting first rather than in a footnote.** Plugged in
the CPU boosts to 4.5 GHz. On battery under the Balanced plan it sits pinned at
its 1890 MHz base clock. Same binary, same test, 1.8x apart:

| 256 B, p50 | plugged in, boosting | on battery, base clock |
|---|---|---|
| `seal` | 16.4 us | 30.0 us |
| `open` | ~14 us | 23.3 us |

Every absolute number below the headline table was taken **on battery at base
clock**, so treat them as an upper bound. The ratios were taken plugged in, as
interleaved arms in one process, which is the only way a ratio survives a machine
that changes speed mid-run.

The comparison that matters, published 0.3.4 from the registry against 0.4.0,
both arms interleaved in one process on AC power:

| 256 B | 0.3.4 | 0.4.0 | |
|---|---|---|---|
| `seal` p50 | 24.86 us | **16.36 us** | 1.52x less CPU |
| overhead per message | 122 B | **34 B** | 3.6x smaller |
| a 20 B message on the wire | 142 B | **54 B** | |
| a 256 B message on the wire | 378 B | **290 B** | |

Where the 8.5 us came from, each isolated in the same harness: merging the AAD
and the header into one buffer instead of serializing the same fields twice, 3.2
us. One HMAC-SHA512 instead of two HMAC-SHA256 for the chain step, 1.5 us.
Routing the CSPRNG through the native probe instead of `@noble`'s wrapper, 0.8
us. The rest is the smaller header moving through the encoder.

**The canonical payload is 256 bytes.** It is this project's working estimate
of a real chat message, and because latency is flat below about 1 kB (see the
sweep) the choice barely moves the number. The previous canonical size here was
200 B; running 200 B and 256 B as two arms of one interleaved loop moves seal
by 0.0 us and open by 0.1 us, which is inside the noise band of either.

256 byte payload, seal and open measured on separate session pairs, because
thousands of seals with no reply walks the receiving side into `MAX_SKIP`. **On
battery at base clock**, so multiply by about 0.55 for a boosting machine:

| | p50 | p99 | min |
|---|---|---|---|
| `sealToEnvelopeBytes` | 30.0 us | 153.3 us | 27.4 us |
| `openFromEnvelopeBytes` | 23.3 us | 104.2 us | 21.0 us |
| round trip (sum of p50s) | 53.3 us | not additive | 48.4 us |

Read the p50 to two significant figures and no further. The `min` column is the
useful one for "how fast can this go when nothing interrupts it": it is within
10% of the p50, which says the median is not being dragged by a long tail, it is
genuinely what a call costs.

Those rows are the synchronous core, `ratchetEncryptToEnvelopeBytes` and
`ratchetDecryptFromEnvelopeBytes`. The public `engine.sealToEnvelopeBytes` is
an `async` wrapper around it; measured as one arm against the sync call in the
same interleaved loop, 256 B, it is 22.1 us p50 against 21.2 us p50, so the
`await` costs about 0.9 us, 4% of a seal. Add that if you call through the
engine, which you should, because the wrapper is what lets the AEAD backend
resolve.

The p99 is 2 to 3x the p50 and that is not noise to be averaged away. It is V8
allocating: a seal allocates about ten short lived objects and buffers, and
every so often one call pays for a young generation collection. If you are
sizing a queue, size it against the p99.

Across sizes. The byte columns are exact and deterministic, not measured with a
clock. A **settled** frame is any message after the first three of a chain; a
**step** frame is one of the first three, which carries the 32 byte ratchet
public key and a second varint:

| payload | settled envelope | step envelope | overhead |
|---|---|---|---|
| 20 B | 54 B | 87 B | **34 B** |
| 100 B | 134 B | 167 B | **34 B** |
| **256 B** | **290 B** | **323 B** | **34 B** |
| 1000 B | 1034 B | 1067 B | **34 B** |
| 4000 B | 4034 B | 4067 B | **34 B** |
| 65535 B | 65569 B | 65602 B | **34 B** |

**34 bytes, flat, at every size from a one word reply to a 64 kB chunk.** In
0.3.x it was 122, also flat. A 20 byte message went from 142 bytes on the wire to
54.

Latency is flat below about 1 kB too: a 200x increase in payload cost 17% more
time when this was measured at 0.3.4, and nothing in 0.4.0 changed the shape of
that curve, only its height. Below about 1 kB the per message cost is fixed cost:
a chain step, a nonce, an AEAD call on a short buffer, and the object churn
around them. The bytes are nearly free and the call is not. That means batching
small messages helps and splitting large ones does not, and it is also why the
canonical 256 byte size is a judgement call rather than a measurement: anything
from a one word reply to a full paragraph lands on the same number.

The p99 is 3 to 5x the p50 and that is not noise to be averaged away. It is V8
allocating: a seal allocates about ten short lived objects and buffers, and every
so often one call pays for a young generation collection. If you are sizing a
queue, size it against the p99, and remember the tail widens further on battery.

### Where the fixed cost goes

Same machine, 256 B, medians of nine repeats of 4000 iterations, each stage
timed in place with `performance.now()` around it.

**Read the method before the numbers, because this is the weakest measurement
on the page.** The stages are produced by importing the real `src/*.ts` modules
and calling the same exported functions in the same order the shipped code
calls them: `kdfChain`, `randomBytes`, `messageAad`, `sealAeadSync`,
`encodeEnvelopeBytes` on the seal side, and `decodeEnvelopeBytes`, `skipKeyId`
plus the map lookup, `kdfChain`, `messageAad`, `openAeadSync` on the open side.
The pieces that are **not** exported, `draftOf`, `commit`, the header object
literal and the session spread, are transcribed by hand out of
[`src/ratchet.ts`](./src/ratchet.ts) into the harness. That row is a copy, not
the shipped code, and if `src/ratchet.ts` changes without the harness changing,
that row silently lies. It is the "everything else" line in both tables and it
is the line to distrust first.

Timer overhead on this machine is **0.058 us per `performance.now()` call**,
median across seven runs, band 0.05 to 0.06. It is **not** subtracted from
anything below. The seal table carries eleven timer calls and the open table
carries eighteen, so roughly 0.6 us and 1.0 us of each sum is the timer itself.

Seal, 256 B:

| stage | p50 | share |
|---|---|---|
| `sealAeadSync`, XChaCha20-Poly1305 | 7.9 us | 37% |
| `kdfChain`, two HMAC-SHA256 | 6.4 us | 30% |
| `randomBytes(24)` nonce | 2.6 us | 12% |
| `messageAad` build | 2.0 us | 9% |
| `encodeEnvelopeBytes` | 1.7 us | 8% |
| everything else: guards, header literal, `wipe`, session spread (transcribed) | 1.0 us | 5% |
| **sum of stages** | **21.6 us** | |

Open, 256 B:

| stage | p50 | share |
|---|---|---|
| `openAeadSync`, XChaCha20-Poly1305 | 7.5 us | 38% |
| `kdfChain`, two HMAC-SHA256 | 6.5 us | 33% |
| `messageAad` rebuild | 1.9 us | 10% |
| `skipKeyId` + skipped-map lookup | 1.8 us | 9% |
| `decodeEnvelopeBytes`, borrowed ciphertext | 1.3 us | 7% |
| everything else: checks, `draftOf`, `commit`, `wipe` (transcribed) | 0.5 us | 3% |
| **sum of stages** | **19.5 us** | |

The check that decides whether these tables get published: the instrumented
path and the whole uninstrumented function are stepped **alternately in the
same loop**, on two separate sessions, so a clock change hits both. Against
that control the seal sum of 21.6 us stands against an uninstrumented whole of
20.6 us, an overshoot of **4.9%**. The open sum of 19.5 us stands against 18.8
us, an overshoot of **3.7%**. Both are under the 15% line at which these tables
would have been withheld instead of printed, and both are roughly the size of
the timer calls the tables carry, so nothing large is hiding in the gap.

Note also that the uninstrumented seal is 20.6 us in this section and 20.1 us
at the top of the page, and the whole sweep is lower again. Run to run on a
laptop that is not a benchmark rig, these numbers move a microsecond. No
reading of them should turn on 1 us.

Three things worth saying out loud:

- **The AEAD is the largest line on both sides, and about 1 us of its 7.7 is
  JavaScript.** XChaCha20 derives a subkey with HChaCha20 in JS and only then
  hands a 12 byte nonce construction to OpenSSL.
- **The chain step is two HMAC-SHA256 calls and stays two.** One HMAC-SHA512
  split in half would cost about a third of this and would also be a different
  protocol. See [`src/kdf.ts`](./src/kdf.ts).
- **Open pays 1.8 us to build a skipped-key lookup string on every message**,
  which base64s the 32 byte ratchet public key whether or not anything was ever
  skipped. That is 9% of an open spent asking a usually empty map a question.

### Against the Signal construction

Same machine, same runtime, same 256 byte payload, `node:crypto` on both sides,
crypto primitives only with no session or envelope work. Both constructions are
stepped as arms of one interleaved loop, so the ratio is not an artefact of two
processes running at two clock speeds.

The Signal shape is: chain step HMAC-SHA256 twice, then HKDF-SHA256 from the
message key out to 80 bytes (encryption key, IV, MAC key), then AES-256-CBC,
then HMAC-SHA256 over the ciphertext truncated to 8 bytes. The 0.4.0 shape is:
chain step HMAC-SHA512 once split 32/32, then ChaCha20-Poly1305.

| 256 B, on battery at base clock | p50 | p99 |
|---|---|---|
| Signal Double Ratchet shape | 81.4 us | 252.5 us |
| ratchet-ts 0.4.0 shape | 27.1 us | 114.4 us |

**Quote 1.9x, not 3.0x.** That table says 3.00x at p50. An earlier interleaved
run on AC power said 1.88x. Both runs were valid, the conditions differed, and I
have not reconciled them, so the honest number to repeat is the conservative one
until a clean repeat on a fixed power state settles it. Publishing 3.0x because
it is the friendlier figure would be the exact move this file exists to avoid.

Two changes since 0.3.4 moved this ratio and both are real: the chain step went
from two HMAC-SHA256 to one HMAC-SHA512, and the AEAD went from XChaCha20 to
ChaCha20, which drops an HChaCha20 subkey derivation that was running in
JavaScript on every message. So the ratio genuinely should be better than 0.3.4's
1.98x. How much better is not yet pinned down.

Now the qualifiers, and they are not optional. All four travel with this
comparison every time it is repeated:

- This is **construction against construction, not implementation against
  implementation**. It measures what the two designs ask a CPU to do.
- It does **not** measure libsignal, which is Rust, and which would be faster
  than this library at either construction.
- It is **CPU only**. It excludes network, storage, serialisation, and the
  handshake.
- It says **nothing whatsoever** about how fast any deployed messenger feels.
  Network round trip time is three to four orders of magnitude larger than
  every number on this page. Nobody has ever noticed 13 microseconds.

What it does tell you is which construction you would pick if you were writing
one today, and that an encrypt-then-MAC pair from 2013 costs more than a modern
AEAD.

Note for anyone comparing this against an earlier draft of this file. A pass
during 0.3.4 put 2.21x here, measured against ChaCha20-Poly1305 with a 12 byte
IETF nonce, and that was wrong at the time: 0.3.4 shipped XChaCha20-Poly1305 with
a 24 byte nonce, so the faster figure was measuring a build nobody ran. It was
corrected down to 1.98x. As of 0.4.0 the IETF variant **is** what ships, so the
same measurement is now the honest one and the correction has expired. Left here
because a number that moved twice for two different reasons is worth being able
to trace.

### Handshake

Once per conversation, same machine and method:

| | on battery, base clock | plugged in, boosting |
|---|---|---|
| `createIdentity`, X25519 + ML-KEM-768 keygen | 1.320 ms | 0.484 ms |
| full key exchange, invite + accept + complete | 5.256 ms | 1.851 ms |

That spread is 2.7x, wider than the 1.8x clock ratio, and I do not have a clean
explanation for the gap. ML-KEM-768 touches far more memory than the message path
does, so it plausibly loses more than clock alone to a laptop in its low power
state, but that is a hypothesis and not something measured here. The AC column
was taken during 0.3.4 and the classical half has not changed since, so it should
still be close, but treat it as indicative rather than fresh.

**Two harnesses disagree about the battery figure and neither is being hidden.**
The 5.256 ms above came from the README harness. The chart further down says
**4.44 ms**, from a longer run: 20 rounds with a 25 second sustained warmup,
phase separated so the handshake loop does not run immediately before the seal
loop, and reporting the median of per-round p50 rather than a single pass. That
method now lives in `bench/machine.mjs` as `npm run bench:machine`, which it did
not when this paragraph was first written: it was typed once and thrown away, so
the number the chart presented as the careful one was the only number here nobody
could reproduce. The longer run is the better number and the chart carries it. Both
are printed here because the 18 percent gap between two honest measurements of
one unchanged binary on one machine is itself the most useful fact in this
section: it is the width of the error bar on every millisecond in this file.
Ratios taken inside a single interleaved process, like the Signal comparison
above, do not carry that error and are the ones worth quoting.

An invite token is 1687 characters and an accept token is 3186, both fixed,
because ML-KEM-768 keys and ciphertexts are fixed size. The handshake is roughly
100 to 175 messages' worth of CPU depending on power state, and you pay it once,
so any conversation longer than a couple of hundred messages is handshake
minority. It is also entirely invisible next to a network round trip.

### Backends, and how to check yours

Three independent native probes, one per primitive:

```js
import {
  aeadBackend, aeadReady,
  curveBackend, curvesReady,
  hashBackend, hashReady,
} from 'ratchet-ts';

await Promise.all([aeadReady(), curvesReady(), hashReady()]);
console.log(aeadBackend(), curveBackend(), hashBackend());
// node with OpenSSL: native native native
```

Every number on this page is a `native native native` number. Each probe falls
back to [@noble](https://github.com/paulmillr/noble-hashes) independently and
silently if its primitive is missing or behaves wrong, which is correct for
portability and expensive for speed: the pure JavaScript path is materially
slower, and the handshake in particular was 4x slower before the native curve
backend landed in 0.3.3. If your numbers look nothing like these, print those
three strings first. It is the fastest question to answer.

### Across machines, and why this chart is honest about being broken

Nine runs on eight machines, and **only two of them are current numbers.** I own
exactly two of these nine boxes: the 7530U laptop and, as of 2026-08-15, an M4
Mac mini. The other seven were run by other people on 0.1.0 and 0.2.0, before the
native curve and hash backends landed in 0.3.3, and I cannot re-measure them. So
the chart draws the mixed vintage instead of hiding it: the two measured rows are
solid, the seven inherited rows are hatched, and the legend says which is which.
A hatched bar is a number from a different version of this library and is not
comparable to a solid one.

**The two solid bars are not comparable to each other either, and they are drawn
in different colours to say so.** The M4 is a desktop on mains, free to boost.
The 7530U is a laptop pinned near its base clock on battery. That is a power
state stacked on top of a hardware difference, and the section above is about why
the power half cannot be divided back out afterwards. The M4 handshake of **0.88
ms** against the 7530U's **4.44 ms** is not a five-times chip gap; the same
laptop did **1.85 ms** plugged in. Treat the two solid rows as two machines in
two states, not as a ranking.

The size of the lie, measured: the 7530U row said **7.6 ms** on 0.2.0. The same
laptop on 0.4.0 does **4.44 ms on battery** and did **1.85 ms plugged in** on
0.3.4, and the classical half of the handshake has not changed between those two
versions. So the inherited handshake column overstates by somewhere between
**1.7x and 4x**, and which end of that range you land on is decided by a power
cable rather than by any code in this repository. The inherited `seal` column is
wrong by an amount I cannot state at all, because those runs did not record
their payload size.

That range is the honest form of the correction and the single number that used
to sit here was not. It is also the reason the generator now demands a `power`
field on every row and refuses to draw one without it: version and date were
never enough to make two bars comparable.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="bench/charts/handshake-dark.svg">
  <img src="bench/charts/handshake-light.svg" alt="Full handshake (invite + accept + open), median ms per machine, lower is better: Ryzen 5 7530U 4.44 (v0.4.0, not re-measured, on battery at 1890 MHz base clock), Apple M1 6.20 (v0.1.0, not re-measured, power state not recorded), Core i5-12500H 6.50 (v0.2.0, not re-measured, power state not recorded), Core i5-12450H 7.00 (v0.2.0, not re-measured, power state not recorded), Ryzen 7 5800X3D 7.30 (v0.2.0, not re-measured, power state not recorded), EPYC 9354P 32-core 8.90 (v0.2.0, not re-measured, power state not recorded), Core i5-10400F 10.90 (v0.2.0, not re-measured, power state not recorded), Core i5-10400F 11.50 (v0.2.0, not re-measured, power state not recorded), Apple M4 14.56 (v0.6.0, measured, on AC, free to boost). Only the Apple M4 row is measured on 0.6.0. READ THE VERSION ON EACH BAR BEFORE COMPARING THEM. The 0.6.0 handshake carries two ML-DSA-65 signatures and every earlier row does not, which on one unchanged machine is the difference between 0.88 ms and 14.6 ms. So a shorter bar on an older version is not a faster machine, it is an unauthenticated handshake. The seven 0.1.0 and 0.2.0 rows additionally predate the native curve and hash backends added in 0.3.3 and none recorded a power state." width="760">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="bench/charts/seal-dark.svg">
  <img src="bench/charts/seal-light.svg" alt="seal, one steady-state send, median ms per machine, lower is better: Apple M4 0.0048 (v0.6.0, measured, on AC, free to boost), Apple M1 0.0190 (v0.1.0, not re-measured, power state not recorded), Core i5-12450H 0.0230 (v0.2.0, not re-measured, power state not recorded), Core i5-12500H 0.0250 (v0.2.0, not re-measured, power state not recorded), Ryzen 7 5800X3D 0.0280 (v0.2.0, not re-measured, power state not recorded), Ryzen 5 7530U 0.0355 (v0.4.0, not re-measured, on battery at 1890 MHz base clock), Core i5-10400F 0.0420 (v0.2.0, not re-measured, power state not recorded), EPYC 9354P 32-core 0.0500 (v0.2.0, not re-measured, power state not recorded), Core i5-10400F 0.0530 (v0.2.0, not re-measured, power state not recorded). Only the Apple M4 row is measured on 0.6.0. The inherited rows recorded neither their payload size nor their power state, so they are not directly comparable to the 256 B measured rows. Unlike the handshake, the seal path did not change in 0.6.0: signatures are a per conversation cost, not a per message one." width="760">
</picture>

| Machine | Node | Version | Handshake | `seal` | `open` |
|---|---|---|---|---|---|
| **Apple M4 (Mac mini 2024, macOS 26)** | **22** | **0.6.0, measured 2026-08-16, on AC and free to boost** | **14.56 ms** | **0.0048 ms** | **0.0044 ms** |
| Apple M4 (same box, same day) | 22 | 0.4.0, before the handshake was signed | 0.88 ms | 0.0046 ms | 0.0042 ms |
| **Ryzen 5 7530U (laptop, Win 11)** | **25** | **0.4.0, measured 2026-08-08, on battery at 1890 MHz** | **4.44 ms** | **0.0355 ms** | **0.0292 ms** |
| Apple M1 (laptop 2020, macOS) | not recorded | 0.1.0, inherited | 6.2 ms | 0.019 ms | not recorded |
| Core i5-12500H (laptop 2022) | 24 | 0.2.0, inherited | 6.5 ms | 0.025 ms | not recorded |
| Core i5-12450H (laptop 2022) | 24 | 0.2.0, inherited | 7.0 ms | 0.023 ms | not recorded |
| Ryzen 7 5800X3D (desktop) | 24 | 0.2.0, inherited | 7.3 ms | 0.028 ms | not recorded |
| EPYC 9354P 32-core (VPS, Linux) | 22 | 0.2.0, inherited | 8.9 ms | 0.050 ms | not recorded |
| Core i5-10400F (desktop 2020, WSL) | 22 | 0.2.0, inherited | 10.9 ms | 0.053 ms | not recorded |
| Core i5-10400F (same box, Windows) | 24 | 0.2.0, inherited | 11.5 ms | 0.042 ms | not recorded |

The measured row is the 256 B payload, 4000 iterations, 500 warmup, median of
nine process runs, all three backends `native`. The inherited rows are whatever
`npm run bench` did at the time on someone else's machine, and their `open`
column has been deleted rather than carried forward: the old table printed an
`open` for every machine, but those values were never separately measured and
had no provenance, so they are gone. Deleting a number is cheaper than
defending one.

**What the inherited rows are still good for.** The shape across machines is a
real finding and it does not depend on the absolute values, because every
inherited row was measured the same wrong way. The bench is single-core bound,
so a newer core beats a bigger machine: the fastest inherited row is a 2020
ultrabook, the M1 tops the column, the 2022 laptop chip behind it still outruns
a 5800X3D desktop, and a 32-core EPYC server lands mid-table. Core count buys
concurrent sessions, not a faster handshake.

The two 12th generation Intel rows are different chips, not one box measured twice: twelve cores on the 12500H against eight on the 12450H. The 12450H handshake is 8 percent slower and its `seal` 8 percent faster, and the run that produced it spread 2.4 percent on handshake and 9.6 percent on `seal` across three runs. A gap smaller than the spread of the run it came from is not a result, so at this workload the two chips are the same speed, and the core count again bought nothing.

The two i5-10400F rows are the same physical box under WSL and under Windows, with different Node versions: the handshake differs by 6 percent, `seal` is 21 percent faster on the Windows run. For scale, three back-to-back runs on the idle VPS varied by 3.3 percent on both handshake and `seal`, so single-digit gaps are run-to-run noise and only the larger one is worth a second look. `keygen` on that same VPS spread 33 percent across the three runs, which is what a noisy neighbour on shared hardware looks like and the reason `--runs` prints the spread at all.

The 7530U row has been wrong twice and this is the third value it has held. It first went in at 13.8 ms, measured while that laptop was running a heavy build in the background. Re-measured idle on 0.2.0 it was 7.6 ms with a 0.3 percent spread across three runs, which moved it from last place to fourth. On 0.3.0 with a normal desktop load it read 8.9 ms handshake, 0.041 ms `seal`, 0.046 ms `open`. On 0.3.4 with native curve and hash backends, plugged in, it was 1.85 ms. On 0.4.0 on battery at 1890 MHz it is 4.44 ms. Four of those five numbers were in this file at some point as if they were the truth, and the fifth is in it now. A bench number is only as good as the machine was quiet, the version it ran on, and the clock the CPU was actually holding, which is why the generator refuses to draw any row missing a version, a date or a power state.

Worth saying plainly, because it is the most useful thing this row teaches: **the spread between 1.85 ms and 4.44 ms on one unchanged machine is larger than the spread between most of the eight machines in the chart.** Anyone quoting a millisecond off this project without saying whether the laptop was on mains is quoting noise.

Protocol overhead is the one column that does not depend on the machine at all. Token overhead for a 256 byte message is **+259 bytes** (ratchet header + AEAD tag + framing) everywhere, because it is protocol math, not hardware, and it re-measures to exactly 259 on 0.3.4. That 259 is not a constant across sizes: the body is base64url, so a third of it scales with the plaintext, and a 65519 byte message pays 22013 bytes. The binary envelope overhead **is** constant, 122 bytes at any size, re-measured on 0.3.4 at 20, 100, 200, 256, 1000 and 4000 bytes, so a 256 byte message is a 378 byte envelope.

**On 0.4.0 that constant is 34 rather than 122**, or 67 on the first three messages of a sending chain, so the same 256 byte message is a 290 byte envelope. The 122 figure and everything derived from it above describes 0.2.1 through 0.3.4. The header rewrite that changed it is documented further up.

The test suite has also passed unmodified on hardware I do not own. Charts come from the table via [`bench/charts/generate.mjs`](./bench/charts/generate.mjs), which now throws rather than draw a row missing its `version`, `measuredOn` or `harness` field. A fixed-iteration CI bench is planned so numbers only move when the code does, and so this section stops being a museum.

### Cost by version

Same machine, same 763.5 kB file, each version installed from its published
tarball. A blank cell means not measured on that version, not zero:

| | 0.1.0 | 0.2.1 | 0.3.0 | 0.3.1 | 0.3.4 | 0.4.0 |
|---|---|---|---|---|---|---|
| wire overhead | | 33.7% | 0.2% | 0.2% | 0.2% | 0.1% |
| sender wall, loopback | | | 56.5 ms | 18.7 ms | | |
| survives a restart | no | yes | yes | yes | yes | yes |
| binary payload, no workaround | no | yes | yes | yes | yes | yes |
| a `ratchet` command | no | yes | yes | yes | yes | yes |
| identity readable off disk | yes | yes | yes | yes | yes | **no, from 0.5.0** |

The 0.3.4 wire overhead cell is measured, on the 10.5 MB transfer in the table
further up, and it is 0.2% at 65519 byte chunks exactly as on 0.3.1: nothing in
0.3.3 or 0.3.4 touched the envelope. The 0.4.0 cell is 0.1% on a 3.1 MB transfer,
which is the envelope going from 122 bytes to 34 showing up at chunk scale. Both
sender wall cells are blank because the 763.5 kB file has not been re-run since
0.3.1. The throughput comparisons that have been run are 0.3.2 against 0.3.4 on a
10.5 MB file, 1.4x, and 0.3.4 against 0.4.0 on the CLI path, 79.98 MB/s to
121.90 MB/s.

Three separate things moved, one per release, and none of them was the
cryptography.

**0.2.0 added a bytes API.** Before it, the only way to send a file was to
smuggle it through the string API, where every byte above 0x7f became two bytes
of UTF-8 on the way out. A 1 KiB binary payload went from 2227 bytes on the wire
to 1539:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="bench/charts/wire-dark.svg">
  <img src="bench/charts/wire-light.svg" alt="Bytes on the wire for a 1 KiB binary payload: 0.1.0 latin1 string workaround 2227 bytes, 0.2.0 sealBytes, native Uint8Array 1539 bytes, 31 percent fewer. Exact byte counts, not timings, measured against the published tarballs, so they do not depend on CPU clock or power state." width="760">
</picture>

It also made a session survivable. On 0.1.0, `JSON.stringify` on a session
silently turned every `Uint8Array` into `{}` and the next `seal` threw, so a
page reload ended the conversation.

**0.3.0 took base64url off the socket**, which is the entire 33.5 point drop in
overhead. base64 taxes payload and envelope alike at exactly a third, so the
saving converges on 25% of the wire at every size above a few kB.

**0.3.1 took the same base64 off the CPU**, where the CLI had been building a
token and parsing it back for every frame it sent or received.

**0.4.0 took the header itself down**, from 122 bytes to 34, which is the drop
from 0.2% to 0.1% in the table above and a much larger drop for anything that is
not a 65 kB chunk. See the message header section further up.

Encryption itself was never the cost. On 0.4.0 a 12 byte nonce and a 16 byte tag
on a 65519 byte chunk is 0.04%. The whole envelope, ratchet public key and sealed
header included, is 0.23% of that 763.5 kB file on 0.3.x and roughly a third of
that on 0.4.0.

**AEAD backend.** [`src/aead.ts`](./src/aead.ts) prefers Node's native
`chacha20-poly1305` and falls back to `@noble/ciphers` everywhere else, with
`aeadBackend()` reporting which one is live. Byte-identical output either way,
checked against 200 random tuples on every bench run before any timing is
reported. At chunk size the native path is somewhere between 3x and 7x, measured
across six captures with the backends alternated inside each repeat so neither
gets the cold cache to itself. At 256 bytes it is a wash, because call overhead
dominates the cipher.

**The floor.** A 20 byte file transfer cost 415 bytes on the wire through 0.3.4
and costs **305 on 0.4.0**. Both re-derive as arithmetic and the 305 was then
confirmed by running the transfer, which reported `wireBytes 305` for
`plainBytes 20`. Two frames go out, a sealed header of 143 JSON bytes and a
sealed 20 byte chunk, each paying an envelope and a 4 byte length prefix. On
0.3.4 the envelope was a constant 122: 122 + 143 + 4 is 269, 122 + 20 + 4 is 146,
269 + 146 is 415. On 0.4.0 both frames are inside the first three messages of the
sending chain, so both are step frames at 67 rather than settled frames at 34:
67 + 143 + 4 is 214, 67 + 20 + 4 is 91, 214 + 91 is 305. A third message in the
same direction would cost 34 over its payload rather than 67.

What is left is the tag, the nonce, the ratchet public key on the frames that
carry it, and a sealed header carrying the filename, and none of it scales down.
This moves files well and chat lines
badly.

A single chat line is cheaper than that, because it pays one frame rather than
two: 122 bytes of envelope plus 4 of length prefix on top of the text. That is
still 126 bytes of tax on a 20 byte line. 0.4.0 is where the floor gets
attacked, because shrinking it changes the wire.

The 0.4.0 header is 34 bytes and **is** the AAD, so `messageAad` stops existing
rather than moving. Today the seal path builds an AAD with a `Writer` and then
builds an envelope with a second `Writer`: at 256 B those are 1.8 us and 1.9 us
on this laptop. The 0.4.0 shape writes those same 34 bytes once into the output
buffer and hands the same array to the AEAD as AAD, which measures 0.2 us. That
is the double serialization gone, by construction rather than by tuning.

This paragraph said 22 bytes while 0.4.0 was being built, and the number moved
for a reason worth recording rather than quietly correcting. A draft carried no
nonce on the wire at all and derived it from the message number instead, which
is what made 22 possible. That draft was built, measured at 3.4 us and 12 bytes
cheaper, and then reverted. The reason is in the `NONCE_LEN` comment in
`src/ratchet.ts` and it is not a performance argument: a counter nonce turns a
restored session snapshot from an integrity failure into a confidentiality one,
because the replayed message key meets the same nonce, produces the same
keystream, and hands anyone holding both ciphertexts the XOR of the two
plaintexts. A random 12 byte nonce under the same rollback is merely bad. The
12 bytes are the price of that difference and they were paid deliberately.

Both shapes were then modelled end to end in one interleaved loop, alternating
0.3.4 and 0.4.0 every iteration on the same machine in the same process, so the
difference between them shares every scheduling artefact instead of being two
separate runs subtracted. Same machine as everything above, 256 B, all three
backends `native`, nine process repeats of 4000 iterations.

| | p50 | p99 |
| --- | --- | --- |
| model of the 0.3.4 seal | 21.8 us | 69.1 us |
| model of the 0.4.0 seal | 18.1 us | 57.5 us |
| paired saving, p50 | **3.5 us** (band 3.0 to 3.7 across nine repeats) | |

Applying that saving to the real measured 0.3.4 seal of 20.1 us p50 projects a
**256 B 0.4.0 seal at 16.6 us p50 on this laptop, call it 16.4 to 17.1** from
the saving band alone, or 15.1 to 18.1 if the run-to-run spread of the seal
itself is also carried through. There is no p99 projection: the p99 here is
dominated by V8 collection, the model does not reproduce the real allocation
mix, and projecting a tail from a model is how you get a number nobody can
reproduce.

That was written before 0.4.0 existed, as a projection, and it is left here
rather than deleted because **the projection can now be scored**. It said 16.6 us
p50, band 16.4 to 17.1. Shipped 0.4.0, measured plugged in against 0.3.4 from the
registry in one interleaved process, does **16.36 us**. That is 1.5% below the
point estimate and a hair under the bottom of the band, which is the right kind
of wrong: the model assumed the chain step and the AEAD were untouched, they were
untouched, and the small extra came from routing the CSPRNG through the native
probe, which the model did not include because it was not planned yet.

Keep the habit rather than the number. A projection that names its assumptions
can be checked later; one that does not is just a hope with a decimal point.

```sh
npm run bench:wire
```

is a second harness, separate from `npm run bench`. It stands the real
[`cli/frame.mjs`](./cli/frame.mjs) server up on loopback with a byte counting
relay in front of it and reports what the socket actually carried rather than
what the arithmetic predicts. The per-release detail behind these numbers, and
the measurements that did not survive into this table, are in
[CHANGELOG.md](./CHANGELOG.md) and the
[releases](https://github.com/gntrs/ratchet-ts/releases).

## License

MIT. Copyright (c) 2026 Gintaras. See [LICENSE](./LICENSE).
