# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-08-15

The four things the roadmap has listed for months, done in one release: the
handshake is signed, you can send to somebody who is offline, two home
connections can meet through a relay, and setup is a pairing code instead of an
IP address.

**This breaks the wire and every fingerprint.** The envelope is `OCX3`, the
binary version byte `0x03`, and the identity carries a third key so the
fingerprint domain moved to v2. A 0.6.0 peer and a 0.5.x peer cannot talk, and
everyone has to compare safety words again. Both are unavoidable and both are
loud rather than silent.

### Added

- **ML-DSA-65 signatures on both handshake frames.** Confidentiality was hybrid
  and authenticity was X25519 alone, which meant an adversary who can solve
  discrete log could impersonate a responder in a live handshake. The accept
  signs the initiator's whole identity as the responder received it, and the
  initiator verifies against the snapshot it took when it sent the invite, which
  is what catches a rewritten invite. No third flight was needed.
- **Offline delivery.** `publishPrekeys`, `sealIntro`, `openIntro`,
  `verifyBundle`, and an `intro` envelope kind. X3DH with a post-quantum arm,
  which is what Signal ships as PQXDH. The sender's ephemeral is wiped before
  the frame is built, which closes the initiator forward secrecy gap the live
  handshake has always had and makes the offline path the stronger of the two.
- **`relay/server.mjs` and `ratchet relay`.** A rendezvous server that
  introduces two sockets and then pipes them. No accounts, no database, no
  persistence. It never sees the pairing secret, only SHA-256 of it.
- **Pairing codes.** `ratchet recv --relay HOST` prints one;
  `ratchet send FILE --code CODE --relay HOST` uses it. 16 bytes of rendezvous
  secret plus 64 bits of the receiver's fingerprint, in Crockford base32 so it
  survives being read aloud.
- **`verifyPeer` on `sendPayload` and `receivePayload`.** The one callback that
  can refuse a transfer. See below for why it exists.
- **`bench/machine.mjs`** and `npm run bench:machine`, the harness the published
  chart row comes from. It existed only as a sentence in the README before.

### Changed

- The handshake costs about 29 times more: **0.88 ms to 25.8 ms** on the same
  machine, and `createIdentity` 0.26 ms to 2.01 ms. The invite token goes 1687
  to 8707 characters and the accept 3186 to 10206. **The message envelope does
  not move at all**, still 34 bytes of overhead, so authentication is a per
  conversation cost and not a per message one.
- The chart generator marks pre-0.6.0 rows as not re-measured rather than
  "pre-0.3.3", which stopped being true the moment a 0.4.0 row went stale, and
  its caveat now says in the alt text that a shorter bar on an older version is
  an unauthenticated handshake rather than a faster machine.

### Fixed

- **A security check that did nothing.** The pairing code comparison went in
  first as an `onHandshake` banner. `announce()` catches everything a banner
  throws, deliberately, because a rendering bug must never cost somebody their
  file. So the refusal was swallowed, and an end to end run sent the file to the
  wrong machine while printing nothing about it. The unit tests were green.
  `verifyPeer` is separate, awaited and unwrapped, and a test now pins both
  halves, because the wrong repair would have been making banners fatal.
- **A relay that ate the first frame.** Reading the hello greedily consumes
  whatever arrived in the same TCP segment, which is the peer's first frame, and
  the handshake then fails much later looking like a crypto problem.
- **`socket.unshift` cannot put those bytes back** once a data listener has put
  the socket in flowing mode: they are re-emitted between the listener being
  removed and the pipe being attached, with nobody listening. Leftover bytes are
  forwarded explicitly now.
- **A relay that would not shut down.** `net.Server.close()` waits for existing
  connections to end, which for a relay is never, so the process ignored SIGTERM
  and the test suite hung with no output at all.

### Note for anyone upgrading

Your identity file still loads, but its fingerprint is different, because the
digest now covers the signing key. Every peer you have verified will show
different words. That is correct: a fingerprint that ignored the new key would
let an attacker keep your other two, swap in a signing key of their own, and
print the words you already trust.

## [0.5.1] - 2026-08-15

CLI only, and it changes one thing: the safety words you are asked to compare
out loud. The library API, the wire format and the envelope are untouched, so a
0.5.1 CLI and a 0.4.0 CLI still talk to each other.

The words are the only defence this tool has against a machine in the middle,
and they were worth half of what they claimed. `pairWords` hashed both
identities together and produced six words, and the comment above it said that
was "exactly as strong as an ordinary fingerprint: 66 bits". It was not. An
attacker in the middle chooses the key it shows to each side, so it never has to
find a preimage: it grinds candidate identities to show Alice and candidate
identities to show Bob until the two six word lines agree. That is a birthday
search over a 66 bit space, about 2^33 work, which is hours on hardware anyone
can rent. The roadmap in the README had said so for a while. The code went on
asserting the comfortable number.

### Changed

- **The compared line is now both identity fingerprints, twelve words, not one
  hash of the pair.** To pass, the words shown to each side must match position
  by position, so the attacker needs an identity whose fingerprint equals
  Alice's AND another whose fingerprint equals Bob's: two independent second
  preimages at 2^66 each, with no birthday discount because both targets are
  fixed before the attack starts.
- **It prints as two rows of six.** Twelve words on one row is about 84 columns
  before any label, and a safety word broken across a line wrap still looks like
  a word and still gets read aloud. The break is on the fingerprint boundary and
  never on terminal width, because the two people comparing are not looking at
  the same window size. One helper does the grouping for both the plain banner
  and the chat TUI, so they cannot disagree about where it breaks.
- **Ordering is by fingerprint hex, not by public key.** An attacker who matched
  both fingerprints did not have to match the keys underneath them, so a key
  order could still print the two rows swapped and invite someone to wave it
  through. Ordering on the thing being compared means the sequence matches if
  and only if the fingerprints do.
- The chat strip is three rows rather than two, and the layout budget moved with
  it. A strip returning more rows than are budgeted does not overflow, it pushes
  the input box off the bottom of the terminal, which is why the constant and
  the function are now pinned to each other by a test.

### Note for anyone who verified a peer before this

You will see twelve words where you saw six, and they will not contain the old
six. Nothing is wrong and nothing was compromised by this change: what you
compared before was worth half the bits it was described as, and this is the
correction. Compare again when convenient.

## [0.5.0] - 2026-08-08

CLI only. The library API, the wire format and the envelope are byte for byte
what 0.4.0 shipped, so a 0.5.0 CLI and a 0.4.0 CLI talk to each other. What
changed is what `ratchet` leaves on your disk.

Until now it left two plain files: an identity holding both secret keys in the
clear, and a peer list naming everyone you had talked to, with addresses and
timestamps. Anyone who could read the directory could read both, and copying the
identity was enough to be you to every peer who had not compared words with you
by hand. Forward secrecy does not cover that, because the identity key is the one
key the ratchet never rotates. Both files are now sealed.

### Added

- **The vault.** One key, resolved in this order: the OS keychain, then a
  passphrase, then nothing. On Windows the keychain is DPAPI, bound to your
  Windows account. macOS uses `security`, Linux uses `secret-tool`. A backend is
  only trusted after it has stored 32 random bytes, handed them back, and matched
  them, so a store that cannot return a key is discarded rather than sealed
  under. If every backend fails the vault says so in one line and falls back to
  plain files, which is exactly what 0.4.0 did, so there is no way to be worse
  off than before.
- **`ratchet lock`** moves the key from the keychain to a passphrase, asked for
  once per command. `scrypt` at N=2^18, so 256 MiB and about 1.2 seconds per
  guess. Memory rather than iterations, because the attacker is a GPU running
  offline against a copied directory and memory is what a GPU has least of.
  `ratchet unlock` moves it back.
- **`RATCHET_PASSPHRASE`** and **`RATCHET_NEW_PASSPHRASE`** for unattended
  machines. Reading a passphrase from a non-TTY stdin is refused rather than
  silently swallowing the next line of somebody's script.

### Changed

- **The identity file is encrypted at rest.** XChaCha20-Poly1305 under a key
  derived from the vault key, with the protection mode bound as associated data
  so editing the header fails authentication instead of producing a confusing
  decrypt error. A plain identity from any earlier version is detected, sealed in
  place, and the user is told once. Your six words do not change.
- **`peers.json` is a sealed store.** Each row is an independent envelope. The
  row name is an HMAC under a vault subkey, not a plain hash, because a salt
  sitting in the same file only stops a precomputed table: it does nothing
  against someone holding one specific public key who just hashes it with the
  salt they can read. Keying it means that question cannot be asked without the
  vault key. Addresses are sealed rather than hashed, because an IPv4 address is
  one of 2^32 and a hash of it with a readable salt is recovered in seconds, so
  hashing would have looked like protection and provided almost none. Bodies are
  padded to 256 byte blocks and the salt is fresh on every write, so two copies
  of one store do not correlate row by row.
- **Timestamps coarsen to the day on the way to disk.** Day resolution answers
  both questions the file exists to answer, "recently?" and "how long have I
  known this key". Millisecond resolution also answered "when is this person at
  their desk", which nobody asked it. In-memory values keep full resolution.
- **`ratchet id --reset` now discards the peer list too**, and says so before
  asking for `--yes`. Those rows were collected under the identity being
  destroyed and they are the only thing in `RATCHET_HOME` that names anybody.
  Keeping them meant "start over" quietly kept a dated list of who this machine
  had talked to.
- `ratchet id` gained one line reporting the protection state, and prints the fix
  underneath when it is `unprotected`.

### What this does not protect against

The keychain key is reachable by anything running as you, including a malicious
`postinstall` in an unrelated package. That is what `ratchet lock` is for, and
only while the process is not running. The keychain path defends against a copied
folder, a backup, a synced directory, another user on the box, and a disk pulled
from a machine whose account password is unknown.

An attacker holding both files and no key still learns that ratchet is installed,
the exact number of peers, which protection mode is in force, and the file
mtimes, which give last-write times at second resolution and so partially undo
the day coarsening. Coarsening mtimes was considered and rejected: `rsync` and
most backup tools compare size and mtime, so two same-day saves with the same
peer count would be silently skipped, and losing a backup is a worse outcome than
leaking a timestamp that filesystem forensics would surrender anyway. They learn
no public key, no words, no label, no address, no date, and not which peers are
verified.

macOS and Linux keychain support is written to the documented `security` and
`secret-tool` interfaces and has not been run on either platform. The
enroll-and-verify round trip means the failure mode is falling back to plain
files with a message, which is 0.4.0's behaviour, not a lockout.

### Fixed

- `cli/vault.mjs` was written by a build step while `npm publish` was reading the
  working tree, so 0.4.0's tarball carries a file that is in no commit and that
  nothing imports. It is inert. It is tracked from this release on.

## [0.4.0] - 2026-08-08

**Breaking. The wire format changed and 0.3.x peers cannot read it.** A 0.3.x
peer fails with `unknown_version` rather than a confusing decode error, and
serialized sessions from 0.3.x fail the same way. Both ends and any persisted
state have to move together.

### Changed

- **Message overhead is 34 bytes, down from 122.** A 20 byte message is 54
  bytes on the wire instead of 142, and a 256 byte message is 290 instead of
  378. The header packs version, kind and a ratchet-key flag into one byte,
  carries a 4 byte session tag instead of a 32 character hex conversation id,
  uses canonical varints for the counters, and drops the length prefix on the
  ciphertext, which now runs to the end of the frame.

  The fields that left the wire did not leave the AEAD. The full 16 byte
  conversation id and the full 32 byte ratchet public key are still bound as
  associated data, rebuilt on the receiving side from session state. Binding
  data that is not transmitted is what associated data is for.

- **The ratchet public key travels on the first three messages of a chain, not
  on all of them.** Sending it once would be enough on a lossless transport and
  is what a 22 byte header assumes. It is not enough on a lossy one: a receiver
  cannot step its DH ratchet until it sees the new key, so losing the single
  message that carried it poisons the rest of that chain. Three costs 33 extra
  bytes on two messages per chain instead of on every message, which keeps
  roughly 90 percent of the saving with a bounded failure.

- **The chain step is one HMAC-SHA512 instead of two HMAC-SHA256.** One call
  produces 64 bytes, split into the next chain key and the message key. That is
  what HKDF-Expand does internally, so it is not a weaker construction, and it
  measured 1.5 microseconds cheaper per message.

- **The header is the associated data.** 0.3.x serialized the same fields twice
  per seal, once into an AAD buffer and once into the envelope. The header is
  now written once into the output buffer and that same slice is handed to the
  AEAD. Worth 3.2 microseconds, the largest single saving in this release.

- **XChaCha20-Poly1305 with a 24 byte nonce became ChaCha20-Poly1305 with a 12
  byte one.** The 24 byte form pays an HChaCha20 subkey derivation in
  TypeScript on every message, because `node:crypto` exposes only the 12 byte
  form. The nonce is still random per seal, from the CSPRNG.

  A draft of this release derived the nonce from the message number instead,
  which would have made the header 22 bytes and saved a further 3.4
  microseconds. It was reverted before shipping. Both schemes are safe under
  correct operation. They differ under state rollback, which `serialize.ts`
  makes a real operation rather than a theoretical one: a derived nonce
  reproduces exactly under a replayed message key, so the two ciphertexts share
  a keystream and an observer holding both recovers the XOR of the plaintexts.
  A random nonce turns the same accident into a forgery risk instead of a
  plaintext disclosure. A restored snapshot is still a dead session either way
  and still requires a re-handshake.

- Skipped message keys are now parked under a chain epoch and a message number
  rather than a base64 encoding of the 32 byte ratchet public key. 0.3.x built
  a 43 character string on every open in order to query a map that is empty in
  the ordinary case. The empty case now allocates nothing.

- `ENVELOPE_VERSION` is `OCX2`, the binary envelope version byte is `0x02`, and
  the serialized session version is 2.

### Removed

- The author email is no longer published in package metadata. It was in every
  release from 0.1.0 through 0.3.4 and those remain on the registry; this stops
  it going out again.

### Performance

Published 0.3.4 from the registry against this tree, both arms interleaved in
one process so scheduler and JIT drift lands on both. AMD Ryzen 5 7530U,
Node v25.8.0, Windows 11, 256 byte payload, AEAD, curve and hash backends all
reporting `native`, medians of many rounds.

| | 0.3.4 | 0.4.0 | |
| --- | --- | --- | --- |
| seal | 24.86 us | 16.36 us | 1.52x less CPU work |
| overhead per message | 122 B | 34 B | |

Against the Signal Double Ratchet message construction measured on the same
machine in the same runtime, 0.4.0 is 1.88x less CPU work at p50. That is
construction against construction, not product against product: libsignal is
Rust and would be faster at the same construction, the figure is CPU only, and
it says nothing about any deployed messenger, where network round trips are
three to four orders of magnitude larger than any of this.

## [0.3.4] - 2026-08-08

### Added

- `hashBackend()` and `hashReady()` are now exported from the package.

  The 0.3.3 notes said they were. They were not. Both functions existed in
  `src/hash.ts` and neither was re-exported from the index, so `import
  { hashBackend } from 'ratchet-ts'` was `undefined` in the published 0.3.3
  tarball. Caught by installing 0.3.3 from the registry and asking it which
  backends were live: it answered for the AEAD and the curves and had nothing
  to say about the hashes.

  Worth having rather than just worth correcting. The chain step is two
  HMAC-SHA256 per message in each direction, which is the most frequently
  executed primitive in the library, and on the JavaScript path it measured at
  roughly a third of the cost of sealing a chat sized message. A machine that
  reports `noble` here while `node:crypto` is available has had the native
  probe reject it, and is paying that on every message with nothing on screen
  to say so.

Nothing else changed. Same wire format, same behaviour, same 179 tests.

## [0.3.3] - 2026-08-08

Same wire format, byte for byte, and the same public API plus three additive
exports. Everything below is speed, honesty about past numbers, and a trust
store the tool should have had from the start.

### Fixed

- **The benchmark was measuring a dead path, and had been for two releases.**
  `bench/wire.mjs` kept its own copy of the frame sequence instead of calling
  `cli/protocol.mjs`. In 0.3.1 the CLI moved from `sealBytes` / `openBytes` to
  `sealToEnvelopeBytes` / `openFromEnvelopeBytes`, which skips a base64url
  round trip on every chunk. The benchmark did not move with it, so for two
  releases it reported the cost of base64url encoding 65535 byte ciphertexts,
  a path nothing has shipped since 0.3.1. It printed 4.37 MB/s where the real
  code did 47.74. The published throughput figures from 0.3.1 and 0.3.2 are
  wrong by roughly 11x, in the library's favour, and `bench/README.md` now
  opens by saying so and marks the stale table as not quotable. The harness no
  longer has a payload path of its own: it imports `sendPayload` and
  `receivePayload` from the real module and takes `PROTOCOL_VERSION` and
  `DEFAULT_CHUNK_BYTES` from it rather than restating them. One section still
  drives the engine directly, because the CLI reports a single cumulative
  `cryptoMs` with no handshake only figure, and that section is now guarded: it
  prints the real `handshakeMs` from both sides beside its own and says `DRIFT`
  if they diverge by more than 2x.
- The sender stalled on every single chunk. A socket's default
  `writableHighWaterMark` is 16 kB and a frame is 64 kB, so `write()` returned
  false every time and the send awaited `'drain'` before returning. Measured:
  160 of 163 writes blocked, and the comment claiming the receiver was opening
  chunk i while the sender sealed chunk i + 1 was simply false, since the loop
  could not reach the next seal until the kernel had taken the whole frame. The
  write window is now 1 MiB, set at construction on both the dialing socket and
  the server, and the wait moved one frame later so the next chunk is sealed
  while the previous one is still with the socket. It is still a bound and not
  a queue: past 1 MiB of unflushed bytes the sender still stops dead, so a slow
  receiver cannot make a fast sender allocate without limit.
- The receiver was charged for work the sender did off the clock. It hashed the
  whole assembled payload in one pass inside `wallMs`, while the sender
  computed its digest before the window opened, because the header carries it.
  The receiver now hashes each chunk as it lands. Same window, same work
  counted, no serial tail. The digest is still fed from the assembled buffer
  and never from the chunk plaintext, because a digest of the chunks would
  agree with itself wherever they landed and the whole point of that hash is to
  catch an assembly bug the per chunk AEAD tags cannot see.

### Added

- **A peer trust store.** Until now a fingerprint change was undetectable:
  `cli/store.mjs` held your own identity and nothing remembered a peer. The six
  safety words could catch a machine in the middle, but only if two humans
  compared them out loud, every session, which nobody does. `~/.ratchet/peers.json`
  now records each peer by identity hex, mode 0600, written with the same
  stage and rename as the identity file. `send`, `recv` and `chat` classify the
  peer at handshake as new, known, verified or changed, and print it before the
  first byte moves.
- The changed verdict is the only alarm, and it fires on one condition: this
  address previously carried a different **verified** key. A previously
  unverified association never raises it, because it never carried a claim, and
  a verified key arriving from a new address is a dim one line note rather than
  an alarm, because the key is what was verified and the key did not change.
  The alarm says out loud that anything already sent this session went to the
  new key, refuses to be dismissed by a keystroke, and offers exactly two typed
  commands.
- `ratchet peers`, `ratchet peers verify WHO [--label NAME]` and
  `ratchet peers forget WHO`, all with `--json`. Verify asks a real question and
  accepts only the literal word `yes`. In chat, `/verify NAME` asks the same
  question through a seam that `bin/` owns, so the chat loop still knows nothing
  about disk.
- `hashBackend()`, `hashReady()`, `curveBackend()` and `curvesReady()` are
  exported alongside the existing `aeadBackend()` and `base64Backend()`. A
  handshake that takes 27 ms instead of 5 ms is a backend question, not a
  mystery, and there was no way to ask it. The raw curve and hash primitives are
  deliberately not exported: nobody needs a bare x25519 from this package, and
  every public primitive is one more thing that can be misused.
- `sealToEnvelopeBytes` takes an optional `{ reserve }` that leaves N zero bytes
  in front of the envelope inside the same allocation, so a transport can stamp
  its own length prefix in place instead of copying the whole frame to prepend
  four bytes. The CLI asks the channel how many it wants rather than assuming,
  so a transport that needs no prefix reports 0 and nothing changes.

### Changed

- **Native backends for the curves and the hashes**, resolved by the same probe
  and silent fallback shape `src/aead.ts` already used. The probe refuses the
  native path unless it reproduces the reference implementation exactly,
  including rejecting every low order point, and a backend that fails any of it
  is discarded with nobody the wiser. Errors are the load bearing detail here:
  OpenSSL and noble throw different error objects for the same bad input, which
  a caller matching on a message could use to tell which backend answered, so
  the native path never reports a failure. It returns null and the wrapper
  re runs through noble, which throws the error it has always thrown, byte for
  byte, at the cost of one wasted call on an input that was going to throw
  anyway.
- Fewer full size copies. The envelope encoder allocates once instead of three
  times, the decoder hands the AEAD a view of the ciphertext instead of a copy,
  and the native AEAD open returns its own buffer when the final block is empty,
  which for ChaCha20-Poly1305 it always is. Profiling had byte copies at 1.5x
  the cost of the encryption itself.
- `pairWords` and the failure explanation table lived in two files each. The two
  copies of `pairWords` had not drifted, checked byte for byte before touching
  them, but two independent copies of a security critical derivation is a bug
  waiting for whoever edits one of them: a user comparing a chat against a
  transfer and seeing two different word sets would conclude, wrongly, that
  something was wrong. Both are now single exports. The explanation table gained
  a second column so a chat says something a chat can act on, rather than the
  raw reason code it printed before.

### Numbers

Same machine, published 0.3.2 against this release, arms interleaved, real
`ratchet send` and `ratchet recv` processes, wire bytes and payload SHA-256
identical across every run.

| | 0.3.2 | 0.3.3 |
| --- | --- | --- |
| sender | 56.48 MB/s | 79.98 MB/s |
| receiver | 50.31 MB/s | 69.22 MB/s |
| handshake key exchange | 27.2 ms | 4.6 ms |
| wire overhead | 0.2% | 0.2% |

The throughput gain is roughly 1.4x. It is not the 11x implied by comparing
against the old published figure, and that comparison should not be made: most
of that gap was the benchmark measuring something nothing shipped.

### A note on what is now on your disk

Before this release, running `ratchet` left one identity key and no history. It
now leaves a durable timestamped list of who this machine talked to and from
what address, which is a social graph that was previously nowhere on disk. It
holds no message content: no text, no filename, no size, no count, no payload
hash. `ratchet peers forget` takes a row back. The chat closing line changed
from "Nothing was written to disk" to "No message was written to disk", because
the old sentence stopped being true.

Suite is 179 tests.

## [0.3.2] - 2026-08-07

### Fixed

- `recv --once` no longer switches itself off when something connects without
  sending anything. The help says one transfer and the code meant one
  connection, so a port scan, a monitoring probe, or a peer whose link dropped
  during the handshake would silently end a listener that the person on the
  other machine still believed was waiting. Found by opening a bare socket to
  a live receiver on a second box and closing it again, which killed it. A
  transport failure now prints the reason and keeps listening. A crypto
  failure still exits with code 2, unchanged, because bytes that do not verify
  are somebody producing bytes, and looping there would hand them unlimited
  attempts against a listener meant to take one file.
- Three tests cover it, and they are the first in the suite to run the real
  binary as a child process. The bug was in the accept loop in
  `bin/ratchet.mjs`, which no unit test reaches, so a fake socket would have
  proven nothing. The suite is 115 tests.

### Changed

- The README lost 224 lines of benchmark prose without losing a number. Four
  releases of measurements had each been written up in place, so the same
  763.5 kB file was described five times over and a reader had to assemble the
  trend themselves. The per release narration is now one table, `Cost by
  version`, and the detail that only matters once, method notes and
  counterfactuals, moved to the release notes where it belongs. What a
  transfer costs, and what changed between 0.3.0 and 0.3.1, stayed.

No code changed beyond the accept loop. Same wire format, same API, same
numbers.

## [0.3.1] - 2026-08-07

Nothing on the wire moved. This release deletes base64 that was never on the
wire in the first place: 0.3.0 encoded every frame into an `OCX1.` token and
decoded it straight back out again, twice per transfer, purely because the
engine's byte oriented surface spoke tokens at both ends. The bytes on the
socket are identical to 0.3.0, byte for byte, proven by a deterministic capture
of all 17 frames of a 763.5 kB transfer under a seeded RNG. A 0.3.0 peer and a
0.3.1 peer interoperate in both directions.

### Added

- `engine.sealToEnvelopeBytes(session, plaintext)` and
  `engine.openFromEnvelopeBytes(session, envelope)`: plaintext bytes in,
  envelope bytes out, and back. These are the third and fourth members of a
  family whose names are easy to confuse, so `src/index.ts` now carries a map:
  `sealBytes` is about the plaintext being bytes and still returns a token,
  `encodeEnvelopeBytes` is a pure codec that does no crypto, and the two new
  ones are the full ratchet step with binary at both ends. Nothing was renamed
  and nothing was removed.
  Those two engine methods are the whole of the new public surface. The package
  exports the same 24 names it did in 0.3.0, in ESM and in CommonJS, plus these
  two methods on the existing `engine` object. `src/ratchet.ts` gained a
  matching `ratchetEncryptToEnvelopeBytes` / `ratchetDecryptFromEnvelopeBytes`
  pair one layer down, but those are internal and are deliberately not exported,
  because two more top level names in a family this easy to confuse buys nothing
  a caller cannot get from `engine`.
- A fifth section in `npm run bench:wire`, "representation cost, token versus
  bytes", which measures the six conversions side by side and checks byte
  identity before it reports a single timing.

### Performance

- The CLI no longer builds a token for the frames that carry the file. On a
  763.5 kB transfer over loopback, 12 chunks of 65519 B, native AEAD, Ryzen 5
  7530U, Node v25.8.0, Windows 11. Medians of 21 transfers per version after 4
  warmup runs, the two versions interleaved run by run so neither one gets the
  cold laptop or the boost clock to itself, full observed range in brackets:

  | side | 0.3.0 | 0.3.1 | ratio |
  | --- | --- | --- | --- |
  | sender wall | 56.45 ms [53.2 to 88.5] | 18.65 ms [16.7 to 20.8] | 3.03x |
  | sender throughput | 13.53 MB/s | 40.94 MB/s | 3.03x |
  | receiver wall | 60.84 ms [56.6 to 93.1] | 22.52 ms [21.4 to 24.4] | 2.70x |
  | receiver throughput | 12.55 MB/s | 33.90 MB/s | 2.70x |

  Wall time fell 3.0x on the sender and 2.7x on the receiver. `wireBytes` was
  765286 on all 42 runs and every SHA-256 matched. Both ends have to be 0.3.1:
  with one end still on 0.3.0 the same harness reads about 45 to 50 ms of
  sender wall, because on loopback each side spends part of its wall time
  waiting for the other one's CPU.
- The isolated cost, measured by section 5 of the wire bench on the same 12
  chunks: encoding to a token 9.42 ms against 0.52 ms to bytes (18.0x),
  decoding a token 16.29 ms against 0.35 ms from bytes (46.3x). One round trip
  is 26.44 ms of token against 1.04 ms of bytes. That is per endpoint, and a
  transfer has two, so 52.87 ms across the pair. Four captures of that bench put
  the token round trip at 24.4, 25.7, 26.4 and 27.7 ms, so treat it as a 24 to
  28 ms band per side and not a constant. The end to end saving is larger than the
  band, 37.8 ms of sender wall and 38.3 ms of receiver wall, because on loopback
  deleting CPU on one side also shortens the other side's wait.

### Changed

- `cryptoMs` in `--stats` and `--json` now counts every conversion the payload
  path performs, not some of them. In 0.3.0 the number was quietly wrong in two
  directions at once: the base64 inside `sealBytes` and `openBytes` was counted,
  the base64 in the CLI's own `toWire` and `fromWire` was excluded by a doc
  comment that called the exclusion deliberate. It counted one pass and hid the
  other. Nothing on the payload path is hidden now, and the doc comment in
  `cli/protocol.mjs` says so. The measured effect is that `cryptoMs` falls from
  47.33 ms to 31.47 ms on the sender and 47.96 ms to 28.32 ms on the receiver,
  medians of the same 21 runs, because deleting two base64 passes outweighs
  starting to count what remains. `cryptoMs` still includes the handshake opens,
  which is why it can exceed `wallMs`: `wallMs` starts at the first payload
  frame.
- The three small payload frames, the ready signal, the sealed header and the
  final acknowledgement, still build a token, and so do the invite and the
  accept. A token has to exist there: `engine.open` runs the handshake state
  machine and takes a token, and the invite is a thing a human pastes. The three
  payload ones are converted inside `cryptoMs`. The invite and the accept are
  converted outside it, on purpose, because both fall inside the window
  `handshakeMs` already reports end to end; that pair of conversions measures
  about 0.03 ms, so nothing meaningful is sitting outside either clock.
- A corrupt chunk now reports as `opening chunk 3 of 12` where 0.3.0 said
  `decoding chunk 3 of 12`. Same failure, same exit code, one word of the
  message moved, because the decode step it was named after no longer exists.

### Fixed

- Decoding no longer aliases a `Buffer` the caller passed in. The codec has
  always intended to copy each field out of the input, and the comment saying so
  has been there since the binary envelope landed, but the implementation called
  `.slice()` on the input. That copies for a plain `Uint8Array` and does not
  copy for a `Buffer`, which overrides `slice` as a deprecated alias of
  `subarray` and shares memory. A `Buffer` is exactly what a socket hands the
  CLI on every frame, so the shape the guarantee mattered most for was the one
  shape that never got it. A caller that pooled or reused its read buffer would
  have watched decoded fields, including a ciphertext already sitting in session
  state, change underneath it. The existing regression test only passed a
  `Uint8Array`, which is why it stayed green. Both shapes are tested now.
- Decoded fields are always a plain `Uint8Array`. They used to inherit the
  prototype of whatever was passed in, so feeding a `Buffer` produced `Buffer`
  typed fields, which contradicted the declared return type.
- `decodeEnvelopeBytes` rejects a non `Uint8Array` argument as
  `malformed_token` instead of escaping a raw `TypeError`. The types say
  `Uint8Array`, but a JavaScript caller, a JSON round trip, or a `null` off a
  closed socket can all reach it, and the library's stated invariant is that
  malformed input maps to a reason and never escapes as a raw exception. This
  was reachable in 0.3.0 too.

## [0.3.0] - 2026-08-07

### Breaking changes

- **The CLI wire format changed and there is no version negotiation.** A 0.2.1
  `ratchet send` cannot talk to a 0.3.0 `ratchet recv`, and a 0.3.0 sender
  cannot talk to a 0.2.1 receiver. Both machines have to upgrade, or neither.
  Two things moved at once: frames on the socket are now
  `[u32 big endian length][payload]` instead of newline delimited text, and the
  payload is the binary envelope instead of the `OCX1.` base64url token.
  Mismatched versions fail at the handshake, they do not corrupt anything.
- Nothing in the library API broke. `engine.seal`, `engine.open`,
  `encodeEnvelope`, `decodeEnvelope`, the serialisation helpers and the
  `OCX1.<kind>.<base64url>` token are byte-for-byte what they were in 0.2.1,
  proven by the known-answer vectors in `test/vectors.json` passing untouched.
  Only the CLI transport changed, so a 0.2.1 token still opens under 0.3.0.

### Added

- `encodeEnvelopeBytes(payload)` and `decodeEnvelopeBytes(bytes)`: the same
  three envelopes in self describing binary. One version byte, one kind tag,
  then exactly the bytes the token base64urls. The decoder needs no out-of-band
  hint about which kind is arriving. The version byte is `0x01` so a token,
  which starts with `O` (`0x4f`), is rejected as `unknown_version` rather than
  misparsed. Exported from the package root alongside the token codec.
- `aeadBackend()` reports which XChaCha20-Poly1305 implementation is live,
  `'native'` or `'noble'`, and `aeadReady()` resolves once the choice is made.
  `sealAead` and `openAead` are exported for anyone who wants the primitive.
  When the runtime offers `chacha20-poly1305` through WebCrypto or
  `node:crypto`, the sealing path uses it and falls back to `@noble/ciphers`
  otherwise. Output is byte identical either way, asserted in the tests across
  random keys, nonces, plaintexts and AAD, and both backends are exercised.
  Measured on a Ryzen 5 7530U with Node 25 over nine alternating repeats: 4.8x
  faster seal and 5.7x faster open on 65519 byte chunks at the median, never
  below 3.9x and 4.7x. At 256 bytes it is a wash. No new dependency, and nothing
  to configure.
- `ratchet chat`: the same handshake with a line-oriented terminal on top and
  nothing written to disk. `ratchet chat --port 4477` on one side,
  `ratchet chat --to HOST:4477` on the other. `/quit`, Ctrl-C or Ctrl-D ends
  it and both sides print how many messages moved. Same six safety words, same
  rule about comparing them out loud. A chat only pairs with another chat: both
  ends open with an invite and settle the tiebreak between themselves, so it
  will not talk to `ratchet recv`.
- `--stats` and `--json` gained an `AEAD backend` row so the number is
  attributable to an implementation rather than to the machine.
- `npm run bench:wire`: a second harness that stands up the real framing layer
  over loopback behind a byte counting relay, and reports bytes on the wire at
  five payload sizes, both AEAD backends side by side, and the handshake split
  into crypto and transport. Separate from `npm run bench`, which still
  measures the library in process.
- `AeadBackend` and `EnvelopeBytes` in the public type contract.

### Changed

- The CLI sends binary envelopes over length prefixed frames. On a 763.5 kB
  file the wire went from 1.0 MB to 765.3 kB: overhead 257.0 kB (33.7%) down
  to 1.8 kB (0.2%), and the received bytes hash identical to the sent bytes.
  Those wire figures count the frames that carry the file. The handshake is
  another 2384 bytes out and 1619 bytes back, once per transfer whatever the
  file size. To be plain about what this was: the encryption was always nearly
  free, a 24 byte nonce and a 16 byte tag per chunk, 0.06% of a chunk and 0.23%
  once the whole envelope is counted. The remaining 33.4 points were base64
  paying for a text encoding on a socket where nobody was going to paste
  anything. This release stops paying it on the CLI path and keeps it for the
  token API, where being paste-anywhere text is the entire point.
- The bare `ratchet` command prints a two machine walkthrough that starts with
  `npm i -g ratchet-ts` on both machines, instead of an error. `--help` is
  rewritten to real commands only, and every error message ends with the
  command to type next.
- Address ranking on `ratchet recv` puts LAN addresses first, then CGNAT, then
  virtual adapters, then public, each labelled. Loopback is never printed as
  something to paste at the other machine.
- Transfers over 256 kB show progress. On a TTY it repaints one line, otherwise
  it prints a single quiet line, and `--json` output stays clean either way.
- Sending something that looks like a secret (`.env`, `*.pem`, `*.key`,
  `id_ed25519`, anything with `secret` or `credential` in the name) prints a
  one line warning and then sends. It never prompts and never refuses.
- The test script now picks up `.mjs` test files, so the framing tests run in
  `npm test`. The suite is 89 tests.

### Fixed

- A received file that would overwrite an existing one is written as
  `name (2).ext` and the new name is reported. The write uses `wx` with an
  EEXIST retry, so two receivers racing on one directory cannot both win and
  silently clobber each other.
- Hostile incoming filenames land inside `--out` and nowhere else. Verified by
  a sender that bypasses the CLI entirely: traversal (`../../../..`), absolute
  Windows and POSIX paths, Windows device names (`CON`, `com1.txt`), NTFS
  alternate data stream syntax (`ok.txt:hidden.exe`), embedded CR and ANSI
  escapes, and a right-to-left override. Every one was contained, no alternate
  data stream was created, and rewritten names are reported with the attacker's
  bytes escaped so a filename cannot inject terminal escapes into your shell.
- `ratchet recv --once` no longer hangs after a completed transfer. Sockets are
  closed on a bounded race and stdout is drained before exit.
- Banners fit the terminal. The box sized itself to its content, so a long
  `--out` path drew a box 139 columns wide that wrapped into unreadable
  fragments on a normal 80 column terminal. Lines are now truncated from the
  middle, which keeps the label at the front and the filename at the end,
  ANSI escapes are never cut in half, and the width falls back to 80 when
  stdout is not a terminal.

### Known limits

- Everything under Limits in the README still holds: no audit, post-quantum in
  the handshake only with a classical X25519 ratchet, one token carries at most
  65519 bytes of plaintext, metadata is visible, and sealing from a stale
  session snapshot silently loses a message and rewinds forward secrecy.
- The overhead floor is per chunk, not a percentage. A 20 byte text message
  costs 415 bytes on the wire, 395 of them envelope, and 393 of those 395 if the
  filename is two characters shorter. The protocol part of that floor did not
  change, but the wire cost did: 0.2.1 base64url'd the envelope too, so the same
  message cost 544 bytes of overhead there, re-measured against the published
  0.2.1 tarball.
- Both machines still need a route to each other, in practice the same LAN or a
  tunnel. There is no NAT traversal and no discovery.
- The 0.3.0 numbers above were measured on one machine over loopback. They are
  not comparable to the 0.2.1 figures, which were measured once over a
  Tailscale relay. The byte counts are comparable, the throughput is not.

## [0.2.1] - 2026-08-07

### Added

- A `ratchet` command, shipped with the package. `ratchet recv` listens and
  prints the exact command to run on the other machine; `ratchet send FILE
  --to HOST` streams the file as sealed chunks over a direct TCP connection.
  `--text` sends a message instead, and `-` reads stdin. The filename, size
  and hash travel inside the encryption alongside the payload, so an observer
  sees a byte count and nothing else. There is no relay, no server and no
  account: the two machines talk straight to each other.
- Both ends print six safety words the moment the handshake settles, before
  the transfer finishes, so a person can compare them out of band while the
  bytes are still moving. The words are a fingerprint of the two identities
  hashed in a canonical order, so they are identical on both screens and one
  party can simply read them aloud. They bind the identity pair, not the
  session, which is the same property a Signal safety number has.
- Identities persist under `RATCHET_HOME` (default `~/.ratchet`), written
  0600 in a 0700 directory, so the same two machines keep the same words
  across runs. `ratchet id` shows them, `ratchet id --reset` starts over.
- `--stats` prints the measurement table (handshake, crypto time, wall time,
  wire overhead, throughput, SHA-256 of the plaintext), `--json` emits it for
  scripts with human output moved to stderr.

### Fixed

- Frame reassembly: chunks at the default 65519 byte size straddle TCP `data`
  events, and the reassembler dropped the boundary, corrupting every chunk at
  that size. Verified by moving real files and comparing hashes on both ends.
- `.gitattributes` pins source files to LF. `bin/ratchet.mjs` opens with a
  shebang, and a clone on a machine with `core.autocrlf=true` rewrote it to
  `env node\r`, which fails only on Linux, which is exactly where the CLI is
  most likely to run. Releases are packed from a fresh clone, so this would
  have shipped broken to the platform it was written for.

### Known limits

- The wire format is base64 text, so a transfer costs about 33% more bytes
  than the plaintext. That is the encoding, not the crypto: the per message
  cryptographic overhead is still the constant 259 bytes documented above.
- Both machines need a route to each other, in practice the same LAN or a
  tunnel. There is no NAT traversal and no discovery.

## [0.2.0] - 2026-08-06

### Added

- Binary payload API: `engine.sealBytes` and `engine.openBytes` carry
  `Uint8Array` payloads through the same wire format as the string API. The
  string path is now a thin UTF-8 shim over the byte path, so tokens from
  either API open under both. `openBytes` takes message tokens only; handshake
  tokens stay in `open`, which owns the state machine.
- Session persistence: `serializeSession`, `deserializeSession`,
  `serializePending`, `deserializePending`, `exportIdentity`, and
  `importIdentity`. Each save returns one ASCII string shaped
  `OCX1.<session|pending|identity>.<base64url body>`: 1 version byte, length
  prefixed binary fields, and an 8 byte kind-bound SHA-256 checksum. The
  checksum is corruption detection only, not authentication; encrypt the
  strings at rest, they contain private keys. Wrong prefix or future body
  version fails with `unknown_version`, all other malformed input with
  `malformed_token`, always through `CryptoFailureError`. Restored skipped
  keys are re-validated against the same `MAX_SKIP` bound as the live wire.
- Hybrid pin test suite (`test/hybrid.test.ts`): proves each half of the
  handshake (X25519 and ML-KEM-768) moves the root key on its own, and that
  the live root from a real exchange matches an independent reconstruction
  while diverging from classical-only, PQ-only, and corrupted-ciphertext
  counterfactuals. Closes the "ML-KEM contribution is not pinned by a test"
  gap from the 0.1.0 README.
- Known-answer vectors: `scripts/gen-vectors.mjs` (`npm run gen:vectors`)
  derives the full handshake, root evolution, first message keys, and exact
  wire tokens from fixed seeds and writes `test/vectors.json`;
  `test/vectors.test.ts` re-derives everything from the seeds, byte-compares
  it, and feeds the vector tokens to the real ratchet. Regeneration is
  byte-identical.
- Runtime coverage: `examples/runtime-smoke.mjs` runs the full handshake plus
  a tamper check against the built `dist/index.js` on Node, Bun, and Deno;
  `examples/browser.html` runs the same sequence in a browser via an import
  map. CI gains Bun and Deno jobs alongside the existing Node 20/22/24 matrix.
- `package.json` keywords for discoverability: encryption, cryptography,
  browser, bun, deno, session-persistence.

### Changed

- Test count from 20 to 40. All expected failures still assert a specific
  reason.

### Known limits

- Sealing from a stale session snapshot is not detected and not prevented.
  `deserializeSession` rewinds a conversation, it does not fork one. If the
  original session keeps sealing after a save and the saved copy is later
  restored and sealed from, both branches sit on the same chain key at the same
  message number and derive the same message key. Nothing throws. Nonces are
  random per seal, so this is not a two-time pad and no keystream is shared, but
  it does hand the snapshot holder forward secrecy over everything sealed after
  the save in that chain, and the receiver silently drops whichever colliding
  message arrives second as `replay_detected`. Keep exactly one live copy of a
  session. Documented in the README limits and on the `serializeSession` doc
  comment.
- One token carries at most 65519 bytes of plaintext (u16 envelope length
  prefix). Oversized input surfaces as a `RangeError` from the encoder, not a
  `CryptoFailure`. Chunk above the engine.
- The Bun CI job and Cloudflare Workers are untested at release time: Bun was
  not available on the release machine and the new CI workflow had not yet
  executed. Node and Deno smoke runs passed locally.

## [0.1.0] - 2026-07-23

Initial release.

- Hybrid PQXDH-style handshake: 2x X25519 Diffie-Hellman plus ML-KEM-768
  encapsulation, mixed into an HKDF-SHA256 root key.
- Double Ratchet: X25519 DH ratchet with HMAC-SHA256 symmetric chains.
- XChaCha20-Poly1305 AEAD with the message header bound as additional
  authenticated data.
- Out-of-order and skipped-message handling with a MAX_SKIP bound of 1000.
- Replay rejection and fail-closed tamper handling.
- `OCX1` wire format with `invite`, `accept`, and `message` tokens.
- BIP-39 six-word identity fingerprints.
- 20 tests covering secrecy, hardening, envelope round-trips, and sessions.
