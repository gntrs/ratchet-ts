# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
