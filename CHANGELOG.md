# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
