/**
 * File transfer over one ratchet session.
 *
 * ---------------------------------------------------------------------------
 * WIRE PROTOCOL
 * ---------------------------------------------------------------------------
 *
 * Every frame is one ratchet-ts token, newline delimited by cli/frame.mjs.
 * Nothing but tokens crosses the socket, so a passive observer learns the byte
 * count and nothing else: not the filename, not the size, not the hash.
 *
 *   1. RECEIVER -> SENDER   invite token
 *
 *      The receiver invites. It is the long lived listener, so it is the party
 *      with a stable address, and inviting first means the sender needs no
 *      prior knowledge beyond host and port.
 *
 *   2. SENDER -> RECEIVER   accept token
 *
 *      `engine.open(identity, invite, {})` yields outcome `invite` with a reply
 *      and a session. The reply goes straight back.
 *
 *   3. RECEIVER              `engine.open(identity, reply, { pending })` yields
 *                            outcome `accepted`. Root key agreed on both sides.
 *
 *   3b. RECEIVER -> SENDER  sealed `{ v, ready: true }`
 *
 *      Required by the ratchet, not by this protocol. The party that accepts an
 *      invite is the Double Ratchet responder and has no send chain until the
 *      initiator's first message reveals an initiator ratchet public key. So
 *      the receiver has to speak once before the sender can speak at all. One
 *      sealed frame is the cheapest way to unlock it, and it keeps the payload
 *      direction as specified. handshakeMs covers steps 1 through 3b, because
 *      until 3b lands the sender cannot transmit.
 *
 *   4. SENDER -> RECEIVER   sealed header, JSON
 *                           { v, name, size, sha256, chunks, chunkSize }
 *
 *      Metadata is sealed like everything else. Putting it in a clear preamble
 *      would leak the filename and exact size to anyone watching the wire, and
 *      those two facts are usually the interesting ones.
 *
 *   5. SENDER -> RECEIVER   exactly `chunks` sealed byte frames, in order,
 *                           each at most `chunkSize` plaintext bytes.
 *
 *   6. RECEIVER             opens header, opens each chunk, appends, then
 *                           recomputes sha256 over the assembled bytes and
 *                           compares against the header. Mismatch throws.
 *
 *      Belt and braces over the AEAD. Each chunk authenticates only itself, so
 *      Poly1305 cannot see an assembly bug: a chunk written at the wrong offset
 *      or a dropped tail passes every tag check and still produces the wrong
 *      file. The whole-payload hash is what catches that.
 *
 *   7. RECEIVER -> SENDER   sealed `{ ok: true, sha256 }`
 *
 *      So the sender learns the transfer VERIFIED, rather than merely that the
 *      bytes left the socket.
 *
 * Sessions are immutable. Every seal and open returns a new one and the old one
 * is dead the instant it is used. Each call site here reassigns in place for
 * that reason, and there is deliberately never a second live copy in scope.
 */

import { createHash } from 'node:crypto';

import { engine, fingerprint, formatFingerprint, isCryptoFailure, publicOf } from '../dist/index.js';

/** Bumped only on a breaking frame change, so a mismatch is a clean refusal. */
const PROTOCOL_VERSION = 1;

/**
 * Hard ceiling imposed by the envelope, not chosen here.
 *
 * Every variable length field in an OCX1 envelope carries a u16 length prefix,
 * so a ciphertext cannot exceed 65535 bytes, and XChaCha20-Poly1305 adds a 16
 * byte tag. 65519 plaintext bytes is therefore the largest message the library
 * can encode at all: one byte more and `encodeEnvelope` throws a RangeError
 * before any crypto runs. Raising this needs a u32 prefix in src/envelope.ts,
 * which is a wire format change, so it is not a knob this file can turn.
 */
const WIRE_MAX_PLAINTEXT = 0xffff - 16;

const DEFAULT_CHUNK = Math.min(64 * 1024, WIRE_MAX_PLAINTEXT);
const MIN_CHUNK = 1024;
const MAX_CHUNK = Math.min(4 * 1024 * 1024, WIRE_MAX_PLAINTEXT);

/** Exported so the CLI can show the real figure rather than the one asked for. */
export const MAX_CHUNK_BYTES = MAX_CHUNK;
export const DEFAULT_CHUNK_BYTES = DEFAULT_CHUNK;

/**
 * Clamp rather than throw. A caller passing 10 GiB means "as big as you can",
 * and refusing the transfer over a tuning knob helps nobody.
 */
function clampChunkSize(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return DEFAULT_CHUNK;
  const n = Math.floor(value);
  if (n < MIN_CHUNK) return MIN_CHUNK;
  if (n > MAX_CHUNK) return MAX_CHUNK;
  return n;
}

function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function compareBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

/**
 * Six words that are IDENTICAL on both ends, for reading aloud over the phone.
 *
 * `peerWords` alone cannot do this job. A fingerprint of the peer identity is
 * different on each side by construction: I see your words, you see mine. To
 * compare them out loud one party has to recite what it sees and the other has
 * to look up its OWN fingerprint, which is two strings and a rule nobody
 * remembers under pressure. Hashing both identities in a canonical order gives
 * one string, computed the same way on both machines, that either party can
 * simply read out. Sorting by the X25519 public key is what makes it order
 * independent, since neither side agrees on who is "first".
 *
 * Same digest construction as the library, same wordlist, so it is exactly as
 * strong as an ordinary fingerprint: 66 bits, enough against an automated key
 * swap, not enough against someone grinding keypairs at a named target.
 */
function pairWords(self, peer) {
  const mine = publicOf(self);
  const [first, second] = compareBytes(mine.classicalPublic, peer.classicalPublic) <= 0
    ? [mine, peer]
    : [peer, mine];
  return formatFingerprint(
    fingerprint({
      classicalPublic: Buffer.concat([first.classicalPublic, second.classicalPublic]),
      pqPublic: Buffer.concat([first.pqPublic, second.pqPublic]),
    }),
  );
}

/**
 * A raw reason string is useless to someone staring at a terminal. Translate
 * into what it means for a file transfer, which is a different sentence for
 * each reason: a replay is suspicious, a missing session is a protocol bug, a
 * failed tag is either corruption or an attacker.
 */
const REASONS = {
  malformed_token: 'the peer sent something that is not a ratchet-ts token, so the other end is not speaking this protocol',
  unknown_version: 'the peer is running an incompatible ratchet-ts version, so upgrade one side',
  no_session: 'no live session for that frame, so the two sides fell out of step in the handshake',
  authentication_failed: 'the data was tampered with in transit, or the peer is not who it claims to be. Nothing was written',
  replay_detected: 'the same frame arrived twice, which is either a broken relay or a deliberate replay',
  skip_limit_exceeded: 'too many frames went missing for the ratchet to catch up, so the transfer cannot continue',
  identity_mismatch: 'the reply answers an invite from a different identity, so something re-addressed the handshake',
};

function wrapCrypto(err, during) {
  if (!isCryptoFailure(err)) return err;
  const explained = REASONS[err.reason] ?? err.message;
  const wrapped = new Error(`${during}: ${explained} (${err.reason})`);
  wrapped.cause = err;
  wrapped.reason = err.reason;
  return wrapped;
}

/**
 * Run one crypto call, charging its duration to `clock` and nothing else.
 * cryptoMs minus socket time is the whole point of the split: the gap between
 * cryptoMs and wallMs is the honest answer to network bound or crypto bound.
 */
async function timed(clock, during, fn) {
  const start = performance.now();
  try {
    return await fn();
  } catch (err) {
    throw wrapCrypto(err, during);
  } finally {
    clock.ms += performance.now() - start;
  }
}

/** A closed channel mid-transfer is a distinct failure from a crypto one. */
async function expectFrame(channel, what) {
  const line = await channel.next();
  if (line === null || line === undefined) {
    throw new Error(`connection closed while waiting for ${what}`);
  }
  return line;
}

/** Frame bodies are ASCII base64url plus dots, so length is byte length. */
function frameBytes(token) {
  return Buffer.byteLength(token, 'utf8');
}

/**
 * Fired the instant the handshake settles, carrying the two word strings.
 *
 * Stats only lands when the transfer is over, and by then there is nothing
 * left to abort. A user has to be able to read the safety words aloud WHILE
 * the bytes are moving, so the words need a way out of this module early.
 * Optional and additive: the pinned signatures and the Stats shape are
 * untouched, a caller that does not pass it sees no difference.
 */
function announce(onHandshake, peerWords, sessionWords, handshakeMs) {
  if (typeof onHandshake !== 'function') return;
  try {
    void onHandshake({ peerWords, sessionWords, handshakeMs });
  } catch {
    /* a broken banner must never fail a transfer */
  }
}

/**
 * Progress is cosmetic. Awaiting it would let a slow renderer throttle the
 * transfer, so a returned promise is dropped and a thrown callback is ignored.
 */
function report(onProgress, done, total) {
  if (typeof onProgress !== 'function') return;
  try {
    void onProgress({ done, total });
  } catch {
    /* a broken progress bar must never fail a transfer */
  }
}

/** MB here is 1e6 bytes, not 1048576. Stated so nobody argues about it later. */
function throughput(plainBytes, wallMs) {
  if (wallMs <= 0) return 0;
  return plainBytes / 1e6 / (wallMs / 1000);
}

function parseJson(text, what) {
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${what} was not valid JSON, so the peer is not speaking this protocol`);
  }
}

function expectedChunks(size, chunkSize) {
  return size === 0 ? 0 : Math.ceil(size / chunkSize);
}

/**
 * Sender side. Invited by the peer, so this reads first.
 *
 * `bytes` is borrowed, never modified. Subarrays are views into it, which is
 * why a 4 MiB payload does not become 8 MiB of resident memory.
 */
export async function sendPayload({ channel, identity, name, bytes, chunkSize, onProgress, onHandshake }) {
  const payload = bytes ?? new Uint8Array(0);
  const size = payload.length;
  const chunk = clampChunkSize(chunkSize);
  const chunks = expectedChunks(size, chunk);
  const clock = { ms: 0 };

  const handshakeStart = performance.now();

  const invite = await expectFrame(channel, 'the peer invite');
  let opened = await timed(clock, 'opening the peer invite', () => engine.open(identity, invite, {}));
  if (opened.outcome !== 'invite') {
    throw new Error(`expected an invite from the receiver, got ${opened.outcome}`);
  }
  let session = opened.session;
  await channel.send(opened.reply);

  // The receiver speaks once here so this side gets a send chain. See step 3b.
  const ready = await expectFrame(channel, 'the receiver ready frame');
  const readyOpen = await timed(clock, 'opening the receiver ready frame', () =>
    engine.open(identity, ready, { session }),
  );
  if (readyOpen.outcome !== 'message') {
    throw new Error(`expected a ready frame from the receiver, got ${readyOpen.outcome}`);
  }
  session = readyOpen.session;
  const readyBody = parseJson(readyOpen.plaintext, 'the receiver ready frame');
  if (readyBody.v !== PROTOCOL_VERSION) {
    throw new Error(`receiver speaks protocol v${readyBody.v}, this is v${PROTOCOL_VERSION}`);
  }

  const handshakeMs = performance.now() - handshakeStart;
  const peerWords = formatFingerprint(fingerprint(session.peer));
  const sessionWords = pairWords(identity, session.peer);
  announce(onHandshake, peerWords, sessionWords, handshakeMs);

  const sha256 = sha256Hex(payload);
  const header = JSON.stringify({
    v: PROTOCOL_VERSION,
    name: name ?? 'payload.bin',
    size,
    sha256,
    chunks,
    chunkSize: chunk,
  });

  let wireBytes = 0;
  const wallStart = performance.now();

  const sealedHeader = await timed(clock, 'sealing the header', () => engine.seal(session, header));
  session = sealedHeader.session;
  wireBytes += frameBytes(sealedHeader.token);
  await channel.send(sealedHeader.token);

  report(onProgress, 0, size);
  let done = 0;
  for (let i = 0; i < chunks; i += 1) {
    const start = i * chunk;
    const slice = payload.subarray(start, Math.min(start + chunk, size));
    const sealed = await timed(clock, `sealing chunk ${i + 1} of ${chunks}`, () =>
      engine.sealBytes(session, slice),
    );
    session = sealed.session;
    wireBytes += frameBytes(sealed.token);
    await channel.send(sealed.token);
    done += slice.length;
    report(onProgress, done, size);
  }

  const ackFrame = await expectFrame(channel, 'the receiver acknowledgement');
  const ack = await timed(clock, 'opening the acknowledgement', () =>
    engine.open(identity, ackFrame, { session }),
  );
  if (ack.outcome !== 'message') {
    throw new Error(`expected an acknowledgement, got ${ack.outcome}`);
  }
  session = ack.session;
  const wallMs = performance.now() - wallStart;

  const ackBody = parseJson(ack.plaintext, 'the acknowledgement');
  if (ackBody.ok !== true) {
    throw new Error(`the receiver rejected the transfer: ${ackBody.error ?? 'no reason given'}`);
  }
  if (ackBody.sha256 !== sha256) {
    throw new Error(
      `the receiver assembled a different payload: sent ${sha256}, it verified ${ackBody.sha256}`,
    );
  }

  return {
    handshakeMs,
    cryptoMs: clock.ms,
    wallMs,
    plainBytes: size,
    wireBytes,
    chunks,
    chunkSize: chunk,
    sha256,
    throughputMBs: throughput(size, wallMs),
    peerWords,
    sessionWords,
  };
}

/**
 * Receiver side. Invites first, so this writes first.
 *
 * Returns the assembled bytes rather than writing them, because where the file
 * lands is a CLI decision and this module should not own the filesystem.
 */
export async function receivePayload({ channel, identity, onProgress, onHandshake }) {
  const clock = { ms: 0 };
  const handshakeStart = performance.now();

  const invited = await timed(clock, 'creating the invite', () => engine.invite(identity));
  await channel.send(invited.token);

  const replyFrame = await expectFrame(channel, 'the sender reply');
  const accepted = await timed(clock, 'opening the sender reply', () =>
    engine.open(identity, replyFrame, { pending: invited.pending }),
  );
  if (accepted.outcome !== 'accepted') {
    throw new Error(`expected an accept from the sender, got ${accepted.outcome}`);
  }
  let session = accepted.session;

  const ready = await timed(clock, 'sealing the ready frame', () =>
    engine.seal(session, JSON.stringify({ v: PROTOCOL_VERSION, ready: true })),
  );
  session = ready.session;
  await channel.send(ready.token);

  const handshakeMs = performance.now() - handshakeStart;
  const peerWords = formatFingerprint(fingerprint(session.peer));
  const sessionWords = pairWords(identity, session.peer);
  announce(onHandshake, peerWords, sessionWords, handshakeMs);

  // Starts before the await, so it includes the sender's turnaround. That is
  // the same span the sender measures, give or take one network hop.
  let wireBytes = 0;
  const wallStart = performance.now();

  const headerFrame = await expectFrame(channel, 'the payload header');
  wireBytes += frameBytes(headerFrame);
  const headerOpen = await timed(clock, 'opening the header', () =>
    engine.open(identity, headerFrame, { session }),
  );
  if (headerOpen.outcome !== 'message') {
    throw new Error(`expected a payload header, got ${headerOpen.outcome}`);
  }
  session = headerOpen.session;
  const header = parseJson(headerOpen.plaintext, 'the payload header');

  if (header.v !== PROTOCOL_VERSION) {
    throw new Error(`sender speaks protocol v${header.v}, this is v${PROTOCOL_VERSION}`);
  }
  if (!Number.isSafeInteger(header.size) || header.size < 0) {
    throw new Error(`the header declares a nonsensical size: ${String(header.size)}`);
  }
  const chunkSize = clampChunkSize(header.chunkSize);
  // Recomputed rather than trusted. An inflated chunk count from a hostile peer
  // would otherwise be a licence to make us loop and allocate for as long as it
  // likes, which is the cheapest denial of service in the protocol.
  const chunks = expectedChunks(header.size, chunkSize);
  if (header.chunks !== chunks) {
    throw new Error(
      `the header is inconsistent: ${String(header.chunks)} chunks declared, ${chunks} implied by size and chunk size`,
    );
  }

  const assembled = new Uint8Array(header.size);
  report(onProgress, 0, header.size);
  let done = 0;
  for (let i = 0; i < chunks; i += 1) {
    const frame = await expectFrame(channel, `chunk ${i + 1} of ${chunks}`);
    wireBytes += frameBytes(frame);
    const chunk = await timed(clock, `opening chunk ${i + 1} of ${chunks}`, () =>
      engine.openBytes(session, frame),
    );
    session = chunk.session;
    if (done + chunk.plaintext.length > header.size) {
      throw new Error(`chunk ${i + 1} overruns the declared size of ${header.size} bytes`);
    }
    assembled.set(chunk.plaintext, done);
    done += chunk.plaintext.length;
    report(onProgress, done, header.size);
  }

  if (done !== header.size) {
    throw new Error(`assembled ${done} bytes but the header declared ${header.size}`);
  }

  const sha256 = sha256Hex(assembled);
  if (sha256 !== header.sha256) {
    // Every chunk passed its own AEAD tag, so this is an assembly fault rather
    // than tampering. Say so, otherwise the user hunts for an attacker.
    throw new Error(
      `payload hash mismatch after assembly: expected ${header.sha256}, got ${sha256}. Every chunk authenticated, so the bytes were reassembled wrongly`,
    );
  }

  const ack = await timed(clock, 'sealing the acknowledgement', () =>
    engine.seal(session, JSON.stringify({ ok: true, sha256 })),
  );
  session = ack.session;
  await channel.send(ack.token);
  const wallMs = performance.now() - wallStart;

  return {
    name: typeof header.name === 'string' ? header.name : 'payload.bin',
    bytes: assembled,
    stats: {
      handshakeMs,
      cryptoMs: clock.ms,
      wallMs,
      plainBytes: header.size,
      wireBytes,
      chunks,
      chunkSize,
      sha256,
      throughputMBs: throughput(header.size, wallMs),
      peerWords,
      sessionWords,
    },
  };
}
