/**
 * File transfer over one ratchet session.
 *
 * ---------------------------------------------------------------------------
 * WIRE PROTOCOL
 * ---------------------------------------------------------------------------
 *
 * Every frame is one ratchet-ts envelope in its binary form, length prefixed by
 * cli/frame.mjs: a u32 big endian byte count, then the envelope. No base64 and
 * no newline delimiter, so the bytes on the socket are the bytes the encoder
 * produced. Nothing but envelopes crosses the socket, so a passive observer
 * learns the byte count and nothing else: not the filename, not the size, not
 * the hash.
 *
 *   1. RECEIVER -> SENDER   invite envelope
 *
 *      The receiver invites. It is the long lived listener, so it is the party
 *      with a stable address, and inviting first means the sender needs no
 *      prior knowledge beyond host and port.
 *
 *   2. SENDER -> RECEIVER   accept envelope
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
 *      Pipelined, not lockstep. The sender never waits for a per chunk
 *      acknowledgement, so a high latency link costs one round trip for the
 *      whole transfer instead of one per chunk. It waits only when the socket
 *      is holding more than one write window of unflushed bytes, which is the
 *      memory bound and lives in cli/frame.mjs. Between those waits it is
 *      sealing chunk i + 1 while the socket is still moving chunk i.
 *
 *   6. RECEIVER             opens header, opens each chunk, writes it into the
 *                           assembled buffer and hashes the region it just
 *                           wrote. At the end it compares the running sha256
 *                           against the header. Mismatch throws.
 *
 *      Belt and braces over the AEAD. Each chunk authenticates only itself, so
 *      Poly1305 cannot see an assembly bug: a chunk written at the wrong offset
 *      or a dropped tail passes every tag check and still produces the wrong
 *      file. The payload hash is what catches that, which is why the digest is
 *      fed from the assembled buffer and never from the chunk plaintext: a
 *      digest of the chunks would agree with itself wherever they landed.
 *
 *   7. RECEIVER -> SENDER   sealed `{ ok: true, sha256 }`
 *
 *      So the sender learns the transfer VERIFIED, rather than merely that the
 *      bytes left the socket.
 *
 * Sessions are immutable. Every seal and open returns a new one and the old one
 * is dead the instant it is used. Each call site here reassigns in place for
 * that reason, and there is deliberately never a second live copy in scope.
 *
 * ---------------------------------------------------------------------------
 * WHAT THE NUMBERS MEAN
 * ---------------------------------------------------------------------------
 *
 * People compare these figures against other transports, so the definitions
 * have to be stated rather than inferred:
 *
 *   plainBytes   the payload, exactly. Not the header, not the JSON.
 *   wireBytes    real bytes handed to the socket for the PAYLOAD phase, which
 *                is the sealed header plus every sealed chunk, each counted as
 *                its 4 byte length prefix plus its envelope. Not an estimate.
 *   overhead     wireBytes minus plainBytes, computed by the renderer.
 *   cryptoMs     CPU spent in every seal and every open this side performed,
 *                the two handshake opens included, plus, on the frames that
 *                still build a token, the conversion between that token and the
 *                bytes on the socket. Nothing is left out. Before 0.3.1 the
 *                conversion was, and the exclusion was worth more than it
 *                sounded: see the frame seam note further down for what was
 *                hidden and what deleted it.
 *   wallMs       first payload frame to final acknowledgement.
 *
 *                Unchanged as a definition in 0.3.3, and worth saying plainly
 *                because the number moved: the window is the same span on both
 *                sides, what changed is that the receiver no longer spends the
 *                end of it hashing 10 MB in one go. The sender computes its
 *                digest before the window opens, because the header carries it,
 *                so a whole-payload pass on the receiving side was charging one
 *                side for work the other did off the clock. The receiver now
 *                hashes each chunk as it lands, inside the window, overlapped
 *                with the socket. Same window, same work counted, the receiver
 *                stops paying a serial tail the sender never paid.
 *
 * cryptoMs and wallMs cover different windows, so on a fast payload path
 * cryptoMs can be the larger of the two and that is not a bug. cryptoMs starts
 * at the first handshake open and wallMs starts after the handshake is over, so
 * the post-quantum handshake sits inside cryptoMs and inside handshakeMs and in
 * neither of them twice. Since 0.3.1 deleted almost all of the payload phase
 * CPU, what is left in cryptoMs on a small file is mostly the handshake. To ask
 * whether a transfer was crypto bound or socket bound, compare cryptoMs against
 * handshakeMs plus wallMs, not against wallMs alone.
 *   backend      which AEAD implementation ran, so two machines comparing
 *                throughput can see whether one of them was on the native path.
 *
 * The handshake frames are deliberately OUTSIDE wireBytes. They are measured by
 * handshakeMs instead, and folding a fixed ~2.5 kB post-quantum handshake into
 * an overhead percentage that is defined against the payload would make the
 * percentage say more about the file size than about the protocol.
 */

import { createHash } from 'node:crypto';

import {
  aeadBackend,
  decodeEnvelope,
  decodeEnvelopeBytes,
  encodeEnvelope,
  encodeEnvelopeBytes,
  engine,
  fingerprint,
  formatFingerprint,
  isCryptoFailure,
  publicOf,
} from '../dist/index.js';

/**
 * Bumped for the binary frame format.
 *
 * A v1 peer can never reach this check: it delimits frames with newlines and
 * this one reads a u32 length prefix, so the two disagree about where a frame
 * ends long before anything is sealed or opened. The number is therefore a
 * record of the break rather than a guard against it, and the guard lives in
 * frame.mjs, which refuses an implausible length.
 */
export const PROTOCOL_VERSION = 2;

/** u32 big endian length prefix per frame, set by cli/frame.mjs. */
const FRAME_PREFIX_BYTES = 4;

/**
 * Hard ceiling imposed by the envelope, not chosen here.
 *
 * Every variable length field in an OCX1 envelope carries a u16 length prefix,
 * so a ciphertext cannot exceed 65535 bytes, and XChaCha20-Poly1305 adds a 16
 * byte tag. 65519 plaintext bytes is therefore the largest message the library
 * can encode at all: one byte more and the encoder throws a RangeError before
 * any crypto runs. Raising this needs u32 field prefixes in src/envelope.ts,
 * which is a wire format change, and that change is deliberately not in this
 * release, so it is not a knob this file can turn.
 */
const WIRE_MAX_PLAINTEXT = 0xffff - 16;

const DEFAULT_CHUNK = Math.min(64 * 1024, WIRE_MAX_PLAINTEXT);
const MIN_CHUNK = 1024;
const MAX_CHUNK = Math.min(4 * 1024 * 1024, WIRE_MAX_PLAINTEXT);

// Load time assertion on the arithmetic above. If a future edit raises one of
// these constants past the envelope ceiling, the failure has to be this line
// and not a RangeError thrown from inside the encoder on chunk 900 of 2000,
// after the receiver has already committed to a size and a chunk count.
if (MAX_CHUNK > WIRE_MAX_PLAINTEXT || DEFAULT_CHUNK > WIRE_MAX_PLAINTEXT) {
  throw new Error(
    `chunk ceiling is wrong: default ${DEFAULT_CHUNK}, max ${MAX_CHUNK}, but an OCX1 envelope ` +
      `cannot carry more than ${WIRE_MAX_PLAINTEXT} plaintext bytes in one frame`,
  );
}

/** Exported so the CLI can show the real figure rather than the one asked for. */
export const MAX_CHUNK_BYTES = MAX_CHUNK;
export const DEFAULT_CHUNK_BYTES = DEFAULT_CHUNK;

/**
 * Clamp rather than throw. A caller passing 10 GiB means "as big as you can",
 * and refusing the transfer over a tuning knob helps nobody. The clamp is also
 * what keeps a hostile header from steering the receiver past the ceiling.
 */
function clampChunkSize(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return DEFAULT_CHUNK;
  const n = Math.floor(value);
  if (n < MIN_CHUNK) return MIN_CHUNK;
  if (n > MAX_CHUNK) return MAX_CHUNK;
  return n;
}

/**
 * Last line of defence before the encoder. clampChunkSize already makes this
 * unreachable for chunks, but "unreachable" is a claim about today's call
 * graph, and the failure it prevents is a RangeError with no context raised
 * from inside a library the user did not write.
 */
function assertWireCeiling(length, what) {
  if (length > WIRE_MAX_PLAINTEXT) {
    throw new Error(
      `${what} is ${length} plaintext bytes, over the ${WIRE_MAX_PLAINTEXT} byte ceiling one ` +
        `OCX1 frame can carry. Lower --chunk, or wait for the u32 envelope fields`,
    );
  }
}

function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * Twelve words that are IDENTICAL on both ends, for reading aloud over the
 * phone. They are the two identity fingerprints, in a canonical order, and not
 * a hash of the two identities together.
 *
 * `peerWords` alone cannot do this job. A fingerprint of the peer identity is
 * different on each side by construction: I see your words, you see mine. To
 * compare them out loud one party has to recite what it sees and the other has
 * to look up its OWN fingerprint, which is two strings and a rule nobody
 * remembers under pressure. So this puts both fingerprints in one string that
 * either party can simply read out, ordered so that both machines print the
 * same twelve words in the same sequence.
 *
 * WHY NOT HASH THE PAIR TOGETHER, which is what this did until 2026-08-15.
 * That produced six words and the comment here claimed it was "exactly as
 * strong as an ordinary fingerprint: 66 bits". It was not, and the README had
 * already said so in the roadmap while this file went on asserting the
 * comfortable number. A machine in the middle is not solving one preimage. It
 * chooses the key it shows to EACH side, so it grinds candidate identities to
 * show Alice and candidate identities to show Bob until the two six word lines
 * happen to agree. That is a birthday search over a 66 bit space, about 2^33
 * work, which is hours on hardware anybody can rent. The one control this
 * entire design leans on was worth half the bits it advertised.
 *
 * Concatenating instead of hashing removes the attacker's second degree of
 * freedom. To pass, the words shown to Alice and the words shown to Bob must
 * match position by position, so the attacker needs an identity whose
 * fingerprint equals Alice's AND another whose fingerprint equals Bob's: two
 * independent second preimages at 2^66 each, with no birthday discount because
 * the targets are fixed before the attack starts.
 *
 * TWELVE WORDS IS THE PRICE AND THERE IS NO CHEAPER ONE. Any single string
 * short enough to stay at six words is a 66 bit space, and a two sided attacker
 * always gets the square root of it. Resisting that needs roughly 132 bits in
 * front of the user however it is packaged, as two lines or as one longer line.
 * Signal shows 60 digits for the same reason. Six words was not a tighter
 * design, it was the same design with half the check missing.
 *
 * Ordered by fingerprint hex rather than by public key. Sorting on the key
 * would let the two sides disagree about sequence in exactly the case that
 * matters: an attacker who matched both fingerprints did not have to match the
 * keys underneath them, so a key order could still print the two lines swapped
 * and invite a user to wave it through. Ordering on the thing being compared
 * means the sequence matches if and only if the fingerprints do.
 *
 * THIS IS THE ONLY COPY. cli/chat.mjs used to carry a second one, kept in step
 * by a comment asking whoever edited either to edit both. Two independent
 * copies of a security relevant derivation is a bug with a date on it: the day
 * they drift, a user comparing a chat session against a file transfer sees two
 * different word sets for one pair of identities and concludes, wrongly, that
 * something is wrong. test/peers.test.mjs pins the output against fixed
 * identity bytes so a change here has to be deliberate.
 */
export function pairWords(self, peer) {
  const mine = fingerprint(publicOf(self));
  const theirs = fingerprint(peer);
  const [first, second] = mine.hex <= theirs.hex ? [mine, theirs] : [theirs, mine];
  return `${formatFingerprint(first)} ${formatFingerprint(second)}`;
}


/**
 * A raw reason string is useless to someone staring at a terminal. Translate
 * into what it means, which is a different sentence for each reason: a replay
 * is suspicious, a missing session is a protocol bug, a failed tag is either
 * corruption or an attacker.
 *
 * ONE table, two columns, not two tables. A file transfer and a chat session
 * are not the same situation, and exactly two of these read wrong in the other
 * one: "the transfer cannot continue" is not what happened to a conversation,
 * and "nothing was written" is a strange thing to reassure someone about in a
 * chat that never writes anything. Every other row says the same thing in both
 * places, so `chat` is an override on the row and never a second copy of it.
 * The duplication this replaces is the reason for the rule: cli/chat.mjs used
 * to fall back to the raw library message, so `ratchet send` printed a
 * sentence and `ratchet chat` printed `replay_detected` and nothing else.
 *
 * Every value of the CryptoFailureReason union in src/types.ts has a row here.
 * test/peers.test.mjs reads that union out of the source and fails if a new
 * reason is added upstream without wording in every context.
 */
const REASONS = {
  malformed_token: {
    transfer: 'the peer sent something that is not a ratchet-ts envelope, so the other end is not speaking this protocol',
  },
  unknown_version: {
    transfer: 'the peer is running an incompatible ratchet-ts version, so upgrade one side',
  },
  no_session: {
    transfer: 'no live session for that frame, so the two sides fell out of step in the handshake',
  },
  authentication_failed: {
    transfer: 'the data was tampered with in transit, or the peer is not who it claims to be. Nothing was written',
    chat: 'that frame was tampered with in transit, or the peer is not who it claims to be. Nothing was shown',
  },
  replay_detected: {
    transfer: 'the same frame arrived twice, which is either a broken relay or a deliberate replay',
  },
  skip_limit_exceeded: {
    transfer: 'too many frames went missing for the ratchet to catch up, so the transfer cannot continue',
    chat: 'too many frames went missing for the ratchet to catch up, so the conversation cannot continue',
  },
  identity_mismatch: {
    transfer: 'the reply answers an invite from a different identity, so something re-addressed the handshake',
  },
  // The only reason in this table that names an attacker as the FIRST
  // explanation rather than the last. Every other failure here has a boring
  // cause that is more likely than malice: a dropped frame, a stale session, a
  // resent packet. A signature that does not verify has no boring cause. The
  // bytes were signed by a key, that key is in the same frame, and the two do
  // not agree, which means the frame was built by somebody who could not sign
  // as the identity they are claiming.
  bad_signature: {
    transfer: 'the handshake is signed by the wrong key, so the machine on the other end is not who the frame says it is',
    chat: 'the handshake is signed by the wrong key, so whoever answered is not who the frame says they are',
  },
};

/** Every context REASONS is written for, so a test can walk all of them. */
export const FAILURE_CONTEXTS = ['transfer', 'chat'];

/**
 * The sentence for one reason in one context, or null when this build has no
 * wording for it. Null rather than a stand-in sentence: the caller falls back
 * to the library's own message, which is worse but true, and a stand-in would
 * be neither.
 */
export function explainFailure(reason, context = 'transfer') {
  const row = REASONS[reason];
  if (!row) return null;
  return row[context] ?? row.transfer;
}

/**
 * The reason code stays in the text on purpose. It is the one part of this
 * sentence somebody can paste into an issue and search for, and an error you
 * cannot search for is a failure of its own.
 */
export function wrapCrypto(err, during, context = 'transfer') {
  if (!isCryptoFailure(err)) return err;
  const explained = explainFailure(err.reason, context) ?? err.message;
  const wrapped = new Error(`${during}: ${explained} (${err.reason})`);
  wrapped.cause = err;
  wrapped.reason = err.reason;
  return wrapped;
}

/**
 * The same translation as a plain string, for callers that print rather than
 * throw. Anything that is not a crypto failure passes through carrying its own
 * message, so one call site handles both without having to ask which it holds.
 */
export function explainError(err, during, context = 'transfer') {
  if (isCryptoFailure(err)) return wrapCrypto(err, during, context).message;
  return `${during}: ${err && err.message ? err.message : String(err)}`;
}

/**
 * Run one crypto call, charging its duration to `clock` and nothing else.
 * Keeping socket time out of it is the whole point of the split: what a
 * transfer spends on the CPU and what it spends waiting are different numbers
 * and a single figure covering both answers nothing.
 *
 * Everything a seal or an open costs goes through here, the handshake opens
 * included, and on the frames that still build a token the conversion as well.
 * Nothing is charged anywhere else, which is what makes the number comparable
 * to another transport's. The seam note below says why that used to be untrue
 * and is now. One consequence worth stating where the accumulator lives: the
 * handshake opens land in cryptoMs before wallMs has started counting, so
 * cryptoMs is not a subset of wallMs and never was.
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

// ---------------------------------------------------------------------------
// THE FRAME SEAM
// ---------------------------------------------------------------------------
//
// The socket carries envelope bytes. Some of the engine's surface speaks tokens
// instead, so a conversion has to happen somewhere, and toWire and fromWire are
// the only two places in this file where it does. Every frame reaches them
// through one of the four wrappers below; no call site inside sendPayload or
// receivePayload touches an encoder itself.
//
// WHAT CHANGED IN 0.3.1, and why the arrangement is worth keeping. Until 0.3.1
// every frame paid that conversion, and on the chunks it was pure waste: the
// engine base64ed a sealed envelope into a token, and this file immediately
// un-base64ed it straight back into the bytes it had just been. Twice per chunk
// per transfer, once on each end. Measured on a 763.5 kB file, 12 chunks of
// 65519 bytes, native AEAD, the token round trip cost 24 to 28 ms per endpoint
// across repeated runs against about 1 ms for the same trip in the binary
// codec, roughly 25 times.
//
// engine.sealToEnvelopeBytes and engine.openFromEnvelopeBytes deleted it. They
// emit and accept the identical frame, byte for byte, so this is an internal
// shortcut and not a wire change: a 0.3.0 peer cannot tell which call produced
// the chunk it is opening.
//
// WHAT STILL CONVERTS, and why each one has to. Five frames per transfer, all of
// them small and none of them in a loop:
//
//   invite, accept       engine.invite mints a token and engine.open hands one
//                        back, because both are meant to be pasteable by a
//                        human when there is no socket. No seal is involved, so
//                        no bytes native seal can absorb them.
//   ready, header, ack   sealed strings. engine.seal wipes the transient UTF-8
//                        copy of the plaintext and a caller encoding the string
//                        out here would leave that copy alive, so the string
//                        path stays on engine.seal rather than being talked
//                        into engine.sealToEnvelopeBytes with a hand rolled
//                        utf8ToBytes in front of it. A few hundred bytes of
//                        base64 is a cheaper price than a plaintext copy this
//                        file cannot reach.
//   every inbound frame  that is not a chunk goes through engine.open, which
//                        dispatches on kind and therefore takes a token.
//
// Three of those five, ready and header and ack, are inside timed() as of
// 0.3.1, so cryptoMs no longer excludes anything on the payload path. The
// invite and the accept are not, and that is deliberate rather than an
// oversight: both sit inside the window handshakeMs already reports end to end,
// so charging them to cryptoMs as well would double count them against a clock
// that is printed right beside it. Their conversion measures about 0.03 ms for
// the pair, which is the whole of what neither clock attributes to base64.
//
// Before 0.3.1 cryptoMs excluded one base64 pass per frame and counted the
// other, which is not a distinction any reader would have guessed from the
// name.

/** Engine token to wire bytes. The only outbound conversion in this file. */
function toWire(token, what) {
  try {
    return encodeEnvelopeBytes(decodeEnvelope(token));
  } catch (err) {
    throw wrapCrypto(err, `encoding ${what}`);
  }
}

/**
 * Wire bytes to engine token. The only inbound conversion in this file.
 *
 * Self describing, so no hint about which kind of envelope is arriving: a
 * receiver cannot know whether the next frame is an invite, an accept or a
 * message, and guessing wrong used to be a decode error rather than a protocol
 * error.
 */
function fromWire(bytes, what) {
  try {
    return encodeEnvelope(decodeEnvelopeBytes(bytes));
  } catch (err) {
    throw wrapCrypto(err, `decoding ${what}`);
  }
}

/**
 * Handshake token straight to a frame.
 *
 * The invite and the accept are the two outbound frames a bytes native seal can
 * never absorb, because neither comes out of a seal: one is engine.invite's
 * token and the other is the reply engine.open hands back. This wrapper does
 * nothing toWire does not. It exists so the two frames that still convert are
 * visibly separate from the twelve that no longer do, and it is deliberately
 * not charged to a clock: both frames fall inside the handshake window, which
 * handshakeMs already measures end to end.
 */
function handshakeFrame(token, what) {
  return toWire(token, what);
}

/**
 * Seal one plaintext and hand back the frame that carries it.
 *
 * Every sealed frame this protocol sends comes through here: the ready frame,
 * the payload header, all 12 chunks of a 763.5 kB file, the acknowledgement.
 *
 * The two branches are the same ratchet, since ratchetEncrypt in src/ratchet.ts
 * is utf8ToBytes followed by ratchetEncryptBytes. They differ in what they do
 * with the transient UTF-8 copy and in how they reach the wire. Bytes go
 * straight out as envelope bytes. Strings keep the token detour so that
 * engine.seal keeps ownership of the copy it wipes, and pay one base64 round
 * trip on three small frames per transfer for it.
 *
 * Both branches are timed in full, conversion included. There is no longer a
 * step in the sealing of a payload frame that cryptoMs does not see.
 */
async function sealFrame(clock, session, plaintext, what, { reserve = 0 } = {}) {
  if (typeof plaintext !== 'string') {
    const sealed = await timed(clock, `sealing ${what}`, () =>
      engine.sealToEnvelopeBytes(session, plaintext, reserve > 0 ? { reserve } : undefined),
    );
    return { frame: sealed.envelope, session: sealed.session, reserved: reserve };
  }
  return timed(clock, `sealing ${what}`, async () => {
    const sealed = await engine.seal(session, plaintext);
    return { frame: toWire(sealed.token, what), session: sealed.session, reserved: 0 };
  });
}

/**
 * Open one inbound frame through engine.open, the entry point that can return
 * any outcome. The outcome check stays at the call site, because what a wrong
 * one means is protocol specific: an invite arriving where an accept was
 * expected is a different sentence from an invite arriving where a chunk was.
 *
 * `during` names the crypto step inside an error message and defaults to the
 * wire label, which is right at three of the five call sites. The header and the
 * acknowledgement pass it explicitly because their two labels were already
 * worded differently, and rewording an error a user reads is not part of a
 * refactor.
 *
 * fromWire runs inside the timed callback so the conversion is charged rather
 * than excluded. It keeps its own error wording: it throws an ordinary Error,
 * which wrapCrypto passes through untouched, so a corrupt invite still reads
 * "decoding the peer invite" and not "opening" it.
 */
async function openFrame(clock, identity, context, frame, what, during = `opening ${what}`) {
  return timed(clock, during, () => engine.open(identity, fromWire(frame, what), context));
}

/**
 * Chunk variant, and the reason 0.3.1 exists. engine.openFromEnvelopeBytes is
 * message only, needs no identity, takes the frame exactly as the socket
 * delivered it and hands back raw bytes rather than a UTF-8 decoding that would
 * be lossy on a binary payload.
 *
 * Twelve of the thirteen payload frames in a 763.5 kB transfer arrive through
 * here, so this is the half of the seam that decided what the change was worth.
 *
 * One user visible consequence of losing the separate decode step: a corrupt
 * chunk used to fail as "decoding chunk 3 of 12" and now fails as "opening
 * chunk 3 of 12". The reason code and the explanation are unchanged, and there
 * is genuinely nothing being decoded separately any more, so the new verb is
 * the true one.
 */
async function openChunkFrame(clock, session, frame, what) {
  return timed(clock, `opening ${what}`, () => engine.openFromEnvelopeBytes(session, frame));
}

/**
 * Real cost of putting one frame on the socket, prefix included.
 *
 * `reserved` is how many of those prefix bytes are already sitting inside
 * `frame`, which is nonzero exactly when the frame was sealed with room left in
 * front for the length. Counting the prefix twice there would have inflated
 * every reported overhead figure the moment the no-copy path switched on, and
 * the whole point of that path is that it changes nothing on the wire.
 */
function wireCost(frame, reserved = 0) {
  return FRAME_PREFIX_BYTES - reserved + frame.length;
}

/**
 * A closed channel mid-transfer is a distinct failure from a crypto one.
 *
 * receive() is the binary channel's read. next() is the same call under the
 * name the newline delimited transport used, accepted so this file does not
 * break on a transport that has not been renamed yet.
 */
async function expectFrame(channel, what) {
  const frame = typeof channel.receive === 'function'
    ? await channel.receive()
    : await channel.next();
  if (frame === null || frame === undefined) {
    throw new Error(`connection closed while waiting for ${what}`);
  }
  // A string here means the channel is still the text transport, and feeding
  // that to the binary decoder produces a confusing failure several layers
  // down. Say what is actually wrong instead.
  if (!(frame instanceof Uint8Array)) {
    throw new Error(
      `the channel delivered ${typeof frame} for ${what}, but this protocol reads binary frames`,
    );
  }
  return frame;
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
/**
 * `peerHex` is the first 128 bits of the peer identity digest, the same string
 * `ratchet id --json` prints, and it is what cli/peers.mjs keys its trust store
 * on. The words are a 66 bit projection of that same digest and are for humans
 * only: two different identities colliding in six words is a thing an attacker
 * can work towards, and colliding in the hex is not.
 */
function announce(onHandshake, peerWords, sessionWords, handshakeMs, peerHex) {
  if (typeof onHandshake !== 'function') return;
  try {
    void onHandshake({ peerWords, sessionWords, handshakeMs, peerHex });
  } catch {
    /* a broken banner must never fail a transfer */
  }
}


/**
 * The one callback that is allowed to stop a transfer.
 *
 * `announce` above swallows everything a banner throws, on purpose: a rendering
 * bug must never cost somebody their file. That makes onHandshake exactly the
 * wrong place to put a security decision, and it was tried there first. The
 * pairing code check went in as a banner, the banner threw on a mismatched
 * peer, the catch above ate it, and the file went to the wrong machine anyway.
 * The end to end test caught it; nothing else would have.
 *
 * So this is separate, awaited, and deliberately not wrapped. It runs after the
 * handshake and before the header is sealed, which is the last moment at which
 * refusing costs nothing: the peer has proved who it is and no plaintext has
 * been committed to the wire.
 */
async function gateOnPeer(verifyPeer, peerWords, peerHex, peerIdentity) {
  if (typeof verifyPeer !== 'function') return;
  await verifyPeer({ peerWords, peerHex, peerIdentity });
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
export async function sendPayload({ channel, identity, name, bytes, chunkSize, onProgress, onHandshake, verifyPeer }) {
  const payload = bytes ?? new Uint8Array(0);
  const size = payload.length;
  const chunk = clampChunkSize(chunkSize);
  assertWireCeiling(chunk, 'the requested chunk size');
  const chunks = expectedChunks(size, chunk);
  const clock = { ms: 0 };

  const handshakeStart = performance.now();

  const inviteFrame = await expectFrame(channel, 'the peer invite');
  let opened = await openFrame(clock, identity, {}, inviteFrame, 'the peer invite');
  if (opened.outcome !== 'invite') {
    throw new Error(`expected an invite from the receiver, got ${opened.outcome}`);
  }
  let session = opened.session;
  await channel.send(handshakeFrame(opened.reply, 'the accept'));

  // The receiver speaks once here so this side gets a send chain. See step 3b.
  const readyFrame = await expectFrame(channel, 'the receiver ready frame');
  const readyOpen = await openFrame(clock, identity, { session }, readyFrame, 'the receiver ready frame');
  if (readyOpen.outcome !== 'message') {
    throw new Error(`expected a ready frame from the receiver, got ${readyOpen.outcome}`);
  }
  session = readyOpen.session;
  const readyBody = parseJson(readyOpen.plaintext, 'the receiver ready frame');
  if (readyBody.v !== PROTOCOL_VERSION) {
    throw new Error(`receiver speaks protocol v${readyBody.v}, this is v${PROTOCOL_VERSION}`);
  }

  const handshakeMs = performance.now() - handshakeStart;
  const peerPrint = fingerprint(session.peer);
  const peerWords = formatFingerprint(peerPrint);
  const sessionWords = pairWords(identity, session.peer);
  announce(onHandshake, peerWords, sessionWords, handshakeMs, peerPrint.hex);
  // Can refuse. See gateOnPeer: the banner above cannot, by design.
  await gateOnPeer(verifyPeer, peerWords, peerPrint.hex, session.peer);

  const sha256 = sha256Hex(payload);
  const header = JSON.stringify({
    v: PROTOCOL_VERSION,
    name: name ?? 'payload.bin',
    size,
    sha256,
    chunks,
    chunkSize: chunk,
  });
  // The peer picks the filename length, and a long enough name is the one way
  // a caller could push this JSON past a single frame.
  assertWireCeiling(Buffer.byteLength(header, 'utf8'), 'the payload header');

  let wireBytes = 0;
  const wallStart = performance.now();

  const sealedHeader = await sealFrame(clock, session, header, 'the header');
  session = sealedHeader.session;
  wireBytes += wireCost(sealedHeader.frame);
  await channel.send(sealedHeader.frame);

  report(onProgress, 0, size);
  let done = 0;
  // The backpressure promise for the frame that was handed to the socket last
  // iteration, held rather than awaited, which is what makes the overlap below
  // real. See the comment on the await.
  let inflight = null;
  // How much room the transport wants in front of a frame for its own length
  // prefix. Asking the channel rather than assuming four keeps this file
  // ignorant of the framing, which is the reason the channel is injected at
  // all: a transport that needs no prefix answers 0 and the seal below is
  // byte for byte what it was before. Leaving the room during the seal is what
  // removes the last full-size copy of every chunk, since the prefix is then
  // stamped into the envelope's own allocation instead of a fresh buffer.
  const reserve = Number.isInteger(channel.prefixBytes) ? channel.prefixBytes : 0;
  for (let i = 0; i < chunks; i += 1) {
    const start = i * chunk;
    const slice = payload.subarray(start, Math.min(start + chunk, size));
    const sealed = await sealFrame(clock, session, slice, `chunk ${i + 1} of ${chunks}`, {
      reserve,
    });
    session = sealed.session;
    wireBytes += wireCost(sealed.frame, sealed.reserved);
    // THE PIPELINING, and it is a claim about the order of these three lines.
    //
    // channel.send hands the frame to the socket synchronously and returns a
    // promise for "the socket is back under its write window". So chunk i - 1
    // was submitted before the seal above ran, and the kernel was moving it
    // while this iteration was doing that CPU work. Sealing chunk i + 1 then
    // overlaps chunk i the same way. Nothing here is parallel: the ratchet is
    // strictly ordered, chunks are sealed in sequence and submitted in
    // sequence, and the only thing overlapping is our CPU with the socket's
    // I/O.
    //
    // Awaiting the PREVIOUS send here rather than this one is the whole trick.
    // It is still backpressure, never a reply: awaiting bounds how far ahead of
    // the socket this loop may run, at one write window plus the single frame
    // submitted below. Before 0.3.3 this awaited its own send, and since a
    // sealed 64 KiB chunk is four times Node's default watermark, that meant
    // waiting for the kernel to take every single frame before starting the
    // next seal. The overlap this comment described did not exist.
    if (inflight) await inflight;
    inflight = channel.send(sealed.frame, { prefixReserved: sealed.reserved > 0 });
    // A rejection sitting on an unawaited promise takes the process down with
    // an unhandled rejection if the seal on the next iteration throws first.
    // The await above is what reports the error; this only marks it as seen.
    if (typeof inflight?.catch === 'function') inflight.catch(() => {});
    // Bytes submitted, which is what this counter has always meant. It was
    // never an acknowledgement from the peer, and it is now up to one write
    // window ahead of the wire rather than up to one frame ahead.
    done += slice.length;
    report(onProgress, done, size);
  }
  // The loop only ever waits for the second to last frame, so the last one
  // still has to clear before the acknowledgement can be waited on.
  if (inflight) await inflight;

  const ackFrame = await expectFrame(channel, 'the receiver acknowledgement');
  const ack = await openFrame(
    clock,
    identity,
    { session },
    ackFrame,
    'the receiver acknowledgement',
    'opening the acknowledgement',
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
    backend: aeadBackend(),
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
export async function receivePayload({ channel, identity, onProgress, onHandshake, verifyPeer }) {
  const clock = { ms: 0 };
  const handshakeStart = performance.now();

  const invited = await timed(clock, 'creating the invite', () => engine.invite(identity));
  await channel.send(handshakeFrame(invited.token, 'the invite'));

  const replyFrame = await expectFrame(channel, 'the sender reply');
  const accepted = await openFrame(
    clock,
    identity,
    { pending: invited.pending },
    replyFrame,
    'the sender reply',
  );
  if (accepted.outcome !== 'accepted') {
    throw new Error(`expected an accept from the sender, got ${accepted.outcome}`);
  }
  let session = accepted.session;

  const ready = await sealFrame(
    clock,
    session,
    JSON.stringify({ v: PROTOCOL_VERSION, ready: true }),
    'the ready frame',
  );
  session = ready.session;
  await channel.send(ready.frame);

  const handshakeMs = performance.now() - handshakeStart;
  const peerPrint = fingerprint(session.peer);
  const peerWords = formatFingerprint(peerPrint);
  const sessionWords = pairWords(identity, session.peer);
  announce(onHandshake, peerWords, sessionWords, handshakeMs, peerPrint.hex);
  // Can refuse. See gateOnPeer: the banner above cannot, by design.
  await gateOnPeer(verifyPeer, peerWords, peerPrint.hex, session.peer);

  // Starts before the await, so it includes the sender's turnaround. That is
  // the same span the sender measures, give or take one network hop.
  let wireBytes = 0;
  const wallStart = performance.now();

  const headerFrame = await expectFrame(channel, 'the payload header');
  wireBytes += wireCost(headerFrame);
  const headerOpen = await openFrame(
    clock,
    identity,
    { session },
    headerFrame,
    'the payload header',
    'opening the header',
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
  // Hashed a chunk at a time instead of in one pass over the finished payload.
  //
  // Two reasons, and the accounting one is the smaller of them. The real one is
  // that a single pass at the end is dead time on the critical path: the last
  // chunk has landed, the sender is blocked waiting for the acknowledgement,
  // and this side spends ~15 ms per 10 MB hashing before it can send one. Fed a
  // chunk at a time, the same work happens while the socket is delivering the
  // next frame, which is time this side was going to spend waiting anyway.
  //
  // The accounting one: the sender hashes OUTSIDE its wallMs window, because it
  // needs the digest to build the header before the window opens. So a whole
  // payload pass here charged the receiver for work the sender did off the
  // clock, and the receiver looked slower than it was by exactly that much. It
  // could not be fixed by moving the hash out of the window on this side, since
  // the acknowledgement genuinely cannot go out until the hash is known, and
  // wallMs ends at the acknowledgement. Overlapping it is the honest fix.
  //
  // This still reads back out of `assembled` rather than hashing the plaintext
  // it was handed, which is what keeps step 6's promise intact. The whole point
  // of the payload hash is that the AEAD cannot see an assembly bug, and a
  // digest fed from the chunks directly would be just as blind: it would agree
  // with itself no matter where the bytes were written. Hashing the region of
  // the assembled buffer we just wrote catches a chunk placed at the wrong
  // offset, and the `done !== header.size` check below catches a dropped tail.
  const digest = createHash('sha256');
  for (let i = 0; i < chunks; i += 1) {
    const frame = await expectFrame(channel, `chunk ${i + 1} of ${chunks}`);
    wireBytes += wireCost(frame);
    const chunk = await openChunkFrame(clock, session, frame, `chunk ${i + 1} of ${chunks}`);
    session = chunk.session;
    if (done + chunk.plaintext.length > header.size) {
      throw new Error(`chunk ${i + 1} overruns the declared size of ${header.size} bytes`);
    }
    assembled.set(chunk.plaintext, done);
    const placed = done;
    done += chunk.plaintext.length;
    digest.update(assembled.subarray(placed, done));
    report(onProgress, done, header.size);
  }

  if (done !== header.size) {
    throw new Error(`assembled ${done} bytes but the header declared ${header.size}`);
  }

  const sha256 = digest.digest('hex');
  if (sha256 !== header.sha256) {
    // Every chunk passed its own AEAD tag, so this is an assembly fault rather
    // than tampering. Say so, otherwise the user hunts for an attacker.
    throw new Error(
      `payload hash mismatch after assembly: expected ${header.sha256}, got ${sha256}. Every chunk authenticated, so the bytes were reassembled wrongly`,
    );
  }

  const ack = await sealFrame(
    clock,
    session,
    JSON.stringify({ ok: true, sha256 }),
    'the acknowledgement',
  );
  session = ack.session;
  await channel.send(ack.frame);
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
      backend: aeadBackend(),
      peerWords,
      sessionWords,
    },
  };
}
