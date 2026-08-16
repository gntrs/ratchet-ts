import { sha256 } from '@noble/hashes/sha2.js';

import type { IdentityKeyPair, PendingSession, SessionState } from './contract.js';
import { bytesToUtf8, concat, equal, fromBase64Url, toBase64Url, utf8ToBytes } from './bytes.js';
import { ENVELOPE_VERSION } from './envelope.js';
import { fail } from './errors.js';
import {
  MLDSA65_PUBLIC_LEN,
  MLDSA65_SECRET_LEN,
  MLDSA65_SIGNATURE_LEN,
  MLKEM768_PUBLIC_LEN,
  MLKEM768_SECRET_LEN,
  X25519_PUBLIC_LEN,
  X25519_SECRET_LEN,
} from './identity.js';
import { KEY_LEN } from './kdf.js';
import { MAX_SKIP } from './ratchet.js';

/**
 * Persistence for the three things a caller has to keep across restarts:
 * a live session, a pending invite, and the identity itself.
 *
 * Everything serialises to one pasteable ASCII string in the same shape as the
 * wire envelopes, `OCX2.<kind>.<base64url body>`, because a single line of
 * text is the lowest common denominator of every storage a caller might have:
 * a database column, localStorage, a file, an environment variable. No caller
 * should ever need to know the body layout.
 *
 * The body is compact binary rather than JSON for the same reasons envelope.ts
 * gives: keys this size would bloat by a third under nested base64, and binary
 * makes the round trip trivially byte exact. Byte exactness is not cosmetic
 * here, a restored session must produce the same chains as the one that was
 * saved or every message after the restore fails authentication.
 *
 * SECURITY, SAID PLAINLY:
 *
 *   - These strings ARE the secrets. A serialised session contains the root
 *     key, chain keys, the ratchet private key, and every parked message key.
 *     A serialised identity is the identity. Whoever reads the string can
 *     decrypt, impersonate, or both. This module deliberately does NOT encrypt
 *     at rest, because it cannot invent a key to encrypt under: key management
 *     for storage is the caller's platform problem (OS keychain, encrypted DB,
 *     passphrase KDF) and pretending to solve it here would only hide the
 *     obligation.
 *
 *   - The trailing checksum is corruption detection, not authentication.
 *     Anyone who can edit the stored string can recompute it. Its job is to
 *     turn a bit rotted or half written file into a clean `malformed_token`
 *     failure instead of a session that silently cannot decrypt anything.
 *
 *   - Restoring an old snapshot rewinds the ratchet. Forward secrecy only
 *     deletes keys that are actually deleted, so a caller keeping every
 *     snapshot forever is quietly rebuilding the key escrow this protocol
 *     exists to avoid. Persist the latest state, overwrite the previous one.
 */

/**
 * Format version of the binary body, independent of the outer OCX2 marker.
 * The outer marker names the protocol generation, this byte names the state
 * layout, and the two move at different speeds: a future release can add a
 * session field without touching the wire protocol.
 *
 * BUMPED TO 2 IN 0.4.0. A session gained `previousPeerRatchetPublic` and
 * `peerChainEpoch`, and its `skippedKeys` are keyed by epoch rather than by a
 * base64 ratchet public key. A version 1 body parsed as version 2 would run off
 * the end of the buffer or, worse, read a skipped key id under the wrong scheme
 * and quietly lose every parked key, so it is refused outright. Callers with
 * stored 0.3.x sessions must re-handshake; there is no migration, because the
 * chain keys themselves changed KDF and could not be carried across anyway.
 *
 * In practice a 0.3.x string fails one step earlier, on the OCX1 marker, with
 * `unsupported token version OCX1`. This byte is the backstop for anything that
 * kept the marker and changed the body.
 */
const STATE_VERSION = 2;

const CHECKSUM_LEN = 8;
const CHECKSUM_DOMAIN = utf8ToBytes('OCX2 state checksum v1');

type StateKind = 'session' | 'pending' | 'identity';

// ---------------------------------------------------------------------------
// Binary plumbing
// ---------------------------------------------------------------------------

/**
 * Same Writer/Reader shape as envelope.ts, duplicated on purpose. The envelope
 * codec is private to its module, and exporting it would turn sixty lines of
 * index arithmetic into cross module API that both files then have to keep
 * stable. The duplication is cheaper than the coupling.
 *
 * Every variable length field is length prefixed and the reader refuses
 * trailing bytes, so there is exactly one encoding of any given state. That is
 * what makes `serialize(deserialize(x)) === x` hold, which the tests rely on
 * as the byte exactness proof.
 */
class Writer {
  private readonly parts: Uint8Array[] = [];
  private size = 0;

  u8(value: number): void {
    this.raw(Uint8Array.of(value));
  }

  u32(value: number): void {
    const buf = new Uint8Array(4);
    new DataView(buf.buffer).setUint32(0, value, false);
    this.raw(buf);
  }

  /** u16 length prefix covers every field we store, the largest being 2400. */
  blob(value: Uint8Array): void {
    if (value.length > 0xffff) throw new RangeError('field too long for a u16 length prefix');
    const buf = new Uint8Array(2);
    new DataView(buf.buffer).setUint16(0, value.length, false);
    this.raw(buf);
    this.raw(value);
  }

  text(value: string): void {
    this.blob(utf8ToBytes(value));
  }

  raw(value: Uint8Array): void {
    this.parts.push(value);
    this.size += value.length;
  }

  finish(): Uint8Array {
    const out = new Uint8Array(this.size);
    let at = 0;
    for (const p of this.parts) {
      out.set(p, at);
      at += p.length;
    }
    return out;
  }
}

class Reader {
  private at = 0;

  constructor(private readonly buf: Uint8Array) {}

  u8(): number {
    if (this.at + 1 > this.buf.length) fail('malformed_token', 'truncated byte field');
    return this.buf[this.at++]!;
  }

  u32(): number {
    if (this.at + 4 > this.buf.length) fail('malformed_token', 'truncated integer field');
    const value = new DataView(this.buf.buffer, this.buf.byteOffset + this.at, 4).getUint32(0, false);
    this.at += 4;
    return value;
  }

  blob(): Uint8Array {
    if (this.at + 2 > this.buf.length) fail('malformed_token', 'truncated length prefix');
    const len = new DataView(this.buf.buffer, this.buf.byteOffset + this.at, 2).getUint16(0, false);
    this.at += 2;
    if (this.at + len > this.buf.length) fail('malformed_token', 'length prefix overruns the payload');
    // Copy rather than subarray: the restored state lives for the whole
    // conversation and must not share a backing buffer with the decoded body.
    const out = this.buf.slice(this.at, this.at + len);
    this.at += len;
    return out;
  }

  text(): string {
    return bytesToUtf8(this.blob());
  }

  end(): void {
    if (this.at !== this.buf.length) fail('malformed_token', 'trailing bytes after the payload');
  }
}

// ---------------------------------------------------------------------------
// Token framing
// ---------------------------------------------------------------------------

/** The checksum binds the kind, so a session body relabelled as a pending
 * token fails here even if its field layout happens to parse. */
function checksumOf(kind: StateKind, inner: Uint8Array): Uint8Array {
  return sha256(concat(CHECKSUM_DOMAIN, utf8ToBytes(kind), inner)).slice(0, CHECKSUM_LEN);
}

function encodeState(kind: StateKind, payload: Uint8Array): string {
  const inner = concat(Uint8Array.of(STATE_VERSION), payload);
  const body = concat(inner, checksumOf(kind, inner));
  return `${ENVELOPE_VERSION}.${kind}.${toBase64Url(body)}`;
}

function decodeState(kind: StateKind, value: string): Uint8Array {
  const trimmed = value.trim();
  const parts = trimmed.split('.');
  if (parts.length !== 3) {
    fail('malformed_token', `expected ${ENVELOPE_VERSION}.${kind}.<payload>`);
  }
  const [version, gotKind, encoded] = parts as [string, string, string];
  // Version before kind, mirroring the envelope decoder: an OCX2 string should
  // report "update your client", not "we do not know that kind".
  if (version !== ENVELOPE_VERSION) fail('unknown_version', `unsupported token version ${version}`);
  if (gotKind !== kind) fail('malformed_token', `expected a ${kind} token, got ${gotKind}`);
  const body = fromBase64Url(encoded);
  if (body === null) fail('malformed_token', 'payload is not valid base64url');
  if (body.length < 1 + CHECKSUM_LEN) fail('malformed_token', 'body too short to hold a version and checksum');
  // Format version is checked before the checksum so that a genuinely newer
  // body, whose checksum we would compute over a layout we do not understand,
  // still reports the accurate reason.
  const formatVersion = body[0]!;
  if (formatVersion !== STATE_VERSION) {
    fail('unknown_version', `unsupported ${kind} state format version ${formatVersion}`);
  }
  const inner = body.subarray(0, body.length - CHECKSUM_LEN);
  const stored = body.subarray(body.length - CHECKSUM_LEN);
  if (!equal(checksumOf(kind, inner), stored)) {
    fail('malformed_token', `${kind} checksum mismatch, the stored string is corrupted or was edited`);
  }
  // Copy: everything the Reader hands out is sliced again, but the payload
  // itself should not alias the decoded body either.
  return inner.slice(1);
}

/** Same guard the handshake uses: lengths are checked before the state is
 * trusted, so a corrupted or hostile string produces `malformed_token` rather
 * than a session that fails in some primitive three calls later. */
function requireLength(value: Uint8Array, expected: number, what: string): void {
  if (value.length !== expected) {
    fail('malformed_token', `${what} must be ${expected} bytes, got ${value.length}`);
  }
}

// ---------------------------------------------------------------------------
// SessionState
// ---------------------------------------------------------------------------

/**
 * The four optional session fields, packed into one presence byte. A flags
 * byte instead of four separate markers keeps the encoding canonical: there
 * is exactly one way to say "no send chain yet", and unknown bits are refused
 * on read so a future flag cannot be silently dropped by an old decoder.
 */
const FLAG_PEER_RATCHET = 0b0001;
const FLAG_SEND_CHAIN = 0b0010;
const FLAG_RECV_CHAIN = 0b0100;
const FLAG_PREV_PEER_RATCHET = 0b1000;
const KNOWN_FLAGS = FLAG_PEER_RATCHET | FLAG_SEND_CHAIN | FLAG_RECV_CHAIN | FLAG_PREV_PEER_RATCHET;

/**
 * One conversation's ratchet state as a single storable string.
 *
 * The output contains the root key, both chain keys, the ratchet private key,
 * and every parked message key. Treat it exactly like the session object it
 * came from: store it where an attacker cannot read it, and overwrite it on
 * every state change rather than keeping a history of snapshots, because old
 * snapshots are old keys and old keys are what forward secrecy deletes.
 *
 * ===========================================================================
 * THE ONE WAY TO GET THIS BADLY WRONG: SEALING FROM A STALE SNAPSHOT
 * ===========================================================================
 *
 * A restored session is not a copy of a conversation, it is a REWIND of one.
 * If you save here, keep sealing on the original session, and later restore
 * the saved string and seal from that, both branches are sitting on the same
 * `sendChainKey` at the same `sendCount`. The chain is a deterministic KDF, so
 * the second branch derives the IDENTICAL message key and stamps the IDENTICAL
 * message number onto a different plaintext. Nothing throws. It looks like an
 * ordinary seal, and that silence is exactly what makes it dangerous.
 *
 * What it does and does not cost, measured rather than assumed:
 *
 *   - It is NOT a two-time pad, and that took two attempts to keep. This
 *     bullet is worth reading with its history attached, because a mid-0.4.0
 *     build made the opposite true and it was reverted for this paragraph.
 *     0.3.x drew 24 fresh random bytes per seal, so two branches sealing at the
 *     same message number produced different keystreams and neither ciphertext
 *     could be unmasked. The mid-0.4.0 draft derived the nonce from the message
 *     number and sent nothing, which meant the rewound branch reused the message
 *     key AND the nonce, and the XOR of the two ciphertexts was the XOR of the
 *     two plaintexts: both plaintexts recoverable by anyone holding both
 *     ciphertexts and any crib. The shipped 0.4.0 draws 12 fresh random bytes
 *     per seal and puts them on the wire, so the two branches share a message
 *     key but not a keystream. What a rollback costs here is an attacker who can
 *     forge under a key that was used twice, which is an integrity problem. It
 *     is not a disclosure of the two plaintexts. That is a bound on the damage
 *     and not permission to do it: everything below still applies.
 *
 *   - It DOES destroy forward secrecy over the rewound span. The snapshot is a
 *     live chain key, and a chain key derives every message key ahead of it
 *     until the next DH ratchet step. Whoever holds an old snapshot can read
 *     everything that was sealed after it in that chain. Message keys the
 *     ratchet deleted are simply reconstructed.
 *
 *   - It DOES lose a message, permanently. The receiver takes whichever of the
 *     two colliding message numbers reaches it first and then rejects the
 *     other with `replay_detected`, because from its side a repeated number is
 *     indistinguishable from a replay attack. The losing plaintext is
 *     unreadable forever, and the sender is never told.
 *
 * The rule that avoids all of it: a serialised session is a HANDOFF, not a
 * backup. Save it, stop using the session object it came from, and let the
 * restored one be the only live copy. One writer, always. If you need a
 * disaster-recovery copy, accept that restoring it means the conversation has
 * to re-ratchet, and never seal from both branches.
 */
export function serializeSession(session: SessionState): string {
  const w = new Writer();
  w.text(session.conversationId);
  w.u8(session.role === 'initiator' ? 0 : 1);
  w.blob(session.peer.classicalPublic);
  w.blob(session.peer.pqPublic);
  w.blob(session.peer.sigPublic);
  w.blob(session.rootKey);
  w.blob(session.selfRatchetPublic);
  w.blob(session.selfRatchetSecret);

  let flags = 0;
  if (session.peerRatchetPublic !== undefined) flags |= FLAG_PEER_RATCHET;
  if (session.sendChainKey !== undefined) flags |= FLAG_SEND_CHAIN;
  if (session.recvChainKey !== undefined) flags |= FLAG_RECV_CHAIN;
  if (session.previousPeerRatchetPublic !== undefined) flags |= FLAG_PREV_PEER_RATCHET;
  w.u8(flags);
  if (session.peerRatchetPublic !== undefined) w.blob(session.peerRatchetPublic);
  if (session.sendChainKey !== undefined) w.blob(session.sendChainKey);
  if (session.recvChainKey !== undefined) w.blob(session.recvChainKey);
  if (session.previousPeerRatchetPublic !== undefined) w.blob(session.previousPeerRatchetPublic);

  w.u32(session.sendCount);
  w.u32(session.recvCount);
  w.u32(session.previousSendCount);
  // The epoch counter is what the parked keys below are keyed by, so it has to
  // survive the round trip or every parked key becomes unreachable.
  w.u32(session.peerChainEpoch ?? 0);

  // Insertion order is preserved through the round trip, so re-serialising a
  // restored session reproduces the identical string.
  const skipped = Object.entries(session.skippedKeys);
  w.u32(skipped.length);
  for (const [id, key] of skipped) {
    w.text(id);
    w.blob(key);
  }
  return encodeState('session', w.finish());
}

export function deserializeSession(value: string): SessionState {
  const r = new Reader(decodeState('session', value));

  const conversationId = r.text();
  const roleByte = r.u8();
  if (roleByte !== 0 && roleByte !== 1) fail('malformed_token', `unknown session role ${roleByte}`);
  const role = roleByte === 0 ? ('initiator' as const) : ('responder' as const);

  const classicalPublic = r.blob();
  const pqPublic = r.blob();
  const sigPublic = r.blob();
  const rootKey = r.blob();
  const selfRatchetPublic = r.blob();
  const selfRatchetSecret = r.blob();
  requireLength(classicalPublic, X25519_PUBLIC_LEN, 'peer classical public key');
  requireLength(pqPublic, MLKEM768_PUBLIC_LEN, 'peer ML-KEM public key');
  requireLength(sigPublic, MLDSA65_PUBLIC_LEN, 'peer ML-DSA public key');
  requireLength(rootKey, KEY_LEN, 'root key');
  requireLength(selfRatchetPublic, X25519_PUBLIC_LEN, 'ratchet public key');
  requireLength(selfRatchetSecret, X25519_SECRET_LEN, 'ratchet secret key');

  const flags = r.u8();
  if ((flags & ~KNOWN_FLAGS) !== 0) fail('malformed_token', `unknown session flag bits in 0x${flags.toString(16)}`);
  const peerRatchetPublic = (flags & FLAG_PEER_RATCHET) !== 0 ? r.blob() : undefined;
  const sendChainKey = (flags & FLAG_SEND_CHAIN) !== 0 ? r.blob() : undefined;
  const recvChainKey = (flags & FLAG_RECV_CHAIN) !== 0 ? r.blob() : undefined;
  const previousPeerRatchetPublic = (flags & FLAG_PREV_PEER_RATCHET) !== 0 ? r.blob() : undefined;
  if (peerRatchetPublic !== undefined) requireLength(peerRatchetPublic, X25519_PUBLIC_LEN, 'peer ratchet public key');
  if (sendChainKey !== undefined) requireLength(sendChainKey, KEY_LEN, 'send chain key');
  if (recvChainKey !== undefined) requireLength(recvChainKey, KEY_LEN, 'receive chain key');
  if (previousPeerRatchetPublic !== undefined) {
    requireLength(previousPeerRatchetPublic, X25519_PUBLIC_LEN, 'previous peer ratchet public key');
  }

  const sendCount = r.u32();
  const recvCount = r.u32();
  const previousSendCount = r.u32();
  const peerChainEpoch = r.u32();

  const skippedCount = r.u32();
  // The live engine never parks more than MAX_SKIP keys, so a count above it
  // cannot have come from serializeSession. Refusing here keeps a restored
  // session inside the same memory bound the ratchet enforces on the wire.
  if (skippedCount > MAX_SKIP) {
    fail('malformed_token', `claims ${skippedCount} skipped keys, limit is ${MAX_SKIP}`);
  }
  const skippedKeys: Record<string, Uint8Array> = {};
  for (let i = 0; i < skippedCount; i++) {
    const id = r.text();
    const key = r.blob();
    requireLength(key, KEY_LEN, `skipped message key ${id}`);
    // A duplicate id would make two distinct strings decode to the same state,
    // and the last write would silently win. Refuse instead.
    if (skippedKeys[id] !== undefined) fail('malformed_token', `duplicate skipped key id ${id}`);
    skippedKeys[id] = key;
  }
  r.end();

  return {
    conversationId,
    role,
    peer: { classicalPublic, pqPublic, sigPublic },
    rootKey,
    selfRatchetPublic,
    selfRatchetSecret,
    sendCount,
    recvCount,
    previousSendCount,
    peerChainEpoch,
    skippedKeys,
    ...(peerRatchetPublic ? { peerRatchetPublic } : {}),
    ...(sendChainKey ? { sendChainKey } : {}),
    ...(recvChainKey ? { recvChainKey } : {}),
    ...(previousPeerRatchetPublic ? { previousPeerRatchetPublic } : {}),
  };
}

// ---------------------------------------------------------------------------
// PendingSession
// ---------------------------------------------------------------------------

/**
 * A sent invite that has not been answered yet. Contains no secret material,
 * only the public identity snapshot and a timestamp, but it still has to
 * survive a restart: without it the eventual accept has nothing to match
 * against and the invite is dead.
 */
export function serializePending(pending: PendingSession): string {
  const w = new Writer();
  w.text(pending.conversationId);
  // `role` is not encoded. The type admits exactly one value, so a role byte
  // here could never carry information, it could only ever be wrong.
  w.blob(pending.selfIdentitySnapshot.classicalPublic);
  w.blob(pending.selfIdentitySnapshot.pqPublic);
  w.blob(pending.selfIdentitySnapshot.sigPublic);
  w.text(pending.createdAt);
  return encodeState('pending', w.finish());
}

export function deserializePending(value: string): PendingSession {
  const r = new Reader(decodeState('pending', value));
  const conversationId = r.text();
  const classicalPublic = r.blob();
  const pqPublic = r.blob();
  const sigPublic = r.blob();
  const createdAt = r.text();
  r.end();
  requireLength(classicalPublic, X25519_PUBLIC_LEN, 'snapshot classical public key');
  requireLength(pqPublic, MLKEM768_PUBLIC_LEN, 'snapshot ML-KEM public key');
  requireLength(sigPublic, MLDSA65_PUBLIC_LEN, 'snapshot ML-DSA public key');
  return {
    conversationId,
    role: 'initiator',
    selfIdentitySnapshot: { classicalPublic, pqPublic, sigPublic },
    createdAt,
  };
}

// ---------------------------------------------------------------------------
// IdentityKeyPair
// ---------------------------------------------------------------------------

/**
 * The long term identity as one storable string.
 *
 * READ THIS BEFORE USING IT. The string IS the identity. It contains both
 * private keys, so anyone who obtains it can impersonate this identity and
 * decrypt every handshake ever addressed to it, including recorded past ones,
 * because the handshake secret has no forward secrecy of its own. Leaking it
 * is total compromise with no recovery short of abandoning the identity.
 *
 * The library will not encrypt this for you and that is a design decision,
 * not an omission: at-rest encryption needs a key, and where that key lives
 * (OS keychain, hardware token, user passphrase) is a platform question the
 * caller must answer. Store the string like the private key it is, and never
 * let it near a log line, a URL, or an error report.
 */
export function exportIdentity(identity: IdentityKeyPair): string {
  const w = new Writer();
  w.blob(identity.classicalPublic);
  w.blob(identity.classicalSecret);
  w.blob(identity.pqPublic);
  w.blob(identity.pqSecret);
  w.blob(identity.sigPublic);
  w.blob(identity.sigSecret);
  // Stored rather than recomputed on import. ML-DSA signing is hedged, so a
  // recomputed certificate would be a different 3309 bytes every time the CLI
  // loads its identity, and it would cost 8 ms on every single command.
  w.blob(identity.certificate);
  return encodeState('identity', w.finish());
}

export function importIdentity(value: string): IdentityKeyPair {
  const r = new Reader(decodeState('identity', value));
  const classicalPublic = r.blob();
  const classicalSecret = r.blob();
  const pqPublic = r.blob();
  const pqSecret = r.blob();
  const sigPublic = r.blob();
  const sigSecret = r.blob();
  const certificate = r.blob();
  r.end();
  requireLength(classicalPublic, X25519_PUBLIC_LEN, 'classical public key');
  requireLength(classicalSecret, X25519_SECRET_LEN, 'classical secret key');
  requireLength(pqPublic, MLKEM768_PUBLIC_LEN, 'ML-KEM public key');
  requireLength(pqSecret, MLKEM768_SECRET_LEN, 'ML-KEM secret key');
  requireLength(sigPublic, MLDSA65_PUBLIC_LEN, 'ML-DSA public key');
  requireLength(sigSecret, MLDSA65_SECRET_LEN, 'ML-DSA secret key');
  requireLength(certificate, MLDSA65_SIGNATURE_LEN, 'identity certificate');
  return { classicalPublic, classicalSecret, pqPublic, pqSecret, sigPublic, sigSecret, certificate };
}
