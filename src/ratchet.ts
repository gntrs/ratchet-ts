import { randomBytes } from '@noble/hashes/utils.js';

import type { EnvelopeBytes, MessagePayload, SessionState } from './contract.js';
import { openAeadSync, sealAeadSync } from './aead.js';
import { bytesToUtf8, equal, toBase64Url, utf8ToBytes, wipe } from './bytes.js';
import { x25519Keygen, x25519SharedSecret } from './curves.js';
import type { EncodeEnvelopeBytesOptions } from './envelope.js';
import { decodeEnvelopeBytes, encodeEnvelopeBytes, messageAad } from './envelope.js';
import { fail } from './errors.js';
import { X25519_PUBLIC_LEN } from './identity.js';
import { kdfChain, kdfRoot } from './kdf.js';

/** XChaCha20-Poly1305. 24 byte nonce, which is wide enough that random nonces
 * are safe without a counter, so nothing has to survive a state rollback. */
const NONCE_LEN = 24;

/**
 * Hard bound on how far a single inbound message may drag the receive chain
 * forward. Without it, one message claiming number 2^31 forces us to derive and
 * store that many keys, which is a memory exhaustion primitive handed to anyone
 * who can reach the inbox. It is a security control, not a tuning knob.
 */
export const MAX_SKIP = 1000;

function skipKeyId(ratchetPublic: Uint8Array, messageNumber: number): string {
  return `${toBase64Url(ratchetPublic)}:${messageNumber}`;
}

/**
 * Mutable working copy of the parts of a session the ratchet touches.
 *
 * Every decrypt runs against a draft and only becomes the caller's new session
 * if the AEAD tag verified. That is what stops a forged message from being able
 * to force a DH ratchet step, burn skipped keys, or otherwise wreck a session
 * it cannot read. Failure leaves the caller's state untouched.
 */
interface Draft {
  rootKey: Uint8Array;
  selfRatchetPublic: Uint8Array;
  selfRatchetSecret: Uint8Array;
  peerRatchetPublic?: Uint8Array;
  sendChainKey?: Uint8Array;
  sendCount: number;
  recvChainKey?: Uint8Array;
  recvCount: number;
  previousSendCount: number;
  skipped: Record<string, Uint8Array>;
}

function draftOf(session: SessionState): Draft {
  return {
    rootKey: session.rootKey,
    selfRatchetPublic: session.selfRatchetPublic,
    selfRatchetSecret: session.selfRatchetSecret,
    peerRatchetPublic: session.peerRatchetPublic,
    sendChainKey: session.sendChainKey,
    sendCount: session.sendCount,
    recvChainKey: session.recvChainKey,
    recvCount: session.recvCount,
    previousSendCount: session.previousSendCount,
    skipped: { ...session.skippedKeys },
  };
}

function commit(session: SessionState, draft: Draft): SessionState {
  return {
    conversationId: session.conversationId,
    role: session.role,
    peer: session.peer,
    rootKey: draft.rootKey,
    selfRatchetPublic: draft.selfRatchetPublic,
    selfRatchetSecret: draft.selfRatchetSecret,
    peerRatchetPublic: draft.peerRatchetPublic,
    sendChainKey: draft.sendChainKey,
    sendCount: draft.sendCount,
    recvChainKey: draft.recvChainKey,
    recvCount: draft.recvCount,
    previousSendCount: draft.previousSendCount,
    skippedKeys: draft.skipped,
  };
}

/**
 * Advance the receive chain to `until`, parking the message keys we stepped
 * over so the messages that are merely late can still be read.
 */
function skipTo(draft: Draft, until: number): void {
  if (draft.recvChainKey === undefined || draft.peerRatchetPublic === undefined) return;
  if (until <= draft.recvCount) return;
  const ahead = until - draft.recvCount;
  if (ahead > MAX_SKIP || Object.keys(draft.skipped).length + ahead > MAX_SKIP) {
    fail('skip_limit_exceeded', `refusing to skip ${ahead} messages, limit is ${MAX_SKIP}`);
  }
  while (draft.recvCount < until) {
    const step = kdfChain(draft.recvChainKey);
    draft.skipped[skipKeyId(draft.peerRatchetPublic, draft.recvCount)] = step.messageKey;
    draft.recvChainKey = step.nextChainKey;
    draft.recvCount += 1;
  }
}

/**
 * DH ratchet step. Runs when the peer's ratchet public changes, which is once
 * per direction change. It gives post-compromise security: an attacker holding
 * a stolen chain key is locked out again as soon as one of these lands, because
 * the new root depends on a private key they never saw.
 */
function dhRatchet(draft: Draft, payload: MessagePayload): void {
  // Skipped keys are filed under the OLD peer ratchet public, so this has to
  // happen before we adopt the new one.
  skipTo(draft, payload.previousChainLength);

  draft.previousSendCount = draft.sendCount;
  draft.sendCount = 0;
  draft.recvCount = 0;
  draft.peerRatchetPublic = payload.ratchetPublic;

  const recvDh = x25519SharedSecret(draft.selfRatchetSecret, payload.ratchetPublic);
  const recvStep = kdfRoot(draft.rootKey, recvDh);
  wipe(recvDh);
  draft.rootKey = recvStep.rootKey;
  draft.recvChainKey = recvStep.chainKey;

  const fresh = x25519Keygen();
  const sendDh = x25519SharedSecret(fresh.secretKey, payload.ratchetPublic);
  const sendStep = kdfRoot(draft.rootKey, sendDh);
  wipe(sendDh);
  draft.rootKey = sendStep.rootKey;
  draft.sendChainKey = sendStep.chainKey;
  draft.selfRatchetPublic = fresh.publicKey;
  draft.selfRatchetSecret = fresh.secretKey;
}

/**
 * AEAD open at the byte layer. Every decrypt path funnels through here, so the
 * Poly1305 verdict is decided in exactly one place. Returns the raw plaintext
 * bytes; whether they mean UTF-8 text is the caller's business, not the AEAD's.
 *
 * The synchronous variant is deliberate. `openAeadSync` picks the backend from
 * an already resolved cache, so it never awaits, and the whole ratchet API is
 * synchronous underneath the async engine facade. Reaching for the promise
 * returning form here would make every caller async for no change in output.
 */
function open(messageKey: Uint8Array, payload: MessagePayload): Uint8Array | null {
  const aad = messageAad(payload);
  try {
    return openAeadSync(messageKey, payload.nonce, payload.ciphertext, aad);
  } catch {
    // Poly1305 said no. There is nothing to recover here and no partial result
    // worth returning, so the only correct move is to fail closed. Catching
    // rather than propagating also keeps the reason the caller sees decided by
    // the ratchet, which distinguishes a bad tag from a replay.
    return null;
  }
}

/**
 * Byte-level encrypt. This is the ratchet itself: the string API below is a
 * UTF-8 shim over this function, not a second implementation.
 *
 * Interop rule, stated here so it cannot drift: the wire format is raw bytes,
 * exactly as it was before this function existed. The string path UTF-8
 * encodes before sealing and UTF-8 decodes after opening, so a message sealed
 * by either API opens under both. Bytes sealed here come out of the string API
 * as their UTF-8 decoding (lossy if the bytes were not valid UTF-8, so use the
 * bytes API for binary payloads), and a sealed string comes out of the bytes
 * API as exactly its UTF-8 encoding.
 *
 * The plaintext buffer belongs to the caller and is neither modified nor wiped
 * here. Zero it after the call if it is secret.
 */
export function ratchetEncryptBytes(session: SessionState, plaintext: Uint8Array): { payload: MessagePayload; session: SessionState } {
  if (session.sendChainKey === undefined) {
    fail('no_session', 'no send chain yet, wait for the peer to send the first message');
  }
  const step = kdfChain(session.sendChainKey);
  const nonce = randomBytes(NONCE_LEN);
  const header = {
    conversationId: session.conversationId,
    ratchetPublic: session.selfRatchetPublic,
    messageNumber: session.sendCount,
    previousChainLength: session.previousSendCount,
    nonce,
  };
  const ciphertext = sealAeadSync(step.messageKey, nonce, plaintext, messageAad(header));
  wipe(step.messageKey);

  return {
    payload: { kind: 'message', ...header, ciphertext },
    session: { ...session, sendChainKey: step.nextChainKey, sendCount: session.sendCount + 1 },
  };
}

/**
 * String encrypt. Signature and behaviour are unchanged from before the byte
 * layer existed: existing callers must never notice the refactor. It is a thin
 * shim so there is exactly one ratchet implementation to audit. The transient
 * UTF-8 copy is ours alone, which is why wiping it here is safe.
 */
export function ratchetEncrypt(session: SessionState, plaintext: string): { payload: MessagePayload; session: SessionState } {
  const encoded = utf8ToBytes(plaintext);
  const sealed = ratchetEncryptBytes(session, encoded);
  wipe(encoded);
  return sealed;
}

/**
 * Byte-level decrypt, the mirror of `ratchetEncryptBytes` and the single real
 * implementation of the receive side. See the interop rule on
 * `ratchetEncryptBytes`: the token carries raw bytes, so this opens anything
 * the string API sealed and vice versa.
 *
 * The returned plaintext buffer is owned by the caller. It is a fresh
 * allocation per call, so wiping it after use is both safe and encouraged when
 * the payload is secret.
 */
export function ratchetDecryptBytes(session: SessionState, payload: MessagePayload): { plaintext: Uint8Array; session: SessionState } {
  if (payload.conversationId !== session.conversationId) {
    fail('no_session', 'message belongs to a different conversation');
  }
  if (payload.ratchetPublic.length !== X25519_PUBLIC_LEN) {
    fail('malformed_token', `ratchet public key must be ${X25519_PUBLIC_LEN} bytes`);
  }

  // A parked key is the only path that does not touch the chains, so try it
  // first. Once used it is deleted, which is also what makes a second delivery
  // of the same message land in the replay branch below.
  const parkedId = skipKeyId(payload.ratchetPublic, payload.messageNumber);
  const parked = session.skippedKeys[parkedId];
  if (parked !== undefined) {
    const plain = open(parked, payload);
    if (plain === null) fail('authentication_failed', 'ciphertext failed authentication');
    const draft = draftOf(session);
    delete draft.skipped[parkedId];
    wipe(parked);
    return { plaintext: plain, session: commit(session, draft) };
  }

  const draft = draftOf(session);
  const sameChain = draft.peerRatchetPublic !== undefined && equal(draft.peerRatchetPublic, payload.ratchetPublic);
  if (!sameChain) {
    dhRatchet(draft, payload);
  }

  skipTo(draft, payload.messageNumber);

  if (draft.recvChainKey === undefined) fail('no_session', 'no receive chain for this message');
  if (payload.messageNumber !== draft.recvCount) {
    // We already walked past this number and its parked key is gone, so this is
    // either a duplicate or a deliberate replay. Same handling either way.
    fail('replay_detected', `message ${payload.messageNumber} was already consumed`);
  }

  const step = kdfChain(draft.recvChainKey);
  const plain = open(step.messageKey, payload);
  wipe(step.messageKey);
  if (plain === null) fail('authentication_failed', 'ciphertext failed authentication');

  draft.recvChainKey = step.nextChainKey;
  draft.recvCount += 1;
  return { plaintext: plain, session: commit(session, draft) };
}

/**
 * String decrypt, unchanged signature and behaviour. Decodes the opened bytes
 * as UTF-8 and wipes the intermediate buffer, because once the text exists the
 * byte copy is just one more place the plaintext lives. Note the decode is
 * lossy on invalid UTF-8 (replacement characters), which is exactly why binary
 * payloads should travel through `ratchetDecryptBytes` instead.
 */
export function ratchetDecrypt(session: SessionState, payload: MessagePayload): { plaintext: string; session: SessionState } {
  const opened = ratchetDecryptBytes(session, payload);
  const text = bytesToUtf8(opened.plaintext);
  wipe(opened.plaintext);
  return { plaintext: text, session: opened.session };
}

// ---------------------------------------------------------------------------
// Binary envelope representation
// ---------------------------------------------------------------------------

/**
 * Seal plaintext bytes directly into a binary envelope.
 *
 * ON THE NAME, because this is the third thing in the package with "bytes" in
 * it and the other two mean different layers. `ratchetEncryptBytes` says the
 * PLAINTEXT is bytes, and it hands back a payload the caller still has to
 * encode somehow. `encodeEnvelopeBytes` says the ENVELOPE is bytes, and it
 * takes a payload that is already sealed. This function is both at once, so it
 * spells the layer out: the plaintext side is inherited unchanged from
 * `ratchetEncryptBytes`, and `ToEnvelopeBytes` names the representation coming
 * out. Any shorter name has to drop one of the two words that keep those layers
 * apart, and dropping either is exactly the confusion src/index.ts already
 * warns about beside the `encodeEnvelopeBytes` re-export.
 *
 * There is no second state machine here. The chain step, the AAD, the AEAD call
 * and the session advance are `ratchetEncryptBytes` called unchanged; the only
 * thing this function decides is which of the two envelope encoders runs on the
 * payload that comes out. So the token from `encodeEnvelope` and the bytes from
 * here are one envelope in two spellings rather than two formats, and byte
 * identity between the paths is a property of the encoders rather than an
 * invariant this function has to maintain. test/ratchet-bytes-path.test.ts pins
 * it anyway, because that is the promise 0.3.0 peers are relying on.
 *
 * It exists because the round trip it removes was pure waste. A caller on a
 * binary transport used to base64 the envelope into a token and immediately
 * decode it straight back into the bytes it already had, twice per chunk per
 * direction, for nothing.
 *
 * The plaintext buffer belongs to the caller and is neither modified nor wiped.
 *
 * `options.reserve` leaves that many zero bytes in front of the envelope inside
 * the SAME allocation, so a transport that prefixes a length can stamp it in
 * place instead of concatenating. It changes nothing about the envelope: the
 * bytes from index `reserve` onward are what a caller with no reserve would
 * have received, which is what makes this safe to use on a live wire.
 */
export function ratchetEncryptToEnvelopeBytes(
  session: SessionState,
  plaintext: Uint8Array,
  options?: EncodeEnvelopeBytesOptions,
): { envelope: EnvelopeBytes; session: SessionState } {
  const sealed = ratchetEncryptBytes(session, plaintext);
  return { envelope: encodeEnvelopeBytes(sealed.payload, options), session: sealed.session };
}

/**
 * Open a binary envelope to plaintext bytes. Mirror of the function above, and
 * the same claim about there being one implementation: everything after the
 * decode is `ratchetDecryptBytes`.
 *
 * Message envelopes only, for the reason `engine.openBytes` gives: invite and
 * accept are protocol steps that produce a session rather than a payload, so a
 * caller pulling file chunks off a socket has nothing sensible to do with one.
 * Refusing here instead of widening the return type keeps that caller's happy
 * path a single line.
 *
 * The reason is `malformed_token` so this agrees with `engine.openBytes` on
 * what a misplaced handshake envelope means: a peer that sends one where a
 * chunk belongs is not speaking the protocol, whichever encoding it used. The
 * wording says envelope rather than token because no token existed on this path.
 *
 * The returned plaintext is a fresh allocation the caller owns, so wiping it
 * after use is both safe and encouraged when the payload is secret.
 */
export function ratchetDecryptFromEnvelopeBytes(
  session: SessionState,
  envelope: EnvelopeBytes,
): { plaintext: Uint8Array; session: SessionState } {
  // borrowCiphertext, and this is the one call site in the package that earns
  // it. The decoded payload is local to this function and never escapes it, and
  // the only thing done with `payload.ciphertext` downstream is the single
  // `openAeadSync` call inside `open()`. Both AEAD backends allocate their own
  // output rather than handing back a view of their input, so the plaintext
  // returned from here does not alias `envelope` either. Nothing else reads the
  // field: `messageAad` binds the header and not the ciphertext, and the two
  // fields that do get stored in session state, `ratchetPublic` and `nonce`,
  // are still copied by the decoder. So the caller is free to reuse `envelope`
  // the moment this returns, which is what a socket reader will do.
  const payload = decodeEnvelopeBytes(envelope, { borrowCiphertext: true });
  if (payload.kind !== 'message') {
    fail('malformed_token', `expected a message envelope, got ${payload.kind}`);
  }
  return ratchetDecryptBytes(session, payload);
}
