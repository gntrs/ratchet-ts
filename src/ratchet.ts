import type { EnvelopeBytes, MessagePayload, SessionState } from './contract.js';
import { openAeadSync, sealAeadSync } from './aead.js';
import { bytesToUtf8, equal, utf8ToBytes, wipe } from './bytes.js';
import { x25519Keygen, x25519SharedSecret } from './curves.js';
import type { EncodeEnvelopeBytesOptions, MessageHeader } from './envelope.js';
import {
  MESSAGE_NONCE_LEN,
  SESSION_TAG_LEN,
  conversationIdToBytes,
  decodeEnvelopeBytes,
  messageAad,
  messageHeaderLength,
  sealMessageEnvelope,
} from './envelope.js';
import { fail } from './errors.js';
import { fillRandom } from './hash.js';
import { X25519_PUBLIC_LEN } from './identity.js';
import { kdfChain, kdfRoot } from './kdf.js';

/**
 * RFC 8439 ChaCha20-Poly1305 nonce length. The nonce is random, and it is
 * transmitted.
 *
 * THIS CONSTANT HAS HELD THREE DIFFERENT ANSWERS AND ALL THREE ARGUMENTS ARE
 * WRITTEN DOWN HERE, because two of them were wrong in ways that are only
 * visible next to each other, and a reader who sees only the surviving one will
 * eventually rediscover the middle answer and think it is new.
 *
 * 0.3.x: 24 bytes, random, transmitted. Safe. 24 bytes is wide enough that
 * random nonces collide with negligible probability without any counter, so
 * nothing had to survive a state rollback. Nothing was wrong with it except its
 * price, which was 26 bytes on every frame and, on the native backend, an
 * HChaCha20 subkey derivation in TypeScript on every single message, because
 * node:crypto implements only the 12 byte form and the 24 byte XChaCha20 form
 * has to be reduced to it in userland first.
 *
 * 0.4.0-dev: 12 bytes, derived as `4 zero bytes || 8 byte big endian message
 * number`, not transmitted. Built, measured, and then rejected. The argument for
 * it was not wrong about what ChaCha20-Poly1305 requires. It requires exactly
 * one thing of its nonce, that the (key, nonce) pair never repeats, and it does
 * not require the nonce to be unpredictable, secret, or random. That condition
 * was met: the key is a message key from `kdfChain` and is already unique per
 * (chain, message number), so the nonce was never the thing carrying uniqueness
 * and a counter was sufficient. It was cheap and it was small and under correct
 * operation it was safe.
 *
 * IT WAS REJECTED FOR WHAT IT DID UNDER STATE ROLLBACK, meaning a session
 * restored from an older snapshot, a VM revert, a restore from backup, or a
 * crash that lost the last few state writes. After a rollback the sending chain
 * replays message keys it has already used, and the two schemes diverge sharply
 * on what that costs.
 *
 *   random nonce   two ciphertexts exist under one message key, so the Poly1305
 *                  one time key is reused and forgery becomes possible for an
 *                  observer holding both. Bad. But the two ciphertexts used
 *                  different nonces and therefore different keystreams, so no
 *                  plaintext XOR falls out. An integrity failure.
 *
 *   counter nonce  the replayed message number reproduces the exact nonce, so
 *                  the same key and the same nonce produce the same keystream,
 *                  and an observer with both ciphertexts recovers the XOR of the
 *                  two plaintexts directly. A confidentiality break.
 *
 * The counter turned a bad day into a disclosure. The defence written on that
 * version, that rollback is already fatal here for other reasons because a
 * rolled back receive chain re-accepts replays and a rolled back root key undoes
 * post compromise security, is true and is not enough. Those are integrity and
 * forward secrecy failures against an attacker who must actively do something.
 * Plaintext recovery from two passively captured frames is a different class of
 * outcome, and the goal for this library is maximum security ahead of speed.
 * "Already broken, so it does not matter how much more broken" is not a security
 * argument, it is a way of not counting.
 *
 * 0.4.0 as shipped: 12 bytes, random, transmitted. This is the point that keeps
 * what the counter was actually buying and gives back what it was actually
 * costing. Random restores rollback resilience exactly: two seals under one
 * replayed message key get independent keystreams, so the confidentiality break
 * above cannot occur and rollback is back to being an integrity failure. Twelve
 * bytes keeps the native node:crypto path with no HChaCha20 derivation in
 * TypeScript, which was the larger of the two savings the counter was chasing.
 * And 12 is half the wire cost of 0.3.x's 24. Nonce collision is not a concern
 * at this width for the reason the counter version already established: the
 * message key is unique per (chain, message number), so the nonce is not
 * carrying uniqueness. It is carrying rollback resilience, which is a property
 * random has and a counter does not, and that is the entire reason it is random.
 *
 * The measured cost of choosing random over the counter is one CSPRNG draw per
 * seal and 12 bytes per frame. That is the whole bill, and it is worth paying.
 *
 * None of this makes a restored snapshot safe to send from. `src/serialize.ts`
 * still tells callers to treat one as dead and re-handshake, and they still
 * should: this change bounds the damage when they do not, it does not remove it.
 *
 * The length lives in envelope.ts because envelope.ts owns the wire layout. This
 * is an alias so that reading the ratchet does not require opening two files,
 * not a second declaration that could drift.
 */
const NONCE_LEN = MESSAGE_NONCE_LEN;

/**
 * How many messages at the start of each sending chain repeat the ratchet public
 * key.
 *
 * The key is 32 bytes plus a varint, about 33 of the 67 byte step envelope, and
 * it is identical on every message of a chain. Sending it once would be enough
 * for a lossless transport and is what the 34 byte settled header assumes.
 *
 * It is not enough for a lossy one. A receiver cannot step its DH ratchet until
 * it sees the new key, so if the single message carrying it is dropped, every
 * later message in that chain is undecryptable: they arrive with no key, get
 * attributed to the old chain, and fail. The chain only recovers when the
 * direction changes again.
 *
 * Three is the compromise. Losing all three independently is unlikely enough to
 * ignore on any transport that is not adversarial, and the cost is 33 extra
 * bytes on two messages per chain rather than on every message. A chain of 20
 * messages pays 66 bytes instead of 660, so roughly 90 percent of the saving
 * survives. Raising it buys diminishing robustness at linear cost; lowering it
 * to 1 makes a single dropped packet poison a whole chain.
 */
export const RATCHET_KEY_RESEND = 3;

/**
 * Hard bound on how far a single inbound message may drag the receive chain
 * forward. Without it, one message claiming number 2^31 forces us to derive and
 * store that many keys, which is a memory exhaustion primitive handed to anyone
 * who can reach the inbox. It is a security control, not a tuning knob.
 */
export const MAX_SKIP = 1000;

/**
 * A fresh nonce for one seal.
 *
 * There is deliberately no second way to obtain one. No parameter, no option, no
 * injectable source, no "deterministic mode" for tests or for the vector
 * generator. Two nonce schemes reachable from one build is not a feature flag,
 * it is a second protocol sharing a wire format with the first, and the flag
 * would eventually be set wrong by someone who did not read the NONCE_LEN
 * comment above. `scripts/gen-vectors.mjs` needs reproducible frames and gets
 * them without a seam through this function: it never calls the seal path at
 * all, it rebuilds a frame from the primitives with the nonce as one more
 * pinned input, exactly as it already rebuilds the keys. A vector generator that
 * has to reach into the shipped seal to make it behave is a generator that is no
 * longer checking the shipped seal.
 *
 * The randomness comes through `fillRandom` in src/hash.ts rather than from
 * @noble/hashes directly. @noble's `randomBytes` measured about 0.8 microseconds
 * per call more than node:crypto `randomFillSync` at this size, roughly a third
 * of what carrying a random nonce costs at all, and the earlier version of this
 * comment argued that closing the gap was not worth a direct node:crypto import
 * in this file. That was right about the import and wrong about the conclusion:
 * src/hash.ts already owns the native probe, so the fix belongs there once for
 * every caller. It is the only native path in that file that is not verified
 * against a known answer, because a CSPRNG has none, and the comment on
 * `fillRandom` says so rather than letting it pass as the same discipline.
 */
function freshNonce(): Uint8Array {
  return fillRandom(new Uint8Array(NONCE_LEN));
}

/**
 * Key under which a skipped message key is parked.
 *
 * WHAT CHANGED, AND WHAT IT SAVED. 0.3.x built this from the 32 byte ratchet
 * public key, base64url encoded, on every single open, so that it could look up
 * a map that is empty in the overwhelmingly common in-order case. Measured at
 * 1.8 microseconds, about 9 percent of an open, spent producing a 43 character
 * string that was immediately thrown away.
 *
 * The chain epoch is a small integer that increments once per DH ratchet step,
 * so the id is a handful of characters built from two numbers. The lookup is
 * also skipped entirely when the map is empty, which is checked without
 * allocating (see `isEmptyRecord`), so the normal path now builds no string at
 * all.
 *
 * The epoch is meaningful only inside one session's own state, which is fine:
 * this map is per session and never crosses the wire.
 */
function skipKeyId(epoch: number, messageNumber: number): string {
  return `${epoch}:${messageNumber}`;
}

/**
 * True if the record has no own enumerable keys, without allocating.
 *
 * `Object.keys(x).length === 0` allocates an array to answer a yes or no
 * question, on a path that runs once per message. A for-in that returns on the
 * first key does not.
 */
function isEmptyRecord(record: Readonly<Record<string, unknown>>): boolean {
  for (const _key in record) return false;
  return true;
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
  conversationIdBytes: Uint8Array;
  rootKey: Uint8Array;
  selfRatchetPublic: Uint8Array;
  selfRatchetSecret: Uint8Array;
  peerRatchetPublic?: Uint8Array;
  previousPeerRatchetPublic?: Uint8Array;
  peerChainEpoch: number;
  sendChainKey?: Uint8Array;
  sendCount: number;
  recvChainKey?: Uint8Array;
  recvCount: number;
  previousSendCount: number;
  skipped: Record<string, Uint8Array>;
  skippedEmpty: boolean;
}

/**
 * The 16 raw conversation id bytes, parsed at most once per session rather than
 * once per message. See `SessionState.conversationIdBytes` for why the hex form
 * is still the canonical one.
 */
function conversationBytesOf(session: SessionState): Uint8Array {
  return session.conversationIdBytes ?? conversationIdToBytes(session.conversationId);
}

function draftOf(session: SessionState, conversationIdBytes: Uint8Array): Draft {
  return {
    conversationIdBytes,
    rootKey: session.rootKey,
    selfRatchetPublic: session.selfRatchetPublic,
    selfRatchetSecret: session.selfRatchetSecret,
    peerRatchetPublic: session.peerRatchetPublic,
    previousPeerRatchetPublic: session.previousPeerRatchetPublic,
    peerChainEpoch: session.peerChainEpoch ?? 0,
    sendChainKey: session.sendChainKey,
    sendCount: session.sendCount,
    recvChainKey: session.recvChainKey,
    recvCount: session.recvCount,
    previousSendCount: session.previousSendCount,
    skipped: { ...session.skippedKeys },
    skippedEmpty: isEmptyRecord(session.skippedKeys),
  };
}

function commit(session: SessionState, draft: Draft): SessionState {
  return {
    conversationId: session.conversationId,
    conversationIdBytes: draft.conversationIdBytes,
    role: session.role,
    peer: session.peer,
    rootKey: draft.rootKey,
    selfRatchetPublic: draft.selfRatchetPublic,
    selfRatchetSecret: draft.selfRatchetSecret,
    peerRatchetPublic: draft.peerRatchetPublic,
    previousPeerRatchetPublic: draft.previousPeerRatchetPublic,
    peerChainEpoch: draft.peerChainEpoch,
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
    draft.skipped[skipKeyId(draft.peerChainEpoch, draft.recvCount)] = step.messageKey;
    draft.skippedEmpty = false;
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
function dhRatchet(draft: Draft, ratchetPublic: Uint8Array, previousChainLength: number): void {
  // Skipped keys are filed under the OLD chain epoch, so this has to happen
  // before the epoch advances.
  skipTo(draft, previousChainLength);

  draft.previousSendCount = draft.sendCount;
  draft.sendCount = 0;
  draft.recvCount = 0;
  // Kept for exactly one reason: a message from the chain we are leaving may
  // still be in flight, and if it does not carry the ratchet key (see
  // RATCHET_KEY_RESEND) the only way to rebuild its AAD is from this field.
  draft.previousPeerRatchetPublic = draft.peerRatchetPublic;
  draft.peerRatchetPublic = ratchetPublic;
  draft.peerChainEpoch += 1;

  const recvDh = x25519SharedSecret(draft.selfRatchetSecret, ratchetPublic);
  const recvStep = kdfRoot(draft.rootKey, recvDh);
  wipe(recvDh);
  draft.rootKey = recvStep.rootKey;
  draft.recvChainKey = recvStep.chainKey;

  const fresh = x25519Keygen();
  const sendDh = x25519SharedSecret(fresh.secretKey, ratchetPublic);
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
 * `chainRatchetPublic` is the sending chain's public key. It is on the wire only
 * on the first `RATCHET_KEY_RESEND` messages of a chain, and it is bound into
 * the AAD on all of them, so the caller has to supply it from session state when
 * the header does not carry it. Supplying the wrong one produces a bad tag,
 * which is the point: the binding survives the key leaving the wire.
 *
 * The synchronous variant is deliberate. `openAeadSync` picks the backend from
 * an already resolved cache, so it never awaits, and the whole ratchet API is
 * synchronous underneath the async engine facade. Reaching for the promise
 * returning form here would make every caller async for no change in output.
 */
function open(
  messageKey: Uint8Array,
  payload: MessagePayload,
  conversationId: Uint8Array,
  chainRatchetPublic: Uint8Array,
): Uint8Array | null {
  const aad = messageAad(payload, conversationId, chainRatchetPublic);
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
 * The one seal implementation, shared by the payload API and the envelope API.
 *
 * WHY IT RETURNS AN ENVELOPE RATHER THAN A PAYLOAD. The header is the associated
 * data. Building a payload first and encoding it afterwards would mean writing
 * the header once for the AEAD and once for the wire, which is precisely the
 * double serialization this rewrite exists to delete: it measured 3.7
 * microseconds of a 21.6 microsecond seal in 0.3.4. So the header is written
 * once, straight into the output buffer, and that exact subarray is handed to
 * the AEAD. `ratchetEncryptBytes` then presents a payload view over the result
 * rather than the other way round.
 */
interface SealedMessage {
  envelope: Uint8Array;
  header: MessageHeader;
  headerLength: number;
  session: SessionState;
}

function sealStep(session: SessionState, plaintext: Uint8Array, reserve: number): SealedMessage {
  if (session.sendChainKey === undefined) {
    fail('no_session', 'no send chain yet, wait for the peer to send the first message');
  }
  const conversationId = conversationBytesOf(session);
  const sessionTag = conversationId.subarray(0, SESSION_TAG_LEN);
  const nonce = freshNonce();
  const header: MessageHeader =
    session.sendCount < RATCHET_KEY_RESEND
      ? {
          sessionTag,
          messageNumber: session.sendCount,
          nonce,
          ratchetPublic: session.selfRatchetPublic,
          previousChainLength: session.previousSendCount,
        }
      : { sessionTag, messageNumber: session.sendCount, nonce };

  const step = kdfChain(session.sendChainKey);
  const envelope = sealMessageEnvelope(
    header,
    conversationId,
    session.selfRatchetPublic,
    plaintext.length,
    (aad) => sealAeadSync(step.messageKey, nonce, plaintext, aad),
    reserve,
  );
  wipe(step.messageKey);

  return {
    envelope,
    header,
    headerLength: messageHeaderLength(header),
    session: {
      ...session,
      conversationIdBytes: conversationId,
      sendChainKey: step.nextChainKey,
      sendCount: session.sendCount + 1,
    },
  };
}

/**
 * Byte-level encrypt. This is the ratchet itself: the string API below is a
 * UTF-8 shim over this function, not a second implementation.
 *
 * Interop rule, stated here so it cannot drift: the wire format is raw bytes.
 * The string path UTF-8 encodes before sealing and UTF-8 decodes after opening,
 * so a message sealed by either API opens under both. Bytes sealed here come out
 * of the string API as their UTF-8 decoding (lossy if the bytes were not valid
 * UTF-8, so use the bytes API for binary payloads), and a sealed string comes
 * out of the bytes API as exactly its UTF-8 encoding.
 *
 * `payload.ciphertext` is a view into the envelope this function built, not a
 * separate allocation, and `payload.sessionTag` is a view into the session's
 * cached conversation id. Neither is written to after it is returned. Treat the
 * payload as read only, which the type already says.
 *
 * The plaintext buffer belongs to the caller and is neither modified nor wiped
 * here. Zero it after the call if it is secret.
 */
export function ratchetEncryptBytes(
  session: SessionState,
  plaintext: Uint8Array,
): { payload: MessagePayload; session: SessionState } {
  const sealed = sealStep(session, plaintext, 0);
  return {
    payload: {
      kind: 'message',
      ...sealed.header,
      ciphertext: sealed.envelope.subarray(sealed.headerLength),
    },
    session: sealed.session,
  };
}

/**
 * String encrypt. Signature and behaviour are unchanged from before the byte
 * layer existed: existing callers must never notice the refactor. It is a thin
 * shim so there is exactly one ratchet implementation to audit. The transient
 * UTF-8 copy is ours alone, which is why wiping it here is safe.
 */
export function ratchetEncrypt(
  session: SessionState,
  plaintext: string,
): { payload: MessagePayload; session: SessionState } {
  const encoded = utf8ToBytes(plaintext);
  const sealed = ratchetEncryptBytes(session, encoded);
  wipe(encoded);
  return sealed;
}

/** One place a parked message key might be, and the chain key its AAD needs. */
interface ParkedCandidate {
  epoch: number;
  chainPublic: Uint8Array;
}

/**
 * Where a late message's parked key could be filed.
 *
 * At most two places, and the reason there are two rather than one is the
 * ratchet key leaving the wire. A message that carries the key names its own
 * chain, so it resolves to exactly one epoch. A message that does not carry it
 * is presumed to belong to the current receive chain, which is right almost
 * always, and wrong for a message from the chain we just left that was in flight
 * during a direction change. The previous chain is therefore checked too. The
 * AAD binds the chain key, so a wrong guess cannot open anything: the fallback
 * costs an extra failed Poly1305 in the rare case and nothing at all in the
 * common one, because the whole block is skipped when nothing is parked.
 *
 * Chains older than one back are not reachable this way. 0.3.x could reach them,
 * because every message carried its own chain key. That is a real narrowing, and
 * it is bounded by the same thing that bounds the map: MAX_SKIP entries, which a
 * two chain window covers in every ordering a non-adversarial transport
 * produces.
 */
function parkedCandidates(draft: Draft, payload: MessagePayload): ParkedCandidate[] {
  if (payload.ratchetPublic !== undefined) {
    const key = payload.ratchetPublic;
    if (draft.peerRatchetPublic !== undefined && equal(draft.peerRatchetPublic, key)) {
      return [{ epoch: draft.peerChainEpoch, chainPublic: key }];
    }
    if (draft.previousPeerRatchetPublic !== undefined && equal(draft.previousPeerRatchetPublic, key)) {
      return [{ epoch: draft.peerChainEpoch - 1, chainPublic: key }];
    }
    return [];
  }
  const out: ParkedCandidate[] = [];
  if (draft.peerRatchetPublic !== undefined) {
    out.push({ epoch: draft.peerChainEpoch, chainPublic: draft.peerRatchetPublic });
  }
  if (draft.previousPeerRatchetPublic !== undefined) {
    out.push({ epoch: draft.peerChainEpoch - 1, chainPublic: draft.previousPeerRatchetPublic });
  }
  return out;
}

/**
 * Byte-level decrypt, the mirror of `ratchetEncryptBytes` and the single real
 * implementation of the receive side. See the interop rule on
 * `ratchetEncryptBytes`: the envelope carries raw bytes, so this opens anything
 * the string API sealed and vice versa.
 *
 * The returned plaintext buffer is owned by the caller. It is a fresh
 * allocation per call, so wiping it after use is both safe and encouraged when
 * the payload is secret.
 */
export function ratchetDecryptBytes(
  session: SessionState,
  payload: MessagePayload,
): { plaintext: Uint8Array; session: SessionState } {
  const conversationId = conversationBytesOf(session);
  // Four bytes of routing, not four bytes of security. A collision here sends
  // the frame to the wrong session, where the full 16 bytes in the AAD make it
  // fail to open rather than open as the wrong conversation.
  if (!equal(payload.sessionTag, conversationId.subarray(0, SESSION_TAG_LEN))) {
    fail('no_session', 'message belongs to a different conversation');
  }
  if (payload.ratchetPublic !== undefined && payload.ratchetPublic.length !== X25519_PUBLIC_LEN) {
    fail('malformed_token', `ratchet public key must be ${X25519_PUBLIC_LEN} bytes`);
  }

  const draft = draftOf(session, conversationId);

  // A parked key is the only path that does not touch the chains, so try it
  // first. Once used it is deleted, which is also what makes a second delivery
  // of the same message land in the replay branch below. Skipped entirely when
  // nothing is parked, which is the normal case and costs one for-in that
  // returns immediately.
  if (!draft.skippedEmpty) {
    let sawParked = false;
    for (const candidate of parkedCandidates(draft, payload)) {
      const id = skipKeyId(candidate.epoch, payload.messageNumber);
      const parked = draft.skipped[id];
      if (parked === undefined) continue;
      sawParked = true;
      const plain = open(parked, payload, conversationId, candidate.chainPublic);
      if (plain === null) continue;
      delete draft.skipped[id];
      wipe(parked);
      return { plaintext: plain, session: commit(session, draft) };
    }
    // Only a hard failure when the header named its own chain. Then the parked
    // entry we found is provably the right key for this message number and a bad
    // tag is a bad tag.
    //
    // When the chain was GUESSED, because the key is not on the wire, a parked
    // entry under the same number can belong to a different chain entirely:
    // message 5 of the previous chain can be parked while message 5 of the
    // current chain is arriving legitimately. Failing here would reject it. So
    // the guess falls through to the chain path, which either opens it or
    // reports replay, and the wasted work is one Poly1305 in a rare case.
    if (sawParked && payload.ratchetPublic !== undefined) {
      fail('authentication_failed', 'ciphertext failed authentication');
    }
  }

  // No key on the wire means "same chain as the last one you saw". That is the
  // whole point of RATCHET_KEY_RESEND: a chain announces itself a few times and
  // then goes quiet.
  const sameChain =
    payload.ratchetPublic === undefined ||
    (draft.peerRatchetPublic !== undefined && equal(draft.peerRatchetPublic, payload.ratchetPublic));
  if (!sameChain) {
    const key = payload.ratchetPublic;
    if (draft.previousPeerRatchetPublic !== undefined && key !== undefined && equal(draft.previousPeerRatchetPublic, key)) {
      // Names the chain we already left, and its parked key is gone or was never
      // parked. Stepping the ratchet backwards is not a thing, so this is a
      // duplicate of something already consumed.
      fail('replay_detected', `message ${payload.messageNumber} was already consumed`);
    }
    dhRatchet(draft, payload.ratchetPublic as Uint8Array, payload.previousChainLength ?? 0);
  }

  skipTo(draft, payload.messageNumber);

  if (draft.recvChainKey === undefined) fail('no_session', 'no receive chain for this message');
  if (payload.messageNumber !== draft.recvCount) {
    // We already walked past this number and its parked key is gone, so this is
    // either a duplicate or a deliberate replay. Same handling either way.
    fail('replay_detected', `message ${payload.messageNumber} was already consumed`);
  }

  const step = kdfChain(draft.recvChainKey);
  const chainPublic = payload.ratchetPublic ?? (draft.peerRatchetPublic as Uint8Array);
  const plain = open(step.messageKey, payload, conversationId, chainPublic);
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
export function ratchetDecrypt(
  session: SessionState,
  payload: MessagePayload,
): { plaintext: string; session: SessionState } {
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
 * spells the layer out.
 *
 * There is no second state machine here. This and `ratchetEncryptBytes` are the
 * same `sealStep` call; the difference is only that this one hands back the
 * buffer `sealStep` produced and the other presents a payload view over it. This
 * is now the cheaper of the two, because the payload path has to be re-encoded
 * by `encodeEnvelopeBytes` to reach a wire frame and that re-encoding copies the
 * ciphertext a second time.
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
  const sealed = sealStep(session, plaintext, options?.reserve ?? 0);
  return { envelope: sealed.envelope, session: sealed.session };
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
 * chunk belongs is not speaking the protocol, whichever encoding it used.
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
  // field: the AAD binds the header and not the ciphertext, and the two fields
  // that are compared against or stored in session state, `sessionTag` and
  // `ratchetPublic`, are still copied by the decoder. So the caller is free to
  // reuse `envelope` the moment this returns, which is what a socket reader
  // will do.
  const payload = decodeEnvelopeBytes(envelope, { borrowCiphertext: true });
  if (payload.kind !== 'message') {
    fail('malformed_token', `expected a message envelope, got ${payload.kind}`);
  }
  return ratchetDecryptBytes(session, payload);
}
