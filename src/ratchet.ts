import { x25519 } from '@noble/curves/ed25519.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes } from '@noble/hashes/utils.js';

import type { MessagePayload, SessionState } from './contract.js';
import { bytesToUtf8, equal, toBase64Url, utf8ToBytes, wipe } from './bytes.js';
import { messageAad } from './envelope.js';
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

  const recvDh = x25519.getSharedSecret(draft.selfRatchetSecret, payload.ratchetPublic);
  const recvStep = kdfRoot(draft.rootKey, recvDh);
  wipe(recvDh);
  draft.rootKey = recvStep.rootKey;
  draft.recvChainKey = recvStep.chainKey;

  const fresh = x25519.keygen();
  const sendDh = x25519.getSharedSecret(fresh.secretKey, payload.ratchetPublic);
  const sendStep = kdfRoot(draft.rootKey, sendDh);
  wipe(sendDh);
  draft.rootKey = sendStep.rootKey;
  draft.sendChainKey = sendStep.chainKey;
  draft.selfRatchetPublic = fresh.publicKey;
  draft.selfRatchetSecret = fresh.secretKey;
}

function open(messageKey: Uint8Array, payload: MessagePayload): string | null {
  const aad = messageAad(payload);
  try {
    const plain = xchacha20poly1305(messageKey, payload.nonce, aad).decrypt(payload.ciphertext);
    const text = bytesToUtf8(plain);
    wipe(plain);
    return text;
  } catch {
    // Poly1305 said no. There is nothing to recover here and no partial result
    // worth returning, so the only correct move is to fail closed.
    return null;
  }
}

export function ratchetEncrypt(session: SessionState, plaintext: string): { payload: MessagePayload; session: SessionState } {
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
  const ciphertext = xchacha20poly1305(step.messageKey, nonce, messageAad(header)).encrypt(utf8ToBytes(plaintext));
  wipe(step.messageKey);

  return {
    payload: { kind: 'message', ...header, ciphertext },
    session: { ...session, sendChainKey: step.nextChainKey, sendCount: session.sendCount + 1 },
  };
}

export function ratchetDecrypt(session: SessionState, payload: MessagePayload): { plaintext: string; session: SessionState } {
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
    const text = open(parked, payload);
    if (text === null) fail('authentication_failed', 'ciphertext failed authentication');
    const draft = draftOf(session);
    delete draft.skipped[parkedId];
    wipe(parked);
    return { plaintext: text, session: commit(session, draft) };
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
  const text = open(step.messageKey, payload);
  wipe(step.messageKey);
  if (text === null) fail('authentication_failed', 'ciphertext failed authentication');

  draft.recvChainKey = step.nextChainKey;
  draft.recvCount += 1;
  return { plaintext: text, session: commit(session, draft) };
}
