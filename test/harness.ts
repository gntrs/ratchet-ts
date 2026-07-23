/**
 * Shared plumbing for the suite.
 *
 * Every test drives the real engine through the real wire format. Nothing here
 * reaches past src/index.ts except where a test deliberately plays the role of
 * a network attacker, which is the only reason the envelope codec is imported
 * directly: an attacker gets to see and edit the token, so the tests must be
 * able to as well.
 */

import assert from 'node:assert/strict';
import { engine, isCryptoFailure } from '../src/index.js';
import type {
  CryptoFailureReason,
  EnvelopeToken,
  IdentityKeyPair,
  MessagePayload,
  SessionState,
} from '../src/contract.js';
import { decodeEnvelope, encodeEnvelope } from '../src/envelope.js';

/** A live participant. Mutable on purpose: sessions advance with every call. */
export interface Party {
  readonly name: string;
  readonly identity: IdentityKeyPair;
  session: SessionState;
}

/** Runs the full invite/accept exchange and returns both sides, ready to talk. */
export async function connectedPair(): Promise<{ alice: Party; bob: Party }> {
  const aliceIdentity = await engine.createIdentity();
  const bobIdentity = await engine.createIdentity();

  const invited = await engine.invite(aliceIdentity);

  const bobOpened = await engine.open(bobIdentity, invited.token, {});
  assert.equal(bobOpened.outcome, 'invite');
  if (bobOpened.outcome !== 'invite') throw new Error('unreachable');

  const aliceOpened = await engine.open(aliceIdentity, bobOpened.reply, { pending: invited.pending });
  assert.equal(aliceOpened.outcome, 'accepted');
  if (aliceOpened.outcome !== 'accepted') throw new Error('unreachable');

  // Both sides must land on the same view of who they are talking to, or the
  // fingerprint the user reads out is meaningless.
  assert.deepEqual(bobOpened.peerFingerprint.words, engine.fingerprint(engine.publicOf(aliceIdentity)).words);
  assert.deepEqual(aliceOpened.peerFingerprint.words, engine.fingerprint(engine.publicOf(bobIdentity)).words);

  return {
    alice: { name: 'alice', identity: aliceIdentity, session: aliceOpened.session },
    bob: { name: 'bob', identity: bobIdentity, session: bobOpened.session },
  };
}

/** Seals a message and advances the sender. Returns the token that goes on the wire. */
export async function send(from: Party, plaintext: string): Promise<EnvelopeToken> {
  const sealed = await engine.seal(from.session, plaintext);
  from.session = sealed.session;
  return sealed.token;
}

/** Opens a message and advances the receiver. */
export async function receive(to: Party, token: EnvelopeToken): Promise<string> {
  const opened = await engine.open(to.identity, token, { session: to.session });
  assert.equal(opened.outcome, 'message');
  if (opened.outcome !== 'message') throw new Error('unreachable');
  to.session = opened.session;
  return opened.plaintext;
}

/**
 * Deep copy of a session, byte arrays included.
 *
 * The engine returns a new session object per call but reuses the underlying
 * arrays where it can, so a shallow copy would quietly track the live session
 * and every staleness test would pass for the wrong reason.
 */
export function cloneSession(session: SessionState): SessionState {
  const skippedKeys: Record<string, Uint8Array> = {};
  for (const [id, key] of Object.entries(session.skippedKeys)) {
    skippedKeys[id] = Uint8Array.from(key);
  }
  return {
    conversationId: session.conversationId,
    role: session.role,
    peer: {
      classicalPublic: Uint8Array.from(session.peer.classicalPublic),
      pqPublic: Uint8Array.from(session.peer.pqPublic),
    },
    rootKey: Uint8Array.from(session.rootKey),
    selfRatchetPublic: Uint8Array.from(session.selfRatchetPublic),
    selfRatchetSecret: Uint8Array.from(session.selfRatchetSecret),
    sendCount: session.sendCount,
    recvCount: session.recvCount,
    previousSendCount: session.previousSendCount,
    skippedKeys,
    ...(session.peerRatchetPublic ? { peerRatchetPublic: Uint8Array.from(session.peerRatchetPublic) } : {}),
    ...(session.sendChainKey ? { sendChainKey: Uint8Array.from(session.sendChainKey) } : {}),
    ...(session.recvChainKey ? { recvChainKey: Uint8Array.from(session.recvChainKey) } : {}),
  };
}

/** A party restored from a captured snapshot. Stands in for a compromised device. */
export function restore(from: Party, snapshot: SessionState): Party {
  return { name: `${from.name}-restored`, identity: from.identity, session: cloneSession(snapshot) };
}

/** Asserts the call fails closed with the exact reason, and returns nothing usable. */
export async function expectFailure(
  reason: CryptoFailureReason,
  run: () => Promise<unknown>,
): Promise<void> {
  try {
    await run();
  } catch (error) {
    // fail() returns never, which is also what narrows `error` for the line below.
    if (!isCryptoFailure(error)) assert.fail(`expected a CryptoFailure, got ${String(error)}`);
    assert.equal(error.reason, reason);
    return;
  }
  assert.fail(`expected ${reason} but the call succeeded`);
}

/** Decodes a message token, hands it to the caller to corrupt, and re-encodes it. */
export function editMessage(
  token: EnvelopeToken,
  edit: (payload: MessagePayload) => MessagePayload,
): EnvelopeToken {
  const payload = decodeEnvelope(token);
  assert.equal(payload.kind, 'message');
  if (payload.kind !== 'message') throw new Error('unreachable');
  return encodeEnvelope(edit(payload));
}

/** Flips the low bit of one byte. The smallest change an attacker can make. */
export function flipByte(bytes: Uint8Array, index: number): Uint8Array {
  const copy = Uint8Array.from(bytes);
  const current = copy[index];
  if (current === undefined) throw new Error(`index ${index} out of range`);
  copy[index] = current ^ 0x01;
  return copy;
}
