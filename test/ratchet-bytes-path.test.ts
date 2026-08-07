import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from '@noble/hashes/utils.js';

import type {
  AcceptPayload,
  EnvelopePayload,
  InvitePayload,
  MessagePayload,
} from '../src/contract.js';
import { engine } from '../src/index.js';
import {
  decodeEnvelope,
  decodeEnvelopeBytes,
  encodeEnvelope,
  encodeEnvelopeBytes,
} from '../src/envelope.js';
import {
  MAX_SKIP,
  ratchetDecryptBytes,
  ratchetDecryptFromEnvelopeBytes,
  ratchetEncryptBytes,
  ratchetEncryptToEnvelopeBytes,
} from '../src/ratchet.js';
import { cloneSession, connectedPair, expectFailure, flipByte } from './harness.js';
import type { Party } from './harness.js';

/**
 * The bytes-native seal and open.
 *
 * The whole point of this pair is that it changes NOTHING on the wire. It skips
 * a base64 encode and an immediate base64 decode that a binary transport was
 * paying twice per chunk per direction, and a shortcut that alters the bytes is
 * not a shortcut, it is a fork of the protocol. So the first and heaviest test
 * here is byte identity against the path 0.3.0 shipped, and the second is that
 * envelopes cross between the two paths in both directions. Everything after
 * those two is the ratchet behaviour that must have come along unchanged,
 * which it should have, because the new functions call the same ones.
 *
 * "The path 0.3.0 shipped" means, precisely, what cli/protocol.mjs does today:
 *
 *   send     engine.sealBytes  -> token, then toWire   = encodeEnvelopeBytes(decodeEnvelope(token))
 *   receive  fromWire = encodeEnvelope(decodeEnvelopeBytes(frame)), then engine.openBytes
 *
 * Those four steps are spelled out rather than imported so this file keeps
 * testing the old shape even after the CLI stops using it.
 */

const SIZES = [0, 1, 255, 65_519];

/** What cli/protocol.mjs toWire() does: engine token to the bytes on the socket. */
function toWire(token: string): Uint8Array {
  return encodeEnvelopeBytes(decodeEnvelope(token));
}

/** What cli/protocol.mjs fromWire() does: bytes off the socket to an engine token. */
function fromWire(frame: Uint8Array): string {
  return encodeEnvelope(decodeEnvelopeBytes(frame));
}

/** Narrows a decoded envelope to a message payload or fails the test. */
function asMessage(payload: EnvelopePayload): MessagePayload {
  assert.equal(payload.kind, 'message');
  if (payload.kind !== 'message') throw new Error('unreachable');
  return payload;
}

/** Seals on the new path and advances the sender. Returns the wire bytes. */
function sendWire(from: Party, plaintext: Uint8Array): Uint8Array {
  const sealed = ratchetEncryptToEnvelopeBytes(from.session, plaintext);
  from.session = sealed.session;
  return sealed.envelope;
}

/** Opens on the new path and advances the receiver. */
function receiveWire(to: Party, frame: Uint8Array): Uint8Array {
  const opened = ratchetDecryptFromEnvelopeBytes(to.session, frame);
  to.session = opened.session;
  return opened.plaintext;
}

const CONVERSATION_ID = 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf';

function sampleInvite(): InvitePayload {
  return {
    kind: 'invite',
    conversationId: CONVERSATION_ID,
    sender: { classicalPublic: randomBytes(32), pqPublic: randomBytes(1184) },
  };
}

function sampleAccept(): AcceptPayload {
  return {
    kind: 'accept',
    conversationId: CONVERSATION_ID,
    sender: { classicalPublic: randomBytes(32), pqPublic: randomBytes(1184) },
    kemCiphertext: randomBytes(1088),
    ratchetPublic: randomBytes(32),
  };
}

function sampleMessage(plaintextLength: number): MessagePayload {
  return {
    kind: 'message',
    conversationId: CONVERSATION_ID,
    ratchetPublic: randomBytes(32),
    messageNumber: 7,
    previousChainLength: 3,
    nonce: randomBytes(24),
    ciphertext: randomBytes(plaintextLength + 16),
  };
}

// ---------------------------------------------------------------------------
// Wire identity
// ---------------------------------------------------------------------------

/**
 * The literal comparison the brief asks for, stated exactly as far as it can
 * honestly go.
 *
 * Sealing the same plaintext twice cannot produce the same bytes: the nonce is
 * 24 fresh random bytes per message, deliberately, so that no counter has to
 * survive a state rollback. What CAN be compared, and is the actual claim, is
 * that the two paths differ ONLY in which encoder runs over one sealed payload.
 * So this test takes a payload from a real seal and drives both encoders over
 * it, which is the whole of the difference between the paths, and then checks
 * the new path independently produces an envelope that agrees field for field
 * on everything except the nonce and the ciphertext it seals under that nonce.
 */
test('wire identity: the new seal emits exactly the bytes toWire made from the old token', async () => {
  const { alice } = await connectedPair();

  for (const size of SIZES) {
    const plaintext = randomBytes(size);

    // The 0.3.0 send path, in full.
    const before = cloneSession(alice.session);
    const old = ratchetEncryptBytes(alice.session, plaintext);
    alice.session = old.session;
    const oldFrame = toWire(encodeEnvelope(old.payload));

    // The new path's entire contribution: the other encoder on that payload.
    assert.deepEqual(encodeEnvelopeBytes(old.payload), oldFrame, `size ${size}`);

    // And the new path run for real, from a clone of the session the old seal
    // started from, so the two are answering the identical question.
    const fresh = ratchetEncryptToEnvelopeBytes(before, plaintext);
    const mine = asMessage(decodeEnvelopeBytes(fresh.envelope));
    const theirs = asMessage(decodeEnvelope(fromWire(oldFrame)));

    assert.equal(fresh.envelope.length, oldFrame.length, `size ${size} envelope length`);
    assert.equal(mine.conversationId, theirs.conversationId);
    assert.deepEqual(mine.ratchetPublic, theirs.ratchetPublic);
    assert.equal(mine.messageNumber, theirs.messageNumber);
    assert.equal(mine.previousChainLength, theirs.previousChainLength);
    assert.equal(mine.nonce.length, theirs.nonce.length);
    assert.equal(mine.ciphertext.length, theirs.ciphertext.length);
    // The one field that must differ, because a repeated nonce under one
    // message key is a total break. If this ever passes, the test above is
    // measuring a broken RNG rather than a faithful encoder.
    assert.notDeepEqual(mine.nonce, theirs.nonce);
  }
});

/**
 * The same identity at the envelope layer, for all three kinds and at the
 * sizes the CLI actually meets.
 *
 * Message is the kind the new seal produces, but the CLI pushes invite and
 * accept frames through the same toWire, so if the integrator moves those onto
 * the byte path too the conversion has to be exact for them as well. Cheap to
 * prove now, expensive to discover during a handshake against an older peer.
 */
test('wire identity holds for every envelope kind and every payload size', () => {
  const payloads: EnvelopePayload[] = [
    sampleInvite(),
    sampleAccept(),
    ...SIZES.map((size) => sampleMessage(size)),
  ];
  for (const payload of payloads) {
    const direct = encodeEnvelopeBytes(payload);
    const viaToken = toWire(encodeEnvelope(payload));
    assert.deepEqual(viaToken, direct, `${payload.kind} did not survive the token detour`);
    // Both directions of the detour, since fromWire is the receive half and an
    // asymmetry there would be just as fatal.
    assert.deepEqual(toWire(fromWire(direct)), direct);
    assert.deepEqual(decodeEnvelopeBytes(direct), payload);
  }
});

// ---------------------------------------------------------------------------
// Cross open, which is the 0.3.0 interop proof
// ---------------------------------------------------------------------------

test('a token from the 0.3.0 seal opens on the new bytes path', async () => {
  const { alice, bob } = await connectedPair();

  for (const size of SIZES) {
    const plaintext = randomBytes(size);
    const sealed = await engine.sealBytes(alice.session, plaintext);
    alice.session = sealed.session;
    // A 0.3.0 peer puts exactly toWire(token) on the socket.
    assert.deepEqual(receiveWire(bob, toWire(sealed.token)), plaintext, `size ${size}`);
  }
});

test('bytes from the new seal open on the 0.3.0 string path', async () => {
  const { alice, bob } = await connectedPair();

  for (const size of SIZES) {
    const plaintext = randomBytes(size);
    const frame = sendWire(alice, plaintext);
    // A 0.3.0 peer reads the socket and calls fromWire before engine.openBytes.
    const opened = await engine.openBytes(bob.session, fromWire(frame));
    bob.session = opened.session;
    assert.deepEqual(opened.plaintext, plaintext, `size ${size}`);
  }
});

test('a full conversation alternating between the two paths stays in step', async () => {
  const { alice, bob } = await connectedPair();

  for (let i = 0; i < 6; i += 1) {
    const plaintext = randomBytes(64 + i);
    if (i % 2 === 0) {
      const sealed = await engine.sealBytes(alice.session, plaintext);
      alice.session = sealed.session;
      assert.deepEqual(receiveWire(bob, toWire(sealed.token)), plaintext);
    } else {
      const frame = sendWire(alice, plaintext);
      const opened = await engine.openBytes(bob.session, fromWire(frame));
      bob.session = opened.session;
      assert.deepEqual(opened.plaintext, plaintext);
    }
  }
  assert.equal(alice.session.sendCount, 6);
  assert.equal(bob.session.recvCount, 6);
});

// ---------------------------------------------------------------------------
// The session must not have moved either
// ---------------------------------------------------------------------------

/**
 * Byte identity on the wire would still be a fork if the two paths left the
 * caller holding different state, because the next message would then be sealed
 * under a different chain. Sessions are compared whole, arrays included, which
 * `deepEqual` does for Uint8Array.
 *
 * The send side really is fully deterministic given the session: the random
 * nonce lands in the payload, never in the state.
 */
test('the session after the new seal is field for field the session after the old one', async () => {
  const { alice } = await connectedPair();

  for (const size of SIZES) {
    const plaintext = randomBytes(size);
    const start = cloneSession(alice.session);
    const oldWay = ratchetEncryptBytes(cloneSession(start), plaintext);
    const newWay = ratchetEncryptToEnvelopeBytes(cloneSession(start), plaintext);
    assert.deepEqual(newWay.session, oldWay.session, `size ${size}`);
    alice.session = newWay.session;
  }
});

test('the session after the new open is field for field the session after the old one', async () => {
  const { alice, bob } = await connectedPair();

  // One message first, to get the receive chain established. The very first
  // inbound message runs a DH ratchet step, and that step mints a fresh
  // keypair, so the state it produces is deliberately not reproducible. The
  // next test covers that case on its own terms rather than weakening this one.
  const opener = randomBytes(8);
  assert.deepEqual(receiveWire(bob, sendWire(alice, opener)), opener);

  for (const size of SIZES) {
    const frame = sendWire(alice, randomBytes(size));
    const start = cloneSession(bob.session);
    const oldWay = ratchetDecryptBytes(cloneSession(start), asMessage(decodeEnvelope(fromWire(frame))));
    const newWay = ratchetDecryptFromEnvelopeBytes(cloneSession(start), frame);
    assert.deepEqual(newWay.plaintext, oldWay.plaintext, `size ${size}`);
    assert.deepEqual(newWay.session, oldWay.session, `size ${size}`);
    bob.session = newWay.session;
  }
});

/**
 * The one place the two paths are allowed to end up holding different state,
 * and why that is correct rather than a bug in the shortcut.
 *
 * A DH ratchet step mints a fresh X25519 keypair, which is the entire mechanism
 * behind post-compromise security: an attacker holding a stolen chain key is
 * locked out the moment a step lands, precisely because the new root depends on
 * a private key they never saw. A step that produced the same keypair twice
 * would not do that. So the receive half, which is derived from state the caller
 * already had, must match to the byte, and the send half, which is derived from
 * the new secret, must not.
 */
test('a chain change agrees on everything except the fresh keypair it exists to mint', async () => {
  const { alice, bob } = await connectedPair();

  const plaintext = randomBytes(512);
  const frame = sendWire(alice, plaintext);
  const start = cloneSession(bob.session);
  const oldWay = ratchetDecryptBytes(cloneSession(start), asMessage(decodeEnvelope(fromWire(frame))));
  const newWay = ratchetDecryptFromEnvelopeBytes(cloneSession(start), frame);

  assert.deepEqual(newWay.plaintext, oldWay.plaintext);
  assert.deepEqual(newWay.session.recvChainKey, oldWay.session.recvChainKey);
  assert.equal(newWay.session.recvCount, oldWay.session.recvCount);
  assert.deepEqual(newWay.session.peerRatchetPublic, oldWay.session.peerRatchetPublic);
  assert.equal(newWay.session.sendCount, oldWay.session.sendCount);
  assert.equal(newWay.session.previousSendCount, oldWay.session.previousSendCount);
  assert.deepEqual(newWay.session.skippedKeys, oldWay.session.skippedKeys);

  assert.notDeepEqual(newWay.session.selfRatchetSecret, oldWay.session.selfRatchetSecret);
  assert.notDeepEqual(newWay.session.sendChainKey, oldWay.session.sendChainKey);
});

// ---------------------------------------------------------------------------
// Ratchet behaviour on the new path
// ---------------------------------------------------------------------------

test('out of order delivery parks keys and every message still opens', async () => {
  const { alice, bob } = await connectedPair();

  const plaintexts = [0, 1, 2, 3].map((i) => randomBytes(200 + i));
  const frames = plaintexts.map((p) => sendWire(alice, p));

  // Two arrive late. Opening m2 first has to park the keys for m0 and m1.
  assert.deepEqual(receiveWire(bob, frames[2]!), plaintexts[2]!);
  assert.equal(Object.keys(bob.session.skippedKeys).length, 2);

  assert.deepEqual(receiveWire(bob, frames[0]!), plaintexts[0]!);
  assert.equal(Object.keys(bob.session.skippedKeys).length, 1);
  assert.deepEqual(receiveWire(bob, frames[1]!), plaintexts[1]!);
  assert.equal(Object.keys(bob.session.skippedKeys).length, 0);

  // And the chain carries on from where m2 left it.
  assert.deepEqual(receiveWire(bob, frames[3]!), plaintexts[3]!);
  assert.equal(bob.session.recvCount, 4);
});

test('a parked key survives a chain change and still opens afterwards', async () => {
  const { alice, bob } = await connectedPair();

  const stranded = randomBytes(128);
  const strandedFrame = sendWire(alice, stranded);
  const next = randomBytes(128);
  assert.deepEqual(receiveWire(bob, sendWire(alice, next)), next);
  assert.equal(Object.keys(bob.session.skippedKeys).length, 1);

  // Bob replies, which gives him a send chain and hands Alice a new ratchet
  // public. Alice's next message therefore arrives on a different chain.
  const before = bob.session.peerRatchetPublic;
  const reply = randomBytes(64);
  const replyFrame = sendWire(bob, reply);
  assert.deepEqual(receiveWire(alice, replyFrame), reply);

  const afterTurn = randomBytes(96);
  assert.deepEqual(receiveWire(bob, sendWire(alice, afterTurn)), afterTurn);
  assert.notDeepEqual(bob.session.peerRatchetPublic, before);

  // The stranded message is from the dead chain and still opens from its
  // parked key, which is the property the whole skipped-key table exists for.
  assert.deepEqual(receiveWire(bob, strandedFrame), stranded);
  assert.equal(Object.keys(bob.session.skippedKeys).length, 0);
});

test('a flipped bit fails closed and leaves the session usable', async () => {
  const { alice, bob } = await connectedPair();

  const plaintext = randomBytes(1024);
  const honest = sendWire(alice, plaintext);
  // Deep inside the ciphertext, past the two byte header and the fixed body
  // fields, so this is a payload edit rather than a decode error.
  const tampered = flipByte(honest, honest.length - 64);

  await expectFailure('authentication_failed', async () => receiveWire(bob, tampered));
  // Fail closed means the forgery advanced nothing, so the honest copy of the
  // same message still opens byte exact.
  assert.deepEqual(receiveWire(bob, honest), plaintext);
  assert.equal(bob.session.recvCount, 1);
});

test('a corrupted envelope header fails closed as a malformed envelope', async () => {
  const { alice, bob } = await connectedPair();

  const honest = sendWire(alice, randomBytes(64));
  const badVersion = flipByte(honest, 0);
  await expectFailure('unknown_version', async () => receiveWire(bob, badVersion));
  await expectFailure('malformed_token', async () => receiveWire(bob, honest.subarray(0, 20)));
  // A handshake envelope where a chunk belongs is a protocol error, not a
  // decode error, and must not reach the ratchet at all.
  await expectFailure('malformed_token', async () =>
    receiveWire(bob, encodeEnvelopeBytes(sampleInvite())),
  );
  assert.equal(bob.session.recvCount, 0);
});

test('replay is detected on the new path', async () => {
  const { alice, bob } = await connectedPair();

  const plaintext = randomBytes(256);
  const frame = sendWire(alice, plaintext);
  assert.deepEqual(receiveWire(bob, frame), plaintext);
  // The message key was burned on first use, so the second delivery has nothing
  // left to open it with and is reported as what it is.
  await expectFailure('replay_detected', async () => receiveWire(bob, frame));

  // A replayed parked message is the same verdict by the same mechanism.
  const parked = randomBytes(256);
  const parkedFrame = sendWire(alice, parked);
  const following = randomBytes(256);
  assert.deepEqual(receiveWire(bob, sendWire(alice, following)), following);
  assert.deepEqual(receiveWire(bob, parkedFrame), parked);
  await expectFailure('replay_detected', async () => receiveWire(bob, parkedFrame));
});

test('the skip limit still bounds the work one message can demand', async () => {
  const { alice, bob } = await connectedPair();

  const frame = sendWire(alice, randomBytes(64));
  const payload = asMessage(decodeEnvelopeBytes(frame));
  // A message number far past the receive chain, which is the memory
  // exhaustion primitive MAX_SKIP exists to refuse. The tag would never verify,
  // but that is not the point: the refusal has to come BEFORE the derivation.
  const greedy = encodeEnvelopeBytes({ ...payload, messageNumber: MAX_SKIP + 1 });
  await expectFailure('skip_limit_exceeded', async () => receiveWire(bob, greedy));

  // One inside the limit is allowed to proceed, and then fails on the tag,
  // which confirms the limit is the only thing that stopped the first one.
  const legal = encodeEnvelopeBytes({ ...payload, messageNumber: MAX_SKIP - 1 });
  await expectFailure('authentication_failed', async () => receiveWire(bob, legal));

  // Neither attempt touched the caller's session, so the honest message opens.
  assert.equal(Object.keys(bob.session.skippedKeys).length, 0);
  assert.deepEqual(receiveWire(bob, frame).length, 64);
});

// ---------------------------------------------------------------------------
// The measurement this change exists for
// ---------------------------------------------------------------------------

/**
 * The CLI's real workload, both ways, so the saving is a number rather than a
 * claim: 12 chunks of 65519 bytes, which is one 786 kB file at the largest
 * plaintext an OCX1 frame can carry.
 *
 * Each iteration is a full send and receive. The old path is written out step
 * by step instead of being imported, because the four calls below ARE 0.3.0:
 * engine.sealBytes base64s the envelope into a token, toWire un-base64s it back
 * into the bytes it just was, fromWire base64s those bytes into a token again,
 * and engine.openBytes un-base64s that. Four base64 passes over 786 kB per
 * transfer, all of it round tripping to the same place.
 *
 * The assertion is only that the new path wins, which it must by construction
 * since it does strictly less work on identical input. The interesting output
 * is the log line.
 */
test('the new path is measurably cheaper on the CLI workload', async () => {
  const CHUNKS = 12;
  const CHUNK_BYTES = 65_519;
  const RUNS = 11;

  const { alice, bob } = await connectedPair();
  const chunk = randomBytes(CHUNK_BYTES);

  function oldRun(sender: Party, receiver: Party): void {
    for (let i = 0; i < CHUNKS; i += 1) {
      const sealed = ratchetEncryptBytes(sender.session, chunk);
      sender.session = sealed.session;
      const token = encodeEnvelope(sealed.payload);
      const frame = encodeEnvelopeBytes(decodeEnvelope(token));
      const back = encodeEnvelope(decodeEnvelopeBytes(frame));
      const opened = ratchetDecryptBytes(receiver.session, asMessage(decodeEnvelope(back)));
      receiver.session = opened.session;
    }
  }

  function newRun(sender: Party, receiver: Party): void {
    for (let i = 0; i < CHUNKS; i += 1) {
      const sealed = ratchetEncryptToEnvelopeBytes(sender.session, chunk);
      sender.session = sealed.session;
      const opened = ratchetDecryptFromEnvelopeBytes(receiver.session, sealed.envelope);
      receiver.session = opened.session;
    }
  }

  function median(values: readonly number[]): number {
    const sorted = [...values].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    return sorted.length % 2 === 1 ? sorted[mid]! : (sorted[mid - 1]! + sorted[mid]!) / 2;
  }

  function time(run: (s: Party, r: Party) => void): number[] {
    // One discarded pass so the JIT has seen every function before the clock
    // starts. Without it the first sample is several times the rest and the
    // median of a short series notices.
    run(alice, bob);
    const samples: number[] = [];
    for (let i = 0; i < RUNS; i += 1) {
      const start = performance.now();
      run(alice, bob);
      samples.push(performance.now() - start);
    }
    return samples;
  }

  const oldMs = median(time(oldRun));
  const newMs = median(time(newRun));

  console.log(
    `  bytes path: ${CHUNKS} x ${CHUNK_BYTES} B, median of ${RUNS}: ` +
      `old ${oldMs.toFixed(1)} ms, new ${newMs.toFixed(1)} ms, ` +
      `saved ${(oldMs - newMs).toFixed(1)} ms (${(100 * (1 - newMs / oldMs)).toFixed(0)}%)`,
  );

  assert.ok(
    newMs < oldMs,
    `the new path took ${newMs.toFixed(1)} ms against ${oldMs.toFixed(1)} ms for the old one`,
  );
});
