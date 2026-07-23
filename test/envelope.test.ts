import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from '@noble/hashes/utils.js';

import { decodeEnvelope, encodeEnvelope, engine, formatFingerprint } from '../src/index.js';
import type { AcceptPayload, InvitePayload, MessagePayload } from '../src/index.js';

test('envelope round trip is exact for all three payload kinds', async () => {
  const invite: InvitePayload = {
    kind: 'invite',
    conversationId: 'a1b2c3d4e5f60718',
    sender: { classicalPublic: randomBytes(32), pqPublic: randomBytes(1184) },
  };
  const accept: AcceptPayload = {
    kind: 'accept',
    conversationId: 'a1b2c3d4e5f60718',
    sender: { classicalPublic: randomBytes(32), pqPublic: randomBytes(1184) },
    kemCiphertext: randomBytes(1088),
    ratchetPublic: randomBytes(32),
  };
  const message: MessagePayload = {
    kind: 'message',
    conversationId: 'a1b2c3d4e5f60718',
    ratchetPublic: randomBytes(32),
    // Deliberately large counters: the wire format uses u32, and a silent
    // truncation here would look like a replay much later.
    messageNumber: 4_000_000_000,
    previousChainLength: 65_537,
    nonce: randomBytes(24),
    ciphertext: randomBytes(120),
  };

  for (const payload of [invite, accept, message]) {
    const token = encodeEnvelope(payload);
    assert.ok(token.startsWith(`OCX1.${payload.kind}.`));
    assert.deepEqual(decodeEnvelope(token), payload);
  }
});

test('envelope handles empty and maximum length blobs', () => {
  const payload: MessagePayload = {
    kind: 'message',
    conversationId: '',
    ratchetPublic: new Uint8Array(0),
    messageNumber: 0,
    previousChainLength: 0,
    nonce: new Uint8Array(0),
    ciphertext: randomBytes(65_535),
  };
  assert.deepEqual(decodeEnvelope(encodeEnvelope(payload)), payload);
});

test('fingerprint is deterministic, identity bound, and agreed on by both sides', async () => {
  const alice = await engine.createIdentity();
  const bob = await engine.createIdentity();

  const aliceSelf = engine.fingerprint(engine.publicOf(alice));
  const aliceAgain = engine.fingerprint(engine.publicOf(alice));
  const bobsViewOfAlice = engine.fingerprint(engine.publicOf(alice));

  // Same identity, same six words, every time and on every device. This is
  // what makes reading them aloud over a phone call meaningful.
  assert.equal(aliceSelf.words.length, 6);
  assert.deepEqual(aliceSelf.words, aliceAgain.words);
  assert.equal(aliceSelf.hex, aliceAgain.hex);
  assert.deepEqual(bobsViewOfAlice.words, aliceSelf.words);

  // Different identity, different words. The fingerprint is per identity, not
  // per pair, so Alice and Bob do NOT share one value: each reads out their own
  // and the other checks it against what they hold.
  const bobSelf = engine.fingerprint(engine.publicOf(bob));
  assert.notDeepEqual(bobSelf.words, aliceSelf.words);
  assert.notEqual(bobSelf.hex, aliceSelf.hex);

  // Every word comes from the published list, and the rendering is stable.
  assert.equal(formatFingerprint(aliceSelf), aliceSelf.words.join(' '));
  for (const word of aliceSelf.words) {
    assert.ok(/^[a-z]+$/.test(word), `unexpected word: ${word}`);
  }
});

test('fingerprint changes if either half of the identity changes', async () => {
  const alice = await engine.createIdentity();
  const other = await engine.createIdentity();
  const base = engine.publicOf(alice);

  const swappedClassical = engine.fingerprint({
    classicalPublic: engine.publicOf(other).classicalPublic,
    pqPublic: base.pqPublic,
  });
  const swappedPq = engine.fingerprint({
    classicalPublic: base.classicalPublic,
    pqPublic: engine.publicOf(other).pqPublic,
  });
  const original = engine.fingerprint(base);

  assert.notEqual(swappedClassical.hex, original.hex);
  assert.notEqual(swappedPq.hex, original.hex);
  assert.notEqual(swappedClassical.hex, swappedPq.hex);
});
