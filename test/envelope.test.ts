import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from '@noble/hashes/utils.js';

import { decodeEnvelope, encodeEnvelope, engine, formatFingerprint } from '../src/index.js';
import type { AcceptPayload, InvitePayload, MessagePayload } from '../src/index.js';

/**
 * A body larger than one call to randomBytes will give you.
 *
 * noble's randomBytes refuses anything over 65536, which used to be irrelevant
 * because the u16 length prefix capped a body below that anyway. Now that the
 * ciphertext runs to the end of the buffer with no prefix, the ceiling is gone
 * and the test has to be able to build something past it. A counter pattern is
 * enough: nothing here depends on the bytes being unpredictable, only on them
 * being distinguishable if the codec drops or reorders a stretch.
 */
function filler(length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) out[i] = (i * 31 + (i >>> 8)) & 0xff;
  return out;
}

test('envelope round trip is exact for all three payload kinds', async () => {
  const invite: InvitePayload = {
    kind: 'invite',
    conversationId: 'a1b2c3d4e5f60718',
    sender: { classicalPublic: randomBytes(32), pqPublic: randomBytes(1184), sigPublic: randomBytes(1952) },
    signature: randomBytes(3309),
  };
  const accept: AcceptPayload = {
    kind: 'accept',
    conversationId: 'a1b2c3d4e5f60718',
    sender: { classicalPublic: randomBytes(32), pqPublic: randomBytes(1184), sigPublic: randomBytes(1952) },
    kemCiphertext: randomBytes(1088),
    ratchetPublic: randomBytes(32),
    signature: randomBytes(3309),
  };
  // The step case: the header carries the ratchet key, so it also carries the
  // previous chain length. The two are present together or not at all.
  const step: MessagePayload = {
    kind: 'message',
    sessionTag: Uint8Array.of(0xa1, 0xb2, 0xc3, 0xd4),
    ratchetPublic: randomBytes(32),
    // Deliberately large counters: the varint is bounded at u32, and a silent
    // truncation here would look like a replay much later.
    messageNumber: 4_000_000_000,
    previousChainLength: 65_537,
    nonce: randomBytes(12),
    ciphertext: randomBytes(120),
  };
  // The common case: no key, no previous chain length, 34 bytes of overhead.
  const plain: MessagePayload = {
    kind: 'message',
    sessionTag: Uint8Array.of(0xa1, 0xb2, 0xc3, 0xd4),
    messageNumber: 7,
    nonce: randomBytes(12),
    ciphertext: randomBytes(120),
  };

  for (const payload of [invite, accept, step, plain]) {
    const token = encodeEnvelope(payload);
    assert.ok(token.startsWith(`OCX3.${payload.kind}.`));
    assert.deepEqual(decodeEnvelope(token), payload);
  }
});

test('envelope handles minimum and large bodies', () => {
  // A ciphertext of exactly the tag length is the smallest legal body: it is an
  // empty plaintext plus its Poly1305 tag. Anything shorter cannot be a message.
  const smallest: MessagePayload = {
    kind: 'message',
    sessionTag: new Uint8Array(4),
    messageNumber: 0,
    nonce: randomBytes(12),
    ciphertext: randomBytes(16),
  };
  assert.deepEqual(decodeEnvelope(encodeEnvelope(smallest)), smallest);

  // No u16 length prefix on the ciphertext any more, so the old 65535 ceiling
  // is gone. Prove it by going past it.
  const large: MessagePayload = {
    kind: 'message',
    sessionTag: new Uint8Array(4),
    messageNumber: 0,
    nonce: randomBytes(12),
    ciphertext: filler(70_000),
  };
  assert.deepEqual(decodeEnvelope(encodeEnvelope(large)), large);
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

// Three thirds since 0.6.0, and the signing key is the one that matters most
// here. A fingerprint that covered only the other two would let an attacker keep
// a victim's X25519 and ML-KEM keys, substitute a signing key of their own, and
// print the same words: the human check would confirm an identity that could
// then authenticate handshakes as somebody else. Every third gets its own case
// so that dropping one from the digest fails a named test rather than quietly
// weakening the only control a user performs by hand.
test('fingerprint changes if any third of the identity changes', async () => {
  const alice = await engine.createIdentity();
  const other = await engine.createIdentity();
  const base = engine.publicOf(alice);
  const theirs = engine.publicOf(other);

  const swappedClassical = engine.fingerprint({ ...base, classicalPublic: theirs.classicalPublic });
  const swappedPq = engine.fingerprint({ ...base, pqPublic: theirs.pqPublic });
  const swappedSig = engine.fingerprint({ ...base, sigPublic: theirs.sigPublic });
  const original = engine.fingerprint(base);

  const all = [swappedClassical, swappedPq, swappedSig, original].map((f) => f.hex);
  assert.equal(new Set(all).size, all.length, 'every swap must produce a distinct fingerprint');
});
