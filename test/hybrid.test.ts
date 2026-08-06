import { test } from 'node:test';
import assert from 'node:assert/strict';

import { x25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

import { concat, toHex } from '../src/bytes.js';
import { decodeEnvelope } from '../src/envelope.js';
import { acceptInvite, beginInvite, completeInvite } from '../src/handshake.js';
import { createIdentity } from '../src/identity.js';
import { kdfHandshake, kdfRoot } from '../src/kdf.js';
import { flipByte } from './harness.js';

/**
 * The hybrid pin.
 *
 * The README claims the root key is hybrid: X25519 and ML-KEM-768 must BOTH
 * fall before the handshake secret does. Until now that claim rested on
 * reading handshake.ts and believing it. These tests make it falsifiable in
 * both directions: each half alone must move the root key, and the live
 * handshake code, not just the KDF in isolation, must actually mix the
 * decapsulated ML-KEM secret into the root it stores in the session.
 *
 * If someone ever "simplifies" the handshake so the KEM secret is computed
 * but not mixed, or mixed but truncated, the LIVE HANDSHAKE tests below fail.
 * That is the entire point: the post-quantum claim is now one failing test
 * away from being a lie, instead of one unread source file away.
 */

/** Deterministic filler for the tests that exercise the KDF in isolation. */
function pattern(offset: number, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) out[i] = (offset + i) & 0xff;
  return out;
}

const CID = 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf';

test('HYBRID PIN: the ML-KEM secret alone changes the root key, X25519 inputs fixed', () => {
  // Both X25519 shared secrets held constant, only the KEM half varies. The
  // two shared secrets come from two real encapsulations to the same public
  // key with different explicit messages, so this exercises genuine ML-KEM
  // outputs rather than arbitrary bytes standing in for them.
  const dh1 = x25519.getSharedSecret(pattern(0x00, 32), x25519.keygen(pattern(0x20, 32)).publicKey);
  const dh2 = x25519.getSharedSecret(pattern(0x40, 32), x25519.keygen(pattern(0x20, 32)).publicKey);

  const kemKeys = ml_kem768.keygen(pattern(0x10, 64));
  const encapsA = ml_kem768.encapsulate(kemKeys.publicKey, pattern(0x50, 32));
  const encapsB = ml_kem768.encapsulate(kemKeys.publicKey, pattern(0x51, 32));
  assert.notEqual(toHex(encapsA.sharedSecret), toHex(encapsB.sharedSecret));

  const rootA = kdfHandshake(concat(dh1, dh2, encapsA.sharedSecret), CID);
  const rootB = kdfHandshake(concat(dh1, dh2, encapsB.sharedSecret), CID);
  assert.notEqual(toHex(rootA), toHex(rootB));
});

test('HYBRID PIN: each X25519 half alone changes the root key, ML-KEM input fixed', () => {
  const kemKeys = ml_kem768.keygen(pattern(0x10, 64));
  const encaps = ml_kem768.encapsulate(kemKeys.publicKey, pattern(0x50, 32));

  const peer = x25519.keygen(pattern(0x20, 32)).publicKey;
  const dh1 = x25519.getSharedSecret(pattern(0x00, 32), peer);
  const dh2 = x25519.getSharedSecret(pattern(0x40, 32), peer);
  const baseline = kdfHandshake(concat(dh1, dh2, encaps.sharedSecret), CID);

  // Vary dh1, the identity binding, then dh2, the ratchet binding. Each must
  // move the root on its own or that binding is decorative.
  const otherDh1 = x25519.getSharedSecret(pattern(0x01, 32), peer);
  assert.notEqual(toHex(kdfHandshake(concat(otherDh1, dh2, encaps.sharedSecret), CID)), toHex(baseline));

  const otherDh2 = x25519.getSharedSecret(pattern(0x41, 32), peer);
  assert.notEqual(toHex(kdfHandshake(concat(dh1, otherDh2, encaps.sharedSecret), CID)), toHex(baseline));
});

test('HYBRID PIN: the hybrid root matches neither half alone', () => {
  const kemKeys = ml_kem768.keygen(pattern(0x10, 64));
  const encaps = ml_kem768.encapsulate(kemKeys.publicKey, pattern(0x50, 32));
  const peer = x25519.keygen(pattern(0x20, 32)).publicKey;
  const dh1 = x25519.getSharedSecret(pattern(0x00, 32), peer);
  const dh2 = x25519.getSharedSecret(pattern(0x40, 32), peer);

  const hybrid = kdfHandshake(concat(dh1, dh2, encaps.sharedSecret), CID);
  const classicalOnly = kdfHandshake(concat(dh1, dh2), CID);
  const pqOnly = kdfHandshake(encaps.sharedSecret, CID);
  // A zeroed KEM slot is what an implementation bug that drops the secret but
  // keeps the buffer would produce, so it gets its own counterfactual.
  const pqZeroed = kdfHandshake(concat(dh1, dh2, new Uint8Array(32)), CID);

  assert.notEqual(toHex(hybrid), toHex(classicalOnly));
  assert.notEqual(toHex(hybrid), toHex(pqOnly));
  assert.notEqual(toHex(hybrid), toHex(pqZeroed));
});

test('LIVE HANDSHAKE: the responder root key really contains the decapsulated ML-KEM secret', () => {
  // Real identities, real invite, real acceptInvite. Then the root key the
  // responder stored is reconstructed from first principles, on the
  // initiator's side of the keys, and compared against counterfactuals.
  const alice = createIdentity();
  const bob = createIdentity();

  const invited = beginInvite(alice);
  const invite = decodeEnvelope(invited.token);
  assert.equal(invite.kind, 'invite');
  if (invite.kind !== 'invite') throw new Error('unreachable');

  const accepted = acceptInvite(bob, invite);
  const accept = decodeEnvelope(accepted.token);
  assert.equal(accept.kind, 'accept');
  if (accept.kind !== 'accept') throw new Error('unreachable');

  // Initiator-side reconstruction, mirroring completeInvite: same DH values
  // by the symmetry of X25519, same KEM secret by decapsulation.
  const dh1 = x25519.getSharedSecret(alice.classicalSecret, accept.sender.classicalPublic);
  const dh2 = x25519.getSharedSecret(alice.classicalSecret, accept.ratchetPublic);
  const pq = ml_kem768.decapsulate(accept.kemCiphertext, alice.pqSecret);

  const expected = kdfHandshake(concat(dh1, dh2, pq), invite.conversationId);
  assert.equal(toHex(accepted.session.rootKey), toHex(expected));

  // Counterfactual one: drop the KEM secret. If the live root still matched,
  // the ML-KEM contribution would be decorative and the hybrid claim false.
  const classicalOnly = kdfHandshake(concat(dh1, dh2), invite.conversationId);
  assert.notEqual(toHex(accepted.session.rootKey), toHex(classicalOnly));

  // Counterfactual two: drop both DH values. If the live root still matched,
  // the classical contribution would be decorative instead.
  const pqOnly = kdfHandshake(pq, invite.conversationId);
  assert.notEqual(toHex(accepted.session.rootKey), toHex(pqOnly));

  // Counterfactual three: a corrupted ciphertext decapsulates, by ML-KEM's
  // implicit rejection, to a DIFFERENT well-formed secret, and that different
  // secret must land on a different root. This is the property the first
  // message's AEAD failure relies on, per the comment in completeInvite.
  const wrongPq = ml_kem768.decapsulate(flipByte(accept.kemCiphertext, 0), alice.pqSecret);
  assert.notEqual(toHex(wrongPq), toHex(pq));
  const wrongRoot = kdfHandshake(concat(dh1, dh2, wrongPq), invite.conversationId);
  assert.notEqual(toHex(accepted.session.rootKey), toHex(wrongRoot));
});

test('LIVE HANDSHAKE: the initiator lands one kdfRoot step past the same hybrid root', () => {
  const alice = createIdentity();
  const bob = createIdentity();

  const invited = beginInvite(alice);
  const invite = decodeEnvelope(invited.token);
  assert.equal(invite.kind, 'invite');
  if (invite.kind !== 'invite') throw new Error('unreachable');

  const accepted = acceptInvite(bob, invite);
  const accept = decodeEnvelope(accepted.token);
  assert.equal(accept.kind, 'accept');
  if (accept.kind !== 'accept') throw new Error('unreachable');

  const session = completeInvite(alice, invited.pending, accept);

  // Reconstruct the shared handshake root, then take the same ratchet step
  // completeInvite took, using the ratchet secret it stored in the session.
  const dh1 = x25519.getSharedSecret(alice.classicalSecret, accept.sender.classicalPublic);
  const dh2 = x25519.getSharedSecret(alice.classicalSecret, accept.ratchetPublic);
  const pq = ml_kem768.decapsulate(accept.kemCiphertext, alice.pqSecret);
  const handshakeRoot = kdfHandshake(concat(dh1, dh2, pq), invite.conversationId);

  // Both sides must have started from the same hybrid root.
  assert.equal(toHex(accepted.session.rootKey), toHex(handshakeRoot));

  const stepDh = x25519.getSharedSecret(session.selfRatchetSecret, accept.ratchetPublic);
  const stepped = kdfRoot(handshakeRoot, stepDh);
  assert.equal(toHex(session.rootKey), toHex(stepped.rootKey));
  assert.ok(session.sendChainKey);
  assert.equal(toHex(session.sendChainKey), toHex(stepped.chainKey));

  // And the initiator's stored root must ALSO depend on the KEM secret: the
  // same step taken from a classical-only root diverges.
  const classicalOnlyRoot = kdfHandshake(concat(dh1, dh2), invite.conversationId);
  const classicalStepped = kdfRoot(classicalOnlyRoot, stepDh);
  assert.notEqual(toHex(session.rootKey), toHex(classicalStepped.rootKey));
});
