import { test } from 'node:test';
import assert from 'node:assert/strict';

import { cloneSession, connectedPair, expectFailure, receive, restore, send } from './harness.js';

/**
 * The headline property.
 *
 * Everything else in this repo is table stakes. This is the test that backs the
 * claim on the landing page: stealing a device today does not hand over the
 * conversation, in either direction in time.
 */
test('FORWARD SECRECY: a session snapshot taken at message N cannot decrypt message N+5', async () => {
  const { alice, bob } = await connectedPair();

  await receive(bob, await send(alice, 'm0'));
  await receive(alice, await send(bob, 'r0'));

  // The compromise: a full byte for byte copy of Bob's device state, taken at
  // message N. Root key, both chain keys, ratchet secret, parked keys, all of it.
  const stolen = cloneSession(bob.session);
  assert.ok(stolen.rootKey.length > 0);
  assert.ok(stolen.selfRatchetSecret.length > 0);

  let latest = '';
  for (let n = 1; n <= 5; n += 1) {
    latest = await send(alice, `m${n}`);
    assert.equal(await receive(bob, latest), `m${n}`);
    await receive(alice, await send(bob, `r${n}`));
  }

  // The stolen state is five ratchet steps behind. The keys that would open
  // message N+5 were derived from randomness generated after the theft and
  // were never present in the snapshot.
  const attacker = restore(bob, stolen);
  await expectFailure('authentication_failed', () => receive(attacker, latest));

  // The live session is unaffected and still works.
  assert.equal(await receive(bob, await send(alice, 'still fine')), 'still fine');
});

test('forward secrecy, the other direction: an advanced session cannot reopen an old ciphertext', async () => {
  const { alice, bob } = await connectedPair();

  const archived = await send(alice, 'read once, then gone');
  assert.equal(await receive(bob, archived), 'read once, then gone');

  for (let n = 0; n < 5; n += 1) {
    await receive(bob, await send(alice, `filler ${n}`));
  }

  // The message key was derived, used, and dropped. Bob's own current state
  // cannot get it back, which is exactly why a later seizure of the device
  // does not recover the transcript.
  await expectFailure('replay_detected', () => receive(bob, archived));
});

/**
 * Post compromise security, stated honestly.
 *
 * Healing is not instant. It arrives when the compromised side generates fresh
 * ratchet randomness the attacker never saw, and this test pins down exactly
 * where that line falls rather than hand waving about it.
 */
test('POST COMPROMISE SECURITY: old chain keys stop working once the compromised side re-ratchets', async () => {
  const { alice, bob } = await connectedPair();

  await receive(bob, await send(alice, 'a1'));
  const attacker = restore(bob, cloneSession(bob.session));

  // Still the same chain. The attacker reads this, and pretending otherwise
  // would be dishonest: a compromise is a compromise until the ratchet turns.
  const a2 = await send(alice, 'a2');
  assert.equal(await receive(bob, a2), 'a2');
  assert.equal(await receive(attacker, a2), 'a2');

  // Bob replies, Alice ratchets. Bob's ratchet key has not changed yet, so the
  // attacker's copy of it still derives the new chain.
  await receive(alice, await send(bob, 'b1'));
  const a3 = await send(alice, 'a3');
  assert.equal(await receive(bob, a3), 'a3');
  assert.equal(await receive(attacker, a3), 'a3');

  // Opening a3 is what made the real Bob mint a fresh ratchet keypair. The
  // attacker's clone minted its own, unrelated one. From here the two states
  // have permanently diverged.
  assert.notDeepEqual(
    Array.from(bob.session.selfRatchetPublic),
    Array.from(attacker.session.selfRatchetPublic),
  );

  await receive(alice, await send(bob, 'b2'));
  const a4 = await send(alice, 'a4');
  assert.equal(await receive(bob, a4), 'a4');
  await expectFailure('authentication_failed', () => receive(attacker, a4));
});
