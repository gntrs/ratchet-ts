import { test } from 'node:test';
import assert from 'node:assert/strict';

import { engine, MAX_SKIP } from '../src/index.js';
import { connectedPair, editMessage, expectFailure, receive, send } from './harness.js';

test('happy path: invite, auto-accept, and a two way conversation', async () => {
  const { alice, bob } = await connectedPair();

  const conversation: Array<{ from: 'alice' | 'bob'; text: string }> = [
    { from: 'alice', text: 'first contact' },
    { from: 'alice', text: 'two in a row, same chain' },
    { from: 'bob', text: 'got both' },
    { from: 'alice', text: 'and we are back' },
    { from: 'bob', text: 'still here' },
    { from: 'bob', text: 'and again' },
    { from: 'alice', text: 'last one' },
  ];

  for (const line of conversation) {
    const from = line.from === 'alice' ? alice : bob;
    const to = line.from === 'alice' ? bob : alice;
    const token = await send(from, line.text);
    assert.ok(token.startsWith('OCX3.message.'), 'tokens must be self describing');
    assert.equal(await receive(to, token), line.text);
  }

  // Both sides agree on the conversation, which is what makes the session
  // routable by id on the UI side.
  assert.equal(alice.session.conversationId, bob.session.conversationId);
  assert.equal(alice.session.role, 'initiator');
  assert.equal(bob.session.role, 'responder');
});

test('unicode and empty plaintext survive the round trip', async () => {
  const { alice, bob } = await connectedPair();
  for (const text of ['', 'ok', 'ąčęėįšųū 🔐 \u0000 trailing', 'x'.repeat(4096)]) {
    assert.equal(await receive(bob, await send(alice, text)), text);
  }
});

test('out of order delivery: 1,2,3 arriving as 3,1,2 all decrypt', async () => {
  const { alice, bob } = await connectedPair();

  const one = await send(alice, 'one');
  const two = await send(alice, 'two');
  const three = await send(alice, 'three');

  assert.equal(await receive(bob, three), 'three');
  // The two earlier keys are parked, not lost.
  assert.equal(Object.keys(bob.session.skippedKeys).length, 2);
  assert.equal(await receive(bob, one), 'one');
  assert.equal(await receive(bob, two), 'two');
  // And each parked key is deleted the moment it is used.
  assert.equal(Object.keys(bob.session.skippedKeys).length, 0);
});

test('out of order delivery survives a chain change', async () => {
  const { alice, bob } = await connectedPair();

  const early = await send(alice, 'sent before the ratchet turned');
  // Bob speaks, Alice ratchets, so her next message opens a new chain while
  // `early` is still in flight on the old one.
  await receive(bob, await send(alice, 'seen'));
  await receive(alice, await send(bob, 'reply'));
  const late = await send(alice, 'sent after the ratchet turned');

  assert.equal(await receive(bob, late), 'sent after the ratchet turned');
  assert.equal(await receive(bob, early), 'sent before the ratchet turned');
});

test('replay: a consumed message cannot be delivered twice', async () => {
  const { alice, bob } = await connectedPair();

  const token = await send(alice, 'exactly once');
  assert.equal(await receive(bob, token), 'exactly once');
  await expectFailure('replay_detected', () => receive(bob, token));

  // Same for a message that was consumed out of a parked key.
  const parked = await send(alice, 'parked');
  const later = await send(alice, 'later');
  await receive(bob, later);
  assert.equal(await receive(bob, parked), 'parked');
  await expectFailure('replay_detected', () => receive(bob, parked));
});

test('skip limit: a huge message number is refused instead of allocated', async () => {
  const { alice, bob } = await connectedPair();

  const honest = await send(alice, 'honest');
  const absurd = editMessage(honest, (payload) => ({
    ...payload,
    messageNumber: MAX_SKIP + 1,
  }));

  await expectFailure('skip_limit_exceeded', () => receive(bob, absurd));
  // Nothing was parked, so there is no memory exhaustion primitive here.
  assert.equal(Object.keys(bob.session.skippedKeys).length, 0);
  // And the session is untouched, so the honest message still lands.
  assert.equal(await receive(bob, honest), 'honest');
});

test('no session: a message for an unknown conversation is refused', async () => {
  const { alice, bob } = await connectedPair();
  const other = await connectedPair();

  const token = await send(alice, 'not for you');
  await expectFailure('no_session', () => receive(other.bob, token));
  await expectFailure('no_session', async () =>
    engine.open(bob.identity, token, {}),
  );
});

test('identity mismatch: an accept cannot be opened by the wrong account', async () => {
  const alice = await engine.createIdentity();
  const impostor = await engine.createIdentity();
  const bob = await engine.createIdentity();

  const invited = await engine.invite(alice);
  const bobOpened = await engine.open(bob, invited.token, {});
  assert.equal(bobOpened.outcome, 'invite');
  if (bobOpened.outcome !== 'invite') throw new Error('unreachable');

  await expectFailure('identity_mismatch', async () =>
    engine.open(impostor, bobOpened.reply, { pending: invited.pending }),
  );
  await expectFailure('no_session', async () => engine.open(alice, bobOpened.reply, {}));
});
