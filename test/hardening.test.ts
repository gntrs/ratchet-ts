import { test } from 'node:test';
import assert from 'node:assert/strict';

import { engine } from '../src/index.js';
import type { EnvelopeToken } from '../src/index.js';
import { connectedPair, editMessage, expectFailure, flipByte, receive, send } from './harness.js';

test('tamper: a single flipped bit in the ciphertext body fails closed', async () => {
  const { alice, bob } = await connectedPair();
  const honest = await send(alice, 'the original message');

  const forged = editMessage(honest, (payload) => ({
    ...payload,
    ciphertext: flipByte(payload.ciphertext, 0),
  }));
  await expectFailure('authentication_failed', () => receive(bob, forged));

  // Also the last byte, which lands inside the Poly1305 tag rather than the
  // stream, to prove both halves of the AEAD are actually checked.
  const honest2 = await send(alice, 'another one');
  const forgedTag = editMessage(honest2, (payload) => ({
    ...payload,
    ciphertext: flipByte(payload.ciphertext, payload.ciphertext.length - 1),
  }));
  await expectFailure('authentication_failed', () => receive(bob, forgedTag));
});

test('tamper: flipped bits in the header fail closed, because the header is the AAD', async () => {
  const { alice, bob } = await connectedPair();

  const honest = await send(alice, 'header integrity');

  const bentRatchetKey = editMessage(honest, (payload) => ({
    ...payload,
    ratchetPublic: flipByte(payload.ratchetPublic, 3),
  }));
  await expectFailure('authentication_failed', () => receive(bob, bentRatchetKey));

  const bentCounter = editMessage(honest, (payload) => ({
    ...payload,
    messageNumber: payload.messageNumber + 7,
  }));
  await expectFailure('authentication_failed', () => receive(bob, bentCounter));

  const bentPrevious = editMessage(honest, (payload) => ({
    ...payload,
    previousChainLength: payload.previousChainLength + 1,
  }));
  await expectFailure('authentication_failed', () => receive(bob, bentPrevious));

  // None of the forgeries moved the session on, so the real message still opens.
  assert.equal(await receive(bob, honest), 'header integrity');
});

test('tamper: a flipped bit in the nonce fails closed', async () => {
  const { alice, bob } = await connectedPair();
  const honest = await send(alice, 'nonce integrity');

  const forged = editMessage(honest, (payload) => ({
    ...payload,
    nonce: flipByte(payload.nonce, 11),
  }));
  await expectFailure('authentication_failed', () => receive(bob, forged));
  assert.equal(await receive(bob, honest), 'nonce integrity');
});

test('tamper: a truncated ciphertext fails closed rather than returning a prefix', async () => {
  const { alice, bob } = await connectedPair();
  const honest = await send(alice, 'a reasonably long plaintext to slice');

  const chopped = editMessage(honest, (payload) => ({
    ...payload,
    ciphertext: payload.ciphertext.slice(0, payload.ciphertext.length - 4),
  }));
  await expectFailure('authentication_failed', () => receive(bob, chopped));
});

test('malformed input maps to a reason and never escapes as a raw exception', async () => {
  const { alice, bob } = await connectedPair();
  const honest = await send(alice, 'reference token');

  const cases: Array<{ token: string; reason: 'malformed_token' | 'unknown_version' }> = [
    { token: '', reason: 'malformed_token' },
    { token: 'garbage', reason: 'malformed_token' },
    { token: 'hello world, no dots here', reason: 'malformed_token' },
    { token: 'OCX1.message', reason: 'malformed_token' },
    { token: 'OCX1.message.', reason: 'malformed_token' },
    { token: 'OCX1.bogus.AAAA', reason: 'malformed_token' },
    { token: 'OCX1.message.not+valid/base64url==', reason: 'malformed_token' },
    { token: 'OCX1.message.AAAAAAAA', reason: 'malformed_token' },
    { token: honest.slice(0, honest.length - 20), reason: 'malformed_token' },
    { token: 'OCX9.message.AAAA', reason: 'unknown_version' },
    { token: 'OCX2.invite.AAAA', reason: 'unknown_version' },
    { token: '.'.repeat(3), reason: 'malformed_token' },
  ];

  for (const { token, reason } of cases) {
    await expectFailure(reason, async () =>
      engine.open(bob.identity, token as EnvelopeToken, { session: bob.session }),
    );
  }

  // The session was never touched by any of that.
  assert.equal(await receive(bob, honest), 'reference token');
});
