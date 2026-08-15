import { test } from 'node:test';
import assert from 'node:assert/strict';

import { decodeEnvelope, engine } from '../src/index.js';
import type { EnvelopeToken, MessagePayload } from '../src/index.js';
import { conversationIdToBytes } from '../src/envelope.js';
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

  // Message 0 of a chain always carries the ratchet key, because
  // RATCHET_KEY_RESEND is 3. If that ever stops being true this test is
  // measuring nothing, so it is asserted rather than assumed.
  const first = decodeEnvelope(honest) as MessagePayload;
  assert.ok(first.ratchetPublic !== undefined, 'message 0 of a chain must carry the ratchet key');
  assert.ok(first.previousChainLength !== undefined, 'a key on the wire comes with its chain length');

  const bentRatchetKey = editMessage(honest, (payload) => ({
    ...payload,
    ratchetPublic: flipByte(payload.ratchetPublic as Uint8Array, 3),
  }));
  await expectFailure('authentication_failed', () => receive(bob, bentRatchetKey));

  const bentCounter = editMessage(honest, (payload) => ({
    ...payload,
    messageNumber: payload.messageNumber + 7,
  }));
  await expectFailure('authentication_failed', () => receive(bob, bentCounter));

  const bentPrevious = editMessage(honest, (payload) => ({
    ...payload,
    previousChainLength: (payload.previousChainLength ?? 0) + 1,
  }));
  await expectFailure('authentication_failed', () => receive(bob, bentPrevious));

  // None of the forgeries moved the session on, so the real message still opens.
  assert.equal(await receive(bob, honest), 'header integrity');
});

test('tamper: a bent session tag is routed away rather than opened', async () => {
  // 0.3.x carried the whole conversation id on the wire and this test used to
  // flip a byte of it. Only 4 of the 16 bytes are transmitted now, as a session
  // tag, and the interesting thing about that field is that it is routing, not
  // security. A bent tag means "not this session", which is a different answer
  // from "forged". The nonce is still on the wire, 12 bytes instead of 0.3.x's
  // 24, and flipping a byte of it is a forgery rather than a misroute, so that
  // case lives in test/message-chain.test.ts next to the rest of the nonce work.
  const { alice, bob } = await connectedPair();
  const honest = await send(alice, 'tag integrity');

  const forged = editMessage(honest, (payload) => ({
    ...payload,
    sessionTag: flipByte(payload.sessionTag, 2),
  }));
  await expectFailure('no_session', () => receive(bob, forged));
  assert.equal(await receive(bob, honest), 'tag integrity');
});

test('tamper: the 12 unsent bytes of the conversation id are still bound', async () => {
  // The wire carries 4 bytes of the id. The AAD carries all 16, rebuilt from
  // session state. Bending a byte the sender never transmitted must still break
  // the tag, or the saving would have cost the binding.
  const { alice, bob } = await connectedPair();
  const honest = await send(alice, 'id binding');

  const bent = Uint8Array.from(conversationIdToBytes(bob.session.conversationId));
  bent[9] = bent[9]! ^ 0x01;
  const confused = { ...bob.session, conversationIdBytes: bent };
  await expectFailure('authentication_failed', async () =>
    engine.open(bob.identity, honest, { session: confused }),
  );
  // Unbent, it opens. The only difference was one byte that never left Alice.
  assert.equal(await receive(bob, honest), 'id binding');
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
    { token: 'OCX3.message', reason: 'malformed_token' },
    { token: 'OCX3.message.', reason: 'malformed_token' },
    { token: 'OCX3.bogus.AAAA', reason: 'malformed_token' },
    { token: 'OCX3.message.not+valid/base64url==', reason: 'malformed_token' },
    // 0x3c 0x00 0x00: a well formed packed header with the body cut off before
    // the session tag is complete.
    { token: 'OCX3.message.PAAA', reason: 'malformed_token' },
    // All zero bytes: version nibble 0, which is a version problem and reported
    // as one even though the rest of the frame is nonsense too.
    { token: 'OCX3.message.AAAAAAAA', reason: 'unknown_version' },
    { token: honest.slice(0, honest.length - 30), reason: 'malformed_token' },
    { token: 'OCX9.message.AAAA', reason: 'unknown_version' },
    // The reason the version was bumped: a 0.3.x peer's token is refused with
    // "update your client" rather than dying somewhere inside the body.
    { token: 'OCX1.message.AAAA', reason: 'unknown_version' },
    { token: 'OCX1.invite.AAAA', reason: 'unknown_version' },
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
