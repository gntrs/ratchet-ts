import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from '@noble/hashes/utils.js';

import { engine } from '../src/index.js';
import { decodeEnvelope, decodeEnvelopeBytes, encodeEnvelope, encodeEnvelopeBytes } from '../src/envelope.js';
import { connectedPair, expectFailure, flipByte } from './harness.js';

/**
 * Engine surface for the bytes-native path.
 *
 * test/ratchet-bytes-path.test.ts proves the ratchet functions underneath.
 * These tests exist one layer up, at src/index.ts, because that is where a
 * caller actually meets them, and because the claim that matters for 0.3.1 is
 * an interop claim: a peer that never learned these two methods has to keep
 * working against a peer that uses them for everything.
 */

/** The old two-step outbound path, kept here as the thing to be identical to. */
async function sealTheLongWay(
  session: Parameters<typeof engine.sealBytes>[0],
  plaintext: Uint8Array,
): Promise<{ frame: Uint8Array; session: Parameters<typeof engine.sealBytes>[0] }> {
  const sealed = await engine.sealBytes(session, plaintext);
  return { frame: encodeEnvelopeBytes(decodeEnvelope(sealed.token)), session: sealed.session };
}

test('a frame the short way survives the long way unchanged', async () => {
  const { alice, bob } = await connectedPair();

  // Two seals of the same plaintext can never be compared directly: each draws
  // a fresh nonce. So the identity claim is put the other way round. Take the
  // frame the short path produced and run it through the representation the
  // long path went through, token and back. If those bytes come out different,
  // the two paths disagree about the wire and 0.3.1 is a protocol break.
  for (const size of [0, 1, 255, 65519]) {
    const plaintext = randomBytes(size);
    const direct = await engine.sealToEnvelopeBytes(alice.session, plaintext);
    alice.session = direct.session;

    const throughToken = encodeEnvelopeBytes(
      decodeEnvelope(encodeEnvelope(decodeEnvelopeBytes(direct.envelope))),
    );
    assert.deepEqual(throughToken, direct.envelope, `size ${size}`);

    const opened = await engine.openFromEnvelopeBytes(bob.session, direct.envelope);
    bob.session = opened.session;
    assert.deepEqual(opened.plaintext, plaintext, `size ${size}`);
  }
});

test('both paths advance the session identically', async () => {
  const { alice } = await connectedPair();
  const plaintext = randomBytes(4096);

  // Same starting session, two routes, and everything except the nonce and the
  // ciphertext has to land in the same place. A shortcut that quietly skipped a
  // chain step would still decrypt today and desynchronise tomorrow.
  const viaToken = await sealTheLongWay(alice.session, plaintext);
  const direct = await engine.sealToEnvelopeBytes(alice.session, plaintext);

  assert.equal(direct.session.sendCount, viaToken.session.sendCount);
  assert.equal(direct.session.previousSendCount, viaToken.session.previousSendCount);
  assert.deepEqual(direct.session.sendChainKey, viaToken.session.sendChainKey);
  assert.deepEqual(direct.session.rootKey, viaToken.session.rootKey);
  assert.deepEqual(direct.session.selfRatchetPublic, viaToken.session.selfRatchetPublic);
  assert.equal(direct.envelope.length, viaToken.frame.length);
});

test('a 0.3.0 peer opens what a 0.3.1 peer seals', async () => {
  const { alice, bob } = await connectedPair();
  const plaintext = randomBytes(4096);

  const sealed = await engine.sealToEnvelopeBytes(alice.session, plaintext);
  alice.session = sealed.session;

  // What 0.3.0 does with an inbound frame: base64 it into a token, then open
  // the token. Nothing about the frame lets it tell the two senders apart.
  const asToken = encodeEnvelope(decodeEnvelopeBytes(sealed.envelope));
  const opened = await engine.openBytes(bob.session, asToken);
  bob.session = opened.session;

  assert.deepEqual(opened.plaintext, plaintext);
});

test('a 0.3.1 peer opens what a 0.3.0 peer sealed', async () => {
  const { alice, bob } = await connectedPair();
  const plaintext = randomBytes(4096);

  const sealed = await sealTheLongWay(alice.session, plaintext);
  alice.session = sealed.session;

  const opened = await engine.openFromEnvelopeBytes(bob.session, sealed.frame);
  bob.session = opened.session;

  assert.deepEqual(opened.plaintext, plaintext);
});

test('a handshake envelope handed to openFromEnvelopeBytes fails closed', async () => {
  const { bob } = await connectedPair();
  const invited = await engine.invite(bob.identity);
  const inviteFrame = encodeEnvelopeBytes(decodeEnvelope(invited.token));

  // The state machine for invite and accept lives in `open`, and there is no
  // bytes-native door into it on purpose. Sending one here must be a named
  // refusal, not a cast that half works.
  await expectFailure('malformed_token', () =>
    engine.openFromEnvelopeBytes(bob.session, inviteFrame),
  );
});

test('a tampered frame fails closed and leaves the session untouched', async () => {
  const { alice, bob } = await connectedPair();
  const sealed = await engine.sealToEnvelopeBytes(alice.session, randomBytes(1024));
  alice.session = sealed.session;

  const before = bob.session;
  // Late in the frame is inside the ciphertext, which the AEAD tag covers.
  const corrupted = flipByte(sealed.envelope, sealed.envelope.length - 5);
  await expectFailure('authentication_failed', () =>
    engine.openFromEnvelopeBytes(bob.session, corrupted),
  );

  assert.equal(bob.session, before);
  assert.equal(bob.session.recvCount, 0);

  // The good frame still opens afterwards: a rejected forgery must not have
  // consumed the chain step the real message needs.
  const opened = await engine.openFromEnvelopeBytes(bob.session, sealed.envelope);
  assert.equal(opened.session.recvCount, 1);
});
