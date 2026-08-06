import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from '@noble/hashes/utils.js';

import type { MessagePayload } from '../src/contract.js';
import { utf8ToBytes, bytesToUtf8 } from '../src/bytes.js';
import { decodeEnvelope, encodeEnvelope } from '../src/envelope.js';
import { ratchetDecryptBytes, ratchetEncryptBytes } from '../src/ratchet.js';
import { connectedPair, editMessage, expectFailure, flipByte, receive, send } from './harness.js';
import type { Party } from './harness.js';

/**
 * Binary payload coverage.
 *
 * These tests reach into src/ratchet.ts directly, one layer past the usual
 * src/index.ts boundary, because the byte API ships from the ratchet this
 * round and the engine sealBytes/openBytes wrappers land with the integrator.
 * Everything here still runs through the real wire format where a token is
 * involved, so nothing is being simulated.
 */

/** Seals bytes and advances the sender, mirroring `send` in the harness. */
function sendBytes(from: Party, plaintext: Uint8Array): MessagePayload {
  const sealed = ratchetEncryptBytes(from.session, plaintext);
  from.session = sealed.session;
  return sealed.payload;
}

/** Opens bytes and advances the receiver, mirroring `receive` in the harness. */
function receiveBytes(to: Party, payload: MessagePayload): Uint8Array {
  const opened = ratchetDecryptBytes(to.session, payload);
  to.session = opened.session;
  return opened.plaintext;
}

/** Narrows a decoded envelope to a message payload or fails the test. */
function asMessage(token: string): MessagePayload {
  const payload = decodeEnvelope(token);
  assert.equal(payload.kind, 'message');
  if (payload.kind !== 'message') throw new Error('unreachable');
  return payload;
}

test('a 64 KiB random payload round trips byte exact', async () => {
  const { alice, bob } = await connectedPair();

  // Random bytes are the worst case for any accidental text assumption: they
  // contain every byte value and are almost never valid UTF-8.
  const blob = randomBytes(64 * 1024);
  const payload = sendBytes(alice, blob);
  const opened = receiveBytes(bob, payload);

  assert.equal(opened.length, blob.length);
  assert.deepEqual(opened, blob);
  // The ratchet advanced exactly as it would for a text message: one chain
  // step, no special casing for size or content.
  assert.equal(alice.session.sendCount, 1);
  assert.equal(bob.session.recvCount, 1);
});

test('bytes that are not valid UTF-8 come back exactly, where a string round trip would mangle them', async () => {
  const { alice, bob } = await connectedPair();

  // Invalid in several distinct ways: bare continuation byte, overlong-ish
  // lead byte with a wrong follower, an unpaired surrogate encoding, and a
  // stray 0xff which is never legal in UTF-8. Plus an embedded NUL for luck.
  const evil = Uint8Array.of(0xff, 0xfe, 0x80, 0x00, 0xc3, 0x28, 0xed, 0xa0, 0x80, 0xf8);

  // First, the reason this API exists: a UTF-8 decode/encode round trip does
  // NOT preserve these bytes. The string path would silently corrupt them.
  assert.notDeepEqual(utf8ToBytes(bytesToUtf8(evil)), evil);

  // The bytes path preserves them exactly, end to end through the wire format.
  const token = encodeEnvelope(sendBytes(alice, evil));
  assert.deepEqual(receiveBytes(bob, asMessage(token)), evil);
});

test('interop: a string-sealed token opened as bytes is exactly the UTF-8 encoding', async () => {
  const { alice, bob } = await connectedPair();

  const text = 'ąčęėįšųū 🔐 same wire format';
  const token = await send(alice, text);
  assert.deepEqual(receiveBytes(bob, asMessage(token)), utf8ToBytes(text));
});

test('interop: a bytes-sealed token holding valid UTF-8 opens on the string path', async () => {
  const { alice, bob } = await connectedPair();

  const text = 'bytes in, string out';
  const token = encodeEnvelope(sendBytes(alice, utf8ToBytes(text)));
  assert.equal(await receive(bob, token), text);
});

test('tampering with one bit of a bytes-sealed token fails closed and leaves the session usable', async () => {
  const { alice, bob } = await connectedPair();

  const blob = randomBytes(1024);
  const honest = encodeEnvelope(sendBytes(alice, blob));
  const tampered = editMessage(honest, (payload) => ({
    ...payload,
    ciphertext: flipByte(payload.ciphertext, 100),
  }));

  await expectFailure('authentication_failed', async () => receiveBytes(bob, asMessage(tampered)));
  // Fail closed means the receiver's state was not advanced by the forgery, so
  // the honest copy of the same message still opens byte exact.
  assert.deepEqual(receiveBytes(bob, asMessage(honest)), blob);
});

test('an empty Uint8Array round trips, including through the wire format', async () => {
  const { alice, bob } = await connectedPair();

  const empty = new Uint8Array(0);
  const token = encodeEnvelope(sendBytes(alice, empty));
  const opened = receiveBytes(bob, asMessage(token));
  assert.equal(opened.length, 0);
  assert.deepEqual(opened, empty);

  // And the session keeps working afterwards in both directions.
  assert.equal(await receive(bob, await send(alice, 'still alive')), 'still alive');
  assert.equal(await receive(alice, await send(bob, 'both ways')), 'both ways');
});
