import { test } from 'node:test';
import assert from 'node:assert/strict';

import { engine } from '../src/index.js';
import {
  deserializePending,
  deserializeSession,
  exportIdentity,
  importIdentity,
  serializePending,
  serializeSession,
} from '../src/serialize.js';
import { fromBase64Url, toBase64Url } from '../src/bytes.js';
import { connectedPair, expectFailure, flipByte, receive, send } from './harness.js';

test('a session survives death and restore mid conversation, parked key included', async () => {
  const { alice, bob } = await connectedPair();

  // A real conversation with traffic both ways, so both chains and the DH
  // ratchet have all turned at least once before the snapshot.
  assert.equal(await receive(bob, await send(alice, 'first')), 'first');
  assert.equal(await receive(alice, await send(bob, 'second')), 'second');
  assert.equal(await receive(bob, await send(alice, 'third')), 'third');
  assert.equal(await receive(alice, await send(bob, 'fourth')), 'fourth');

  // Park a key: `early` is sent first but `late` arrives first, so Bob steps
  // over one message key and files it under skippedKeys.
  const early = await send(alice, 'early, delayed in transit');
  const late = await send(alice, 'late, overtook it');
  assert.equal(await receive(bob, late), 'late, overtook it');
  assert.equal(Object.keys(bob.session.skippedKeys).length, 1);

  const savedBob = serializeSession(bob.session);
  const savedAlice = serializeSession(alice.session);
  assert.ok(savedBob.startsWith('OCX2.session.'), 'stored state must be self describing');
  assert.ok(/^[A-Za-z0-9._-]+$/.test(savedBob), 'stored state must be one pasteable ASCII token');

  // Byte exactness proof: the encoding is canonical (length prefixed fields,
  // no trailing bytes, one flags byte), so re-serialising the restored state
  // can only reproduce the identical string if every field, optional fields
  // and every skipped key included, round tripped exactly.
  assert.equal(serializeSession(deserializeSession(savedBob)), savedBob);
  assert.equal(serializeSession(deserializeSession(savedAlice)), savedAlice);

  // Both devices die. Everything below runs on state rebuilt from the strings.
  const rebornAlice = { name: 'alice-reborn', identity: alice.identity, session: deserializeSession(savedAlice) };
  const rebornBob = { name: 'bob-reborn', identity: bob.identity, session: deserializeSession(savedBob) };

  // The out of order message that was in flight across the restart still
  // opens, which proves the parked key survived byte exact.
  assert.equal(await receive(rebornBob, early), 'early, delayed in transit');
  assert.equal(Object.keys(rebornBob.session.skippedKeys).length, 0);

  // And the ratchet keeps turning in both directions.
  assert.equal(await receive(rebornBob, await send(rebornAlice, 'alice, after the restore')), 'alice, after the restore');
  assert.equal(await receive(rebornAlice, await send(rebornBob, 'bob, after the restore')), 'bob, after the restore');
  assert.equal(await receive(rebornBob, await send(rebornAlice, 'and back again')), 'and back again');
});

test('a pending invite survives serialize/deserialize and the accept still completes', async () => {
  const aliceIdentity = await engine.createIdentity();
  const bobIdentity = await engine.createIdentity();

  const invited = await engine.invite(aliceIdentity);
  const saved = serializePending(invited.pending);
  assert.ok(saved.startsWith('OCX2.pending.'), 'stored pending must be self describing');

  const restored = deserializePending(saved);
  assert.deepEqual(restored, invited.pending);

  // Alice restarts between sending the invite and receiving the accept, which
  // is exactly the window PendingSession persistence exists for.
  const bobOpened = await engine.open(bobIdentity, invited.token, {});
  assert.equal(bobOpened.outcome, 'invite');
  if (bobOpened.outcome !== 'invite') throw new Error('unreachable');

  const aliceOpened = await engine.open(aliceIdentity, bobOpened.reply, { pending: restored });
  assert.equal(aliceOpened.outcome, 'accepted');
});

test('an exported identity imports byte exact and completes a real handshake', async () => {
  const original = await engine.createIdentity();
  const exported = exportIdentity(original);
  assert.ok(exported.startsWith('OCX2.identity.'), 'exported identity must be self describing');

  const imported = importIdentity(exported);
  assert.deepEqual(imported, original);
  // Same identity means same fingerprint, which is what a user re-verifying
  // after a device migration would actually check.
  assert.deepEqual(engine.fingerprint(engine.publicOf(imported)).words, engine.fingerprint(engine.publicOf(original)).words);

  // Structural equality is not the bar, working crypto is: the imported
  // identity runs the whole hybrid handshake and seals a real message.
  const peer = await engine.createIdentity();
  const invited = await engine.invite(imported);
  const peerOpened = await engine.open(peer, invited.token, {});
  assert.equal(peerOpened.outcome, 'invite');
  if (peerOpened.outcome !== 'invite') throw new Error('unreachable');

  const importedOpened = await engine.open(imported, peerOpened.reply, { pending: invited.pending });
  assert.equal(importedOpened.outcome, 'accepted');
  if (importedOpened.outcome !== 'accepted') throw new Error('unreachable');

  const sealed = await engine.seal(importedOpened.session, 'proof the imported identity works');
  const opened = await engine.open(peer, sealed.token, { session: peerOpened.session });
  assert.equal(opened.outcome, 'message');
  if (opened.outcome !== 'message') throw new Error('unreachable');
  assert.equal(opened.plaintext, 'proof the imported identity works');
});

test('truncated, corrupted, mislabeled, and future version state all fail closed', async () => {
  const { bob } = await connectedPair();
  const saved = serializeSession(bob.session);
  const [, , encodedBody] = saved.split('.') as [string, string, string];
  const body = fromBase64Url(encodedBody);
  assert.ok(body !== null);

  // A truncated paste: the tail of the body, checksum included, is gone.
  await expectFailure('malformed_token', async () => deserializeSession(saved.slice(0, saved.length - 12)));

  // A single flipped bit in the middle of the body. Nothing structural breaks,
  // a key just silently changes, which is exactly what the checksum is for.
  const flipped = flipByte(body, Math.floor(body.length / 2));
  await expectFailure('malformed_token', async () => deserializeSession(`OCX2.session.${toBase64Url(flipped)}`));

  // A valid session token fed to the wrong deserializer. The kind label and
  // the kind-bound checksum both refuse it.
  await expectFailure('malformed_token', async () => deserializePending(saved));
  await expectFailure('malformed_token', async () => importIdentity(saved));

  // A future outer protocol version.
  await expectFailure('unknown_version', async () => deserializeSession(`OCX3.session.${encodedBody}`));

  // The 0.3.x outer marker. A state file written by the previous release is a
  // version problem and has to say so, because the layout behind it genuinely
  // cannot be read: peerChainEpoch did not exist and skippedKeys were keyed by
  // a base64 ratchet public rather than an epoch.
  await expectFailure('unknown_version', async () => deserializeSession(`OCX1.session.${encodedBody}`));

  // A future body format version: same token shape, bumped version byte.
  const bumped = Uint8Array.from(body);
  bumped[0] = 3;
  await expectFailure('unknown_version', async () => deserializeSession(`OCX2.session.${toBase64Url(bumped)}`));

  // The 0.3.x body format version, which is the case that actually happens: a
  // 0.3.4 session token pasted into a 0.4.0 build. It must not be read as a
  // 0.4.0 body with fields shifted, so the version byte is checked before any
  // field is parsed and the failure is a version failure.
  const stale = Uint8Array.from(body);
  stale[0] = 1;
  await expectFailure('unknown_version', async () => deserializeSession(`OCX2.session.${toBase64Url(stale)}`));

  // Assorted garbage that is not even token shaped.
  await expectFailure('malformed_token', async () => deserializeSession('not a token at all'));
  await expectFailure('malformed_token', async () => deserializeSession('OCX2.session.!!not-base64url!!'));
  await expectFailure('malformed_token', async () => deserializeSession('OCX2.session.'));
  await expectFailure('malformed_token', async () => importIdentity(''));
});
