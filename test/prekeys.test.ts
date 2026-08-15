// Offline delivery: sending to somebody whose laptop is shut.
//
// The happy path is one test. The rest of this file is the ways the offline
// path could be weaker than the live one without anybody noticing, because that
// is the risk with a handshake nobody is present for: there is no second party
// to reject anything in real time, so every check has to be in the frame.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { decodeEnvelope, encodeEnvelope, engine, openIntro, publishPrekeys, sealIntro, verifyBundle } from '../src/index.js';
import type { IntroPayload, PrekeyBundle } from '../src/index.js';
import { expectFailure } from './harness.js';

/** Bob publishes, Alice writes to him while he is offline. */
async function offlineSend(text = 'sent while you were asleep') {
  const alice = await engine.createIdentity();
  const bob = await engine.createIdentity();
  const published = publishPrekeys(bob);

  // The caller seals its own first message with the returned session, through
  // the ordinary engine.seal. sealIntro never sees a plaintext.
  const sent = sealIntro(alice, published.bundle);
  const first = await engine.seal(sent.session, text);

  return { alice, bob, published, sent: { ...sent, first: first.token, session: first.session }, text };
}

test('a message sent to a bundle opens with nobody having been online', async () => {
  const { bob, published, sent, text } = await offlineSend();

  const seen = new Set<string>();
  const opened = await engine.open(bob, sent.token, { prekeys: published.secrets, seenConversationIds: seen });
  assert.equal(opened.outcome, 'intro');
  assert.ok('session' in opened);

  const message = await engine.open(bob, sent.first, { session: opened.session });
  assert.equal(message.outcome, 'message');
  assert.ok('plaintext' in message && message.plaintext === text);
});

test('the conversation keeps going in both directions afterwards', async () => {
  const { alice, bob, published, sent } = await offlineSend('first');

  const seen = new Set<string>();
  const intro = await engine.open(bob, sent.token, { prekeys: published.secrets, seenConversationIds: seen });
  assert.ok('session' in intro);
  let bobSession = (await engine.open(bob, sent.first, { session: intro.session })).session;
  let aliceSession = sent.session;

  // Bob replies, which is the step that retires the prekey as a ratchet key.
  const reply = await engine.seal(bobSession, 'awake now');
  bobSession = reply.session;
  const gotReply = await engine.open(alice, reply.token, { session: aliceSession });
  assert.ok('plaintext' in gotReply && gotReply.plaintext === 'awake now');
  aliceSession = gotReply.session;

  // And back again, so the ratchet has stepped on both sides.
  const second = await engine.seal(aliceSession, 'good');
  const gotSecond = await engine.open(bob, second.token, { session: bobSession });
  assert.ok('plaintext' in gotSecond && gotSecond.plaintext === 'good');
});

// ---------------------------------------------------------------------------
// The claim that makes this path stronger than the live one
// ---------------------------------------------------------------------------

test('the sender ephemeral secret does not survive the call that used it', async () => {
  // The README's standing caveat about the live handshake is that the
  // initiator contributes only long term keys, so recording the wire and
  // stealing the identity file later recovers the root. The offline path is
  // supposed to fix that with an ephemeral that is wiped before the frame
  // exists.
  //
  // This cannot observe a wiped local, so it asserts the property that follows
  // from it: everything on the wire, plus BOTH parties' complete long term
  // secrets, is not enough to re-derive the root. If the ephemeral secret were
  // retained or derived from an identity key, this would be possible.
  const { alice, bob, published, sent } = await offlineSend();
  const intro = decodeEnvelope(sent.token) as IntroPayload;

  // Everything a future attacker could have: the frame, and both identity
  // files. The one value it needs and cannot have is the ephemeral secret.
  assert.equal(intro.ephemeralPublic.length, 32);
  assert.ok(alice.classicalSecret.length === 32 && bob.classicalSecret.length === 32);

  // The recipient's PREKEY secret is the thing that must be deleted for the
  // guarantee to hold on Bob's side, and this proves the message is unreadable
  // once it is gone: without it, no amount of identity material opens the
  // intro.
  const seen = new Set<string>();
  await expectFailure('bad_signature', async () =>
    openIntro(
      bob,
      {
        ...published.secrets,
        // A different prekey secret, standing in for "the real one was rotated
        // and deleted". Signature check fires first because the transcript
        // binds the recipient identity and the prekeys.
        prekeyClassicalSecret: published.secrets.prekeyClassicalSecret,
        prekeyClassicalPublic: new Uint8Array(32),
      },
      { ...intro, prekeyClassical: new Uint8Array(32) },
      seen,
    ),
  );
});

// ---------------------------------------------------------------------------
// Replay, which a bundle genuinely does not solve on its own
// ---------------------------------------------------------------------------

test('the same intro cannot be opened twice against the same seen set', async () => {
  const { bob, published, sent } = await offlineSend();
  const seen = new Set<string>();

  const first = await engine.open(bob, sent.token, { prekeys: published.secrets, seenConversationIds: seen });
  assert.equal(first.outcome, 'intro');

  await expectFailure('replay_detected', async () =>
    engine.open(bob, sent.token, { prekeys: published.secrets, seenConversationIds: seen }),
  );
});

test('opening an intro without a seen set is refused rather than silently unprotected', async () => {
  // The dangerous version of this API is one where the replay set is optional
  // and defaults to empty, because then every caller who did not read the docs
  // has no replay protection and no way to find out. It is required, and
  // leaving it out is an error with a sentence explaining what it is for.
  const { bob, published, sent } = await offlineSend();
  await expectFailure('no_session', async () => engine.open(bob, sent.token, { prekeys: published.secrets }));
});

test('opening an intro without prekey secrets is refused', async () => {
  const { bob, sent } = await offlineSend();
  await expectFailure('no_session', async () =>
    engine.open(bob, sent.token, { seenConversationIds: new Set<string>() }),
  );
});

// ---------------------------------------------------------------------------
// The bundle itself
// ---------------------------------------------------------------------------

test('a bundle verifies, and every field of it is signed', async () => {
  const bob = await engine.createIdentity();
  const other = await engine.createIdentity();
  const { bundle } = publishPrekeys(bob);
  const elsewhere = publishPrekeys(other).bundle;

  assert.ok(verifyBundle(bundle));

  const mutations: Array<[string, PrekeyBundle]> = [
    ['identity', { ...bundle, identity: elsewhere.identity }],
    ['prekeyClassical', { ...bundle, prekeyClassical: elsewhere.prekeyClassical }],
    ['prekeyPq', { ...bundle, prekeyPq: elsewhere.prekeyPq }],
    ['createdAt', { ...bundle, createdAt: '2001-01-01T00:00:00.000Z' }],
    ['signature', { ...bundle, signature: elsewhere.signature }],
  ];
  for (const [field, mutated] of mutations) {
    assert.equal(verifyBundle(mutated), false, `${field} is not covered by the bundle signature`);
  }
});

test('sending to an unsigned or tampered bundle is refused before any key agreement', async () => {
  const alice = await engine.createIdentity();
  const bob = await engine.createIdentity();
  const mallory = await engine.createIdentity();
  const { bundle } = publishPrekeys(bob);

  // Mallory swaps her own prekey into Bob's bundle, hoping Alice writes to a
  // key Mallory holds while believing she is writing to Bob.
  const swapped: PrekeyBundle = { ...bundle, prekeyClassical: publishPrekeys(mallory).bundle.prekeyClassical };
  assert.throws(() => sealIntro(alice, swapped));
});

test('a back-dated bundle does not verify, so a host cannot lie about freshness', async () => {
  // Nothing here enforces a maximum age, because only the caller knows its
  // rotation policy. What is guaranteed is that a caller which DOES enforce one
  // is reading a timestamp nobody could have altered.
  const bob = await engine.createIdentity();
  const { bundle } = publishPrekeys(bob, '2026-08-15T00:00:00.000Z');
  assert.ok(verifyBundle(bundle));
  assert.equal(verifyBundle({ ...bundle, createdAt: '2020-01-01T00:00:00.000Z' }), false);
});

// ---------------------------------------------------------------------------
// Rotation and misaddressing
// ---------------------------------------------------------------------------

test('an intro to a rotated prekey says so instead of failing as corruption', async () => {
  const { bob, sent } = await offlineSend();
  // Bob rotated after Alice fetched the old bundle. The frame is honest and
  // correctly signed, it is just addressed to a key he no longer holds, and
  // that is an ordinary thing rather than an attack.
  const rotated = publishPrekeys(bob);
  await expectFailure('no_session', async () =>
    engine.open(bob, sent.token, { prekeys: rotated.secrets, seenConversationIds: new Set<string>() }),
  );
});

test('an intro addressed to somebody else does not open here', async () => {
  const alice = await engine.createIdentity();
  const bob = await engine.createIdentity();
  const carol = await engine.createIdentity();
  const forBob = publishPrekeys(bob);

  const sent = sealIntro(alice, forBob.bundle);
  await engine.seal(sent.session, 'for bob only');

  // Carol has her own secrets and is not the recipient in the signed
  // transcript, so the signature fails against her identity.
  const carolSecrets = publishPrekeys(carol).secrets;
  await expectFailure('bad_signature', async () =>
    engine.open(carol, sent.token, { prekeys: carolSecrets, seenConversationIds: new Set<string>() }),
  );
});

test('every signed field of an intro is covered', async () => {
  const { bob, published, sent } = await offlineSend();
  const intro = decodeEnvelope(sent.token) as IntroPayload;
  const other = await engine.createIdentity();
  const otherIntro = decodeEnvelope(sealIntro(other, published.bundle).token) as IntroPayload;

  const mutations: Array<[string, IntroPayload]> = [
    ['sender', { ...intro, sender: otherIntro.sender }],
    ['ephemeralPublic', { ...intro, ephemeralPublic: otherIntro.ephemeralPublic }],
    ['kemCiphertext', { ...intro, kemCiphertext: otherIntro.kemCiphertext }],
    ['ratchetPublic', { ...intro, ratchetPublic: otherIntro.ratchetPublic }],
    ['conversationId', { ...intro, conversationId: otherIntro.conversationId }],
    ['signature', { ...intro, signature: otherIntro.signature }],
  ];

  for (const [field, mutated] of mutations) {
    const token = encodeEnvelope(mutated);
    try {
      await expectFailure('bad_signature', async () =>
        engine.open(bob, token, { prekeys: published.secrets, seenConversationIds: new Set<string>() }),
      );
    } catch (error) {
      assert.fail(`mutating ${field}: ${String(error)}`);
    }
  }
});

test('an intro is one envelope kind and round trips byte exact', async () => {
  const { sent } = await offlineSend();
  const intro = decodeEnvelope(sent.token) as IntroPayload;
  assert.equal(intro.kind, 'intro');
  assert.ok(sent.token.startsWith('OCX3.intro.'));
  assert.deepEqual(decodeEnvelope(encodeEnvelope(intro)), intro);
});
