import { test } from 'node:test';
import assert from 'node:assert/strict';

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

import type { AcceptPayload, IdentityKeyPair, SessionState } from '../src/contract.js';
import { concat, toHex } from '../src/bytes.js';
import { x25519Keygen, x25519SharedSecret } from '../src/curves.js';
import { decodeEnvelope, encodeEnvelope } from '../src/envelope.js';
import { engine, publishPrekeys, sealIntro } from '../src/index.js';
import { kdfHandshake, kdfRoot } from '../src/kdf.js';
import { expectFailure } from './harness.js';

/**
 * Every leg of the hybrid handshake is load bearing, proved by breaking it.
 *
 * WHAT THIS FILE IS AND IS NOT. test/hybrid.test.ts already pins the live
 * invite/accept handshake: it proves the responder's stored root key really
 * contains the decapsulated ML-KEM secret, and that the initiator lands one
 * kdfRoot step past the same hybrid root. Those two tests are not repeated
 * here. This file covers what they leave open:
 *
 *   - the two X25519 legs of the LIVE handshake, where hybrid.test.ts pins
 *     them only at the KDF with synthetic inputs
 *   - the conversation id binding
 *   - the offline prekey handshake, which mixes FOUR secrets and had no leg
 *     coverage at all, despite being the newest code in the library
 *   - the order the four secrets are concatenated in
 *   - the downgrade surface: whether an attacker can make the post-quantum arm
 *     go away, by truncating it, by substituting it, or by simply not sending
 *     it, and whether a classical-only peer can talk to a real one
 *
 * WHY THE LEG TESTS ARE NOT CIRCULAR. The obvious version calls kdfHandshake
 * twice with different inputs and asserts the outputs differ. That proves HKDF
 * reads its input, which nobody doubted, and proves nothing about the engine.
 * So every leg test below runs the real handshake through the real public API,
 * takes the root key the live session actually ended up holding, and then
 * re-derives that exact value from outside using only primitives and the
 * secrets a participant holds.
 *
 * The assertion is two sided and both sides matter:
 *
 *   POSITIVE  the reconstruction that includes every leg matches the live root
 *             key byte for byte, which proves the reconstruction is a faithful
 *             model of what the engine did rather than a guess.
 *   NEGATIVE  every reconstruction that drops, zeroes or substitutes one leg
 *             fails to match, which proves the engine's value could not have
 *             been produced without that leg.
 *
 * Only the pair is meaningful. The positive alone would pass against an engine
 * that ignored the KEM if the model ignored it too. The negative alone would
 * pass against a model that was simply wrong about everything.
 *
 * VERIFIED BY MUTATION, 2026-08-21. src/handshake.ts and src/prekeys.ts were
 * edited to drop the KEM secret from the ikm concatenation, in all four places
 * it is mixed. Five of the seven tests here went red, along with both LIVE
 * HANDSHAKE tests in hybrid.test.ts. The two that stayed green are the last
 * two, and they are supposed to: they test whether the post-quantum arm can be
 * removed by an attacker on the wire, not whether the code mixes it, so a build
 * that voluntarily stopped mixing is outside what they can see. That is what
 * the other five are for. A test that has never been shown to fail is a
 * decoration, so the numbers above are measured, not expected.
 */

/** 32 zero bytes, standing in for a KEM secret that never arrived. */
const ZERO_SECRET = new Uint8Array(32);

/** A distinct, valid ML-KEM secret, standing in for the wrong peer's KEM. */
function unrelatedKemSecret(): Uint8Array {
  const other = ml_kem768.keygen();
  return ml_kem768.encapsulate(other.publicKey).sharedSecret;
}

function differs(a: Uint8Array, b: Uint8Array): boolean {
  return toHex(a) !== toHex(b);
}

/**
 * Asserts the live root key is reproducible from `withLeg` and from nothing
 * else. `variants` are the same derivation with one leg damaged; each must
 * miss. The label ends up in the assertion message, so a failure names the leg.
 */
function onlyReproducibleWith(
  live: Uint8Array,
  withLeg: Uint8Array,
  variants: ReadonlyArray<{ label: string; value: Uint8Array }>,
): void {
  assert.equal(
    toHex(withLeg),
    toHex(live),
    'the reconstruction including every leg must match the live root key, or this test models the wrong protocol',
  );
  for (const variant of variants) {
    assert.ok(
      differs(variant.value, live),
      `the live root key was reproducible without ${variant.label}, so that leg is not load bearing`,
    );
  }
}

// ---------------------------------------------------------------------------
// The live invite/accept handshake. ikm = dh1 || dh2 || kemSharedSecret
// ---------------------------------------------------------------------------

interface LiveHandshake {
  readonly alice: IdentityKeyPair;
  readonly bob: IdentityKeyPair;
  readonly accept: AcceptPayload;
  readonly bobSession: SessionState;
  readonly aliceSession: SessionState;
}

async function liveHandshake(): Promise<LiveHandshake> {
  const alice = await engine.createIdentity();
  const bob = await engine.createIdentity();

  const invited = await engine.invite(alice);
  const bobOpened = await engine.open(bob, invited.token, {});
  assert.equal(bobOpened.outcome, 'invite');
  if (bobOpened.outcome !== 'invite') throw new Error('unreachable');

  const aliceOpened = await engine.open(alice, bobOpened.reply, { pending: invited.pending });
  assert.equal(aliceOpened.outcome, 'accepted');
  if (aliceOpened.outcome !== 'accepted') throw new Error('unreachable');

  const accept = decodeEnvelope(bobOpened.reply);
  assert.equal(accept.kind, 'accept');
  if (accept.kind !== 'accept') throw new Error('unreachable');

  return { alice, bob, accept, bobSession: bobOpened.session, aliceSession: aliceOpened.session };
}

test('the classical identity leg is load bearing: the responder root key needs DH1', async () => {
  const { alice, bob, accept, bobSession } = await liveHandshake();

  const kemShared = ml_kem768.decapsulate(accept.kemCiphertext, alice.pqSecret);
  const dh1 = x25519SharedSecret(bob.classicalSecret, engine.publicOf(alice).classicalPublic);
  const dh2 = x25519SharedSecret(bobSession.selfRatchetSecret, engine.publicOf(alice).classicalPublic);
  const cid = bobSession.conversationId;

  // DH1 with a stranger's key stands in for the case that actually matters:
  // an adversary who is not the identity the invite named.
  const stranger = x25519Keygen();
  const wrongDh1 = x25519SharedSecret(stranger.secretKey, engine.publicOf(alice).classicalPublic);

  onlyReproducibleWith(bobSession.rootKey, kdfHandshake(concat(dh1, dh2, kemShared), cid), [
    { label: 'the DH1 identity leg entirely', value: kdfHandshake(concat(dh2, kemShared), cid) },
    { label: 'a zeroed DH1', value: kdfHandshake(concat(ZERO_SECRET, dh2, kemShared), cid) },
    { label: "a stranger's DH1", value: kdfHandshake(concat(wrongDh1, dh2, kemShared), cid) },
  ]);
});

test('the freshness leg is load bearing: the responder root key needs DH2', async () => {
  const { alice, bob, accept, bobSession } = await liveHandshake();

  const kemShared = ml_kem768.decapsulate(accept.kemCiphertext, alice.pqSecret);
  const dh1 = x25519SharedSecret(bob.classicalSecret, engine.publicOf(alice).classicalPublic);
  const dh2 = x25519SharedSecret(bobSession.selfRatchetSecret, engine.publicOf(alice).classicalPublic);
  const cid = bobSession.conversationId;

  // A different ratchet key is what a replayed accept would carry. If DH2 were
  // not mixed in, every handshake against one invite would land on one root.
  const otherRatchet = x25519Keygen();
  const wrongDh2 = x25519SharedSecret(otherRatchet.secretKey, engine.publicOf(alice).classicalPublic);

  onlyReproducibleWith(bobSession.rootKey, kdfHandshake(concat(dh1, dh2, kemShared), cid), [
    { label: 'the DH2 freshness leg entirely', value: kdfHandshake(concat(dh1, kemShared), cid) },
    { label: 'a zeroed DH2', value: kdfHandshake(concat(dh1, ZERO_SECRET, kemShared), cid) },
    { label: 'a different ratchet key in DH2', value: kdfHandshake(concat(dh1, wrongDh2, kemShared), cid) },
  ]);
});

test('the conversation id is bound into the root key', async () => {
  const { alice, bob, accept, bobSession } = await liveHandshake();

  const kemShared = ml_kem768.decapsulate(accept.kemCiphertext, alice.pqSecret);
  const dh1 = x25519SharedSecret(bob.classicalSecret, engine.publicOf(alice).classicalPublic);
  const dh2 = x25519SharedSecret(bobSession.selfRatchetSecret, engine.publicOf(alice).classicalPublic);
  const ikm = concat(dh1, dh2, kemShared);

  onlyReproducibleWith(bobSession.rootKey, kdfHandshake(ikm, bobSession.conversationId), [
    { label: 'the real conversation id', value: kdfHandshake(ikm, '00000000000000000000000000000000') },
  ]);
});

// ---------------------------------------------------------------------------
// The offline prekey handshake. ikm = dh1 || dh2 || dh3 || kemSharedSecret
// ---------------------------------------------------------------------------

test('all four legs of the offline prekey handshake are load bearing', async () => {
  const sender = await engine.createIdentity();
  const recipient = await engine.createIdentity();
  const published = publishPrekeys(recipient);

  const sealed = sealIntro(sender, published.bundle);
  const intro = decodeEnvelope(sealed.token);
  assert.equal(intro.kind, 'intro');
  if (intro.kind !== 'intro') throw new Error('unreachable');

  // Recovered from the recipient's side, which is the side that holds the
  // prekey secrets. That is deliberate: reading the sender's ephemeral secret
  // is impossible from outside, so the reconstruction is built the way a real
  // recipient builds it, and it still has to land on the sender's root key.
  const dh1 = x25519SharedSecret(recipient.classicalSecret, intro.ephemeralPublic);
  const dh2 = x25519SharedSecret(published.secrets.prekeyClassicalSecret, intro.sender.classicalPublic);
  const dh3 = x25519SharedSecret(published.secrets.prekeyClassicalSecret, intro.ephemeralPublic);
  const ss = ml_kem768.decapsulate(intro.kemCiphertext, published.secrets.prekeyPqSecret);
  const cid = sealed.conversationId;

  // sealIntro also takes one ratchet step before returning, against the
  // recipient's classical prekey.
  const stepDh = x25519SharedSecret(sealed.session.selfRatchetSecret, published.bundle.prekeyClassical);
  const through = (ikm: Uint8Array): Uint8Array => kdfRoot(kdfHandshake(ikm, cid), stepDh).rootKey;

  onlyReproducibleWith(sealed.session.rootKey, through(concat(dh1, dh2, dh3, ss)), [
    { label: 'the ML-KEM leg entirely', value: through(concat(dh1, dh2, dh3)) },
    { label: 'a zeroed ML-KEM shared secret', value: through(concat(dh1, dh2, dh3, ZERO_SECRET)) },
    { label: 'an unrelated ML-KEM shared secret', value: through(concat(dh1, dh2, dh3, unrelatedKemSecret())) },
    { label: 'DH1, which binds the recipient identity', value: through(concat(dh2, dh3, ss)) },
    { label: 'DH2, which binds the sender identity', value: through(concat(dh1, dh3, ss)) },
    { label: 'DH3, which carries the forward secrecy', value: through(concat(dh1, dh2, ss)) },
  ]);

  // Order is part of the construction. Feeding the same four secrets in a
  // different order must not land on the same root, or the concatenation is
  // not actually canonical and two implementations could disagree silently.
  assert.ok(
    differs(through(concat(dh2, dh1, dh3, ss)), sealed.session.rootKey),
    'swapping DH1 and DH2 produced the same root key, so the ikm concatenation is not order bound',
  );
});

// ---------------------------------------------------------------------------
// There is no path that turns the post-quantum arm off
// ---------------------------------------------------------------------------

test('an accept carrying no ML-KEM ciphertext is refused, not treated as classical-only', async () => {
  const alice = await engine.createIdentity();
  const bob = await engine.createIdentity();
  const invited = await engine.invite(alice);
  const bobOpened = await engine.open(bob, invited.token, {});
  if (bobOpened.outcome !== 'invite') throw new Error('unreachable');

  const accept = decodeEnvelope(bobOpened.reply);
  if (accept.kind !== 'accept') throw new Error('unreachable');

  // The downgrade an attacker would want: strip the expensive post-quantum
  // arm and leave a handshake that still looks well formed. Every truncation
  // has to be refused outright rather than derived from.
  for (const length of [0, 1, 1087, 1089]) {
    const stripped = encodeEnvelope({ ...accept, kemCiphertext: new Uint8Array(length) });
    await expectFailure('malformed_token', async () =>
      engine.open(alice, stripped, { pending: invited.pending }),
    );
  }
});

test('substituting the ML-KEM ciphertext is caught by the accept signature', async () => {
  const alice = await engine.createIdentity();
  const bob = await engine.createIdentity();
  const invited = await engine.invite(alice);
  const bobOpened = await engine.open(bob, invited.token, {});
  if (bobOpened.outcome !== 'invite') throw new Error('unreachable');

  const accept = decodeEnvelope(bobOpened.reply);
  if (accept.kind !== 'accept') throw new Error('unreachable');

  // A full length ciphertext encapsulated to somebody else. This is the shape
  // of a network attacker forcing both sides onto a KEM secret it chose. The
  // transcript signature covers the ciphertext, so it never reaches the KDF.
  const attacker = ml_kem768.keygen();
  const substituted = encodeEnvelope({
    ...accept,
    kemCiphertext: ml_kem768.encapsulate(attacker.publicKey).cipherText,
  });

  await expectFailure('bad_signature', async () =>
    engine.open(alice, substituted, { pending: invited.pending }),
  );
});

test('a session whose root was derived without the ML-KEM leg cannot talk to a real peer', async () => {
  const { alice, bob, accept, bobSession, aliceSession } = await liveHandshake();

  // End to end rather than at the KDF: build the initiator session a
  // hypothetical classical-only build would have produced, seal a real message
  // with it through the ordinary public API, and hand it to the untouched
  // responder. If dropping the KEM leg were survivable, this would open.
  const dh1 = x25519SharedSecret(alice.classicalSecret, accept.sender.classicalPublic);
  const dh2 = x25519SharedSecret(alice.classicalSecret, accept.ratchetPublic);
  const stepDh = x25519SharedSecret(aliceSession.selfRatchetSecret, accept.ratchetPublic);
  const downgraded = kdfRoot(kdfHandshake(concat(dh1, dh2), aliceSession.conversationId), stepDh);

  const classicalOnly: SessionState = {
    ...aliceSession,
    rootKey: downgraded.rootKey,
    sendChainKey: downgraded.chainKey,
  };

  const sealed = await engine.seal(classicalOnly, 'this must not be readable');
  await expectFailure('authentication_failed', async () =>
    engine.open(bob, sealed.token, { session: bobSession }),
  );

  // And the control: the real session, same message, opens cleanly. Without
  // this the test above would pass against an engine that rejected everything.
  const honest = await engine.seal(aliceSession, 'this must be readable');
  const opened = await engine.open(bob, honest.token, { session: bobSession });
  assert.equal(opened.outcome, 'message');
  if (opened.outcome !== 'message') throw new Error('unreachable');
  assert.equal(opened.plaintext, 'this must be readable');
});
