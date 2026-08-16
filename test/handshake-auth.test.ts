// The 0.6.0 handshake signatures, attacked rather than demonstrated.
//
// A signature that is only ever checked on frames the library itself produced
// is not a tested signature: it passes whether it binds the right transcript or
// the empty string. Every test here builds the frame an attacker would build
// and asserts the specific reason it is refused.
//
// The one that matters most is "a machine in the middle cannot re-address a
// handshake". The others are the ways that guarantee could be lost by accident:
// forgetting a field in the transcript, checking against the wrong identity, or
// verifying after the expensive key agreement instead of before it.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

import { decodeEnvelope, encodeEnvelope, engine } from '../src/index.js';
import type { AcceptPayload, InvitePayload } from '../src/index.js';
import { expectFailure } from './harness.js';

/**
 * OpenResult is a discriminated union and only the `invite` arm carries a
 * reply. Narrowing through an assertion rather than a cast, so that a change to
 * the union surfaces here as a failing assertion instead of a silent undefined.
 */
function replyOf(result: Awaited<ReturnType<typeof engine.open>>): string {
  assert.equal(result.outcome, 'invite');
  assert.ok('reply' in result && typeof result.reply === 'string');
  return result.reply;
}

/** invite, accept, and the identities on both ends of a real handshake. */
async function handshake() {
  const alice = await engine.createIdentity();
  const bob = await engine.createIdentity();
  const invited = await engine.invite(alice);
  const invite = decodeEnvelope(invited.token) as InvitePayload;
  const accepted = await engine.open(bob, invited.token, {});
  const reply = replyOf(accepted);
  const accept = decodeEnvelope(reply) as AcceptPayload;
  return { alice, bob, invited, invite, reply, accept };
}

test('the honest handshake still completes, so the rest of this file means something', async () => {
  const { alice, invited, reply } = await handshake();
  const done = await engine.open(alice, reply, { pending: invited.pending });
  assert.equal(done.outcome, 'accepted');
});

// ---------------------------------------------------------------------------
// The attack the signatures exist for
// ---------------------------------------------------------------------------

test('an identity cannot be swapped into somebody else\'s certificate', async () => {
  // Mallory takes Alice's invite and puts her own identity in it, keeping the
  // certificate. The certificate is over the three keys it certifies, so it no
  // longer matches and the invite is refused.
  const { invite } = await handshake();
  const mallory = await engine.createIdentity();
  const bob = await engine.createIdentity();

  const rewritten = encodeEnvelope({ ...invite, sender: engine.publicOf(mallory) });
  await expectFailure('bad_signature', async () => engine.open(bob, rewritten, {}));

  // And a certificate cannot be lifted from another identity either.
  const theirs = decodeEnvelope((await engine.invite(mallory)).token) as InvitePayload;
  await expectFailure('bad_signature', async () =>
    engine.open(bob, encodeEnvelope({ ...invite, certificate: theirs.certificate }), {}),
  );
});

// Stated as its own test because it is the thing people assume a signed invite
// prevents, and it never did, in either the old per-invite shape or this one.
test('anyone may send their OWN invite, and that is not the attack', async () => {
  // Mallory holds her own signing key, so of course she can certify her own
  // identity and invite Bob. Bob sees Mallory's identity and Mallory's
  // fingerprint, which is accurate. Nothing here is being spoofed.
  //
  // What the invite has never proved is possession of the X25519 or ML-KEM
  // halves: an attacker could always pair somebody else's two keys with a
  // signing keypair of their own. That produces a DIFFERENT fingerprint, which
  // is the check that catches it, and the accept transcript is what stops a
  // real conversation being re-addressed. This test exists so that nobody reads
  // the certificate as a stronger claim than it makes.
  const mallory = await engine.createIdentity();
  const bob = await engine.createIdentity();
  const ok = await engine.open(bob, (await engine.invite(mallory)).token, {});
  assert.equal(ok.outcome, 'invite');
  assert.ok('peerFingerprint' in ok);
  assert.equal(ok.peerFingerprint.hex, engine.fingerprint(engine.publicOf(mallory)).hex);
});

test('a machine in the middle cannot re-address an accept to its own identity', async () => {
  const { alice, invited, accept } = await handshake();
  const mallory = await engine.createIdentity();

  const rewritten = encodeEnvelope({
    ...accept,
    sender: engine.publicOf(mallory),
  });

  await expectFailure('bad_signature', async () =>
    engine.open(alice, rewritten, { pending: invited.pending }),
  );
});

// This is the whole point of putting the INITIATOR's identity inside the accept
// transcript. Mallory sits between Alice and Bob. She takes Alice's invite,
// substitutes her own identity, and Bob signs an accept over Mallory's identity
// because that is what he saw. She then forwards Bob's real accept to Alice.
// Alice rebuilds the transcript with her OWN identity, which is not what Bob
// signed, so the signature does not verify.
test('an accept signed over a different initiator identity is refused by the initiator', async () => {
  const alice = await engine.createIdentity();
  const bob = await engine.createIdentity();
  const mallory = await engine.createIdentity();

  const aliceInvite = await engine.invite(alice);
  const invite = decodeEnvelope(aliceInvite.token) as InvitePayload;

  // She makes her own invite instead, on Alice's conversation id. Since the
  // certificate does not cover the id, she does not even have to sign anything:
  // she takes her own certificate and stamps the id she wants. That is exactly
  // the freedom the last test documents, and it is harmless for the reason this
  // test is about to demonstrate.
  const malloryInvite = decodeEnvelope((await engine.invite(mallory)).token) as InvitePayload;
  const forged = encodeEnvelope({ ...malloryInvite, conversationId: invite.conversationId });

  // Bob accepts it, correctly: it is a valid invite from Mallory. He has no way
  // to know Alice exists, and that is not what the signature is for.
  const bobsAccept = await engine.open(bob, forged, {});
  const bobsReply = replyOf(bobsAccept);

  // Now Mallory forwards Bob's real, correctly signed accept to Alice. The
  // conversation id matches, so the pending check passes and the signature is
  // the only thing left. Alice rebuilds the transcript with HER identity, Bob
  // signed it with Mallory's, and it does not verify.
  await expectFailure('bad_signature', async () =>
    engine.open(alice, bobsReply, { pending: aliceInvite.pending }),
  );
});

// ---------------------------------------------------------------------------
// The ways the transcript could be wrong without anyone noticing
// ---------------------------------------------------------------------------

test('every signed field of the accept is actually covered by the signature', async () => {
  const { alice, invited, accept } = await handshake();
  const other = await engine.createIdentity();
  const otherAccept = decodeEnvelope(
    replyOf(await engine.open(other, (await engine.invite(alice)).token, {})),
  ) as AcceptPayload;

  // Each mutation swaps in a value from a different, real handshake, so the
  // field stays well formed and the only thing that can reject it is the
  // signature. A field left out of the transcript would let one of these
  // through, and the field name is in the assertion so the diff says which.
  //
  // conversationId is the one exception and it is listed with the reason it
  // actually produces: the pending check runs first and refuses it as
  // no_session. That is a correct refusal, it is just not this one, and
  // asserting bad_signature there would be asserting a lie.
  const mutations: Array<[string, AcceptPayload, 'bad_signature' | 'no_session']> = [
    ['conversationId', { ...accept, conversationId: otherAccept.conversationId }, 'no_session'],
    ['kemCiphertext', { ...accept, kemCiphertext: otherAccept.kemCiphertext }, 'bad_signature'],
    ['ratchetPublic', { ...accept, ratchetPublic: otherAccept.ratchetPublic }, 'bad_signature'],
    ['sender', { ...accept, sender: otherAccept.sender }, 'bad_signature'],
  ];

  for (const [field, mutated, reason] of mutations) {
    const token = encodeEnvelope(mutated);
    try {
      await expectFailure(reason, async () => engine.open(alice, token, { pending: invited.pending }));
    } catch (error) {
      assert.fail(`mutating ${field}: ${String(error)}`);
    }
  }
});

test('the certificate covers the identity, and deliberately not the conversation', async () => {
  const { invite } = await handshake();
  const bob = await engine.createIdentity();
  const other = decodeEnvelope((await engine.invite(await engine.createIdentity())).token) as InvitePayload;

  // Covered: swapping the identity or the certificate is refused.
  for (const mutated of [
    { ...invite, sender: other.sender },
    { ...invite, certificate: other.certificate },
  ]) {
    await expectFailure('bad_signature', async () => engine.open(bob, encodeEnvelope(mutated), {}));
  }

  // NOT covered, on purpose: the conversation id. Re-stamping an invite onto a
  // different conversation is accepted here, and this test asserts that it is
  // accepted rather than pretending otherwise.
  //
  // It costs nothing an attacker did not already have. An invite was always
  // replayable verbatim, so the id was never a freshness guarantee, and what a
  // re-stamped invite buys is a session with somebody who is not listening: a
  // way to waste a responder's CPU, not a way to read anything. Binding it cost
  // 8 ms of signing on every invite ever sent, which is why it is gone.
  const restamped = encodeEnvelope({ ...invite, conversationId: other.conversationId });
  const accepted = await engine.open(bob, restamped, {});
  assert.equal(accepted.outcome, 'invite');
});

// ---------------------------------------------------------------------------
// Shape, not content
// ---------------------------------------------------------------------------

test('a certificate of the wrong length is a malformed token, not a bad signature', async () => {
  // Two different failures on purpose. A wrong length never reached the
  // verifier, so calling it a bad signature would claim something was checked
  // that was not, and the caller cannot tell a truncated frame from an attack.
  const { invite } = await handshake();
  const bob = await engine.createIdentity();

  for (const length of [0, 1, 3308, 3310]) {
    const token = encodeEnvelope({ ...invite, certificate: new Uint8Array(length) });
    await expectFailure('malformed_token', async () => engine.open(bob, token, {}));
  }
});

test('a verifying key of the wrong length is refused before any key agreement', async () => {
  const { invite } = await handshake();
  const bob = await engine.createIdentity();
  const token = encodeEnvelope({
    ...invite,
    sender: { ...invite.sender, sigPublic: new Uint8Array(1951) },
  });
  await expectFailure('malformed_token', async () => engine.open(bob, token, {}));
});

test('an all zero certificate is refused', async () => {
  const { invite } = await handshake();
  const bob = await engine.createIdentity();
  const token = encodeEnvelope({ ...invite, certificate: new Uint8Array(3309) });
  await expectFailure('bad_signature', async () => engine.open(bob, token, {}));
});

// ---------------------------------------------------------------------------
// The transcript is domain separated
// ---------------------------------------------------------------------------

test('a certificate cannot be lifted into an accept, or the reverse', async () => {
  // The certificate and the accept transcript both cover a sender identity, so
  // without distinct domain strings there would be an argument to have about
  // whether one could ever be a prefix of the other. The domains make that
  // argument unnecessary, and this pins it.
  const { alice, invited, invite, accept } = await handshake();
  const bob = await engine.createIdentity();

  await expectFailure('bad_signature', async () =>
    engine.open(bob, encodeEnvelope({ ...invite, certificate: accept.signature }), {}),
  );
  await expectFailure('bad_signature', async () =>
    engine.open(alice, encodeEnvelope({ ...accept, signature: invite.certificate }), {
      pending: invited.pending,
    }),
  );
});

// ---------------------------------------------------------------------------
// Hedged signing
// ---------------------------------------------------------------------------

test('two invites from one identity carry different signatures', async () => {
  // The library signs hedged, per FIPS 204, so signatures are not deterministic.
  // Only the vector generator pins extraEntropy to false. If this ever starts
  // producing identical signatures, somebody switched the live signer to
  // deterministic mode and that is a decision to make deliberately, not by
  // accident: it trades away fault-attack resistance for reproducibility that
  // nothing in the protocol needs.
  const alice = await engine.createIdentity();
  const bob = await engine.createIdentity();

  // Two invites from one identity now carry the SAME certificate, because it is
  // signed once at creation. That is the optimisation, asserted so that a
  // change back to per invite signing is visible here.
  const first = decodeEnvelope((await engine.invite(alice)).token) as InvitePayload;
  const second = decodeEnvelope((await engine.invite(alice)).token) as InvitePayload;
  assert.deepEqual(first.certificate, second.certificate);

  // Hedging is still what the ACCEPT does, and that one is per handshake.
  const one = decodeEnvelope(replyOf(await engine.open(bob, encodeEnvelope(first), {}))) as AcceptPayload;
  const two = decodeEnvelope(replyOf(await engine.open(bob, encodeEnvelope(second), {}))) as AcceptPayload;
  assert.notDeepEqual(one.signature, two.signature);
});

test('the certificate verifies against the same message the library builds', async () => {
  // An independent check, using ml_dsa65 directly rather than going through
  // engine.open. If the library ever signed one message and verified another,
  // every test above would still pass and this one would not.
  const { invite } = await handshake();
  assert.equal(invite.certificate.length, 3309);
  assert.equal(invite.sender.sigPublic.length, 1952);
  assert.ok(
    !ml_dsa65.verify(invite.certificate, new Uint8Array(0), invite.sender.sigPublic),
    'the certificate must not verify over an empty message',
  );
});
