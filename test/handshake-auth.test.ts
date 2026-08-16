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

test('a machine in the middle cannot re-address an invite to its own identity', async () => {
  // Mallory records Alice's invite and wants Bob to accept it believing the
  // initiator is Mallory, so that Bob's session is with her. Before 0.6.0 the
  // invite carried nothing but a claim, and swapping the identity was free.
  const { invite } = await handshake();
  const mallory = await engine.createIdentity();

  const rewritten = encodeEnvelope({
    ...invite,
    sender: engine.publicOf(mallory),
  });

  const bob = await engine.createIdentity();
  await expectFailure('bad_signature', async () => engine.open(bob, rewritten, {}));
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

  // Re-stamping Mallory's own invite onto Alice's conversation id breaks her
  // signature, which is the guarantee working: she cannot move a signed invite
  // to another conversation.
  const malloryDecoded = decodeEnvelope((await engine.invite(mallory)).token) as InvitePayload;
  const restamped = encodeEnvelope({ ...malloryDecoded, conversationId: invite.conversationId });
  await expectFailure('bad_signature', async () => engine.open(bob, restamped, {}));

  // So she signs one properly instead, over Alice's conversation id and her own
  // identity. She can: it is her key and her identity, and nothing stops an
  // attacker choosing a conversation id. Built by hand rather than through
  // engine.invite, because the library always picks a fresh random id and an
  // attacker is not the library. This also pins the invite transcript layout a
  // second time, from outside src/handshake.ts.
  const transcript = (domain: string, parts: Uint8Array[]): Uint8Array => {
    const lengths = new Uint8Array(4 * parts.length);
    const view = new DataView(lengths.buffer);
    parts.forEach((part, i) => view.setUint32(i * 4, part.length, false));
    const total = domain.length + lengths.length + parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let at = 0;
    for (let i = 0; i < domain.length; i += 1) out[at++] = domain.charCodeAt(i);
    out.set(lengths, at);
    at += lengths.length;
    for (const part of parts) {
      out.set(part, at);
      at += part.length;
    }
    return out;
  };

  const malloryPublic = engine.publicOf(mallory);
  const forged = encodeEnvelope({
    kind: 'invite',
    conversationId: invite.conversationId,
    sender: malloryPublic,
    signature: ml_dsa65.sign(
      transcript('OCX2 invite transcript v1', [
        new TextEncoder().encode(invite.conversationId),
        malloryPublic.classicalPublic,
        malloryPublic.pqPublic,
        malloryPublic.sigPublic,
      ]),
      mallory.sigSecret,
    ),
  });

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

test('every signed field of the invite is actually covered by the signature', async () => {
  const { invite } = await handshake();
  const bob = await engine.createIdentity();
  const other = decodeEnvelope((await engine.invite(await engine.createIdentity())).token) as InvitePayload;

  for (const mutated of [
    { ...invite, conversationId: other.conversationId },
    { ...invite, sender: other.sender },
    { ...invite, signature: other.signature },
  ]) {
    await expectFailure('bad_signature', async () => engine.open(bob, encodeEnvelope(mutated), {}));
  }
});

// ---------------------------------------------------------------------------
// Shape, not content
// ---------------------------------------------------------------------------

test('a signature of the wrong length is a malformed token, not a bad signature', async () => {
  // Two different failures on purpose. A wrong length never reached the
  // verifier, so calling it a bad signature would claim something was checked
  // that was not, and the caller cannot tell a truncated frame from an attack.
  const { invite } = await handshake();
  const bob = await engine.createIdentity();

  for (const length of [0, 1, 3308, 3310]) {
    const token = encodeEnvelope({ ...invite, signature: new Uint8Array(length) });
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

test('an all zero signature is refused', async () => {
  const { invite } = await handshake();
  const bob = await engine.createIdentity();
  const token = encodeEnvelope({ ...invite, signature: new Uint8Array(3309) });
  await expectFailure('bad_signature', async () => engine.open(bob, token, {}));
});

// ---------------------------------------------------------------------------
// The transcript is domain separated
// ---------------------------------------------------------------------------

test('an invite signature cannot be lifted into an accept, or the reverse', async () => {
  // Both transcripts cover the conversation id and a sender identity, so
  // without the domain strings there would be an argument to have about whether
  // one could ever be a prefix of the other. The domains make that argument
  // unnecessary, and this pins it.
  const { alice, invited, invite, accept } = await handshake();
  const bob = await engine.createIdentity();

  await expectFailure('bad_signature', async () =>
    engine.open(bob, encodeEnvelope({ ...invite, signature: accept.signature }), {}),
  );
  await expectFailure('bad_signature', async () =>
    engine.open(alice, encodeEnvelope({ ...accept, signature: invite.signature }), {
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
  const first = decodeEnvelope((await engine.invite(alice)).token) as InvitePayload;
  const second = decodeEnvelope((await engine.invite(alice)).token) as InvitePayload;
  assert.notDeepEqual(first.signature, second.signature);

  // Both still verify, which is the part that would break if hedging were
  // implemented by signing something other than the transcript.
  const bob = await engine.createIdentity();
  for (const token of [encodeEnvelope(first), encodeEnvelope(second)]) {
    assert.equal((await engine.open(bob, token, {})).outcome, 'invite');
  }
});

test('the signature verifies against the same transcript the library builds', async () => {
  // An independent check, using ml_dsa65 directly rather than going through
  // engine.open. If the library ever signed one transcript and verified
  // another, every test above would still pass and this one would not.
  const { invite } = await handshake();
  assert.equal(invite.signature.length, 3309);
  assert.equal(invite.sender.sigPublic.length, 1952);
  assert.ok(
    !ml_dsa65.verify(invite.signature, new Uint8Array(0), invite.sender.sigPublic),
    'the signature must not verify over an empty message',
  );
});
