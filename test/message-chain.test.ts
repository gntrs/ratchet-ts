/**
 * The 0.4.0 chain, at the level the wire change actually altered it.
 *
 * Three things moved in this release and all three land here rather than in the
 * envelope tests, because none of them is visible from the bytes alone:
 *
 *   1. The ratchet public key is on the wire for the first RATCHET_KEY_RESEND
 *      messages of a chain and absent after that. That saves 33 bytes a message
 *      and buys a failure mode: lose the keyed messages and the rest of the
 *      chain is undecryptable until one arrives. The bound on that is what the
 *      constant is for, and it is measured here rather than asserted in prose.
 *
 *   2. The AAD still binds the whole 16 byte conversation id and the whole 32
 *      byte ratchet public even though only 4 bytes of the first and none of the
 *      second are transmitted. The receiver rebuilds them from session state.
 *      If that binding were quietly dropped the protocol would still work
 *      perfectly, every test would still pass, and the security property would
 *      be gone. So it is tested by corrupting the state the receiver rebuilds
 *      from and demanding the tag notice.
 *
 *   3. skippedKeys is keyed by a chain epoch counter rather than by a base64 of
 *      the ratchet public. That is a performance change with a correctness
 *      surface: the epoch has to survive a direction change, or keys parked
 *      before the change become unreachable after it.
 *
 *   4. The nonce is 12 random bytes drawn per seal and carried on the wire. A
 *      draft of this release derived it from the message number instead, which
 *      is cheaper and is safe as long as no message key is ever used twice. The
 *      draft was rejected because a session restored from a stale snapshot does
 *      reuse a message key, and a reused key under a reproducible nonce leaks
 *      the XOR of the two plaintexts. Randomness is what stops a rollback from
 *      turning into a confidentiality break, so the tests that prove it is
 *      really random are here, not in the envelope suite: the envelope only
 *      sees the twelve bytes it was handed.
 *
 * The out of order, replay and skip limit cases are here too. They are not new,
 * but they are the properties most likely to be broken by a rewrite of the
 * chain step, and a test that only proves the happy path is worth very little.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import type { MessagePayload, SessionState } from '../src/contract.js';
import { decodeEnvelope } from '../src/index.js';
import { conversationIdToBytes } from '../src/envelope.js';
import { MAX_SKIP, RATCHET_KEY_RESEND } from '../src/ratchet.js';
import { cloneSession, connectedPair, editMessage, expectFailure, flipByte, receive, send } from './harness.js';
import type { Party } from './harness.js';

/** Bytes to hex, so a nonce can be a Set member. Local, because the suite runs
 * without @types/node and Buffer is declared here with a narrower signature. */
function hex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

/** The decoded message behind a token, which is all these tests ever want. */
function asMessage(token: string): MessagePayload {
  const payload = decodeEnvelope(token);
  assert.equal(payload.kind, 'message');
  return payload as MessagePayload;
}

// ---------------------------------------------------------------------------
// The resend window
// ---------------------------------------------------------------------------

/**
 * The constant is load bearing, so pin it.
 *
 * Three is a choice, not a derivation: it keeps roughly ninety percent of the
 * saving over always sending the key, while bounding recovery after loss to the
 * first three messages of a chain rather than to one. If someone changes it,
 * every claim in the tests below about which message carries a key changes with
 * it, and this assertion is where they find that out.
 */
test('the ratchet key rides the first three messages of a chain and no more', async () => {
  const { alice, bob } = await connectedPair();
  assert.equal(RATCHET_KEY_RESEND, 3);

  const tokens: string[] = [];
  for (let i = 0; i < 6; i += 1) tokens.push(await send(alice, `m${i}`));

  for (let i = 0; i < 6; i += 1) {
    const message = asMessage(tokens[i]!);
    assert.equal(message.messageNumber, i);
    if (i < RATCHET_KEY_RESEND) {
      assert.ok(message.ratchetPublic !== undefined, `message ${i} must carry the key`);
      // The two travel together. A key with no chain length would leave the
      // receiver unable to park the tail of the previous chain.
      assert.ok(message.previousChainLength !== undefined, `message ${i} must carry the chain length`);
    } else {
      assert.equal(message.ratchetPublic, undefined, `message ${i} must not carry the key`);
      assert.equal(message.previousChainLength, undefined, `message ${i} must not carry the chain length`);
    }
  }

  // And the wire cost of the choice, which is the whole point of making it.
  const keyed = asMessage(tokens[0]!);
  const bare = asMessage(tokens[5]!);
  assert.equal(keyed.ciphertext.length, bare.ciphertext.length, 'same plaintext length, so the difference is header only');

  for (const token of tokens) assert.ok((await receive(bob, token)).startsWith('m'));
});

/**
 * The loss case the resend window exists for.
 *
 * Message 0 never arrives. Messages 1 and 2 still carry the key, so the receiver
 * can still perform the DH step, park the key for the message it missed, and
 * open everything that did arrive. Under a one-shot key this whole chain would
 * be dead until message 0 was retransmitted.
 */
test('a chain survives losing message 0 because 1 and 2 still carry the key', async () => {
  const { alice, bob } = await connectedPair();

  const m0 = await send(alice, 'lost');
  const m1 = await send(alice, 'first survivor');
  const m2 = await send(alice, 'second survivor');

  // m0 is dropped on the floor. It is never handed to bob.
  assert.equal(await receive(bob, m1), 'first survivor');
  assert.equal(await receive(bob, m2), 'second survivor');

  // The key for the message that never came is parked, not lost, so a
  // retransmission still opens.
  assert.equal(Object.keys(bob.session.skippedKeys).length, 1);
  assert.equal(await receive(bob, m0), 'lost');
  assert.equal(Object.keys(bob.session.skippedKeys).length, 0);
});

/**
 * The bill for the same choice, stated rather than hidden.
 *
 * Lose all three keyed messages and the chain stalls: message 3 carries no key,
 * the receiver has no way to derive the new chain, and the tag refuses it. This
 * is the cost of the 33 bytes and it is a real one. What matters is that it is
 * bounded and self healing: the moment any keyed message arrives the whole chain
 * opens, including the one that had already been refused.
 */
test('losing the whole resend window stalls the chain, and one keyed message unstalls it', async () => {
  const { alice, bob } = await connectedPair();

  // Establish a chain in each direction first, so the stall below is a chain
  // CHANGE being missed rather than the opening chain.
  await receive(bob, await send(alice, 'hello'));
  await receive(alice, await send(bob, 'hello back'));

  const keyed = [await send(alice, 'k0'), await send(alice, 'k1'), await send(alice, 'k2')];
  const bare = await send(alice, 'k3');

  // All three keyed messages are lost. The bare one cannot stand on its own.
  await expectFailure('authentication_failed', () => receive(bob, bare));

  // One keyed message is enough to recover everything, in any order.
  assert.equal(await receive(bob, keyed[2]!), 'k2');
  assert.equal(await receive(bob, bare), 'k3');
  assert.equal(await receive(bob, keyed[0]!), 'k0');
  assert.equal(await receive(bob, keyed[1]!), 'k1');
});

// ---------------------------------------------------------------------------
// The nonce is random, and that is the whole point of it
// ---------------------------------------------------------------------------

/**
 * The test the counter nonce could not have passed.
 *
 * Both seals start from the SAME session object, so both produce message number
 * 0 of the same chain under the same message key. That is exactly the situation
 * a restored snapshot creates, and it is the situation the counter nonce was
 * rejected for: under a derived nonce these two frames would share a keystream
 * and their ciphertexts would XOR to the XOR of the two plaintexts.
 *
 * The plaintext is held identical on purpose. Anything else and the ciphertexts
 * would differ for a reason that has nothing to do with the nonce.
 *
 * What this does NOT claim is that sealing twice from one session is safe. It is
 * not, and src/serialize.ts says so at length: the key is still reused and the
 * forgery surface is still open. The claim is narrower and it is the one the
 * change was made for, that the confidentiality of the two plaintexts survives
 * it.
 */
test('two seals from one session state produce different nonces and different bodies', async () => {
  const { alice } = await connectedPair();
  const before = cloneSession(alice.session);

  const first = asMessage(await send(alice, 'the same words twice'));
  alice.session = cloneSession(before);
  const second = asMessage(await send(alice, 'the same words twice'));

  // Same chain position, so the message key behind both is the same one.
  assert.equal(first.messageNumber, second.messageNumber);
  assert.equal(first.nonce.length, 12);
  assert.equal(second.nonce.length, 12);
  assert.notDeepEqual(first.nonce, second.nonce);
  assert.notDeepEqual(first.ciphertext, second.ciphertext);

  // The lengths match, so the difference is in the bytes and not in the shape.
  assert.equal(first.ciphertext.length, second.ciphertext.length);
});

/**
 * No nonce is used twice across a chain.
 *
 * 200 messages is past RATCHET_KEY_RESEND, past the one byte varint boundary at
 * 128, and long enough that a generator quietly seeded once per chain, or reset
 * on a header shape change, would collide inside the run. A birthday collision
 * among 200 draws from 2^96 is not a thing that happens, so any duplicate here
 * is a bug in the source and not bad luck.
 *
 * The receive side runs too. A test that only sealed would pass just as happily
 * against an encoder that wrote the nonce into a field the decoder ignores.
 */
test('200 seals in one chain use 200 distinct nonces', async () => {
  const { alice, bob } = await connectedPair();
  const seen = new Set<string>();

  for (let i = 0; i < 200; i += 1) {
    const token = await send(alice, `m${i}`);
    const message = asMessage(token);
    assert.equal(message.nonce.length, 12);
    seen.add(hex(message.nonce));
    assert.equal(await receive(bob, token), `m${i}`);
  }

  assert.equal(seen.size, 200);
});

/**
 * The nonce travels, so an attacker can edit it, so it has to be authenticated.
 *
 * It sits inside the header, and the header is the AAD, so this ought to be free.
 * It is tested anyway because "ought to be free" is what a field looks like right
 * up until someone reorders the header and moves it past the end of the AAD
 * slice. The failure would be silent: every honest message would still open.
 */
test('a flipped nonce byte on the wire fails authentication', async () => {
  const { alice, bob } = await connectedPair();
  const token = await send(alice, 'unedited');

  for (const index of [0, 6, 11]) {
    const edited = editMessage(token, (message) => ({
      ...message,
      nonce: flipByte(message.nonce, index),
    }));
    await expectFailure('authentication_failed', () => receive(bob, edited));
  }

  // The receiver refused all three without advancing, so the honest frame still
  // opens. A fail-closed check that quietly consumed the message would leave
  // this line failing instead.
  assert.equal(await receive(bob, token), 'unedited');
});

// ---------------------------------------------------------------------------
// What the AAD binds that the wire does not carry
// ---------------------------------------------------------------------------

/**
 * The 12 unsent bytes of the conversation id.
 *
 * Only 4 bytes of the id travel, as a routing tag. All 16 are in the AAD,
 * rebuilt on the receiving side from session state. Bend one bit of the twelve
 * that never left the sender and the tag must notice, which is the proof that
 * the binding is real rather than decorative: nothing on the wire changed, so
 * only the AAD can be the thing that failed.
 */
test('the AAD binds the 12 bytes of conversation id that are never transmitted', async () => {
  const { alice, bob } = await connectedPair();
  const honest = await send(alice, 'bound to this conversation');

  const good = cloneSession(bob.session);
  for (const index of [4, 9, 15]) {
    const bent = conversationIdToBytes(bob.session.conversationId);
    bent[index] = bent[index]! ^ 0x01;
    bob.session = { ...good, conversationIdBytes: bent };
    await expectFailure('authentication_failed', () => receive(bob, honest));
  }

  // The session that was not tampered with still opens the same token, so the
  // failures above were the corruption and not the message.
  bob.session = good;
  assert.equal(await receive(bob, honest), 'bound to this conversation');
});

/**
 * The 32 byte ratchet public that is not on the wire at all.
 *
 * This is the more dangerous of the two, because after the resend window the key
 * is absent from every message: if the AAD stopped binding it, a ciphertext from
 * one chain could be replayed into another chain that happens to share a message
 * number, and nothing in the header would contradict it. The test bends the
 * receiver's stored copy of the sender's key and demands the tag fail.
 *
 * Message 3 is used deliberately. Messages 0 to 2 carry the key on the wire, so
 * corrupting the stored copy would be caught by the chain lookup rather than by
 * the AAD, and the test would prove nothing about the binding.
 */
test('the AAD binds the 32 byte ratchet public even when it is not transmitted', async () => {
  const { alice, bob } = await connectedPair();

  for (let i = 0; i < 3; i += 1) await receive(bob, await send(alice, `warmup ${i}`));
  const bare = await send(alice, 'no key on the wire');
  assert.equal(asMessage(bare).ratchetPublic, undefined, 'this test needs a keyless message');

  const good = cloneSession(bob.session);
  assert.ok(good.peerRatchetPublic !== undefined);
  for (const index of [0, 17, 31]) {
    const bent = Uint8Array.from(good.peerRatchetPublic);
    bent[index] = bent[index]! ^ 0x01;
    bob.session = { ...cloneSession(good), peerRatchetPublic: bent };
    await expectFailure('authentication_failed', () => receive(bob, bare));
  }

  bob.session = good;
  assert.equal(await receive(bob, bare), 'no key on the wire');
});

/**
 * And the wire fields, which are the AAD directly.
 *
 * The header is handed to the AEAD as associated data verbatim rather than being
 * serialized a second time into a separate buffer, so this is really a test that
 * the single-writer arrangement did not accidentally hand the cipher a subarray
 * that stops short of some field. Bending each field in turn is the cheapest way
 * to find out that one of them fell outside the range.
 */
test('every transmitted header field is inside the AAD', async () => {
  const { alice, bob } = await connectedPair();
  const honest = await send(alice, 'header integrity');
  const original = asMessage(honest);
  assert.ok(original.ratchetPublic !== undefined && original.previousChainLength !== undefined);

  const bent: MessagePayload[] = [
    { ...original, messageNumber: original.messageNumber + 1 },
    { ...original, previousChainLength: original.previousChainLength + 1 },
    {
      ...original,
      ratchetPublic: Uint8Array.from(original.ratchetPublic, (b, i) => (i === 5 ? b ^ 0x01 : b)),
    },
  ];

  // The message number is the nonce as well as an AAD field since 0.4.0, so
  // bending it changes two inputs at once: the receiver walks its chain one step
  // further and decrypts under a different nonce. It is worth being precise about
  // why this is not a replay: message 1 has not been seen, so the receiver skips
  // ahead to it quite legitimately, parks the key for 0 on the way, and only then
  // finds a tag that does not verify. The refusal comes from the tag.
  await expectFailure('authentication_failed', () => receive(bob, editMessage(honest, () => bent[0]!)));
  await expectFailure('authentication_failed', () => receive(bob, editMessage(honest, () => bent[1]!)));
  await expectFailure('authentication_failed', () => receive(bob, editMessage(honest, () => bent[2]!)));

  assert.equal(await receive(bob, honest), 'header integrity');
});

// ---------------------------------------------------------------------------
// Ordering, replay, and the skip bound
// ---------------------------------------------------------------------------

test('out of order delivery parks keys and every message still opens', async () => {
  const { alice, bob } = await connectedPair();

  const tokens: string[] = [];
  for (let i = 0; i < 5; i += 1) tokens.push(await send(alice, `m${i}`));

  // 2 first, not 3, and the difference is the whole point of RATCHET_KEY_RESEND.
  // The first message bob sees on a chain has to be one that carries the ratchet
  // key, because bob cannot derive the chain without it. Messages 0, 1 and 2 all
  // do; 3 onward do not. Starting at 3 is the stall tested above, not this test.
  assert.equal(await receive(bob, tokens[2]!), 'm2');
  // 0 and 1 were parked on the way past.
  assert.equal(Object.keys(bob.session.skippedKeys).length, 2);

  // The parked keys are addressed by chain epoch and message number, not by a
  // base64 of the ratchet public as they were in 0.3.x.
  for (const id of Object.keys(bob.session.skippedKeys)) {
    assert.ok(/^\d+:\d+$/.test(id), `parked key id ${id} must be epoch:number`);
  }

  // 4 skips past 3, which parks one more, and the rest arrive from the park.
  assert.equal(await receive(bob, tokens[4]!), 'm4');
  assert.equal(Object.keys(bob.session.skippedKeys).length, 3);
  assert.equal(await receive(bob, tokens[1]!), 'm1');
  assert.equal(await receive(bob, tokens[0]!), 'm0');
  assert.equal(await receive(bob, tokens[3]!), 'm3');
  assert.equal(Object.keys(bob.session.skippedKeys).length, 0);
});

test('a key parked before a direction change still opens after it', async () => {
  const { alice, bob } = await connectedPair();

  const stranded = await send(alice, 'stranded');
  const later = await send(alice, 'later');
  // bob sees only the second one, so the first is parked under the old epoch.
  assert.equal(await receive(bob, later), 'later');
  assert.equal(Object.keys(bob.session.skippedKeys).length, 1);

  // Two full direction changes, which move the epoch on.
  assert.equal(await receive(alice, await send(bob, 'reply')), 'reply');
  assert.equal(await receive(bob, await send(alice, 'and back')), 'and back');

  // The parked key is addressed by the epoch it was parked under, so it is still
  // reachable. Rekeying by anything the epoch replaced would strand it here.
  assert.equal(await receive(bob, stranded), 'stranded');
});

test('replay of an already opened message is refused', async () => {
  const { alice, bob } = await connectedPair();

  const token = await send(alice, 'once');
  assert.equal(await receive(bob, token), 'once');
  await expectFailure('replay_detected', () => receive(bob, token));

  // Also for a message opened out of order, which takes the parked path: the
  // key is deleted on use, so the second attempt has nothing to find.
  const first = await send(alice, 'first');
  const second = await send(alice, 'second');
  assert.equal(await receive(bob, second), 'second');
  assert.equal(await receive(bob, first), 'first');
  await expectFailure('replay_detected', () => receive(bob, first));
  await expectFailure('replay_detected', () => receive(bob, second));
});

test('the skip limit still bounds the work one message can demand', async () => {
  const { alice, bob } = await connectedPair();
  const honest = await send(alice, 'reachable');

  // A message number past MAX_SKIP would ask the receiver to derive a thousand
  // and one keys before it could even check the tag. It is refused first.
  const absurd = editMessage(honest, (payload) => ({ ...payload, messageNumber: MAX_SKIP + 1 }));
  await expectFailure('skip_limit_exceeded', () => receive(bob, absurd));

  // Right at the edge is legal, and fails on the tag instead, which proves the
  // bound is a bound and not an off by one.
  const edge = editMessage(honest, (payload) => ({ ...payload, messageNumber: MAX_SKIP }));
  await expectFailure('authentication_failed', () => receive(bob, edge));

  assert.equal(await receive(bob, honest), 'reachable');
});

// ---------------------------------------------------------------------------
// The long conversation
// ---------------------------------------------------------------------------

/**
 * Both sides in step over several direction changes.
 *
 * The invariant is that after every delivered message the sender's send chain
 * key equals the receiver's receive chain key. That is the thing the chain step
 * rewrite could break silently: a chain step that consumed a different input on
 * one side would still produce valid looking keys, and the first symptom would
 * be an authentication failure some unknown number of messages later.
 *
 * The root keys are NOT asserted equal, and that is not an oversight. After the
 * first direction change each side has performed a different number of root
 * steps, because the sender takes its next step at the moment it changes
 * direction while the receiver takes it on delivery. They converge in shape, not
 * in value, and asserting otherwise would be asserting a bug.
 */
test('a conversation with many direction changes keeps both chains in step', async () => {
  const { alice, bob } = await connectedPair();

  const script: { from: Party; to: Party; count: number }[] = [
    { from: alice, to: bob, count: 3 },
    { from: bob, to: alice, count: 1 },
    { from: alice, to: bob, count: 5 },
    { from: bob, to: alice, count: 4 },
    { from: alice, to: bob, count: 1 },
    { from: bob, to: alice, count: 2 },
  ];

  let turn = 0;
  for (const leg of script) {
    for (let i = 0; i < leg.count; i += 1) {
      const text = `${leg.from.name} ${turn}.${i}`;
      const token = await send(leg.from, text);
      assert.equal(await receive(leg.to, token), text);

      assert.ok(leg.from.session.sendChainKey !== undefined);
      assert.ok(leg.to.session.recvChainKey !== undefined);
      assert.deepEqual(
        Array.from(leg.from.session.sendChainKey),
        Array.from(leg.to.session.recvChainKey),
        `chains diverged at ${text}`,
      );
      assert.equal(leg.from.session.sendCount, leg.to.session.recvCount);
    }
    turn += 1;
  }

  // Nothing was parked: every message arrived in order and was consumed.
  assert.equal(Object.keys(alice.session.skippedKeys).length, 0);
  assert.equal(Object.keys(bob.session.skippedKeys).length, 0);

  // And the roots have legitimately diverged, which is the claim in the comment
  // above rather than a thing being tolerated silently.
  assert.notDeepEqual(Array.from(alice.session.rootKey), Array.from(bob.session.rootKey));
});

/**
 * Forward secrecy and post compromise security, restated for the new chain step.
 *
 * These are covered in secrecy.test.ts against the engine surface. The reason
 * they are worth one more pass here is that the chain step changed primitive in
 * this release, from two HMAC-SHA256 calls to one HMAC-SHA512 split in half, and
 * both properties rest entirely on that step being one way and on the old key
 * being dropped rather than kept.
 */
test('a captured session cannot read the messages that preceded it', async () => {
  const { alice, bob } = await connectedPair();

  const early = await send(alice, 'before the capture');
  assert.equal(await receive(bob, early), 'before the capture');

  // The attacker takes bob's state at exactly this point.
  const stolen: SessionState = cloneSession(bob.session);

  const later = await send(alice, 'after the capture');
  assert.equal(await receive(bob, later), 'after the capture');

  // The stolen state opens what came after it, which is what compromise means.
  const attacker: Party = { name: 'attacker', identity: bob.identity, session: cloneSession(stolen) };
  assert.equal(await receive(attacker, later), 'after the capture');

  // It cannot open what came before: that key was consumed and dropped, and the
  // chain step cannot be run backwards to recover it.
  const replay: Party = { name: 'replay', identity: bob.identity, session: cloneSession(stolen) };
  await expectFailure('replay_detected', () => receive(replay, early));
});

/**
 * Post compromise security, and exactly how many turns it takes to arrive.
 *
 * It is tempting to write this test as "steal the state, one direction change,
 * attacker is out". That is wrong, and writing it that way would have pinned a
 * property the protocol does not have. The healing is real but it costs two
 * round trips, and the reason is worth spelling out because it is the shape of
 * every Double Ratchet, not a quirk of this one.
 *
 * A receiver mints its fresh keypair when it takes a DH step, and that step is
 * driven by a peer key that arrives on the wire. An attacker holding a copy of
 * the state sees the same wire and takes the same step, so up to that point it
 * follows along. What it CANNOT copy is the fresh secret bob generates during
 * that step: bob's is random and the attacker's is a different random. From
 * that moment the two states hold different secrets behind the same public
 * history, and the attacker is only still able to read because alice has not
 * yet used bob's new public key for anything.
 *
 * She uses it the moment bob's next message reaches her. Her step after that
 * mixes in a DH the attacker cannot compute, and her following message is the
 * first one that is out of reach. So: compromise, alice sends (attacker still
 * reads, and diverges silently), bob replies, alice sends again, attacker is
 * out. Each of those four legs is asserted below rather than assumed.
 */
test('two direction changes after a compromise lock the attacker out', async () => {
  const { alice, bob } = await connectedPair();
  await receive(bob, await send(alice, 'hello'));

  const attacker: Party = {
    name: 'attacker',
    identity: bob.identity,
    session: cloneSession(bob.session),
  };

  // Leg 1. bob replies on the chain he already has, so nothing new is minted.
  await receive(alice, await send(bob, 'reply'));

  // Leg 2. alice's answer is on a new chain, so both bob and the attacker take
  // the DH step, and both open it. This is the compromise window, stated rather
  // than skipped over: the attacker is still reading here.
  const stillReadable = await send(alice, 'still in the window');
  assert.equal(await receive(attacker, stillReadable), 'still in the window');
  assert.equal(await receive(bob, stillReadable), 'still in the window');

  // But the fresh secrets minted during that step differ, and only bob's public
  // half reaches alice.
  assert.notDeepEqual(
    Array.from(bob.session.selfRatchetSecret),
    Array.from(attacker.session.selfRatchetSecret),
  );

  // Leg 3. bob replies, carrying his new public. Leg 4. alice steps on it.
  await receive(alice, await send(bob, 'second reply'));
  const afterHeal = await send(alice, 'unreachable now');

  await expectFailure('authentication_failed', () => receive(attacker, afterHeal));
  assert.equal(await receive(bob, afterHeal), 'unreachable now');
});
