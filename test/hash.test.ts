/**
 * The native HMAC-SHA256 fast path has exactly one job beyond being fast: being
 * invisible. Every key this library derives comes out of src/hash.ts, so a
 * single differing byte is not a slower peer, it is a peer whose next message
 * fails its Poly1305 tag and stays failed forever. A faster backend that
 * produces different bytes is not a faster backend, it is a second protocol.
 *
 * So this suite is differential in the same way test/aead.test.ts and
 * test/curves.test.ts are: @noble is the reference implementation, it is what
 * derived every key in every session already persisted on disk, and every test
 * here asks whether the other path can be told apart from it. Nothing here
 * measures speed.
 *
 * The tests that earn their keep are the key-length boundary cases and the
 * split-backend conversation. HMAC hashes any key longer than 64 bytes before
 * using it, and that branch is where implementations diverge; the conversation
 * is where a divergence anywhere in the key schedule turns into an
 * authentication failure that no amount of unit testing the primitive would
 * have predicted.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { expand, extract } from '@noble/hashes/hkdf.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

import { concat, toHex, utf8ToBytes } from '../src/bytes.js';
import { decodeEnvelope } from '../src/envelope.js';
import { x25519SharedSecret } from '../src/curves.js';
import {
  forceHashBackend,
  hashBackend,
  hashReady,
  hkdfSha256,
  hmacSha256,
} from '../src/hash.js';
import type { HashBackend } from '../src/hash.js';
import { acceptInvite, beginInvite, completeInvite } from '../src/handshake.js';
import { createIdentity } from '../src/identity.js';
import { kdfChain, kdfHandshake, kdfRoot } from '../src/kdf.js';
import { ratchetDecrypt, ratchetEncrypt } from '../src/ratchet.js';

/** Whether this machine has a usable native backend at all. Every native
 * specific assertion below is gated on it, because a browser or a locked down
 * runtime genuinely has none and the correct behaviour there is to run on
 * @noble, not to fail the suite. */
const NATIVE_AVAILABLE = (() => {
  const got = forceHashBackend('native');
  forceHashBackend('auto');
  return got === 'native';
})();

/** Restores the automatic backend no matter how the body exits, so one failing
 * assertion cannot leave every later test pinned to the wrong path. Returns
 * false when the requested backend does not exist here. */
function withBackend(choice: HashBackend, body: () => void): boolean {
  const effective = forceHashBackend(choice);
  try {
    if (effective !== choice) return false;
    body();
    return true;
  } finally {
    forceHashBackend('auto');
  }
}

/** Same thing for a call that produces a value. Only used where the caller has
 * already established that the backend exists. */
function on<T>(choice: HashBackend, body: () => T): T {
  const effective = forceHashBackend(choice);
  try {
    assert.equal(effective, choice, `backend ${choice} is not available on this runtime`);
    return body();
  } finally {
    forceHashBackend('auto');
  }
}

function hex(text: string): Uint8Array {
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function list(bytes: Uint8Array): number[] {
  return Array.from(bytes);
}

/**
 * Captures how a call failed, as a comparable value. Lifted from
 * test/curves.test.ts because the claim is the same one: a caller must not be
 * able to tell which backend answered, and the message is the only part of a
 * thrown Error a caller realistically inspects.
 */
function failureOf(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    const shape = error as { constructor?: { name?: string }; message?: string };
    return `${shape.constructor?.name ?? 'unknown'}: ${shape.message ?? ''}`;
  }
  return 'DID NOT THROW';
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

/** 500 random key and message pairs, as the byte identity proof asks for. Key
 * lengths are drawn across the block boundary rather than fixed at 32, so the
 * random corpus exercises the key-hashing branch too instead of leaving it
 * entirely to the fixed cases below. */
const CORPUS: { key: Uint8Array; message: Uint8Array }[] = Array.from({ length: 500 }, (_unused, i) => ({
  key: randomBytes(i % 70),
  message: randomBytes(i % 137),
}));

/** The lengths an HMAC implementation can get wrong while looking correct on
 * everything else. 64 is exactly one SHA-256 block, 65 is the first length that
 * forces the key to be hashed down first, and 0 is the case a wrapper is most
 * likely to reject outright. */
const EDGE_KEY_LENGTHS = [0, 1, 31, 32, 33, 55, 56, 63, 64, 65, 96, 128, 129, 255, 1024];
const EDGE_MESSAGE_LENGTHS = [0, 1, 2, 31, 32, 55, 56, 63, 64, 65, 127, 128, 1000];

/** RFC 4231 section 4. Case 5 is absent on purpose: the RFC publishes only its
 * 128 bit truncation, so a full digest for it would be a number this project
 * computed rather than one the RFC did. */
const RFC4231: [string, string, string, string][] = [
  ['case 1', '0b'.repeat(20), '4869205468657265', 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'],
  [
    'case 2',
    '4a656665',
    '7768617420646f2079612077616e7420666f72206e6f7468696e673f',
    '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
  ],
  ['case 3', 'aa'.repeat(20), 'dd'.repeat(50), '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe'],
  [
    'case 4',
    '0102030405060708090a0b0c0d0e0f10111213141516171819',
    'cd'.repeat(50),
    '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b',
  ],
  [
    'case 6, 131 byte key',
    'aa'.repeat(131),
    '54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374',
    '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
  ],
  [
    'case 7, 131 byte key and long data',
    'aa'.repeat(131),
    '5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e64206' +
      '1206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f2062652068617368' +
      '6564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e',
    '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2',
  ],
];

/** RFC 5869 appendix A, the SHA-256 cases. */
const RFC5869: [string, string, string, string, number, string][] = [
  [
    'case 1',
    '0b'.repeat(22),
    '000102030405060708090a0b0c',
    'f0f1f2f3f4f5f6f7f8f9',
    42,
    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
  ],
  [
    'case 3, empty salt and info',
    '0b'.repeat(22),
    '',
    '',
    42,
    '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
  ],
];

// ---------------------------------------------------------------------------
// The primitive against @noble
// ---------------------------------------------------------------------------

test('hmacSha256 matches noble on 500 random key and message pairs', () => {
  for (const c of CORPUS) {
    assert.deepEqual(
      list(hmacSha256(c.key, c.message)),
      list(hmac(sha256, c.key, c.message)),
      `mismatch at key ${c.key.length} message ${c.message.length} on backend ${hashBackend()}`,
    );
  }
});

test('hmacSha256 matches noble across every key and message length boundary', () => {
  for (const keyLength of EDGE_KEY_LENGTHS) {
    const key = randomBytes(keyLength);
    for (const messageLength of EDGE_MESSAGE_LENGTHS) {
      const message = randomBytes(messageLength);
      assert.deepEqual(
        list(hmacSha256(key, message)),
        list(hmac(sha256, key, message)),
        `key ${keyLength} message ${messageLength} on backend ${hashBackend()}`,
      );
    }
  }
});

test('RFC 4231 published vectors', () => {
  for (const [name, key, data, mac] of RFC4231) {
    // Against the RFC first, so a broken @noble would be caught rather than
    // used as the reference for itself.
    assert.equal(toHex(hmac(sha256, hex(key), hex(data))), mac, `${name}: noble disagrees with the RFC`);
    assert.equal(toHex(hmacSha256(hex(key), hex(data))), mac, `${name} on backend ${hashBackend()}`);
    for (const backend of ['noble', 'native'] as const) {
      if (backend === 'native' && !NATIVE_AVAILABLE) continue;
      assert.ok(
        withBackend(backend, () => {
          assert.equal(toHex(hmacSha256(hex(key), hex(data))), mac, `${name} on pinned ${backend}`);
        }),
      );
    }
  }
});

test('RFC 5869 published vectors', () => {
  for (const [name, ikm, salt, info, length, okm] of RFC5869) {
    const expected = expand(sha256, extract(sha256, hex(ikm), hex(salt)), hex(info), length);
    assert.equal(toHex(expected), okm, `${name}: noble disagrees with the RFC`);
    assert.equal(toHex(hkdfSha256(hex(ikm), hex(salt), hex(info), length)), okm, `${name} on backend ${hashBackend()}`);
    for (const backend of ['noble', 'native'] as const) {
      if (backend === 'native' && !NATIVE_AVAILABLE) continue;
      assert.ok(
        withBackend(backend, () => {
          assert.equal(toHex(hkdfSha256(hex(ikm), hex(salt), hex(info), length)), okm, `${name} on pinned ${backend}`);
        }),
      );
    }
  }
});

test('hkdfSha256 matches noble on random inputs and at the length limits', () => {
  for (let i = 0; i < 200; i++) {
    const ikm = randomBytes(i % 97);
    const salt = randomBytes(i % 71);
    const info = randomBytes(i % 43);
    const length = 1 + (i % 96);
    assert.deepEqual(
      list(hkdfSha256(ikm, salt, info, length)),
      list(expand(sha256, extract(sha256, ikm, salt), info, length)),
      `mismatch at ikm ${ikm.length} salt ${salt.length} info ${info.length} length ${length}`,
    );
  }

  // 255 blocks is the largest output RFC 5869 defines. It is also where a
  // counter byte that wraps instead of stopping would first show.
  const ikm = randomBytes(32);
  const salt = randomBytes(32);
  const max = 32 * 255;
  assert.deepEqual(
    list(hkdfSha256(ikm, salt, new Uint8Array(0), max)),
    list(expand(sha256, extract(sha256, ikm, salt), new Uint8Array(0), max)),
  );
});

// ---------------------------------------------------------------------------
// The two backends against each other
// ---------------------------------------------------------------------------

test('the two backends produce identical macs on the whole corpus', () => {
  if (!NATIVE_AVAILABLE) {
    // Not a pass by omission: every test above already ran against whichever
    // single backend exists here, and this line records which one that was.
    console.log('no native hash backend on this runtime, cross backend comparison skipped');
    return;
  }

  for (const c of CORPUS) {
    const noble = on('noble', () => hmacSha256(c.key, c.message));
    const native = on('native', () => hmacSha256(c.key, c.message));
    assert.deepEqual(list(native), list(noble), `key ${c.key.length} message ${c.message.length}`);
  }

  for (const keyLength of EDGE_KEY_LENGTHS) {
    const key = randomBytes(keyLength);
    for (const messageLength of EDGE_MESSAGE_LENGTHS) {
      const message = randomBytes(messageLength);
      const noble = on('noble', () => hmacSha256(key, message));
      const native = on('native', () => hmacSha256(key, message));
      assert.deepEqual(list(native), list(noble), `key ${keyLength} message ${messageLength}`);
    }
  }
});

test('the two backends produce identical kdf output on 500 random inputs', () => {
  if (!NATIVE_AVAILABLE) return;

  // The claim that actually matters, stated at the level the ratchet uses.
  for (let i = 0; i < 500; i++) {
    const chainKey = randomBytes(32);
    const noble = on('noble', () => kdfChain(chainKey));
    const native = on('native', () => kdfChain(chainKey));
    assert.deepEqual(list(native.messageKey), list(noble.messageKey), `message key diverged at ${i}`);
    assert.deepEqual(list(native.nextChainKey), list(noble.nextChainKey), `chain key diverged at ${i}`);

    const rootKey = randomBytes(32);
    const dhOutput = randomBytes(32);
    const nobleRoot = on('noble', () => kdfRoot(rootKey, dhOutput));
    const nativeRoot = on('native', () => kdfRoot(rootKey, dhOutput));
    assert.deepEqual(list(nativeRoot.rootKey), list(nobleRoot.rootKey), `root diverged at ${i}`);
    assert.deepEqual(list(nativeRoot.chainKey), list(nobleRoot.chainKey), `root chain diverged at ${i}`);

    const ikm = randomBytes(1 + (i % 160));
    const conversationId = `conv-${i}-${toHex(randomBytes(4))}`;
    assert.deepEqual(
      list(on('native', () => kdfHandshake(ikm, conversationId))),
      list(on('noble', () => kdfHandshake(ikm, conversationId))),
      `handshake root diverged at ${i}`,
    );
  }
});

test('the kdf edge cases both backends could disagree on', () => {
  // Degenerate chain keys are not something the ratchet produces, but a
  // deserialised session is caller-supplied and this library has never
  // validated the entropy of one. Both backends have to treat them the same.
  const chainKeys = [
    new Uint8Array(0),
    new Uint8Array(32),
    new Uint8Array(32).fill(0xff),
    new Uint8Array(64).fill(0x36),
    new Uint8Array(65).fill(0x5c),
  ];
  for (const chainKey of chainKeys) {
    const reference = kdfChain(chainKey);
    assert.deepEqual(list(reference.messageKey), list(hmac(sha256, chainKey, Uint8Array.of(0x01))));
    assert.deepEqual(list(reference.nextChainKey), list(hmac(sha256, chainKey, Uint8Array.of(0x02))));
    if (!NATIVE_AVAILABLE) continue;
    const noble = on('noble', () => kdfChain(chainKey));
    const native = on('native', () => kdfChain(chainKey));
    assert.deepEqual(list(native.messageKey), list(noble.messageKey), `${chainKey.length} byte chain key`);
    assert.deepEqual(list(native.nextChainKey), list(noble.nextChainKey), `${chainKey.length} byte chain key`);
  }

  // Empty ikm and an empty conversation id, which is the degenerate handshake.
  const empty = new Uint8Array(0);
  assert.deepEqual(
    list(kdfHandshake(empty, '')),
    list(expand(sha256, extract(sha256, empty, utf8ToBytes('OCX1 hybrid handshake v1')), empty, 32)),
  );
  if (NATIVE_AVAILABLE) {
    assert.deepEqual(list(on('native', () => kdfHandshake(empty, ''))), list(on('noble', () => kdfHandshake(empty, ''))));
    assert.deepEqual(
      list(on('native', () => kdfRoot(empty, empty).chainKey)),
      list(on('noble', () => kdfRoot(empty, empty).chainKey)),
    );
  }
});

// ---------------------------------------------------------------------------
// Error observability
// ---------------------------------------------------------------------------

test('a non byte input fails identically on both backends', () => {
  // node:crypto would happily hash a string or an ArrayBuffer under an encoding
  // of its own choosing, where @noble throws. If the native path answered those
  // calls, a mistyped call site would work on a server and throw in a browser,
  // which is worse than either behaviour alone. src/hash.ts declines them so
  // @noble throws the error it has always thrown.
  const bad: [string, unknown][] = [
    ['string', 'not bytes'],
    ['number', 7],
    ['null', null],
    ['undefined', undefined],
    ['plain array', [1, 2, 3]],
    ['ArrayBuffer', new ArrayBuffer(32)],
    ['Int8Array', new Int8Array(32)],
  ];
  const key = randomBytes(32);
  const message = Uint8Array.of(0x01);

  for (const [name, value] of bad) {
    const reference = failureOf(() => hmac(sha256, value as Uint8Array, message));
    const referenceMessage = failureOf(() => hmac(sha256, key, value as Uint8Array));
    assert.notEqual(reference, 'DID NOT THROW', `${name}: noble accepted it as a key`);

    assert.equal(failureOf(() => hmacSha256(value as Uint8Array, message)), reference, `${name} as key`);
    assert.equal(failureOf(() => hmacSha256(key, value as Uint8Array)), referenceMessage, `${name} as message`);

    if (!NATIVE_AVAILABLE) continue;
    let noble = 'unset';
    let native = 'unset';
    assert.ok(withBackend('noble', () => { noble = failureOf(() => hmacSha256(value as Uint8Array, message)); }));
    assert.ok(withBackend('native', () => { native = failureOf(() => hmacSha256(value as Uint8Array, message)); }));
    assert.equal(native, noble, `${name}: the native backend reported a different failure`);
  }
});

test('an out of range hkdf length fails identically on both backends', () => {
  // Past 255 blocks HKDF is undefined and @noble throws. A native path that
  // answered anyway would be inventing key material.
  const ikm = randomBytes(32);
  const salt = randomBytes(32);
  const info = new Uint8Array(0);
  for (const length of [0, -1, 1.5, 32 * 255 + 1, Number.NaN]) {
    const reference = failureOf(() => expand(sha256, extract(sha256, ikm, salt), info, length));
    const actual = failureOf(() => hkdfSha256(ikm, salt, info, length));
    assert.equal(actual, reference, `length ${length} on backend ${hashBackend()}`);
    if (!NATIVE_AVAILABLE) continue;
    let noble = 'unset';
    let native = 'unset';
    assert.ok(withBackend('noble', () => { noble = failureOf(() => hkdfSha256(ikm, salt, info, length)); }));
    assert.ok(withBackend('native', () => { native = failureOf(() => hkdfSha256(ikm, salt, info, length)); }));
    assert.equal(native, noble, `length ${length}: the native backend reported a different failure`);
  }
});

// ---------------------------------------------------------------------------
// Backend selection
// ---------------------------------------------------------------------------

test('hashBackend reports honestly', async () => {
  await hashReady();

  // Forced noble must report noble on every runtime, with no exceptions. This
  // is the fallback path: it is what a browser gets, and it has to be reachable
  // on demand or it is untested code.
  assert.equal(forceHashBackend('noble'), 'noble');
  assert.equal(hashBackend(), 'noble');

  // Forcing native cannot conjure one. The return value is the truth, and it
  // has to agree with what the getter says afterwards.
  const forcedNative = forceHashBackend('native');
  assert.equal(hashBackend(), forcedNative);
  assert.equal(forcedNative, NATIVE_AVAILABLE ? 'native' : 'noble');

  assert.equal(forceHashBackend('auto'), NATIVE_AVAILABLE ? 'native' : 'noble');
  assert.ok(hashBackend() === 'native' || hashBackend() === 'noble');
});

test('the pure JavaScript fallback is complete on its own', () => {
  // Everything the library asks of this module, with the native path switched
  // off. If the fast path were load bearing for correctness rather than for
  // speed, this is where it would show.
  assert.ok(
    withBackend('noble', () => {
      const chainKey = randomBytes(32);
      const step = kdfChain(chainKey);
      assert.deepEqual(list(step.messageKey), list(hmac(sha256, chainKey, Uint8Array.of(0x01))));
      const stepped = kdfRoot(randomBytes(32), randomBytes(32));
      assert.equal(stepped.rootKey.length, 32);
      assert.equal(stepped.chainKey.length, 32);
      assert.equal(kdfHandshake(randomBytes(96), 'conv').length, 32);
    }),
  );
});

// ---------------------------------------------------------------------------
// The protocol on top of it
// ---------------------------------------------------------------------------

test('a handshake and a conversation complete across a backend split', () => {
  if (!NATIVE_AVAILABLE) {
    console.log('no native hash backend on this runtime, split backend conversation skipped');
    return;
  }

  // The end to end version of the claim. Alice's whole key schedule runs on one
  // backend and Bob's on the other, in both assignments. Every derived value
  // has to match across the split: the handshake root, the chain keys, and the
  // message keys, and any divergence in any of them surfaces immediately as an
  // authentication failure rather than as a wrong number nobody looks at.
  for (const [aliceBackend, bobBackend] of [
    ['native', 'noble'],
    ['noble', 'native'],
  ] as const) {
    const alice = createIdentity();
    const bob = createIdentity();

    const invited = on(aliceBackend, () => beginInvite(alice));
    const invite = decodeEnvelope(invited.token);
    assert.equal(invite.kind, 'invite');
    if (invite.kind !== 'invite') throw new Error('unreachable');

    const accepted = on(bobBackend, () => acceptInvite(bob, invite));
    const accept = decodeEnvelope(accepted.token);
    assert.equal(accept.kind, 'accept');
    if (accept.kind !== 'accept') throw new Error('unreachable');

    // Bob's root key was derived on Bob's backend inside acceptInvite. Rebuild
    // the same input keying material from Alice's side and run it through the
    // handshake KDF on Alice's backend: the two roots have to be the same 32
    // bytes or nothing after this point can work.
    const aliceIkm = concat(
      x25519SharedSecret(alice.classicalSecret, accept.sender.classicalPublic),
      x25519SharedSecret(alice.classicalSecret, accept.ratchetPublic),
      ml_kem768.decapsulate(accept.kemCiphertext, alice.pqSecret),
    );
    const aliceRoot = on(aliceBackend, () => kdfHandshake(aliceIkm, invite.conversationId));
    assert.deepEqual(
      list(aliceRoot),
      list(accepted.session.rootKey),
      `handshake roots differ with alice on ${aliceBackend} and bob on ${bobBackend}`,
    );

    let aliceSession = on(aliceBackend, () => completeInvite(alice, invited.pending, accept));
    let bobSession = accepted.session;

    // Twelve messages, alternating direction so every DH ratchet step runs with
    // one side on each backend, with a burst in one direction so the chain walks
    // more than one step before it turns around.
    const script: ('alice' | 'bob')[] = [
      'alice', 'alice', 'alice', 'bob', 'bob', 'alice', 'bob', 'alice', 'alice', 'bob', 'bob', 'alice',
    ];
    script.forEach((sender, index) => {
      const plaintext = `message ${index} from ${sender} with alice on ${aliceBackend}`;
      if (sender === 'alice') {
        const sealed = on(aliceBackend, () => ratchetEncrypt(aliceSession, plaintext));
        aliceSession = sealed.session;
        const opened = on(bobBackend, () => ratchetDecrypt(bobSession, sealed.payload));
        bobSession = opened.session;
        assert.equal(opened.plaintext, plaintext);
      } else {
        const sealed = on(bobBackend, () => ratchetEncrypt(bobSession, plaintext));
        bobSession = sealed.session;
        const opened = on(aliceBackend, () => ratchetDecrypt(aliceSession, sealed.payload));
        aliceSession = opened.session;
        assert.equal(opened.plaintext, plaintext);
      }

      // Stronger than "it decrypted". The sender's advanced send chain and the
      // receiver's advanced receive chain are the same secret, derived
      // independently on two different implementations of HMAC-SHA256.
      const senderChain = sender === 'alice' ? aliceSession.sendChainKey : bobSession.sendChainKey;
      const receiverChain = sender === 'alice' ? bobSession.recvChainKey : aliceSession.recvChainKey;
      assert.ok(senderChain !== undefined && receiverChain !== undefined);
      assert.deepEqual(list(senderChain), list(receiverChain), `chain keys diverged after message ${index}`);
    });

    // Do NOT assert the two root keys are equal here. They are not, and that is
    // the protocol working rather than a bug: receiving a new ratchet public key
    // advances the root twice, once for the receive chain and once for the fresh
    // send chain derived in the same step, while the sender advanced it only
    // once. So after the first change of direction the two roots sit one kdfRoot
    // apart forever. Verified against a single backend with no split involved,
    // so anyone who reads a mismatch here as a hash divergence is chasing a
    // ghost. What the split actually has to prove is proved above: the handshake
    // roots matched, and both chain keys matched after every one of the twelve
    // messages.
    //
    // The end state claim that IS true is that the conversation is still live in
    // both directions, which is only possible if every kdfRoot and kdfChain step
    // on both backends agreed byte for byte the whole way through.
    const lastFromAlice = on(aliceBackend, () => ratchetEncrypt(aliceSession, 'still live'));
    aliceSession = lastFromAlice.session;
    const bobReads = on(bobBackend, () => ratchetDecrypt(bobSession, lastFromAlice.payload));
    bobSession = bobReads.session;
    assert.equal(bobReads.plaintext, 'still live');

    const lastFromBob = on(bobBackend, () => ratchetEncrypt(bobSession, 'both ways'));
    bobSession = lastFromBob.session;
    const aliceReads = on(aliceBackend, () => ratchetDecrypt(aliceSession, lastFromBob.payload));
    aliceSession = aliceReads.session;
    assert.equal(aliceReads.plaintext, 'both ways');

    assert.ok(aliceSession.recvChainKey !== undefined && bobSession.sendChainKey !== undefined);
    assert.deepEqual(
      list(bobSession.sendChainKey),
      list(aliceSession.recvChainKey),
      `final chain keys differ with alice on ${aliceBackend} and bob on ${bobBackend}`,
    );
  }
});
