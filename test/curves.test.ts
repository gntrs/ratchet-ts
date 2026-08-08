/**
 * The native X25519 fast path has exactly one job beyond being fast: being
 * invisible. A public key derived on one backend has to be the key the other
 * backend derives from the same secret, a shared secret has to be the same 32
 * bytes on both, and a rejected key has to be rejected the same way with the
 * same error. A faster backend that produces different bytes is not a faster
 * backend, it is a second protocol.
 *
 * So this suite is differential in the same way test/aead.test.ts is: @noble is
 * the reference implementation and every test here asks whether the other path
 * can be told apart from it. Nothing here measures speed.
 *
 * The low order point tests are the ones that earn their keep. That is the one
 * place where node:crypto and @noble genuinely behave differently underneath
 * (they reject the same inputs, but with different error objects), and
 * src/curves.ts handles it by never letting the native path be the thing that
 * reports a failure. These tests are what pins that.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { x25519 } from '@noble/curves/ed25519.js';
import { randomBytes } from '@noble/hashes/utils.js';

import {
  curveBackend,
  curvesReady,
  forceCurveBackend,
  x25519Keygen,
  x25519PublicKey,
  x25519SharedSecret,
} from '../src/curves.js';
import { decodeEnvelope } from '../src/envelope.js';
import { acceptInvite, beginInvite, completeInvite } from '../src/handshake.js';
import { createIdentity } from '../src/identity.js';

/** Whether this machine has a usable native backend at all. Every native
 * specific assertion below is gated on it, because a browser or a locked down
 * runtime genuinely has none and the correct behaviour there is to run on
 * @noble, not to fail the suite. */
const NATIVE_AVAILABLE = (() => {
  const got = forceCurveBackend('native');
  forceCurveBackend('auto');
  return got === 'native';
})();

/** Restores the automatic backend no matter how the body exits, so one failing
 * assertion cannot leave every later test pinned to the wrong path. Returns
 * false when the requested backend does not exist here. */
function withBackend(choice: 'native' | 'noble', body: () => void): boolean {
  const effective = forceCurveBackend(choice);
  try {
    if (effective !== choice) return false;
    body();
    return true;
  } finally {
    forceCurveBackend('auto');
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
 * Captures how a call failed, as a comparable value.
 *
 * Comparing the message and the constructor name rather than the object is the
 * point: the claim is that a caller cannot tell which backend answered, and the
 * message is the only part of a thrown Error a caller realistically inspects.
 * OpenSSL's own error text is completely different from @noble's, so if the
 * native path ever reported a rejection itself this would catch it immediately.
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

interface Pair {
  aSecret: Uint8Array;
  bSecret: Uint8Array;
}

/** 120 random pairs. Fewer than the AEAD suite's 300 because a @noble scalar
 * multiplication costs about a thousand times what a small AEAD call does, and
 * 120 pairs is already 480 curve operations per backend per test. */
const CORPUS: Pair[] = Array.from({ length: 120 }, () => ({
  aSecret: randomBytes(32),
  bSecret: randomBytes(32),
}));

/**
 * Secrets that are not what a generator would ever produce.
 *
 * X25519 clamps the scalar before use: it clears the low three bits, clears the
 * top bit and sets bit 254. An implementation that skips clamping agrees with
 * @noble on every random secret and disagrees only on these, which is exactly
 * the kind of bug that ships.
 */
const EDGE_SECRETS: [string, Uint8Array][] = [
  ['all zero', new Uint8Array(32)],
  ['all ff', new Uint8Array(32).fill(0xff)],
  ['low bits set', hex('0700000000000000000000000000000000000000000000000000000000000000')],
  ['top bit set', hex('0000000000000000000000000000000000000000000000000000000000000080')],
  ['bit 254 clear', hex('00000000000000000000000000000000000000000000000000000000000000bf')],
  ['one', hex('0100000000000000000000000000000000000000000000000000000000000000')],
];

/**
 * The classical low order points, as u-coordinates. Each one drives the scalar
 * multiplication to the identity, so the shared secret would be all zeroes and
 * would carry no contributory secrecy at all. Both backends must refuse them,
 * and must refuse them the same way.
 */
const LOW_ORDER_POINTS: [string, Uint8Array][] = [
  ['zero, order 1', hex('0000000000000000000000000000000000000000000000000000000000000000')],
  ['one, order 1', hex('0100000000000000000000000000000000000000000000000000000000000000')],
  ['order 8 a', hex('e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800')],
  ['order 8 b', hex('5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157')],
  ['p minus 1, order 2', hex('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f')],
  ['p, order 4', hex('edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f')],
  ['p plus 1', hex('eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f')],
];

/** Malformed lengths. Neither backend may quietly pad or truncate: a 33 byte
 * "public key" is a protocol error, not a key with a spare byte. node:crypto
 * will in fact parse some of these, which is why src/curves.ts checks the
 * length itself before it ever calls out. */
const BAD_LENGTHS = [0, 1, 31, 33, 64];

// ---------------------------------------------------------------------------
// Byte identity against @noble
// ---------------------------------------------------------------------------

test('x25519PublicKey is byte identical to noble on 120 random secrets', () => {
  for (const p of CORPUS) {
    assert.deepEqual(
      list(x25519PublicKey(p.aSecret)),
      list(x25519.getPublicKey(p.aSecret)),
      `public key mismatch on backend ${curveBackend()}`,
    );
  }
});

test('x25519SharedSecret is byte identical to noble on 120 random pairs', () => {
  for (const p of CORPUS) {
    const bPublic = x25519.getPublicKey(p.bSecret);
    assert.deepEqual(
      list(x25519SharedSecret(p.aSecret, bPublic)),
      list(x25519.getSharedSecret(p.aSecret, bPublic)),
      `shared secret mismatch on backend ${curveBackend()}`,
    );
  }
});

test('the exchange actually closes: both sides derive the same secret', () => {
  for (const p of CORPUS) {
    const aPublic = x25519PublicKey(p.aSecret);
    const bPublic = x25519PublicKey(p.bSecret);
    assert.deepEqual(list(x25519SharedSecret(p.aSecret, bPublic)), list(x25519SharedSecret(p.bSecret, aPublic)));
  }
});

test('RFC 7748 published vectors', () => {
  // Section 6.1. If this fails, the backend is not X25519 whatever it claims.
  const aliceSecret = hex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
  const bobSecret = hex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
  const alicePublic = hex('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
  const bobPublic = hex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
  const shared = hex('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742');

  assert.deepEqual(list(x25519PublicKey(aliceSecret)), list(alicePublic));
  assert.deepEqual(list(x25519PublicKey(bobSecret)), list(bobPublic));
  assert.deepEqual(list(x25519SharedSecret(aliceSecret, bobPublic)), list(shared));
  assert.deepEqual(list(x25519SharedSecret(bobSecret, alicePublic)), list(shared));

  // Section 5.2, the raw scalar multiplication vectors.
  assert.deepEqual(
    list(
      x25519SharedSecret(
        hex('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'),
        hex('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c'),
      ),
    ),
    list(hex('c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552')),
  );
  assert.deepEqual(
    list(
      x25519SharedSecret(
        hex('4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d'),
        hex('e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493'),
      ),
    ),
    list(hex('95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957')),
  );
});

test('unclamped and degenerate secrets still match noble', () => {
  for (const [name, secret] of EDGE_SECRETS) {
    assert.deepEqual(
      list(x25519PublicKey(secret)),
      list(x25519.getPublicKey(secret)),
      `${name} public key diverged on backend ${curveBackend()}`,
    );
  }
});

test('keygen returns a self consistent pair that noble agrees with', () => {
  for (let i = 0; i < 40; i++) {
    const pair = x25519Keygen();
    assert.equal(pair.secretKey.length, 32);
    assert.equal(pair.publicKey.length, 32);
    // The public half must be the public half OF that secret, on noble's
    // reckoning. Anything else and a session restored from disk stops working.
    assert.deepEqual(list(pair.publicKey), list(x25519.getPublicKey(pair.secretKey)));
    // Two calls must not return the same key. A generator that got stuck would
    // otherwise pass every other test in this file.
    assert.notDeepEqual(list(pair.secretKey), list(x25519Keygen().secretKey));
  }
});

// ---------------------------------------------------------------------------
// The two backends against each other
// ---------------------------------------------------------------------------

test('the two backends produce identical public keys and shared secrets', () => {
  if (!NATIVE_AVAILABLE) {
    // Not a pass by omission: every test above already ran against whichever
    // single backend exists here, and this line records which one that was.
    console.log('no native curve backend on this runtime, cross backend comparison skipped');
    return;
  }

  for (const p of CORPUS) {
    let noblePublic: Uint8Array = new Uint8Array(0);
    let nativePublic: Uint8Array = new Uint8Array(0);
    let nobleShared: Uint8Array = new Uint8Array(0);
    let nativeShared: Uint8Array = new Uint8Array(0);
    const bPublic = x25519.getPublicKey(p.bSecret);

    assert.ok(
      withBackend('noble', () => {
        assert.equal(curveBackend(), 'noble');
        noblePublic = x25519PublicKey(p.aSecret);
        nobleShared = x25519SharedSecret(p.aSecret, bPublic);
      }),
    );
    assert.ok(
      withBackend('native', () => {
        assert.equal(curveBackend(), 'native');
        nativePublic = x25519PublicKey(p.aSecret);
        nativeShared = x25519SharedSecret(p.aSecret, bPublic);
      }),
    );

    assert.deepEqual(list(nativePublic), list(noblePublic));
    assert.deepEqual(list(nativeShared), list(nobleShared));
  }
});

test('a keypair made on one backend works on the other', () => {
  if (!NATIVE_AVAILABLE) return;

  // This is the actual interop claim: a browser and a server, or a session
  // persisted by one build and restored by another, must be able to finish the
  // same exchange. Keys are generated on one backend and consumed on the other,
  // in both directions.
  for (let i = 0; i < 25; i++) {
    let fromNative: { secretKey: Uint8Array; publicKey: Uint8Array } = { secretKey: new Uint8Array(0), publicKey: new Uint8Array(0) };
    let fromNoble: { secretKey: Uint8Array; publicKey: Uint8Array } = { secretKey: new Uint8Array(0), publicKey: new Uint8Array(0) };
    assert.ok(withBackend('native', () => { fromNative = x25519Keygen(); }));
    assert.ok(withBackend('noble', () => { fromNoble = x25519Keygen(); }));

    let nativeSide: Uint8Array = new Uint8Array(0);
    let nobleSide: Uint8Array = new Uint8Array(0);
    assert.ok(
      withBackend('native', () => {
        nativeSide = x25519SharedSecret(fromNative.secretKey, fromNoble.publicKey);
      }),
    );
    assert.ok(
      withBackend('noble', () => {
        nobleSide = x25519SharedSecret(fromNoble.secretKey, fromNative.publicKey);
      }),
    );
    assert.deepEqual(list(nativeSide), list(nobleSide));
  }
});

test('unclamped secrets and the edge public keys agree across backends', () => {
  if (!NATIVE_AVAILABLE) return;

  // 0xff repeated looks like it belongs on the low order list and does not: the
  // top bit is masked off before the field reduction, so it is the ordinary
  // point u = 18. Both backends must accept it, and agree on it. A backend that
  // masked differently would diverge here and nowhere else.
  const extraPublics: [string, Uint8Array][] = [
    ...EDGE_SECRETS.map(([name, secret]): [string, Uint8Array] => [name, x25519.getPublicKey(secret)]),
    ['all ff u-coordinate', new Uint8Array(32).fill(0xff)],
    ['u = 9, the base point', hex('0900000000000000000000000000000000000000000000000000000000000000')],
  ];
  const secret = CORPUS[0]!.aSecret;

  for (const [name, publicKey] of extraPublics) {
    let noble = 'unset';
    let native = 'unset';
    assert.ok(withBackend('noble', () => { noble = failureOf(() => list(x25519SharedSecret(secret, publicKey))); }));
    assert.ok(withBackend('native', () => { native = failureOf(() => list(x25519SharedSecret(secret, publicKey))); }));
    assert.equal(native, noble, `${name} behaved differently on the two backends`);

    if (noble === 'DID NOT THROW') {
      let a: Uint8Array = new Uint8Array(0);
      let b: Uint8Array = new Uint8Array(0);
      assert.ok(withBackend('noble', () => { a = x25519SharedSecret(secret, publicKey); }));
      assert.ok(withBackend('native', () => { b = x25519SharedSecret(secret, publicKey); }));
      assert.deepEqual(list(b), list(a), `${name} produced different bytes`);
    }
  }

  for (const [name, secretKey] of EDGE_SECRETS) {
    let noble: Uint8Array = new Uint8Array(0);
    let native: Uint8Array = new Uint8Array(0);
    assert.ok(withBackend('noble', () => { noble = x25519PublicKey(secretKey); }));
    assert.ok(withBackend('native', () => { native = x25519PublicKey(secretKey); }));
    assert.deepEqual(list(native), list(noble), `${name} derived a different public key`);
  }
});

// ---------------------------------------------------------------------------
// Low order points and malformed input
// ---------------------------------------------------------------------------

test('low order points are refused, with the identical error, on both backends', () => {
  const secret = CORPUS[0]!.aSecret;

  for (const [name, point] of LOW_ORDER_POINTS) {
    // The reference behaviour, which is what this library has always done.
    const reference = failureOf(() => x25519.getSharedSecret(secret, point));
    assert.notEqual(reference, 'DID NOT THROW', `${name}: noble accepted a low order point`);

    // The automatic backend, whichever it is, must match it exactly.
    assert.equal(failureOf(() => x25519SharedSecret(secret, point)), reference, `${name} on backend ${curveBackend()}`);

    if (!NATIVE_AVAILABLE) continue;
    let noble = 'unset';
    let native = 'unset';
    assert.ok(withBackend('noble', () => { noble = failureOf(() => x25519SharedSecret(secret, point)); }));
    assert.ok(withBackend('native', () => { native = failureOf(() => x25519SharedSecret(secret, point)); }));
    assert.equal(noble, reference, `${name}: pinned noble drifted from the reference`);
    // The one that matters. OpenSSL rejects these too, but with its own error
    // text, so a native path that reported the rejection itself would fail here.
    assert.equal(native, noble, `${name}: the native backend reported a different failure`);
  }
});

test('a low order point never yields an all zero shared secret', () => {
  // The failure mode this guards is not an exception, it is a backend that
  // returns the zeroes instead of erroring. Those 32 zero bytes would then be
  // fed to the KDF as a root key that the attacker chose.
  const secret = CORPUS[0]!.aSecret;
  for (const [name, point] of LOW_ORDER_POINTS) {
    for (const backend of ['noble', 'native'] as const) {
      if (backend === 'native' && !NATIVE_AVAILABLE) continue;
      assert.ok(
        withBackend(backend, () => {
          let returned: Uint8Array | null = null;
          try {
            returned = x25519SharedSecret(secret, point);
          } catch {
            returned = null;
          }
          if (returned !== null) {
            assert.fail(`${backend} returned a shared secret for the low order point ${name}`);
          }
        }),
      );
    }
  }
});

test('malformed key lengths are rejected identically, not padded', () => {
  const secret = CORPUS[0]!.aSecret;
  const publicKey = x25519.getPublicKey(secret);

  for (const length of BAD_LENGTHS) {
    const badPublic = randomBytes(length);
    const badSecret = randomBytes(length);

    const publicReference = failureOf(() => x25519.getSharedSecret(secret, badPublic));
    const secretReference = failureOf(() => x25519.getSharedSecret(badSecret, publicKey));
    const deriveReference = failureOf(() => x25519.getPublicKey(badSecret));
    assert.notEqual(publicReference, 'DID NOT THROW', `a ${length} byte public key was accepted by noble`);
    assert.notEqual(secretReference, 'DID NOT THROW', `a ${length} byte secret was accepted by noble`);

    for (const backend of ['noble', 'native'] as const) {
      if (backend === 'native' && !NATIVE_AVAILABLE) continue;
      assert.ok(
        withBackend(backend, () => {
          assert.equal(failureOf(() => x25519SharedSecret(secret, badPublic)), publicReference, `${backend}, public ${length}`);
          assert.equal(failureOf(() => x25519SharedSecret(badSecret, publicKey)), secretReference, `${backend}, secret ${length}`);
          assert.equal(failureOf(() => x25519PublicKey(badSecret)), deriveReference, `${backend}, derive ${length}`);
        }),
      );
    }
  }
});

// ---------------------------------------------------------------------------
// Backend selection
// ---------------------------------------------------------------------------

test('curveBackend reports honestly', async () => {
  await curvesReady();

  // Forced noble must report noble on every runtime, with no exceptions. This
  // is the fallback path: it is what a browser gets, and it has to be reachable
  // on demand or it is untested code.
  assert.equal(forceCurveBackend('noble'), 'noble');
  assert.equal(curveBackend(), 'noble');

  // Forcing native cannot conjure one. The return value is the truth, and it
  // has to agree with what the getter says afterwards.
  const forcedNative = forceCurveBackend('native');
  assert.equal(curveBackend(), forcedNative);
  assert.equal(forcedNative, NATIVE_AVAILABLE ? 'native' : 'noble');

  assert.equal(forceCurveBackend('auto'), NATIVE_AVAILABLE ? 'native' : 'noble');
  assert.ok(curveBackend() === 'native' || curveBackend() === 'noble');
});

test('the pure JavaScript fallback is complete on its own', () => {
  // Everything the library asks of this module, with the native path switched
  // off. If the fast path were load bearing for correctness rather than for
  // speed, this is where it would show.
  assert.ok(
    withBackend('noble', () => {
      const a = x25519Keygen();
      const b = x25519Keygen();
      assert.deepEqual(list(a.publicKey), list(x25519.getPublicKey(a.secretKey)));
      assert.deepEqual(list(x25519SharedSecret(a.secretKey, b.publicKey)), list(x25519SharedSecret(b.secretKey, a.publicKey)));
      assert.deepEqual(
        list(x25519SharedSecret(a.secretKey, b.publicKey)),
        list(x25519.getSharedSecret(a.secretKey, b.publicKey)),
      );
    }),
  );
});

// ---------------------------------------------------------------------------
// The handshake on top of it
// ---------------------------------------------------------------------------

test('a handshake completes across a backend split', () => {
  if (!NATIVE_AVAILABLE) return;

  // The end to end version of the interop claim. Alice's identity and her half
  // of the handshake run on one backend, Bob's on the other, and the two root
  // keys still have to match. This is the test that would have caught a curve
  // change that was byte correct in isolation and wired up wrong.
  for (const [aliceBackend, bobBackend] of [
    ['native', 'noble'],
    ['noble', 'native'],
  ] as const) {
    let aliceRoot: Uint8Array = new Uint8Array(0);
    let bobRoot: Uint8Array = new Uint8Array(0);

    const alice = forceCurveBackend(aliceBackend) === aliceBackend ? createIdentity() : null;
    forceCurveBackend('auto');
    assert.ok(alice !== null);

    const bob = forceCurveBackend(bobBackend) === bobBackend ? createIdentity() : null;
    forceCurveBackend('auto');
    assert.ok(bob !== null);

    try {
      forceCurveBackend(aliceBackend);
      const invited = beginInvite(alice);
      const invite = decodeEnvelope(invited.token);
      assert.equal(invite.kind, 'invite');
      if (invite.kind !== 'invite') throw new Error('unreachable');

      forceCurveBackend(bobBackend);
      const accepted = acceptInvite(bob, invite);
      bobRoot = accepted.session.rootKey;
      const accept = decodeEnvelope(accepted.token);
      assert.equal(accept.kind, 'accept');
      if (accept.kind !== 'accept') throw new Error('unreachable');

      forceCurveBackend(aliceBackend);
      // Alice takes a DH ratchet step on completion, so her root key has moved
      // one step past Bob's. Comparing the ratchet publics is the equality that
      // survives that: Bob's session must hold the key Alice is now talking to.
      const aliceSession = completeInvite(alice, invited.pending, accept);
      aliceRoot = aliceSession.rootKey;
      assert.deepEqual(list(aliceSession.peerRatchetPublic ?? new Uint8Array(0)), list(accepted.session.selfRatchetPublic));

      // And the step Bob will take on his side has to land on Alice's root.
      const bobCatchUp = x25519SharedSecret(accepted.session.selfRatchetSecret, aliceSession.selfRatchetPublic);
      const aliceStep = x25519SharedSecret(aliceSession.selfRatchetSecret, accepted.session.selfRatchetPublic);
      assert.deepEqual(list(bobCatchUp), list(aliceStep));
    } finally {
      forceCurveBackend('auto');
    }

    assert.equal(aliceRoot.length, 32);
    assert.equal(bobRoot.length, 32);
    assert.notDeepEqual(list(aliceRoot), list(bobRoot));
  }
});
