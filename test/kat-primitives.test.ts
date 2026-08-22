import { test } from 'node:test';
import assert from 'node:assert/strict';

import { toHex, utf8ToBytes } from '../src/bytes.js';
import { x25519PublicKey, x25519SharedSecret } from '../src/curves.js';
import { hkdfSha256, hmacSha512 } from '../src/hash.js';
import { openAead, sealAead } from '../src/aead.js';
import { expectFailure } from './harness.js';

/** Local, because src/bytes.ts exports toHex but deliberately not its inverse:
 * nothing in the library parses hex except the conversation id, which has its
 * own strict parser. Vectors arrive as hex, so the tests need one. */
function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * Published known-answer vectors from the standards themselves.
 *
 * WHY THIS EXISTS WHEN @noble ALREADY PASSES THESE
 *
 * It is true that the primitives come from audited libraries and that those
 * libraries test against these same vectors. The reason to run them here anyway
 * is that this repository does not call the primitives directly. Every one of
 * them goes through a wrapper in src/ that picks a backend: curves.ts and
 * hash.ts prefer node:crypto where it exists and fall back to pure JS, and
 * aead.ts does the same for ChaCha20-Poly1305. Those wrappers are the thing a
 * user of this library actually depends on, and a wrapper can be wrong in ways
 * the library underneath is not: a swapped argument order, a key and a nonce
 * transposed, a backend selected but never actually exercised, an endianness
 * assumption in a conversion helper.
 *
 * So these tests are aimed at the seam, not at the primitive. They also change
 * the repository from one that CITES the standards to one that DEMONSTRATES
 * conformance to them, which is the difference between a reader taking the
 * README's word for it and a reader running `npm test`.
 *
 * Every vector below was taken from the RFC text, not from memory and not from
 * another implementation's test suite. The section is named on each one so it
 * can be checked against the source document.
 */

// ---------------------------------------------------------------------------
// X25519, RFC 7748
// ---------------------------------------------------------------------------

test('RFC 7748 section 5.2: X25519 scalar multiplication known answers', () => {
  const cases = [
    {
      scalar: 'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4',
      u: 'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c',
      out: 'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552',
    },
    {
      scalar: '4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d',
      u: 'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493',
      out: '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957',
    },
  ];
  for (const c of cases) {
    assert.equal(toHex(x25519SharedSecret(fromHex(c.scalar), fromHex(c.u))), c.out);
  }
});

test('RFC 7748 section 6.1: the Alice and Bob Diffie-Hellman exchange', () => {
  const alicePrivate = fromHex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
  const alicePublic = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a';
  const bobPrivate = fromHex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
  const bobPublic = 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f';
  const shared = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';

  assert.equal(toHex(x25519PublicKey(alicePrivate)), alicePublic);
  assert.equal(toHex(x25519PublicKey(bobPrivate)), bobPublic);
  // Both directions, because a shared secret that only works one way is not one.
  assert.equal(toHex(x25519SharedSecret(alicePrivate, fromHex(bobPublic))), shared);
  assert.equal(toHex(x25519SharedSecret(bobPrivate, fromHex(alicePublic))), shared);
});

// ---------------------------------------------------------------------------
// HKDF-SHA256, RFC 5869
// ---------------------------------------------------------------------------

test('RFC 5869 appendix A: HKDF-SHA256 known answers', () => {
  const ikm = fromHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');

  // A.1, the basic case.
  assert.equal(
    toHex(hkdfSha256(ikm, fromHex('000102030405060708090a0b0c'), fromHex('f0f1f2f3f4f5f6f7f8f9'), 42)),
    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
  );

  // A.3, zero length salt and info. Worth pinning separately because an empty
  // salt is not the same as no salt: RFC 5869 substitutes a string of
  // HashLen zeros, and an implementation that skips that step produces a
  // different answer while looking correct in every other case.
  assert.equal(
    toHex(hkdfSha256(ikm, new Uint8Array(0), new Uint8Array(0), 42)),
    '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
  );
});

// ---------------------------------------------------------------------------
// HMAC-SHA512, RFC 4231
// ---------------------------------------------------------------------------

test('RFC 4231 section 4: HMAC-SHA512 known answers', () => {
  // Test case 1.
  assert.equal(
    toHex(hmacSha512(fromHex('0b'.repeat(20)), fromHex('4869205468657265'))),
    '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde' +
      'daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
  );

  // Test case 2, a short key and a longer message.
  assert.equal(
    toHex(hmacSha512(utf8ToBytes('Jefe'), utf8ToBytes('what do ya want for nothing?'))),
    '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d03' +
      '4f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
  );
});

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305, RFC 8439
// ---------------------------------------------------------------------------

test('RFC 8439 section 2.8.2: the AEAD_CHACHA20_POLY1305 known answer', async () => {
  const key = fromHex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
  // The 96 bit nonce is the 32 bit fixed-common part 07000000 followed by the
  // 64 bit IV 4041424344454647, which is how the RFC presents it.
  const nonce = fromHex('070000004041424344454647');
  const aad = fromHex('50515253c0c1c2c3c4c5c6c7');
  const plaintext = utf8ToBytes(
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
  );
  const expected =
    'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6' +
    '3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36' +
    '92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc' +
    '3ff4def08e4b7a9de576d26586cec64b6116';
  const tag = '1ae10b594f09e26a7e902ecbd0600691';

  // sealAead returns ciphertext with the tag appended, which is the standard
  // combined form and is what the wire carries.
  const sealed = await sealAead(key, nonce, plaintext, aad);
  assert.equal(toHex(sealed), expected + tag);

  // And the other direction, against the RFC's own bytes rather than against
  // whatever this library just produced.
  const opened = await openAead(key, nonce, fromHex(expected + tag), aad);
  assert.deepEqual(opened, plaintext);
});

test('RFC 8439 section 2.8.2: the same vector fails closed when the AAD is wrong', async () => {
  const key = fromHex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
  const nonce = fromHex('070000004041424344454647');
  const sealed = fromHex(
    'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6' +
      '3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36' +
      '92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc' +
      '3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691',
  );
  // One bit of associated data, changed. A KAT that only ever checks the happy
  // path cannot tell an AEAD from a stream cipher that ignores its AAD.
  await expectFailure('authentication_failed', () =>
    openAead(key, nonce, sealed, fromHex('50515253c0c1c2c3c4c5c6c6')),
  );
});
