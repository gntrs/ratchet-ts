/**
 * The only thing that matters about the native AEAD fast path is that it is
 * invisible. Same bytes out, same failures, on every runtime. A performance
 * win that changes one byte of ciphertext is not a win, it is a wire format
 * fork that splits browsers from servers.
 *
 * So this suite is almost entirely differential: @noble is the reference
 * implementation and everything here asks whether the other path can be told
 * apart from it. Nothing here measures speed.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes } from '@noble/hashes/utils.js';

import {
  AEAD_KEY_LEN,
  AEAD_NONCE_LEN,
  AEAD_TAG_LEN,
  aeadBackend,
  aeadReady,
  forceAeadBackend,
  openAead,
  openAeadSync,
  sealAead,
  sealAeadSync,
} from '../src/aead.js';
import { isCryptoFailure } from '../src/errors.js';

/** Whether this machine has a usable native backend at all. Every native
 * specific assertion below is gated on it, because a browser or an older Node
 * genuinely has none and the correct behaviour there is to run on @noble, not
 * to fail the suite. */
const NATIVE_AVAILABLE = (() => {
  const got = forceAeadBackend('native');
  forceAeadBackend('auto');
  return got === 'native';
})();

/** Restores the automatic backend no matter how the body exits, so one failing
 * assertion cannot leave every later test pinned to the wrong path. */
function withBackend(choice: 'native' | 'noble', body: () => void): boolean {
  const effective = forceAeadBackend(choice);
  try {
    if (effective !== choice) return false;
    body();
    return true;
  } finally {
    forceAeadBackend('auto');
  }
}

/** noble's randomBytes refuses anything over 65536 bytes, and the whole point
 * of the large cases is to exceed that. Chunking keeps the randomness real
 * rather than falling back to a repeating pattern that would hide a block
 * indexing bug. */
function randomBuf(length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let at = 0; at < length; at += 65536) {
    out.set(randomBytes(Math.min(65536, length - at)), at);
  }
  return out;
}

function reference(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
  return xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
}

/** Sizes chosen to straddle the ChaCha 64 byte block and the Poly1305 16 byte
 * block in both directions, since off by one padding bugs hide exactly there.
 * The 70000 entry is the "larger than 64 KiB" case. */
const PLAINTEXT_SIZES = [0, 1, 15, 16, 17, 31, 63, 64, 65, 127, 128, 255, 1024, 4096, 70000];
const AAD_SIZES = [0, 1, 15, 16, 17, 64, 200];

interface Tuple {
  key: Uint8Array;
  nonce: Uint8Array;
  plaintext: Uint8Array;
  aad: Uint8Array;
}

function tuples(count: number): Tuple[] {
  const out: Tuple[] = [];
  for (let i = 0; i < count; i++) {
    out.push({
      key: randomBuf(AEAD_KEY_LEN),
      nonce: randomBuf(AEAD_NONCE_LEN),
      plaintext: randomBuf(PLAINTEXT_SIZES[i % PLAINTEXT_SIZES.length]!),
      aad: randomBuf(AAD_SIZES[i % AAD_SIZES.length]!),
    });
  }
  return out;
}

// A single shared corpus. Every byte identity test below runs the same inputs
// so a failure in one can be compared directly against the others.
const CORPUS = tuples(300);

test('sealAeadSync is byte identical to noble on 300 random tuples', () => {
  for (const t of CORPUS) {
    const expected = reference(t.key, t.nonce, t.plaintext, t.aad);
    const actual = sealAeadSync(t.key, t.nonce, t.plaintext, t.aad);
    assert.deepEqual(
      Array.from(actual),
      Array.from(expected),
      `mismatch at plaintext ${t.plaintext.length} aad ${t.aad.length} on backend ${aeadBackend()}`,
    );
  }
});

test('empty plaintext and empty aad seal to noble bytes', () => {
  const key = randomBuf(AEAD_KEY_LEN);
  const nonce = randomBuf(AEAD_NONCE_LEN);
  const empty = new Uint8Array(0);

  // A zero length plaintext still produces the 16 byte tag, so the output is
  // never empty. That is the case a length based short circuit would break.
  const sealed = sealAeadSync(key, nonce, empty, empty);
  assert.equal(sealed.length, AEAD_TAG_LEN);
  assert.deepEqual(Array.from(sealed), Array.from(reference(key, nonce, empty, empty)));

  // Omitting the aad argument entirely must equal passing a zero length one,
  // otherwise the optional parameter is a silent interop fork.
  assert.deepEqual(Array.from(sealAeadSync(key, nonce, empty)), Array.from(sealed));
  assert.deepEqual(Array.from(openAeadSync(key, nonce, sealed)), []);
});

test('plaintext larger than 64 KiB is byte identical to noble', () => {
  const key = randomBuf(AEAD_KEY_LEN);
  const nonce = randomBuf(AEAD_NONCE_LEN);
  const plaintext = randomBuf(200_000);
  const aad = randomBuf(37);
  assert.deepEqual(
    Array.from(sealAeadSync(key, nonce, plaintext, aad)),
    Array.from(reference(key, nonce, plaintext, aad)),
  );
});

test('open reverses seal for every tuple', () => {
  for (const t of CORPUS) {
    const sealed = sealAeadSync(t.key, t.nonce, t.plaintext, t.aad);
    assert.deepEqual(Array.from(openAeadSync(t.key, t.nonce, sealed, t.aad)), Array.from(t.plaintext));
  }
});

test('open accepts ciphertext that noble produced', () => {
  // The direction that proves a browser sealed message opens here.
  for (const t of CORPUS.slice(0, 40)) {
    const sealed = reference(t.key, t.nonce, t.plaintext, t.aad);
    assert.deepEqual(Array.from(openAeadSync(t.key, t.nonce, sealed, t.aad)), Array.from(t.plaintext));
  }
});

test('the two backends produce identical ciphertext', () => {
  if (!NATIVE_AVAILABLE) {
    // Not a pass by omission: the whole suite already ran against whichever
    // single backend exists here, and the handoff records which one that was.
    console.log('no native backend on this runtime, cross backend comparison skipped');
    return;
  }
  for (const t of CORPUS) {
    let fromNoble: Uint8Array = new Uint8Array(0);
    let fromNative: Uint8Array = new Uint8Array(0);

    assert.ok(withBackend('noble', () => {
      assert.equal(aeadBackend(), 'noble');
      fromNoble = sealAeadSync(t.key, t.nonce, t.plaintext, t.aad);
    }));
    assert.ok(withBackend('native', () => {
      assert.equal(aeadBackend(), 'native');
      fromNative = sealAeadSync(t.key, t.nonce, t.plaintext, t.aad);
    }));

    assert.deepEqual(Array.from(fromNative), Array.from(fromNoble));

    // Cross open in both directions. This is the actual claim: a message
    // sealed on a browser opens on a server and the reverse.
    assert.ok(withBackend('native', () => {
      assert.deepEqual(Array.from(openAeadSync(t.key, t.nonce, fromNoble, t.aad)), Array.from(t.plaintext));
    }));
    assert.ok(withBackend('noble', () => {
      assert.deepEqual(Array.from(openAeadSync(t.key, t.nonce, fromNative, t.aad)), Array.from(t.plaintext));
    }));
  }
});

/** Every way an attacker can touch the inputs, one bit at a time. */
function tamperCases(t: Tuple, sealed: Uint8Array): { name: string; run: () => void }[] {
  const flip = (bytes: Uint8Array, index: number): Uint8Array => {
    const copy = bytes.slice();
    copy[index] = copy[index]! ^ 0x01;
    return copy;
  };
  const cases: { name: string; run: () => void }[] = [
    // First ciphertext byte, last ciphertext byte, and inside the tag.
    { name: 'ciphertext head', run: () => openAeadSync(t.key, t.nonce, flip(sealed, 0), t.aad) },
    { name: 'ciphertext tail', run: () => openAeadSync(t.key, t.nonce, flip(sealed, sealed.length - AEAD_TAG_LEN - 1 < 0 ? 0 : sealed.length - AEAD_TAG_LEN - 1), t.aad) },
    { name: 'tag', run: () => openAeadSync(t.key, t.nonce, flip(sealed, sealed.length - 1), t.aad) },
    // Nonce bits in both halves: the first 16 bytes go through HChaCha20 and
    // the last 8 go to the inner cipher, so a bug could easily catch one and
    // ignore the other.
    { name: 'nonce prefix', run: () => openAeadSync(t.key, flip(t.nonce, 0), sealed, t.aad) },
    { name: 'nonce suffix', run: () => openAeadSync(t.key, flip(t.nonce, AEAD_NONCE_LEN - 1), sealed, t.aad) },
    { name: 'key', run: () => openAeadSync(flip(t.key, 0), t.nonce, sealed, t.aad) },
    { name: 'truncated', run: () => openAeadSync(t.key, t.nonce, sealed.subarray(0, sealed.length - 1), t.aad) },
    { name: 'extended', run: () => openAeadSync(t.key, t.nonce, new Uint8Array([...sealed, 0]), t.aad) },
  ];
  if (t.aad.length > 0) {
    cases.push({ name: 'aad', run: () => openAeadSync(t.key, t.nonce, sealed, flip(t.aad, 0)) });
  } else {
    // With no aad to flip, adding one is the equivalent tamper.
    cases.push({ name: 'aad added', run: () => openAeadSync(t.key, t.nonce, sealed, new Uint8Array([9])) });
  }
  return cases;
}

function assertFailsClosed(name: string, run: () => void, backend: string): void {
  let threw = false;
  try {
    run();
  } catch (error) {
    threw = true;
    assert.ok(isCryptoFailure(error), `${backend}: ${name} threw a raw error, not a CryptoFailureError`);
    assert.equal((error as { reason: string }).reason, 'authentication_failed', `${backend}: ${name}`);
  }
  assert.ok(threw, `${backend}: tampered ${name} was accepted`);
}

test('a flipped bit fails closed on the automatic backend', () => {
  // Non empty plaintext and aad on purpose, plus one empty-plaintext tuple, so
  // the tamper set covers both.
  const sample = [...CORPUS.slice(0, 30), ...CORPUS.filter((t) => t.plaintext.length === 0).slice(0, 3)];
  for (const t of sample) {
    const sealed = sealAeadSync(t.key, t.nonce, t.plaintext, t.aad);
    for (const c of tamperCases(t, sealed)) {
      assertFailsClosed(c.name, c.run, aeadBackend());
    }
  }
});

test('a flipped bit fails closed on both backends explicitly', () => {
  const sample = CORPUS.slice(0, 12);
  for (const backend of ['noble', 'native'] as const) {
    if (backend === 'native' && !NATIVE_AVAILABLE) continue;
    const ran = withBackend(backend, () => {
      for (const t of sample) {
        const sealed = sealAeadSync(t.key, t.nonce, t.plaintext, t.aad);
        for (const c of tamperCases(t, sealed)) assertFailsClosed(c.name, c.run, backend);
      }
    });
    assert.ok(ran, `could not pin backend ${backend}`);
  }
});

test('malformed key and nonce lengths are rejected, not silently padded', () => {
  const key = randomBuf(AEAD_KEY_LEN);
  const nonce = randomBuf(AEAD_NONCE_LEN);
  for (const badKey of [randomBuf(31), randomBuf(33), new Uint8Array(0)]) {
    assert.throws(() => sealAeadSync(badKey, nonce, new Uint8Array(4)));
  }
  // 12 is no longer here: since 0.4.0 it is the RFC 8439 nonce the ratchet
  // actually uses, and the 24 byte form is kept only for callers that still
  // want an extended nonce. Both are legal, everything either side is not.
  for (const badNonce of [randomBuf(11), randomBuf(13), randomBuf(23), randomBuf(25)]) {
    assert.throws(() => sealAeadSync(key, badNonce, new Uint8Array(4)));
  }
});

test('aeadBackend reports honestly', async () => {
  await aeadReady();

  // Forced noble must report noble on every runtime, with no exceptions.
  assert.equal(forceAeadBackend('noble'), 'noble');
  assert.equal(aeadBackend(), 'noble');

  // Forcing native cannot conjure one. The return value is the truth, and it
  // has to agree with what the getter says afterwards.
  const forcedNative = forceAeadBackend('native');
  assert.equal(aeadBackend(), forcedNative);
  assert.equal(forcedNative, NATIVE_AVAILABLE ? 'native' : 'noble');

  assert.equal(forceAeadBackend('auto'), NATIVE_AVAILABLE ? 'native' : 'noble');
  assert.ok(aeadBackend() === 'native' || aeadBackend() === 'noble');
});

test('the async API agrees with the sync API', async () => {
  for (const t of CORPUS.slice(0, 25)) {
    const sealed = await sealAead(t.key, t.nonce, t.plaintext, t.aad);
    assert.deepEqual(Array.from(sealed), Array.from(sealAeadSync(t.key, t.nonce, t.plaintext, t.aad)));
    assert.deepEqual(Array.from(await openAead(t.key, t.nonce, sealed, t.aad)), Array.from(t.plaintext));
  }
  // assert.rejects is not in the local ambient declarations for node:assert,
  // and @types/node is deliberately absent, so the rejection is unwrapped here
  // by hand rather than by widening that file.
  const t = CORPUS[0]!;
  const sealed = await sealAead(t.key, t.nonce, t.plaintext, t.aad);
  sealed[sealed.length - 1] = sealed[sealed.length - 1]! ^ 0x01;
  let rejected = false;
  try {
    await openAead(t.key, t.nonce, sealed, t.aad);
  } catch (error) {
    rejected = true;
    assert.ok(isCryptoFailure(error));
  }
  assert.ok(rejected, 'openAead resolved on a tampered tag');
});
