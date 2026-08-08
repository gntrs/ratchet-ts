/**
 * HMAC-SHA256, HMAC-SHA512 and HKDF-SHA256 with an optional native fast path.
 *
 * Same contract as src/aead.ts and src/curves.ts, for the same reason: this
 * file exists to make the key schedule faster and to change nothing else. Every
 * derived key in this library comes out of here, so a single differing byte is
 * not a slow peer, it is a peer that can no longer decrypt anything. "native"
 * is therefore a performance decision and never a protocol decision, and the
 * native path is probed against the JavaScript path before it is trusted with a
 * real chain key.
 *
 * WHY THIS FILE EXISTS AT ALL. A profile of one 200 byte `seal` put kdfChain at
 * 18.3 us of 51.7 us, which is 35%, and on `open` at 19.4 us of 48.8 us. That is
 * the single largest line item in both directions, in a build that was already
 * shipping a native AEAD and a native curve. Two @noble HMAC-SHA256 calls are
 * pure JavaScript SHA-256 compression; node:crypto hands the same two calls to
 * OpenSSL, which on this machine costs about 5.5 us less per direction.
 *
 * WHAT CHANGED IN 0.4.0. The paragraph that used to sit here said kdfChain
 * performs exactly two HMAC-SHA256 invocations and that collapsing them into one
 * HMAC-SHA512 split into halves "belongs to a breaking release". This is that
 * breaking release, so `hmacSha512` now lives beside `hmacSha256` and src/kdf.ts
 * calls it once per chain step instead of calling HMAC-SHA256 twice. The
 * argument for why one PRF is not a weakening is in kdf.ts, next to the code it
 * justifies.
 *
 * The two digests share one resolved backend and one probe. A runtime whose
 * node:crypto has SHA-256 but not SHA-512 therefore loses the fast path for
 * both rather than getting a half-native key schedule, which is the safer of
 * the two failure modes: the fallback is @noble, which is correct everywhere,
 * and a partially native probe result is a thing nobody would think to look at
 * when the numbers came out wrong.
 *
 * Portability rule, inherited verbatim from aead.ts and equally non negotiable:
 * src/ contains no static `node:` import. Reaching node:crypto happens lazily,
 * inside try/catch, at most once, and any failure whatsoever lands silently on
 * the @noble backend. A browser must reach the JavaScript path with no thrown
 * error and nothing printed to the console.
 */

import { hmac } from '@noble/hashes/hmac.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { expand, extract } from '@noble/hashes/hkdf.js';
import { randomBytes as nobleRandomBytes } from '@noble/hashes/utils.js';

/** Algorithm names as node:crypto spells them. */
const NATIVE_HMAC_ALGORITHM = 'sha256';
const NATIVE_HMAC512_ALGORITHM = 'sha512';
const NATIVE_HKDF_DIGEST = 'sha256';

/**
 * Which HMAC-SHA256 implementation is doing the work.
 *
 * Mirrors `AeadBackend` in the type contract and `CurveBackend` in curves.ts,
 * and means the same thing: the two backends are selected automatically and
 * produce identical output for every input, so this is reporting rather than
 * configuration.
 *
 * Declared here rather than in types.ts for the reason curves.ts gives: no
 * consumer of the public API can currently observe the hash backend. If
 * `hashBackend()` is ever re-exported from src/index.ts, this type belongs
 * beside `AeadBackend` and should move there rather than being duplicated.
 */
export type HashBackend = 'native' | 'noble';

// ---------------------------------------------------------------------------
// Probe vectors
// ---------------------------------------------------------------------------

/** Local hex reader, for the reason curves.ts gives: bytes.ts has `toHex` and
 * no inverse, and the published vectors below are only auditable written out as
 * hex. */
function fromHex(text: string): Uint8Array {
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function repeated(byte: number, length: number): Uint8Array {
  return new Uint8Array(length).fill(byte);
}

const EMPTY = new Uint8Array(0);

/**
 * Key and message shapes an HMAC implementation can disagree on.
 *
 * The 65 byte key is the one that earns its place. HMAC hashes any key longer
 * than the 64 byte block down to 32 bytes before padding it, and the boundary
 * between "pad this key" and "hash this key first" is where implementations
 * historically diverge. 64 bytes exactly is the other half of that boundary.
 * Empty key and empty message are here because a zero length input is the case
 * a wrapper is most likely to special-case into oblivion, and because
 * MESSAGE_KEY_CONSTANT in kdf.ts is one byte long, which is close enough to
 * that edge to be worth pinning.
 */
const PROBE_HMAC_CASES: readonly { readonly key: Uint8Array; readonly message: Uint8Array }[] = [
  { key: EMPTY, message: EMPTY },
  { key: EMPTY, message: Uint8Array.of(0x01) },
  { key: repeated(0x2b, 32), message: EMPTY },
  // The real case: a 32 byte chain key under the two kdfChain constants.
  { key: repeated(0x2b, 32), message: Uint8Array.of(0x01) },
  { key: repeated(0x2b, 32), message: Uint8Array.of(0x02) },
  { key: repeated(0x5c, 64), message: Uint8Array.of(0x01) },
  { key: repeated(0x36, 65), message: Uint8Array.of(0x01) },
  { key: repeated(0x36, 200), message: repeated(0xa5, 300) },
];

/**
 * RFC 4231 section 4, the published HMAC-SHA-256 test cases.
 *
 * Cases 1, 2, 3, 4, 6 and 7. Case 5 is omitted on purpose: the RFC publishes
 * only its 128 bit truncation, so pinning a full digest for it would be pinning
 * a number this project computed rather than one the RFC did, which is the
 * opposite of what a published vector is for.
 *
 * These are checked against @noble as well as against the native path, so a
 * transcription error here fails the probe rather than silently weakening it.
 */
const RFC4231: readonly { readonly key: string; readonly data: string; readonly mac: string }[] = [
  {
    key: '0b'.repeat(20),
    data: '4869205468657265',
    mac: 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
  },
  {
    key: '4a656665',
    data: '7768617420646f2079612077616e7420666f72206e6f7468696e673f',
    mac: '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
  },
  {
    key: 'aa'.repeat(20),
    data: 'dd'.repeat(50),
    mac: '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',
  },
  {
    key: '0102030405060708090a0b0c0d0e0f10111213141516171819',
    data: 'cd'.repeat(50),
    mac: '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b',
  },
  // Case 6 and case 7: a 131 byte key, which is the key-hashing branch again,
  // this time at a size no ordinary caller would ever produce by accident.
  {
    key: 'aa'.repeat(131),
    data:
      '54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a' +
      '65204b6579202d2048617368204b6579204669727374',
    mac: '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
  },
  {
    key: 'aa'.repeat(131),
    data:
      '5468697320697320612074657374207573696e672061206c6172676572207468' +
      '616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074' +
      '68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565' +
      '647320746f20626520686173686564206265666f7265206265696e6720757365' +
      '642062792074686520484d414320616c676f726974686d2e',
    mac: '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2',
  },
];

/**
 * The same idea for SHA-512, moved to that digest's own boundaries.
 *
 * SHA-512 has a 128 byte block, not 64, so the "pad the key" against "hash the
 * key first" split that PROBE_HMAC_CASES probes at 64/65 lives at 128/129 here.
 * A wrapper that hard coded 64 would agree with @noble on every ordinary key
 * and diverge only in this band, which is why the band is what gets looked at.
 *
 * The 32 byte key with a one byte message is the real case: that is exactly what
 * kdfChain asks for on every single message in both directions.
 */
const PROBE_HMAC512_CASES: readonly { readonly key: Uint8Array; readonly message: Uint8Array }[] = [
  { key: EMPTY, message: EMPTY },
  { key: repeated(0x2b, 32), message: Uint8Array.of(0x01) },
  { key: repeated(0x2b, 32), message: EMPTY },
  { key: repeated(0x5c, 128), message: Uint8Array.of(0x01) },
  { key: repeated(0x36, 129), message: Uint8Array.of(0x01) },
  { key: repeated(0x36, 200), message: repeated(0xa5, 300) },
];

/**
 * RFC 4231 section 4 again, the HMAC-SHA-512 half.
 *
 * Cases 1, 2, 3, 4 and 6. Case 5 is omitted for the reason the SHA-256 list
 * gives, that the RFC publishes only its truncation. Case 7 is omitted because
 * its data block could not be transcribed from the RFC with the same confidence
 * as the rest, and a vector this file cannot vouch for is worse than no vector:
 * it would look like an independent check while actually pinning a number this
 * project computed for itself. The 200 byte key and 300 byte message in
 * PROBE_HMAC512_CASES already exercise the long key and long data path against
 * @noble, which is what case 7 is for.
 *
 * These are checked against @noble as well as against the candidate, so a
 * transcription error fails the probe rather than silently weakening it.
 */
const RFC4231_SHA512: readonly { readonly key: string; readonly data: string; readonly mac: string }[] = [
  {
    key: '0b'.repeat(20),
    data: '4869205468657265',
    mac:
      '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde' +
      'daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
  },
  {
    key: '4a656665',
    data: '7768617420646f2079612077616e7420666f72206e6f7468696e673f',
    mac:
      '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554' +
      '9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
  },
  {
    key: 'aa'.repeat(20),
    data: 'dd'.repeat(50),
    mac:
      'fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39' +
      'bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb',
  },
  {
    key: '0102030405060708090a0b0c0d0e0f10111213141516171819',
    data: 'cd'.repeat(50),
    mac:
      'b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db' +
      'a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd',
  },
  {
    key: 'aa'.repeat(131),
    data:
      '54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a' +
      '65204b6579202d2048617368204b6579204669727374',
    mac:
      '80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352' +
      '6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598',
  },
];

/**
 * HKDF shapes. The first two are exactly what kdfRoot and kdfHandshake ask for,
 * including their output lengths, because an expand that is correct at 32 bytes
 * and wrong at 64 is a plausible bug and 64 is what the root ratchet uses. The
 * rest are the degenerate salt and info cases, where RFC 5869 says an absent
 * salt means a block of zeroes and a wrapper is free to get that wrong.
 */
const PROBE_HKDF_CASES: readonly {
  readonly ikm: Uint8Array;
  readonly salt: Uint8Array;
  readonly info: Uint8Array;
  readonly length: number;
}[] = [
  { ikm: repeated(0x11, 32), salt: repeated(0x22, 32), info: repeated(0x33, 20), length: 64 },
  { ikm: repeated(0x11, 96), salt: repeated(0x22, 24), info: repeated(0x33, 36), length: 32 },
  { ikm: repeated(0x11, 32), salt: EMPTY, info: EMPTY, length: 32 },
  { ikm: EMPTY, salt: repeated(0x22, 32), info: EMPTY, length: 42 },
  // 255 blocks is the last legal output length for HKDF-SHA256. One more is an
  // error on both backends, which `probeRejects` below pins.
  { ikm: repeated(0x11, 32), salt: repeated(0x22, 32), info: EMPTY, length: 32 * 255 },
];

/** RFC 5869 appendix A, the SHA-256 cases. Case 1 is the ordinary one, case 3
 * is the zero length salt and info. Case 2 is omitted only because its 80 byte
 * inputs add nothing the shapes above do not already cover. */
const RFC5869: readonly {
  readonly ikm: string;
  readonly salt: string;
  readonly info: string;
  readonly length: number;
  readonly okm: string;
}[] = [
  {
    ikm: '0b'.repeat(22),
    salt: '000102030405060708090a0b0c',
    info: 'f0f1f2f3f4f5f6f7f8f9',
    length: 42,
    okm: '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
  },
  {
    ikm: '0b'.repeat(22),
    salt: '',
    info: '',
    length: 42,
    okm: '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
  },
];

// ---------------------------------------------------------------------------
// Native backend resolution
// ---------------------------------------------------------------------------

/** Opaque to us. node:crypto hands one back from createHmac and the only things
 * we do to it are feed it the message and ask for the digest. */
interface NativeHmac {
  update(data: Uint8Array): unknown;
  digest(): Uint8Array;
}

interface NativeCryptoLike {
  createHmac(algorithm: string, key: Uint8Array): NativeHmac;
  hkdfSync(digest: string, ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, keylen: number): ArrayBuffer;
  /**
   * Optional on purpose. `looksUsable` does not require it, because demanding
   * it would demote a runtime that has `createHmac` and `hkdfSync` but not this
   * off the native path for all three, trading 5.5 us to save 0.8.
   */
  randomFillSync?(buffer: Uint8Array): Uint8Array;
}

let resolved: NativeCryptoLike | null = null;
let syncProbeDone = false;
let asyncProbeDone = false;
let readyPromise: Promise<void> | null = null;
let override: HashBackend | 'auto' = 'auto';

function looksUsable(mod: unknown): mod is NativeCryptoLike {
  if (typeof mod !== 'object' || mod === null) return false;
  const candidate = mod as Partial<NativeCryptoLike>;
  return typeof candidate.createHmac === 'function' && typeof candidate.hkdfSync === 'function';
}

/** A plain loop, not `equal` from bytes.ts, for the reason aead.ts gives: this
 * is a self test against a value we generated, not a secret comparison, and it
 * must not depend on a module whose own behaviour is under test elsewhere. */
function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]!) return false;
  return true;
}

/**
 * A runtime can ship node:crypto, accept the algorithm name "sha256", and still
 * be wrong. The failure modes that matter are a shim whose HMAC skips the key
 * hashing branch for keys over one block, a shim that treats a zero length key
 * as an error or as a different key, and an hkdfSync that reads the salt and
 * info arguments in the other order. Each of those agrees with @noble on the
 * ordinary 32 byte case and diverges only where the cases above look, which is
 * exactly why the cases above look there.
 *
 * The published RFC vectors are checked against @noble too, not only against
 * the candidate. If a future @noble ever disagreed with the RFC, the honest
 * result is to fall back to @noble anyway, because @noble is what produced
 * every key already sitting in every persisted session.
 */
function probe(mod: NativeCryptoLike): boolean {
  for (const testCase of PROBE_HMAC_CASES) {
    const expected = hmac(sha256, testCase.key, testCase.message);
    const actual = nativeHmacSha256(mod, testCase.key, testCase.message);
    if (actual === null || !sameBytes(actual, expected)) return false;
  }

  for (const vector of RFC4231) {
    const key = fromHex(vector.key);
    const data = fromHex(vector.data);
    const mac = fromHex(vector.mac);
    if (!sameBytes(hmac(sha256, key, data), mac)) return false;
    const actual = nativeHmacSha256(mod, key, data);
    if (actual === null || !sameBytes(actual, mac)) return false;
  }

  for (const testCase of PROBE_HMAC512_CASES) {
    const expected = hmac(sha512, testCase.key, testCase.message);
    const actual = nativeHmacSha512(mod, testCase.key, testCase.message);
    if (actual === null || !sameBytes(actual, expected)) return false;
  }

  for (const vector of RFC4231_SHA512) {
    const key = fromHex(vector.key);
    const data = fromHex(vector.data);
    const mac = fromHex(vector.mac);
    if (!sameBytes(hmac(sha512, key, data), mac)) return false;
    const actual = nativeHmacSha512(mod, key, data);
    if (actual === null || !sameBytes(actual, mac)) return false;
  }

  for (const testCase of PROBE_HKDF_CASES) {
    const expected = nobleHkdfSha256(testCase.ikm, testCase.salt, testCase.info, testCase.length);
    const actual = nativeHkdfSha256(mod, testCase.ikm, testCase.salt, testCase.info, testCase.length);
    if (actual === null || !sameBytes(actual, expected)) return false;
  }

  for (const vector of RFC5869) {
    const ikm = fromHex(vector.ikm);
    const salt = fromHex(vector.salt);
    const info = fromHex(vector.info);
    const okm = fromHex(vector.okm);
    if (!sameBytes(nobleHkdfSha256(ikm, salt, info, vector.length), okm)) return false;
    const actual = nativeHkdfSha256(mod, ikm, salt, info, vector.length);
    if (actual === null || !sameBytes(actual, okm)) return false;
  }

  // An output length past 255 blocks is undefined in RFC 5869 and rejected by
  // @noble. A candidate that answers anyway would be inventing key material,
  // and would do it silently, since the wrapper only falls back when the native
  // path declines. Requiring it to decline is what keeps the fallback honest.
  if (nativeHkdfSha256(mod, repeated(0x11, 32), EMPTY, EMPTY, 32 * 255 + 1) !== null) return false;

  return true;
}

/**
 * Synchronous reach for node:crypto.
 *
 * `process.getBuiltinModule` is the only way to get a builtin synchronously
 * from ESM without a static import, and it has to be synchronous here because
 * kdfChain runs in the middle of a synchronous encrypt and decrypt and cannot
 * await a dynamic import. Node 20.16+, Deno 2 and recent Bun have it. Where it
 * does not exist, `resolveAsync` still gets the fast path for callers that can
 * await, and everything else quietly runs on @noble.
 *
 * In a browser `process` is undefined, the optional chain yields undefined, and
 * we return null without touching the catch. That path prints nothing.
 */
function resolveSync(): NativeCryptoLike | null {
  if (resolved !== null) return resolved;
  if (syncProbeDone) return null;
  syncProbeDone = true;
  try {
    const proc = (globalThis as { process?: { getBuiltinModule?: (id: string) => unknown } }).process;
    const mod = proc?.getBuiltinModule?.('node:crypto');
    if (looksUsable(mod) && probe(mod)) resolved = mod;
  } catch {
    // Missing module, blocked permission, a FIPS build with the digest disabled:
    // every one of them means "no native backend here", and none of them is
    // worth a console line in an application that is working fine.
  }
  return resolved;
}

/**
 * Asynchronous fallback for runtimes without `process.getBuiltinModule`.
 *
 * The specifier is assembled at runtime on purpose. A literal
 * `import('node:crypto')` is followed statically by bundlers, and a browser
 * bundle that tries to resolve node:crypto fails to build, which is exactly the
 * portability promise this file exists to keep.
 */
async function resolveAsync(): Promise<void> {
  if (resolved !== null || asyncProbeDone) return;
  asyncProbeDone = true;
  try {
    const specifier = 'node:' + 'crypto';
    const mod: unknown = await import(/* @vite-ignore */ specifier);
    if (looksUsable(mod) && probe(mod)) resolved = mod;
  } catch {
    // Same reasoning as resolveSync: silence is the correct browser behaviour.
  }
}

/**
 * Resolves the backend once and caches the result. Awaiting this is only
 * necessary on a runtime where the synchronous probe cannot work; everything in
 * this file works without it, just on @noble.
 */
export function hashReady(): Promise<void> {
  if (readyPromise === null) {
    readyPromise = (async () => {
      if (resolveSync() !== null) return;
      await resolveAsync();
    })();
  }
  return readyPromise;
}

function activeNative(): NativeCryptoLike | null {
  if (override === 'noble') return null;
  return resolveSync();
}

/** Which backend the next call will actually use. Honest by construction: it
 * asks the same function the KDF path asks, so it cannot claim a fast path that
 * a probe already rejected. */
export function hashBackend(): HashBackend {
  return activeNative() === null ? 'noble' : 'native';
}

/**
 * Test hook. Pins the backend so a suite can prove the two paths agree on the
 * same input, which is the property that lets a browser and a server share a
 * conversation.
 *
 * Returns the backend that is actually in effect afterwards, so asking for
 * 'native' on a machine that has none reports 'noble' rather than pretending.
 */
export function forceHashBackend(choice: HashBackend | 'auto'): HashBackend {
  override = choice;
  return hashBackend();
}

// ---------------------------------------------------------------------------
// The two backends
// ---------------------------------------------------------------------------

/**
 * True only for a real byte array.
 *
 * This is the error observability guard, and it is the whole of it. HMAC itself
 * cannot fail on any well formed input: there is no key or message length that
 * either backend rejects, empty included, which the probe pins. The one way the
 * two paths could be told apart is a caller that passes something that is not a
 * Uint8Array at all. @noble throws on it; node:crypto happily accepts a string
 * or a plain ArrayBuffer and hashes it under whichever encoding it guesses. So
 * a mistyped call would succeed on a server and throw in a browser, which is a
 * far worse bug than either behaviour on its own.
 *
 * Declining here sends those calls to @noble, which throws the error it has
 * always thrown, with the identical message and stack. Same resolution as
 * `nativeSharedSecret` in curves.ts reached for low order points, for the same
 * reason: the native path is never the thing that reports a failure.
 */
function isBytes(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array;
}

/**
 * Native HMAC-SHA256. Returns null rather than throwing so that every caller
 * has exactly one thing to do on failure: ask @noble instead.
 *
 * The digest is copied rather than wrapped. node hands back a Buffer, which can
 * be a window onto a shared pool, and the 32 bytes this returns are a message
 * key or a chain key that the ratchet will hold, hand to the AEAD and later
 * wipe. Copying is what keeps `wipe` zeroing memory this library owns instead
 * of a slice of somebody else's pool. It measured at roughly 0.15 us of the
 * 6.6 us call, which is not the part worth optimising.
 */
function nativeHmacSha256(mod: NativeCryptoLike, key: Uint8Array, message: Uint8Array): Uint8Array | null {
  if (!isBytes(key) || !isBytes(message)) return null;
  try {
    const mac = mod.createHmac(NATIVE_HMAC_ALGORITHM, key);
    mac.update(message);
    return Uint8Array.from(mac.digest());
  } catch {
    return null;
  }
}

/**
 * Native HMAC-SHA512, and the same contract as the SHA-256 one above: null
 * rather than a throw, so every caller has exactly one thing to do on failure.
 *
 * The digest is copied for the same reason too. This one is the chain step, so
 * its 64 bytes ARE the next chain key and the message key, and `wipe` has to be
 * zeroing memory this library owns rather than a window onto Node's Buffer pool.
 */
function nativeHmacSha512(mod: NativeCryptoLike, key: Uint8Array, message: Uint8Array): Uint8Array | null {
  if (!isBytes(key) || !isBytes(message)) return null;
  try {
    const mac = mod.createHmac(NATIVE_HMAC512_ALGORITHM, key);
    mac.update(message);
    return Uint8Array.from(mac.digest());
  } catch {
    return null;
  }
}

/**
 * Native HKDF-SHA256, extract and expand in one call.
 *
 * hkdfSync returns a freshly allocated ArrayBuffer rather than a pooled Buffer,
 * so unlike the HMAC above this one wraps instead of copying.
 */
function nativeHkdfSha256(
  mod: NativeCryptoLike,
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array | null {
  if (!isBytes(ikm) || !isBytes(salt) || !isBytes(info)) return null;
  if (!Number.isSafeInteger(length) || length < 1) return null;
  try {
    const out = new Uint8Array(mod.hkdfSync(NATIVE_HKDF_DIGEST, ikm, salt, info, length));
    // A backend that returned a short buffer would hand the caller a key that
    // is partly zeroes, so length is checked rather than assumed.
    return out.length === length ? out : null;
  } catch {
    return null;
  }
}

/** The reference implementation, and the one that has produced every key in
 * every session persisted by every release so far. */
function nobleHkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  return expand(sha256, extract(sha256, ikm, salt), info, length);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * HMAC-SHA256. Byte identical on both backends for every key and message
 * length, including empty keys, empty messages, and keys either side of the
 * 64 byte block boundary.
 *
 * The key belongs to the caller and is neither modified nor wiped.
 */
export function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
  const native = activeNative();
  if (native !== null) {
    const mac = nativeHmacSha256(native, key, message);
    if (mac !== null) return mac;
  }
  return hmac(sha256, key, message);
}

/**
 * HMAC-SHA512. Byte identical on both backends for every key and message
 * length, including empty keys, empty messages, and keys either side of the
 * 128 byte block boundary.
 *
 * The key belongs to the caller and is neither modified nor wiped. The 64 bytes
 * that come back are secret key material in every current call site: wipe them.
 */
export function hmacSha512(key: Uint8Array, message: Uint8Array): Uint8Array {
  const native = activeNative();
  if (native !== null) {
    const mac = nativeHmacSha512(native, key, message);
    if (mac !== null) return mac;
  }
  return hmac(sha512, key, message);
}

/**
 * HKDF-SHA256 as RFC 5869 defines it: extract with `salt` as the HMAC key, then
 * expand under `info` to `length` bytes.
 *
 * Argument order follows the RFC and node:crypto rather than @noble's
 * `extract(hash, ikm, salt)`, so the salt cannot quietly swap places with the
 * input keying material when a call site is edited.
 */
export function hkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const native = activeNative();
  if (native !== null) {
    const okm = nativeHkdfSha256(native, ikm, salt, info, length);
    if (okm !== null) return okm;
  }
  return nobleHkdfSha256(ikm, salt, info, length);
}

/**
 * Fill `out` with cryptographic randomness, natively where node:crypto is here.
 *
 * THIS ONE IS NOT PROBED, AND THE REASON MATTERS. Every other native path in
 * this file earns its place by producing bytes identical to the JavaScript one
 * on a fixed corpus. A CSPRNG has no known answer, so there is nothing to
 * compare against and the only check available is a shape check: the method
 * exists and it returned as many bytes as we asked for. That is a weaker
 * guarantee than the rest of the file offers and it should not be mistaken for
 * the same discipline.
 *
 * It is acceptable here for two reasons. Both paths bottom out in the same
 * platform entropy source one level down, `@noble/hashes` calling
 * `crypto.getRandomValues` and node calling its own CSPRNG, so this is a
 * wrapper choice rather than an entropy choice. And a wrong answer here is not
 * a wire incompatibility that surfaces months later on somebody else's machine:
 * a nonce of the wrong length is refused by the encoder immediately.
 *
 * Worth 0.81 us per seal at 12 bytes, measured, which is about a third of what
 * carrying a random nonce costs at all.
 */
export function fillRandom(out: Uint8Array): Uint8Array {
  const native = activeNative();
  if (native !== null && typeof native.randomFillSync === 'function') {
    const filled = native.randomFillSync(out);
    if (filled.length === out.length) return out;
  }
  out.set(nobleRandomBytes(out.length));
  return out;
}
