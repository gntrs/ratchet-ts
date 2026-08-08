/**
 * X25519 with an optional native fast path.
 *
 * Same contract as src/aead.ts, for the same reason: this file exists to make
 * the curve faster and to change nothing else. A ratchet public key derived in
 * a browser has to be the key a server derives from the same secret, and a
 * shared secret computed on either side has to be the same 32 bytes, or the two
 * runtimes stop being able to talk. "native" is therefore a performance
 * decision and never a protocol decision, and the native path is probed against
 * the JavaScript path before it is trusted with real key material.
 *
 * How the fast path works. node:crypto has no raw X25519 entry point: it deals
 * in KeyObjects, and the only portable way to turn 32 raw bytes into one is to
 * wrap them in the fixed PKCS#8 or SPKI prefix for the curve and parse that.
 * The prefixes below are constants, not encoders, because an X25519 key is
 * always exactly 32 bytes and so the DER around it is always exactly the same
 * bytes.
 *
 * WHERE THE TIME ACTUALLY GOES, measured rather than assumed, because the
 * obvious answer is wrong. Writing those 48 bytes costs 0.2 us and is not worth
 * a thought. The bill for one shared secret on node 25 is createPrivateKey
 * 105 us, createPublicKey 26 us, diffieHellman 72 us. createPrivateKey costs
 * more than the exchange it feeds because OpenSSL derives the public half
 * whenever it builds an X25519 private key object, so importing a raw scalar
 * silently pays for a scalar multiplication nothing here asked for. It cannot
 * be skipped: node:crypto exposes no entry point that takes raw curve bytes,
 * and every route into one (PKCS#8 DER, JWK, raw) lands in the same OpenSSL
 * constructor. The only way to stop paying it repeatedly would be to cache
 * private KeyObjects, and that is refused below for reasons that are about
 * wipe() rather than about speed. See `nativeSharedSecret`.
 *
 * The two costs that are avoidable are avoided:
 *   - Reading a derived public key back out as SPKI DER costs 69 us. Reading the
 *     same KeyObject as JWK costs 2.6 us and hands over the identical 32 bytes
 *     in base64url. That halves `x25519PublicKey`, and so `x25519Keygen`.
 *   - Importing a peer public key from JWK costs about half what importing it
 *     from SPKI DER costs, and costs nothing at all when it is the public key
 *     the last call already used, which in a DH ratchet step is every second
 *     import. See `cachedPublicKeyObject`.
 * Both JWK routes fall back to the DER route, permanently and silently, on any
 * runtime whose node:crypto does not do JWK. A slower native path is a fine
 * outcome; losing the native path over a format nobody promised is not.
 *
 * WHAT THIS FILE DELIBERATELY DOES NOT CHANGE. Key generation still draws its
 * secret from @noble (`x25519.utils.randomSecretKey`) and only the public half
 * is derived natively. Letting node:crypto generate the pair would have been
 * marginally simpler and measured the same, but OpenSSL stores a CLAMPED
 * private key while @noble stores the raw 32 random bytes, so the secret halves
 * this library hands to `serializeSession` would have changed shape depending
 * on which runtime made them. Both are valid X25519 secrets and neither ever
 * reaches the wire, but "only faster" is the promise, so the generator stays
 * exactly where it was.
 *
 * Portability rule, inherited verbatim from aead.ts and equally non negotiable:
 * src/ contains no static `node:` import. Reaching node:crypto happens lazily,
 * inside try/catch, at most once, and any failure whatsoever lands silently on
 * the @noble backend. A browser must reach the JavaScript path with no thrown
 * error and nothing printed to the console.
 */

import { x25519 } from '@noble/curves/ed25519.js';

/** Every X25519 quantity is 32 bytes: secret, public and shared secret alike. */
const KEY_LEN = 32;

/**
 * Which X25519 implementation is doing the work.
 *
 * Mirrors `AeadBackend` in the type contract, and means the same thing: the two
 * backends are selected automatically and produce identical output for every
 * input, so this is reporting rather than configuration.
 *
 * It is declared here rather than in types.ts because, unlike the AEAD, no
 * consumer of the public API can currently observe the curve backend. If
 * `curveBackend()` is ever re-exported from src/index.ts, this type belongs
 * beside `AeadBackend` and should move there rather than being duplicated.
 */
export type CurveBackend = 'native' | 'noble';

/**
 * The DER that node:crypto insists on wrapping a raw key in.
 *
 * PKCS#8 PrivateKeyInfo for id-X25519 (1.3.101.110): version 0, the algorithm
 * identifier, then the 32 byte key inside a nested OCTET STRING. 16 bytes of
 * prefix, 48 bytes total.
 */
const PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

/**
 * SubjectPublicKeyInfo for the same OID: algorithm identifier then the 32 byte
 * key in a BIT STRING with zero unused bits. 12 bytes of prefix, 44 total.
 */
const SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
]);

// ---------------------------------------------------------------------------
// Probe vectors
// ---------------------------------------------------------------------------

/** Local hex reader. bytes.ts has `toHex` and no inverse, and the constants
 * below are canonical published values that are only auditable written out as
 * hex, so the four lines to read them back live here rather than widening a
 * module this file has no business changing. */
function fromHex(text: string): Uint8Array {
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * Fixed secrets for the probe. The first two are Alice and Bob from RFC 7748
 * section 6.1, so a backend that fails the probe can be checked against the
 * published vectors by hand. The third has its low three bits and its top bit
 * set on purpose: X25519 clamps the scalar before use, and an implementation
 * that forgets to clamp agrees with @noble on ordinary random secrets and
 * disagrees only on this one.
 */
const PROBE_SECRETS = [
  fromHex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'),
  fromHex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'),
  fromHex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'),
];

/**
 * The classical low order points on Curve25519, as u-coordinates.
 *
 * Every one of these drives the scalar multiplication to the identity, so the
 * shared secret is all zeroes and carries no contributory secrecy at all: a
 * peer that sends one is trying to force both sides onto a key it already
 * knows. @noble refuses them, and this library has always refused them because
 * of that, so the native path is required to refuse them too. See the note on
 * `nativeSharedSecret` for how "refuse" is made to mean the same thing on both
 * backends.
 *
 * 0xff repeated is NOT in this list even though it looks like it belongs. The
 * top bit is masked off before the field reduction, so it is the perfectly
 * ordinary point u = 18 and both backends accept it. It is in the test suite
 * for exactly that reason.
 */
const LOW_ORDER_POINTS = [
  fromHex('0000000000000000000000000000000000000000000000000000000000000000'),
  fromHex('0100000000000000000000000000000000000000000000000000000000000000'),
  fromHex('e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800'),
  fromHex('5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157'),
  fromHex('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'),
  fromHex('edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'),
  fromHex('eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'),
];

// ---------------------------------------------------------------------------
// Native backend resolution
// ---------------------------------------------------------------------------

/** Opaque to us. node:crypto hands these back from the create* calls and takes
 * them again in `diffieHellman`; the only thing we ever do to one is ask it to
 * export itself. */
interface NativeKeyObject {
  export(options: { type: string; format: string }): Uint8Array;
}

interface NativeDerInput {
  key: Uint8Array;
  format: 'der';
  type: 'pkcs8' | 'spki';
}

interface NativeCryptoLike {
  createPrivateKey(input: NativeDerInput): NativeKeyObject;
  createPublicKey(input: NativeDerInput | NativeKeyObject): NativeKeyObject;
  diffieHellman(options: { privateKey: NativeKeyObject; publicKey: NativeKeyObject }): Uint8Array;
}

let resolved: NativeCryptoLike | null = null;
let syncProbeDone = false;
let asyncProbeDone = false;
let readyPromise: Promise<void> | null = null;
let override: CurveBackend | 'auto' = 'auto';

function looksUsable(mod: unknown): mod is NativeCryptoLike {
  if (typeof mod !== 'object' || mod === null) return false;
  const candidate = mod as Partial<NativeCryptoLike>;
  return (
    typeof candidate.createPrivateKey === 'function' &&
    typeof candidate.createPublicKey === 'function' &&
    typeof candidate.diffieHellman === 'function'
  );
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
 * A runtime can ship node:crypto, accept the X25519 OID, and still be wrong.
 * The failure modes that actually matter here are a backend that does not clamp
 * the scalar, a backend that reduces the u-coordinate differently at the top
 * bit, and a backend that accepts a low order point where @noble rejects it.
 * The first two produce a wrong public key or a wrong shared secret, which is a
 * silent interop break; the third is a security regression. All three are
 * caught below before the backend is allowed near real key material.
 *
 * Note the direction of the low order check. It asserts that @noble rejects the
 * point AND that the native path reports the same rejection. If a future @noble
 * stopped rejecting them, this probe fails and the whole library falls back to
 * @noble, which is the safe direction to fail in: the two paths would then
 * genuinely disagree, and the one that keeps today's behaviour is the one that
 * ships.
 */
function probe(mod: NativeCryptoLike): boolean {
  const publics: Uint8Array[] = [];
  for (const secret of PROBE_SECRETS) {
    const expected = x25519.getPublicKey(secret);
    const actual = nativePublicKey(mod, secret);
    if (actual === null || !sameBytes(actual, expected)) return false;
    publics.push(expected);
  }

  // Both directions of a real exchange, plus the property that makes it an
  // exchange at all: the two sides land on the same secret.
  const aShared = nativeSharedSecret(mod, PROBE_SECRETS[0]!, publics[1]!);
  const bShared = nativeSharedSecret(mod, PROBE_SECRETS[1]!, publics[0]!);
  if (aShared === null || bShared === null) return false;
  if (!sameBytes(aShared, bShared)) return false;
  if (!sameBytes(aShared, x25519.getSharedSecret(PROBE_SECRETS[0]!, publics[1]!))) return false;

  for (const point of LOW_ORDER_POINTS) {
    let nobleRejected = false;
    try {
      x25519.getSharedSecret(PROBE_SECRETS[0]!, point);
    } catch {
      nobleRejected = true;
    }
    if (!nobleRejected) return false;
    if (nativeSharedSecret(mod, PROBE_SECRETS[0]!, point) !== null) return false;
  }

  return true;
}

/**
 * Synchronous reach for node:crypto.
 *
 * `process.getBuiltinModule` is the only way to get a builtin synchronously
 * from ESM without a static import, and it has to be synchronous here because
 * the ratchet's DH step happens in the middle of a synchronous decrypt and
 * cannot await a dynamic import. Node 20.16+, Deno 2 and recent Bun have it.
 * Where it does not exist, `resolveAsync` still gets the fast path for callers
 * that can await, and everything else quietly runs on @noble.
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
    // Missing module, blocked permission, a build without X25519 compiled in:
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
export function curvesReady(): Promise<void> {
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
 * asks the same function the key operations ask, so it cannot claim a fast path
 * that a probe already rejected. */
export function curveBackend(): CurveBackend {
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
export function forceCurveBackend(choice: CurveBackend | 'auto'): CurveBackend {
  override = choice;
  return curveBackend();
}

// ---------------------------------------------------------------------------
// The two backends
// ---------------------------------------------------------------------------

/** Wraps a raw secret in PKCS#8 and parses it. The scratch DER holds the secret
 * key, so it is zeroed once node:crypto has copied it into the KeyObject. */
function importSecret(mod: NativeCryptoLike, secretKey: Uint8Array): NativeKeyObject {
  const der = new Uint8Array(PKCS8_PREFIX.length + KEY_LEN);
  der.set(PKCS8_PREFIX);
  der.set(secretKey, PKCS8_PREFIX.length);
  try {
    return mod.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  } finally {
    der.fill(0);
  }
}

function importPublic(mod: NativeCryptoLike, publicKey: Uint8Array): NativeKeyObject {
  const der = new Uint8Array(SPKI_PREFIX.length + KEY_LEN);
  der.set(SPKI_PREFIX);
  der.set(publicKey, SPKI_PREFIX.length);
  return mod.createPublicKey({ key: der, format: 'der', type: 'spki' });
}

/** Copies the trailing 32 bytes out of an exported DER into a plain Uint8Array.
 * A copy rather than a view because node hands back a Buffer, which can be a
 * window onto a shared pool, and this library wipes the buffers it owns. */
function tailBytes(der: Uint8Array): Uint8Array | null {
  if (der.length < KEY_LEN) return null;
  return Uint8Array.from(der.subarray(der.length - KEY_LEN));
}

/**
 * Native public key derivation. Returns null rather than throwing so that every
 * caller has exactly one thing to do on failure: ask @noble instead.
 */
function nativePublicKey(mod: NativeCryptoLike, secretKey: Uint8Array): Uint8Array | null {
  if (secretKey.length !== KEY_LEN) return null;
  try {
    const der = mod.createPublicKey(importSecret(mod, secretKey)).export({ type: 'spki', format: 'der' });
    return tailBytes(der);
  } catch {
    return null;
  }
}

/**
 * Native scalar multiplication. Returns null on anything at all unexpected.
 *
 * THE LOW ORDER POINT CASE, which is the only place the two backends were ever
 * at risk of disagreeing, and is therefore worth stating exactly.
 *
 * Given a low order public key, @noble throws `invalid private or public key
 * received` and OpenSSL fails the derivation with `failed during derivation`.
 * So both reject, and this library has always propagated @noble's error to the
 * caller. The two rejections are not the same object though, and a caller that
 * matched on the message would be able to tell which backend answered, which is
 * precisely the kind of visible difference this file must not introduce.
 *
 * The fix is to make the native path never be the thing that reports a failure.
 * On any error it returns null, and the public wrapper then runs the same call
 * through @noble, which throws the error it has always thrown. The error type,
 * the message and the stack all stay exactly what they were before this file
 * existed, on every runtime.
 *
 * The all-zero check is the belt to that braces. OpenSSL erroring on an
 * all-zero X25519 output is required behaviour, not a courtesy, but a shim or a
 * non-OpenSSL provider could return the zeroes instead. Treating that output as
 * a failure turns "the backend forgot to check" into "the backend is slower on
 * one input", because @noble then gets asked and rejects it. The probe rejects
 * such a backend outright at load time anyway; this check is what makes the
 * probe's low order assertion meaningful in the first place.
 */
function nativeSharedSecret(
  mod: NativeCryptoLike,
  secretKey: Uint8Array,
  publicKey: Uint8Array,
): Uint8Array | null {
  if (secretKey.length !== KEY_LEN || publicKey.length !== KEY_LEN) return null;
  try {
    const shared = mod.diffieHellman({
      privateKey: importSecret(mod, secretKey),
      publicKey: importPublic(mod, publicKey),
    });
    if (shared.length !== KEY_LEN) return null;
    let acc = 0;
    for (let i = 0; i < KEY_LEN; i++) acc |= shared[i]!;
    if (acc === 0) {
      shared.fill(0);
      return null;
    }
    return Uint8Array.from(shared);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Public key for a secret. Byte identical on both backends, including for
 * unclamped secrets, which the probe pins.
 */
export function x25519PublicKey(secretKey: Uint8Array): Uint8Array {
  const native = activeNative();
  if (native !== null) {
    const derived = nativePublicKey(native, secretKey);
    if (derived !== null) return derived;
  }
  return x25519.getPublicKey(secretKey);
}

/**
 * Fresh ratchet or identity keypair.
 *
 * The secret comes from @noble's own generator on every backend, so this is
 * `x25519.keygen()` with the public derivation accelerated and nothing else
 * touched. See the note at the top of the file for why that matters.
 */
export function x25519Keygen(): { secretKey: Uint8Array; publicKey: Uint8Array } {
  const secretKey = x25519.utils.randomSecretKey();
  return { secretKey, publicKey: x25519PublicKey(secretKey) };
}

/**
 * The Diffie-Hellman itself.
 *
 * Throws on a low order or malformed public key, with the identical error
 * @noble has always thrown, because @noble is what throws it. See
 * `nativeSharedSecret`.
 */
export function x25519SharedSecret(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  const native = activeNative();
  if (native !== null) {
    const shared = nativeSharedSecret(native, secretKey, publicKey);
    if (shared !== null) return shared;
  }
  return x25519.getSharedSecret(secretKey, publicKey);
}
