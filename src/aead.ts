/**
 * XChaCha20-Poly1305 with an optional native fast path.
 *
 * The whole point of this file is that it produces the same bytes everywhere.
 * A message sealed in a browser on the pure JavaScript backend must open on a
 * server running the native backend, and the reverse, so "native" here is a
 * performance decision and never a format decision. Anything that could make
 * the two backends disagree is a bug, which is why the native path is probed
 * against the JavaScript path before it is ever trusted with real traffic.
 *
 * How the fast path works. XChaCha20 is ChaCha20 with a nonce extension bolted
 * on the front: hash the key together with the first 16 nonce bytes into a
 * subkey (HChaCha20), then run ordinary ChaCha20-Poly1305 under that subkey
 * with a 12 byte nonce of four zero bytes plus the remaining 8 nonce bytes.
 * HChaCha20 is one block operation and stays here in JavaScript. Everything
 * that scales with message length, which is the ChaCha20 keystream and the
 * Poly1305 pass, is what gets handed to the native cipher.
 *
 * Portability rule, and it is not negotiable: src/ contains no static
 * `node:` import. A static import would be resolved by every browser bundler
 * on the planet and would break the browser, Deno and Bun claims in the
 * README. Reaching node:crypto happens lazily, inside try/catch, at most once,
 * and any failure whatsoever lands silently on the @noble backend. A browser
 * must reach the JavaScript path with no thrown error and nothing printed to
 * the console.
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';

import type { AeadBackend } from './types.js';
import { concat, wipe } from './bytes.js';
import { fail } from './errors.js';

export const AEAD_KEY_LEN = 32;
export const AEAD_NONCE_LEN = 24;
export const AEAD_TAG_LEN = 16;

/** Algorithm id as node:crypto spells it. Not the extended nonce variant: the
 * nonce extension is done here, in `hchacha20`, before the native call. */
const NATIVE_ALGORITHM = 'chacha20-poly1305';

const EMPTY = new Uint8Array(0);

// Declared in the public type contract rather than here, so the union cannot
// drift apart from the one consumers import.
export type { AeadBackend };

// ---------------------------------------------------------------------------
// HChaCha20
// ---------------------------------------------------------------------------

/** ChaCha constants, "expand 32-byte k" read as four little endian words. */
const SIGMA_0 = 0x61707865;
const SIGMA_1 = 0x3320646e;
const SIGMA_2 = 0x79622d32;
const SIGMA_3 = 0x6b206574;

function rotl32(x: number, n: number): number {
  return (x << n) | (x >>> (32 - n));
}

function readLe32(bytes: Uint8Array, at: number): number {
  return (bytes[at]! | (bytes[at + 1]! << 8) | (bytes[at + 2]! << 16) | (bytes[at + 3]! << 24)) >>> 0;
}

function writeLe32(bytes: Uint8Array, at: number, value: number): void {
  bytes[at] = value & 0xff;
  bytes[at + 1] = (value >>> 8) & 0xff;
  bytes[at + 2] = (value >>> 16) & 0xff;
  bytes[at + 3] = (value >>> 24) & 0xff;
}

/**
 * The ChaCha quarter round. `state` is an Int32Array specifically so that every
 * addition truncates to 32 bits on store without an explicit mask. Swap it for
 * a plain array and the additions silently become float64 and the output is
 * wrong past the first carry.
 */
function quarterRound(state: Int32Array, a: number, b: number, c: number, d: number): void {
  state[a] = state[a]! + state[b]!;
  state[d] = rotl32(state[d]! ^ state[a]!, 16);
  state[c] = state[c]! + state[d]!;
  state[b] = rotl32(state[b]! ^ state[c]!, 12);
  state[a] = state[a]! + state[b]!;
  state[d] = rotl32(state[d]! ^ state[a]!, 8);
  state[c] = state[c]! + state[d]!;
  state[b] = rotl32(state[b]! ^ state[c]!, 7);
}

/**
 * HChaCha20 from draft-irtf-cfrg-xchacha. 32 byte key plus 16 nonce bytes into
 * a 32 byte subkey.
 *
 * Unlike the ChaCha block function this deliberately does NOT add the original
 * state back in at the end, and it takes words 0 to 3 and 12 to 15 rather than
 * the whole state. Both of those are what make it a one way compression of the
 * key rather than a keystream block, and getting either wrong produces output
 * that still looks random while being a completely different cipher.
 */
function hchacha20(key: Uint8Array, noncePrefix: Uint8Array): Uint8Array {
  const state = new Int32Array(16);
  state[0] = SIGMA_0;
  state[1] = SIGMA_1;
  state[2] = SIGMA_2;
  state[3] = SIGMA_3;
  for (let i = 0; i < 8; i++) state[4 + i] = readLe32(key, i * 4);
  for (let i = 0; i < 4; i++) state[12 + i] = readLe32(noncePrefix, i * 4);

  for (let round = 0; round < 10; round++) {
    quarterRound(state, 0, 4, 8, 12);
    quarterRound(state, 1, 5, 9, 13);
    quarterRound(state, 2, 6, 10, 14);
    quarterRound(state, 3, 7, 11, 15);
    quarterRound(state, 0, 5, 10, 15);
    quarterRound(state, 1, 6, 11, 12);
    quarterRound(state, 2, 7, 8, 13);
    quarterRound(state, 3, 4, 9, 14);
  }

  const subkey = new Uint8Array(32);
  for (let i = 0; i < 4; i++) writeLe32(subkey, i * 4, state[i]!);
  for (let i = 0; i < 4; i++) writeLe32(subkey, 16 + i * 4, state[12 + i]!);
  // The state still holds the key words. Nothing guarantees the engine did not
  // copy them, but leaving them sitting in a live buffer is a choice, not luck.
  state.fill(0);
  return subkey;
}

/** The 12 byte nonce the inner cipher sees: four zero counter bytes then the
 * last 8 bytes of the extended nonce. This layout is the XChaCha spec, not a
 * convention, so it must not be "tidied". */
function innerNonce(nonce: Uint8Array): Uint8Array {
  const iv = new Uint8Array(12);
  iv.set(nonce.subarray(16), 4);
  return iv;
}

// ---------------------------------------------------------------------------
// Native backend resolution
// ---------------------------------------------------------------------------

interface NativeCipher {
  setAAD(aad: Uint8Array, options?: { plaintextLength: number }): unknown;
  update(data: Uint8Array): Uint8Array;
  final(): Uint8Array;
  getAuthTag(): Uint8Array;
}

interface NativeDecipher {
  setAAD(aad: Uint8Array, options?: { plaintextLength: number }): unknown;
  setAuthTag(tag: Uint8Array): unknown;
  update(data: Uint8Array): Uint8Array;
  final(): Uint8Array;
}

interface NativeCryptoLike {
  createCipheriv(
    algorithm: string,
    key: Uint8Array,
    iv: Uint8Array,
    options?: { authTagLength: number },
  ): NativeCipher;
  createDecipheriv(
    algorithm: string,
    key: Uint8Array,
    iv: Uint8Array,
    options?: { authTagLength: number },
  ): NativeDecipher;
}

let resolved: NativeCryptoLike | null = null;
let syncProbeDone = false;
let asyncProbeDone = false;
let readyPromise: Promise<void> | null = null;
let override: AeadBackend | 'auto' = 'auto';

function looksUsable(mod: unknown): mod is NativeCryptoLike {
  if (typeof mod !== 'object' || mod === null) return false;
  const candidate = mod as Partial<NativeCryptoLike>;
  return typeof candidate.createCipheriv === 'function' && typeof candidate.createDecipheriv === 'function';
}

/**
 * Some runtimes ship node:crypto but not this particular cipher, and at least
 * one shim in the wild accepts the algorithm name and then produces the wrong
 * tag. Exporting a backend on the strength of `typeof createCipheriv` alone
 * would therefore be a silent interop break rather than a clean failure, so the
 * candidate has to reproduce the JavaScript backend byte for byte before it is
 * allowed anywhere near a real message.
 *
 * Both an empty and a non empty AAD are checked because the two take different
 * branches in `nativeSeal`, and a round trip is checked because a cipher that
 * encrypts correctly and rejects its own valid tag is just as broken.
 */
function probe(mod: NativeCryptoLike): boolean {
  const key = new Uint8Array(AEAD_KEY_LEN);
  const nonce = new Uint8Array(AEAD_NONCE_LEN);
  for (let i = 0; i < key.length; i++) key[i] = i * 7 + 1;
  for (let i = 0; i < nonce.length; i++) nonce[i] = i * 11 + 3;
  const plaintext = new Uint8Array(77);
  for (let i = 0; i < plaintext.length; i++) plaintext[i] = i * 5;
  const aads = [EMPTY, new Uint8Array([1, 2, 3, 4, 5])];

  for (const aad of aads) {
    const expected = xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
    const actual = nativeSeal(mod, key, nonce, plaintext, aad);
    if (actual.length !== expected.length) return false;
    // A plain loop, not `equal` from bytes.ts: this is a self test against a
    // value we generated, not a secret comparison, and it must not depend on a
    // module whose own behaviour is what is under test elsewhere.
    for (let i = 0; i < expected.length; i++) if (actual[i] !== expected[i]!) return false;

    const reopened = nativeOpen(mod, key, nonce, expected, aad);
    if (reopened === null || reopened.length !== plaintext.length) return false;
    for (let i = 0; i < plaintext.length; i++) if (reopened[i] !== plaintext[i]!) return false;
  }
  return true;
}

/**
 * Synchronous reach for node:crypto.
 *
 * `process.getBuiltinModule` is the only way to get a builtin synchronously
 * from ESM without a static import, which matters because the ratchet's own
 * encrypt and decrypt are synchronous and cannot await a dynamic import mid
 * message. It exists in Node 20.16+, Deno 2 and recent Bun. Where it does not
 * exist, `resolveAsync` below still gets the fast path for callers that can
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
    // Missing module, blocked permission, a shim that throws on an unknown
    // algorithm: every one of them means "no native backend here", and none of
    // them is worth a console line in an application that is working fine.
  }
  return resolved;
}

/**
 * Asynchronous fallback for runtimes without `process.getBuiltinModule`.
 *
 * The specifier is assembled at runtime on purpose. A literal
 * `import('node:crypto')` is followed statically by bundlers, and a browser
 * bundle that tries to resolve node:crypto fails to build, which is exactly the
 * portability promise this file exists to keep. Splitting the string means the
 * bundler sees a dynamic expression it cannot follow and leaves it alone.
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
 * necessary on a runtime where the synchronous probe cannot work; the async
 * `sealAead` and `openAead` do it for you.
 */
export function aeadReady(): Promise<void> {
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
 * asks the same function the seal and open paths ask, so it cannot claim a
 * fast path that a probe already rejected. */
export function aeadBackend(): AeadBackend {
  return activeNative() === null ? 'noble' : 'native';
}

/**
 * Test hook. Pins the backend so a suite can prove the two paths agree on the
 * same input, which is the property that lets a browser and a server talk.
 *
 * Returns the backend that is actually in effect afterwards, so asking for
 * 'native' on a machine that has none reports 'noble' rather than pretending.
 */
export function forceAeadBackend(choice: AeadBackend | 'auto'): AeadBackend {
  override = choice;
  return aeadBackend();
}

// ---------------------------------------------------------------------------
// The two backends
// ---------------------------------------------------------------------------

function nativeSeal(
  mod: NativeCryptoLike,
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  const subkey = hchacha20(key, nonce.subarray(0, 16));
  try {
    const cipher = mod.createCipheriv(NATIVE_ALGORITHM, subkey, innerNonce(nonce), {
      authTagLength: AEAD_TAG_LEN,
    });
    // Skipped when empty. Poly1305 pads the AAD block to a multiple of 16, and
    // a zero length AAD pads to nothing, so declaring it and omitting it are
    // the same bytes. Omitting also sidesteps runtimes that are fussy about a
    // zero length setAAD.
    if (aad.length > 0) cipher.setAAD(aad, { plaintextLength: plaintext.length });
    const head = cipher.update(plaintext);
    const tail = cipher.final();
    // Tag appended after the ciphertext, which is the layout @noble emits. The
    // wire format is defined by that layout, so this order is load bearing.
    return concat(head, tail, cipher.getAuthTag());
  } finally {
    wipe(subkey);
  }
}

/** Returns null on any authentication failure so the caller owns the error
 * type. The probe needs a boolean, the public API needs a typed throw. */
function nativeOpen(
  mod: NativeCryptoLike,
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Uint8Array | null {
  if (ciphertext.length < AEAD_TAG_LEN) return null;
  const split = ciphertext.length - AEAD_TAG_LEN;
  const subkey = hchacha20(key, nonce.subarray(0, 16));
  try {
    const decipher = mod.createDecipheriv(NATIVE_ALGORITHM, subkey, innerNonce(nonce), {
      authTagLength: AEAD_TAG_LEN,
    });
    decipher.setAuthTag(ciphertext.subarray(split));
    if (aad.length > 0) decipher.setAAD(aad, { plaintextLength: split });
    const head = decipher.update(ciphertext.subarray(0, split));
    // final() is where Poly1305 renders its verdict. It throws on a bad tag,
    // and the plaintext from update() must be discarded when it does.
    const tail = decipher.final();
    return concat(head, tail);
  } catch {
    return null;
  } finally {
    wipe(subkey);
  }
}

function nobleOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Uint8Array | null {
  try {
    return xchacha20poly1305(key, nonce, aad).decrypt(ciphertext);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

function checkInputs(key: Uint8Array, nonce: Uint8Array): void {
  if (key.length !== AEAD_KEY_LEN) {
    fail('malformed_token', `aead key must be ${AEAD_KEY_LEN} bytes, got ${key.length}`);
  }
  if (nonce.length !== AEAD_NONCE_LEN) {
    fail('malformed_token', `aead nonce must be ${AEAD_NONCE_LEN} bytes, got ${nonce.length}`);
  }
}

/**
 * Synchronous seal. Output is ciphertext followed by the 16 byte Poly1305 tag,
 * byte identical on both backends.
 *
 * The plaintext buffer belongs to the caller and is neither modified nor wiped.
 */
export function sealAeadSync(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Uint8Array {
  checkInputs(key, nonce);
  const associated = aad ?? EMPTY;
  const native = activeNative();
  if (native === null) return xchacha20poly1305(key, nonce, associated).encrypt(plaintext);
  return nativeSeal(native, key, nonce, plaintext, associated);
}

/**
 * Synchronous open. Fails closed on any tag, nonce or AAD mismatch: there is no
 * partial result worth returning, and returning one is how a decrypt oracle
 * gets built.
 */
export function openAeadSync(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array,
): Uint8Array {
  checkInputs(key, nonce);
  const associated = aad ?? EMPTY;
  const native = activeNative();
  const opened =
    native === null
      ? nobleOpen(key, nonce, ciphertext, associated)
      : nativeOpen(native, key, nonce, ciphertext, associated);
  if (opened === null) fail('authentication_failed', 'ciphertext failed authentication');
  return opened;
}

/**
 * Seal, awaiting backend resolution first.
 *
 * This is the form to prefer at an application boundary. On a runtime that
 * needs the dynamic import to reach node:crypto, awaiting here is what gets the
 * fast path selected at all; the synchronous variants would have already
 * answered on @noble. The bytes are the same either way.
 */
export async function sealAead(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  await aeadReady();
  return sealAeadSync(key, nonce, plaintext, aad);
}

/** Open, awaiting backend resolution first. See `sealAead`. */
export async function openAead(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  await aeadReady();
  return openAeadSync(key, nonce, ciphertext, aad);
}
