import { clean } from '@noble/hashes/utils.js';

/**
 * Byte plumbing. Nothing here is cryptographic, it is the boring layer that
 * keeps the cryptographic files free of index arithmetic.
 */

export function concat(...parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/**
 * Constant time comparison. Used for identity pinning and for anything else
 * where a length-dependent early exit would leak which prefix matched.
 */
export function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function utf8ToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function bytesToUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/**
 * base64url without padding.
 *
 * The pure JavaScript pair below is the definition of the format for this
 * package: unpadded, `-` and `_` for the last two alphabet slots, and a hard
 * reject on any character outside it, on a length that is 1 modulo 4, and on a
 * final quantum whose unused low bits are not zero. That last rule is what
 * keeps the encoding injective, and it is the one every platform base64
 * decoder gets wrong in the lenient direction.
 *
 * These two functions are also the reference the fast paths further down are
 * measured against, which is why they stay hand written rather than being
 * deleted in favour of the platform. See `resolveCodec`.
 */
function toBase64UrlJs(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out += B64URL[(n >>> 18) & 63]! + B64URL[(n >>> 12) & 63]! + B64URL[(n >>> 6) & 63]! + B64URL[n & 63]!;
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i]! << 16;
    out += B64URL[(n >>> 18) & 63]! + B64URL[(n >>> 12) & 63]!;
  } else if (rest === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out += B64URL[(n >>> 18) & 63]! + B64URL[(n >>> 12) & 63]! + B64URL[(n >>> 6) & 63]!;
  }
  return out;
}

const B64URL_INVERSE: Readonly<Record<string, number>> = (() => {
  const table: Record<string, number> = {};
  for (let i = 0; i < B64URL.length; i++) table[B64URL[i]!] = i;
  return table;
})();

function fromBase64UrlJs(text: string): Uint8Array | null {
  const len = text.length;
  if (len % 4 === 1) return null;
  const outLen = Math.floor((len * 3) / 4);
  const out = new Uint8Array(outLen);
  let bits = 0;
  let acc = 0;
  let at = 0;
  for (let i = 0; i < len; i++) {
    const v = B64URL_INVERSE[text[i]!];
    if (v === undefined) return null;
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[at++] = (acc >>> bits) & 0xff;
    }
  }
  // Leftover bits must be zero, otherwise two distinct strings decode to the
  // same bytes and the round trip stops being injective.
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) return null;
  return at === outLen ? out : out.subarray(0, at);
}

// ---------------------------------------------------------------------------
// Platform fast paths
// ---------------------------------------------------------------------------

/**
 * The JavaScript loops above walk one character at a time doing a string index
 * plus an object property lookup on a dictionary-mode map. That is roughly 25x
 * slower than `Buffer` on the encode side and 50x on the decode side, and it
 * shows up on the token path, which is the one a human pastes.
 *
 * So: probe the platform, verify the candidate against the reference above, and
 * only then use it. Same shape and same reasoning as the native cipher probe in
 * src/aead.ts, and for the same reason. A platform decoder that disagrees with
 * this one by a single byte is not a speedup, it is a wire format fork, and
 * `Buffer.from(text, 'base64url')` in particular disagrees loudly: it silently
 * drops characters outside the alphabet instead of rejecting them, and it
 * accepts a final quantum with dirty low bits. Both of those are handled here,
 * in front of the platform call, and both are what the probe checks.
 *
 * Portability rule inherited from src/aead.ts: no static `node:` import. The
 * platform is reached through globals only, so a browser bundle sees nothing to
 * resolve and quietly lands on `atob`/`btoa` or on the reference loops.
 */

type Encoder = (bytes: Uint8Array) => string;
type Decoder = (text: string) => Uint8Array | null;

export type Base64Backend = 'buffer' | 'btoa' | 'js';

/** Structural, not `node:buffer`, because src/ must not import from node. */
interface NodeBufferLike {
  readonly buffer: ArrayBufferLike;
  readonly byteOffset: number;
  readonly length: number;
  toString(encoding: string): string;
}

interface BufferCtorLike {
  from(value: ArrayBufferLike, byteOffset: number, length: number): NodeBufferLike;
  from(value: string, encoding: string): NodeBufferLike;
}

/** Anything outside the base64url alphabet. Tested for presence rather than
 * anchoring the whole string, so no assumption about `$` is involved. */
const NOT_B64URL = /[^A-Za-z0-9_-]/;

/**
 * True when the trailing partial quantum carries no set bits it should not.
 *
 * A 2 character tail encodes 12 bits for 8 bytes' worth of output, so the final
 * character has 4 unused low bits; a 3 character tail leaves 2. The reference
 * decoder rejects a non zero remainder, so every fast path has to as well or
 * two distinct strings start decoding to the same bytes.
 */
function canonicalTail(text: string): boolean {
  const rest = text.length & 3;
  if (rest === 0) return true;
  const v = B64URL_INVERSE[text[text.length - 1]!];
  if (v === undefined) return false;
  return rest === 2 ? (v & 15) === 0 : (v & 3) === 0;
}

function bufferEncoder(ctor: BufferCtorLike): Encoder {
  return (bytes) => ctor.from(bytes.buffer, bytes.byteOffset, bytes.length).toString('base64url');
}

function bufferDecoder(ctor: BufferCtorLike): Decoder {
  return (text) => {
    if ((text.length & 3) === 1) return null;
    if (NOT_B64URL.test(text)) return null;
    if (!canonicalTail(text)) return null;
    const buf = ctor.from(text, 'base64url');
    // A view, not a copy, and deliberately a plain Uint8Array rather than the
    // Buffer that came back: every decoded field in this package is a
    // Uint8Array, and callers compare prototypes.
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.length);
  };
}

function btoaEncoder(encode: (binary: string) => string): Encoder {
  // 0x8000 at a time because `String.fromCharCode.apply` blows the argument
  // limit somewhere above that, and the limit is engine specific.
  const CHUNK = 0x8000;
  return (bytes) => {
    let binary = '';
    for (let i = 0; i < bytes.length; i += CHUNK) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK) as unknown as number[]);
    }
    // btoa emits standard base64: same alphabet bar the last two slots, plus
    // padding this format does not carry.
    return encode(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  };
}

function atobDecoder(decode: (standard: string) => string): Decoder {
  return (text) => {
    if ((text.length & 3) === 1) return null;
    if (NOT_B64URL.test(text)) return null;
    if (!canonicalTail(text)) return null;
    let standard = text.replace(/-/g, '+').replace(/_/g, '/');
    const rest = standard.length & 3;
    if (rest === 2) standard += '==';
    else if (rest === 3) standard += '=';
    let binary: string;
    try {
      binary = decode(standard);
    } catch {
      return null;
    }
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i) & 0xff;
    return out;
  };
}

/**
 * Corpus the candidate has to reproduce exactly.
 *
 * Chosen for the cases a platform codec actually gets wrong rather than for
 * volume: empty input, every length modulo 3 on the encode side, every length
 * modulo 4 on the decode side, high bytes so a sign extension bug shows, and
 * the rejects that separate this format from a lenient one.
 */
function probeVectors(): { bytes: Uint8Array[]; strings: string[] } {
  const bytes: Uint8Array[] = [];
  for (let len = 0; len <= 12; len++) {
    const b = new Uint8Array(len);
    for (let i = 0; i < len; i++) b[i] = (i * 37 + 11) & 0xff;
    bytes.push(b);
  }
  bytes.push(new Uint8Array(300).fill(0xff), new Uint8Array(300));
  const strings: string[] = [];
  for (const b of bytes) strings.push(toBase64UrlJs(b));
  strings.push(
    // Rejects: bad alphabet, standard base64 alphabet, padding, whitespace,
    // an impossible length, and dirty low bits in both tail shapes.
    'AA.AA',
    'A+B/',
    'AA==',
    'AA AA',
    'A',
    'AAAAA',
    'AB',
    'AC',
    'AP',
    'ABB',
    'ABC',
    'ABP',
    // And the canonical tails, which must survive.
    'AA',
    'AQ',
    'Ag',
    'ABA',
    'ABE',
    'ABw',
  );
  return { bytes, strings };
}

function agrees(encoder: Encoder, decoder: Decoder): boolean {
  const { bytes, strings } = probeVectors();
  for (const b of bytes) {
    if (encoder(b) !== toBase64UrlJs(b)) return false;
  }
  for (const s of strings) {
    const fast = decoder(s);
    const reference = fromBase64UrlJs(s);
    if (fast === null || reference === null) {
      if (fast !== reference) return false;
      continue;
    }
    if (fast.length !== reference.length) return false;
    for (let i = 0; i < fast.length; i++) if (fast[i] !== reference[i]!) return false;
  }
  return true;
}

let fastEncode: Encoder | null = null;
let fastDecode: Decoder | null = null;
let fastName: Base64Backend = 'js';
let probeDone = false;
let forced: Base64Backend | 'auto' = 'auto';

function resolveCodec(): void {
  if (probeDone) return;
  probeDone = true;
  try {
    const g = globalThis as {
      Buffer?: BufferCtorLike;
      atob?: (s: string) => string;
      btoa?: (s: string) => string;
    };
    if (typeof g.Buffer?.from === 'function') {
      const encoder = bufferEncoder(g.Buffer);
      const decoder = bufferDecoder(g.Buffer);
      if (agrees(encoder, decoder)) {
        fastEncode = encoder;
        fastDecode = decoder;
        fastName = 'buffer';
        return;
      }
    }
    if (typeof g.atob === 'function' && typeof g.btoa === 'function') {
      const encoder = btoaEncoder(g.btoa);
      const decoder = atobDecoder(g.atob);
      if (agrees(encoder, decoder)) {
        fastEncode = encoder;
        fastDecode = decoder;
        fastName = 'btoa';
      }
    }
  } catch {
    // A runtime with a Buffer shim that throws, a locked down global, an atob
    // that rejects something it should not: all of them mean "no fast path
    // here", and none of them is worth a console line when the reference
    // implementation is right there and correct.
    fastEncode = null;
    fastDecode = null;
    fastName = 'js';
  }
}

/** Which implementation the next call will use. Asks the same resolver the
 * encode and decode paths ask, so it cannot claim a path the probe rejected. */
export function base64Backend(): Base64Backend {
  resolveCodec();
  return forced === 'auto' ? fastName : forced === fastName ? fastName : 'js';
}

/**
 * Test hook. Pins the implementation so a suite can prove the platform path and
 * the reference path agree on the same input, which is the property that lets a
 * token encoded in a browser decode on a server. Returns what is actually in
 * effect afterwards rather than what was asked for.
 */
export function forceBase64Backend(choice: Base64Backend | 'auto'): Base64Backend {
  forced = choice;
  return base64Backend();
}

function activeEncoder(): Encoder | null {
  if (forced === 'js') return null;
  resolveCodec();
  if (forced !== 'auto' && forced !== fastName) return null;
  return fastEncode;
}

function activeDecoder(): Decoder | null {
  if (forced === 'js') return null;
  resolveCodec();
  if (forced !== 'auto' && forced !== fastName) return null;
  return fastDecode;
}

/** base64url without padding. Byte identical on every backend. */
export function toBase64Url(bytes: Uint8Array): string {
  const fast = activeEncoder();
  return fast === null ? toBase64UrlJs(bytes) : fast(bytes);
}

/** Returns null rather than throwing so the caller decides the failure reason. */
export function fromBase64Url(text: string): Uint8Array | null {
  const fast = activeDecoder();
  return fast === null ? fromBase64UrlJs(text) : fast(text);
}

/**
 * Best effort zeroing. JavaScript gives no guarantee that a copy was not made
 * by the engine, so this reduces the window rather than closing it. Said out
 * loud in the README instead of being implied here.
 */
export function wipe(...secrets: readonly (Uint8Array | undefined)[]): void {
  for (const s of secrets) if (s) clean(s);
}
