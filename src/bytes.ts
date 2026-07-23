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
 * base64url without padding, hand written rather than via `btoa` because the
 * binary-string dance around `btoa` is a reliable source of encoding bugs and
 * this has to be byte exact across Node and every browser we bundle into.
 */
export function toBase64Url(bytes: Uint8Array): string {
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

/** Returns null rather than throwing so the caller decides the failure reason. */
export function fromBase64Url(text: string): Uint8Array | null {
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

/**
 * Best effort zeroing. JavaScript gives no guarantee that a copy was not made
 * by the engine, so this reduces the window rather than closing it. Said out
 * loud in the README instead of being implied here.
 */
export function wipe(...secrets: readonly (Uint8Array | undefined)[]): void {
  for (const s of secrets) if (s) clean(s);
}
