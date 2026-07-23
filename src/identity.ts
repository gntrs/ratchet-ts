import { x25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { sha256 } from '@noble/hashes/sha2.js';

import type { Fingerprint, IdentityKeyPair, PublicIdentity } from './contract.js';
import { concat, equal, toHex, utf8ToBytes } from './bytes.js';
import { FINGERPRINT_WORDS, WORDLIST, WORDLIST_BITS } from './wordlist.js';

export const X25519_PUBLIC_LEN = 32;
export const X25519_SECRET_LEN = 32;
export const MLKEM768_PUBLIC_LEN = 1184;
export const MLKEM768_SECRET_LEN = 2400;
export const MLKEM768_CIPHERTEXT_LEN = 1088;

const FINGERPRINT_DOMAIN = utf8ToBytes('OCX1 identity fingerprint v1');

export function createIdentity(): IdentityKeyPair {
  const classical = x25519.keygen();
  const pq = ml_kem768.keygen();
  return {
    classicalPublic: classical.publicKey,
    classicalSecret: classical.secretKey,
    pqPublic: pq.publicKey,
    pqSecret: pq.secretKey,
  };
}

export function publicOf(identity: IdentityKeyPair): PublicIdentity {
  return { classicalPublic: identity.classicalPublic, pqPublic: identity.pqPublic };
}

export function sameIdentity(a: PublicIdentity, b: PublicIdentity): boolean {
  return equal(a.classicalPublic, b.classicalPublic) && equal(a.pqPublic, b.pqPublic);
}

/**
 * Length prefixes matter here. Without them an attacker with freedom over key
 * encodings could shift bytes between the two halves and land on the same
 * digest, which would let two different identities share a fingerprint. The
 * domain string keeps this digest from colliding with any other use of SHA-256
 * in the protocol.
 */
function identityDigest(identity: PublicIdentity): Uint8Array {
  const lengths = new Uint8Array(8);
  new DataView(lengths.buffer).setUint32(0, identity.classicalPublic.length, false);
  new DataView(lengths.buffer).setUint32(4, identity.pqPublic.length, false);
  return sha256(concat(FINGERPRINT_DOMAIN, lengths, identity.classicalPublic, identity.pqPublic));
}

/**
 * Six words is 66 bits. That is enough to stop an opportunistic or automated
 * key swap, and it is not enough to stop someone willing to grind 2^66 keypairs
 * at a specific target. The README says so plainly rather than letting the word
 * count imply more than it delivers.
 */
export function fingerprint(identity: PublicIdentity): Fingerprint {
  const digest = identityDigest(identity);
  const words: string[] = [];
  let acc = 0n;
  let bits = 0;
  let at = 0;
  while (words.length < FINGERPRINT_WORDS) {
    if (bits < WORDLIST_BITS) {
      acc = (acc << 8n) | BigInt(digest[at++]!);
      bits += 8;
      continue;
    }
    bits -= WORDLIST_BITS;
    const index = Number((acc >> BigInt(bits)) & BigInt((1 << WORDLIST_BITS) - 1));
    words.push(WORDLIST[index]!);
  }
  // Hex carries the first 128 bits, which is strictly more than the words do.
  // Both come from the same digest, so reading either one is a valid check.
  return { words, hex: toHex(digest.subarray(0, 16)) };
}
