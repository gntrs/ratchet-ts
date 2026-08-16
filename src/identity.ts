import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';

import type { Fingerprint, IdentityKeyPair, PublicIdentity } from './contract.js';
import { concat, equal, toHex, utf8ToBytes } from './bytes.js';
import { x25519Keygen } from './curves.js';
import { FINGERPRINT_WORDS, WORDLIST, WORDLIST_BITS } from './wordlist.js';

export const X25519_PUBLIC_LEN = 32;
export const X25519_SECRET_LEN = 32;
export const MLKEM768_PUBLIC_LEN = 1184;
export const MLKEM768_SECRET_LEN = 2400;
export const MLKEM768_CIPHERTEXT_LEN = 1088;
export const MLDSA65_PUBLIC_LEN = 1952;
export const MLDSA65_SECRET_LEN = 4032;
export const MLDSA65_SIGNATURE_LEN = 3309;

/**
 * v2, because 0.6.0 put a third key in the identity and the digest has to cover
 * it. A fingerprint that ignored the signing key would let an attacker keep the
 * two old keys, swap in a signing key of their own, and print the same six
 * words: the one check a human performs would confirm an identity that could
 * then authenticate as somebody else. The domain string changing is what makes
 * that a visibly different fingerprint rather than a silently weaker one.
 *
 * Every fingerprint therefore changes at 0.6.0. That is unavoidable and it is
 * better than the alternative, which is a fingerprint that still matches while
 * meaning less.
 */
const FINGERPRINT_DOMAIN = utf8ToBytes('OCX1 identity fingerprint v2');
const CERTIFICATE_DOMAIN = utf8ToBytes('OCX3 identity certificate v1');

/**
 * The identity, signed by its own signing key, once, at creation.
 *
 * WHY THIS REPLACED A PER INVITE SIGNATURE. Until this landed, `beginInvite`
 * signed the conversation id together with the sender's identity, on every
 * single invite, at 8 ms a time. That was 8 of the 25.8 ms a handshake cost and
 * it was buying nothing, for two reasons.
 *
 * First, the conversation id in there was not load bearing. It bound an invite
 * to one conversation, and an invite was replayable verbatim anyway: the module
 * header in handshake.ts says so and calls it a way to waste a responder's CPU
 * rather than a way to read anything. Removing the id lets an attacker point a
 * recorded identity at a different conversation, which is the same nuisance
 * they already had.
 *
 * Second, and more importantly, neither form ever proved what people assume a
 * signed invite proves. It is signed by the identity's OWN signing key, so it
 * demonstrates possession of `sigSecret` and nothing about `classicalSecret` or
 * `pqSecret`. An attacker can pair somebody else's X25519 and ML-KEM keys with
 * a signing keypair of their own and sign either shape happily. What stops that
 * mattering is that the resulting identity has a different FINGERPRINT, and
 * that the responder's accept binds the initiator identity it actually saw, so
 * the real initiator's `completeInvite` refuses. Both of those are untouched.
 *
 * So the signature says "these three keys are one identity, asserted by the
 * holder of the third". That is a statement about the identity and not about
 * the conversation, it never changes, and it is therefore computed once and
 * carried. The MITM protection lives entirely in the accept transcript, which
 * is per handshake and stays per handshake.
 */
export function certifyIdentity(identity: Omit<IdentityKeyPair, 'certificate'>): Uint8Array {
  return ml_dsa65.sign(certificateMessage(publicOf(identity)), identity.sigSecret);
}

function certificateMessage(identity: PublicIdentity): Uint8Array {
  const lengths = new Uint8Array(12);
  const view = new DataView(lengths.buffer);
  view.setUint32(0, identity.classicalPublic.length, false);
  view.setUint32(4, identity.pqPublic.length, false);
  view.setUint32(8, identity.sigPublic.length, false);
  return concat(
    CERTIFICATE_DOMAIN,
    lengths,
    identity.classicalPublic,
    identity.pqPublic,
    identity.sigPublic,
  );
}

/** Does this identity vouch for itself? Cheap: one ML-DSA verify, about 1.5 ms. */
export function verifyCertificate(identity: PublicIdentity, certificate: Uint8Array): boolean {
  if (certificate.length !== MLDSA65_SIGNATURE_LEN) return false;
  if (identity.sigPublic.length !== MLDSA65_PUBLIC_LEN) return false;
  return ml_dsa65.verify(certificate, certificateMessage(identity), identity.sigPublic);
}

export function createIdentity(): IdentityKeyPair {
  const classical = x25519Keygen();
  const pq = ml_kem768.keygen();
  const sig = ml_dsa65.keygen();
  const base = {
    classicalPublic: classical.publicKey,
    classicalSecret: classical.secretKey,
    pqPublic: pq.publicKey,
    pqSecret: pq.secretKey,
    sigPublic: sig.publicKey,
    sigSecret: sig.secretKey,
  };
  // The one signature this identity will ever need to make about itself. Paid
  // here, once, so that every invite it sends afterwards costs no signing at
  // all. See certifyIdentity for why a per invite signature was not buying
  // anything the fingerprint and the accept transcript were not already.
  return { ...base, certificate: certifyIdentity(base) };
}

export function publicOf(identity: Omit<IdentityKeyPair, 'certificate'>): PublicIdentity {
  return {
    classicalPublic: identity.classicalPublic,
    pqPublic: identity.pqPublic,
    sigPublic: identity.sigPublic,
  };
}

export function sameIdentity(a: PublicIdentity, b: PublicIdentity): boolean {
  return (
    equal(a.classicalPublic, b.classicalPublic) &&
    equal(a.pqPublic, b.pqPublic) &&
    equal(a.sigPublic, b.sigPublic)
  );
}

/**
 * Length prefixes matter here. Without them an attacker with freedom over key
 * encodings could shift bytes between the two halves and land on the same
 * digest, which would let two different identities share a fingerprint. The
 * domain string keeps this digest from colliding with any other use of SHA-256
 * in the protocol.
 */
function identityDigest(identity: PublicIdentity): Uint8Array {
  const lengths = new Uint8Array(12);
  const view = new DataView(lengths.buffer);
  view.setUint32(0, identity.classicalPublic.length, false);
  view.setUint32(4, identity.pqPublic.length, false);
  view.setUint32(8, identity.sigPublic.length, false);
  return sha256(
    concat(
      FINGERPRINT_DOMAIN,
      lengths,
      identity.classicalPublic,
      identity.pqPublic,
      identity.sigPublic,
    ),
  );
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
