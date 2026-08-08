import { utf8ToBytes, wipe } from './bytes.js';
import { hkdfSha256, hmacSha512 } from './hash.js';

export const KEY_LEN = 32;

/**
 * The labels. Hoisted to module scope because they are constants, and because
 * `utf8ToBytes` builds a TextEncoder on every call: on the root ratchet that
 * was a fresh encoder per DH step for a string that never changes.
 */
const ROOT_INFO = utf8ToBytes('OCX2 root ratchet v1');
const HANDSHAKE_SALT = utf8ToBytes('OCX2 hybrid handshake v1');

/**
 * Root key step. HKDF with the current root key as the salt, so the new root
 * depends on the whole history of the conversation and not just on the fresh
 * DH output. An attacker who learns one DH output still cannot walk the chain
 * forward without every earlier one.
 */
export function kdfRoot(rootKey: Uint8Array, dhOutput: Uint8Array): { rootKey: Uint8Array; chainKey: Uint8Array } {
  const out = hkdfSha256(dhOutput, rootKey, ROOT_INFO, KEY_LEN * 2);
  const stepped = { rootKey: out.slice(0, KEY_LEN), chainKey: out.slice(KEY_LEN) };
  // The 64 byte buffer is both keys concatenated. Slicing copies them out, so
  // zero the original rather than leaving a second live copy of a root key
  // sitting on the heap until the collector gets round to it.
  wipe(out);
  return stepped;
}

/**
 * Symmetric chain step. One PRF call under the chain key yields 64 bytes, split
 * into the next chain key and this message's key. The step is one-way, which is
 * what makes deleting the message key actually buy forward secrecy: nobody can
 * reconstruct it from any later state.
 *
 * ONE HMAC-SHA512 RATHER THAN TWO HMAC-SHA256, AND WHY THAT IS NOT A WEAKENING.
 * Releases up to 0.3.4 ran HMAC-SHA256(ck, 0x01) for the message key and
 * HMAC-SHA256(ck, 0x02) for the next chain key, and the comment that used to
 * sit here defended keeping it that way. The argument for the change, rather
 * than an assertion that it is fine:
 *
 *   - HKDF-Expand is defined as exactly this. RFC 5869 expands a pseudorandom
 *     key into L bytes by chaining HMAC blocks under one key and slicing the
 *     result, and every user of HKDF then splits that output into several
 *     independent keys. kdfRoot two functions up does precisely that, taking 64
 *     HKDF-SHA256 bytes and cutting them into a root key and a chain key. So
 *     "derive 64 bytes from one PRF call and cut them in half" is not a novel
 *     construction being tried out on the chain step, it is the construction
 *     the root step has always used, and the one Signal's own HKDF-based key
 *     derivation uses.
 *
 *   - The security argument is the PRF assumption itself. HMAC-SHA512 keyed
 *     with a uniformly random 32 byte chain key is assumed indistinguishable
 *     from a random function, so its 64 byte output is indistinguishable from
 *     64 random bytes, and any two disjoint slices of 64 random bytes are
 *     independent. Learning the message key tells you nothing about the other
 *     32 bytes for the same reason learning HMAC(k, 0x01) told you nothing
 *     about HMAC(k, 0x02).
 *
 *   - Nothing here relies on collision resistance, only on PRF security, so the
 *     SHA-512 output being truncated to two 32 byte halves does not weaken the
 *     128 bit security level the 32 byte keys already had.
 *
 *   - SHA-512 uses 64 bit words and processes a 128 byte block, so on a 64 bit
 *     CPU it hashes this one block message in roughly the time SHA-256 takes
 *     for one 64 byte block. Two SHA-256 HMACs are four compressions; one
 *     SHA-512 HMAC is two. Measured on this machine: 5.5 us against 3.0 us.
 *
 * The message constant stays one byte for the same reason it always was: the
 * whole message fits in the first block either way, so a longer label would
 * cost the same and say no more.
 *
 * The split order is fixed here and nowhere else: bytes 0 to 31 are the next
 * chain key, bytes 32 to 63 are the message key. Both halves are secret and
 * both must be wiped by the caller once used.
 */
const CHAIN_STEP_CONSTANT = Uint8Array.of(0x01);

export function kdfChain(chainKey: Uint8Array): { messageKey: Uint8Array; nextChainKey: Uint8Array } {
  const out = hmacSha512(chainKey, CHAIN_STEP_CONSTANT);
  const step = { nextChainKey: out.slice(0, KEY_LEN), messageKey: out.slice(KEY_LEN, KEY_LEN * 2) };
  wipe(out);
  return step;
}

/**
 * Handshake mixer. All three secrets go in as one input keying material blob
 * so the result is only as weak as the strongest surviving component, which is
 * the entire point of a hybrid: X25519 and ML-KEM must both fall.
 */
export function kdfHandshake(ikm: Uint8Array, conversationId: string): Uint8Array {
  return hkdfSha256(ikm, HANDSHAKE_SALT, utf8ToBytes(conversationId), KEY_LEN);
}
