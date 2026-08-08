import { utf8ToBytes } from './bytes.js';
import { hkdfSha256, hmacSha256 } from './hash.js';

export const KEY_LEN = 32;

/**
 * The labels. Hoisted to module scope because they are constants, and because
 * `utf8ToBytes` builds a TextEncoder on every call: on the root ratchet that
 * was a fresh encoder per DH step for a string that never changes.
 */
const ROOT_INFO = utf8ToBytes('OCX1 root ratchet v1');
const HANDSHAKE_SALT = utf8ToBytes('OCX1 hybrid handshake v1');

/**
 * Root key step. HKDF with the current root key as the salt, so the new root
 * depends on the whole history of the conversation and not just on the fresh
 * DH output. An attacker who learns one DH output still cannot walk the chain
 * forward without every earlier one.
 */
export function kdfRoot(rootKey: Uint8Array, dhOutput: Uint8Array): { rootKey: Uint8Array; chainKey: Uint8Array } {
  const out = hkdfSha256(dhOutput, rootKey, ROOT_INFO, KEY_LEN * 2);
  return { rootKey: out.slice(0, KEY_LEN), chainKey: out.slice(KEY_LEN) };
}

/**
 * Symmetric chain step. Two different constants under the same chain key give
 * a message key and the next chain key. The step is one-way, which is what
 * makes deleting the message key actually buy forward secrecy: nobody can
 * reconstruct it from any later state.
 *
 * Two HMAC-SHA256 calls, and it stays two. One HMAC-SHA512 split into halves
 * would cost a third of this and produce different keys for every session on
 * the planet, so it is a breaking release, not an optimisation. src/hash.ts
 * makes each of the two calls faster and leaves the construction alone.
 */
const MESSAGE_KEY_CONSTANT = Uint8Array.of(0x01);
const CHAIN_KEY_CONSTANT = Uint8Array.of(0x02);

export function kdfChain(chainKey: Uint8Array): { messageKey: Uint8Array; nextChainKey: Uint8Array } {
  return {
    messageKey: hmacSha256(chainKey, MESSAGE_KEY_CONSTANT),
    nextChainKey: hmacSha256(chainKey, CHAIN_KEY_CONSTANT),
  };
}

/**
 * Handshake mixer. All three secrets go in as one input keying material blob
 * so the result is only as weak as the strongest surviving component, which is
 * the entire point of a hybrid: X25519 and ML-KEM must both fall.
 */
export function kdfHandshake(ikm: Uint8Array, conversationId: string): Uint8Array {
  return hkdfSha256(ikm, HANDSHAKE_SALT, utf8ToBytes(conversationId), KEY_LEN);
}
