import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { extract, expand } from '@noble/hashes/hkdf.js';

import { utf8ToBytes } from './bytes.js';

export const KEY_LEN = 32;

/**
 * Root key step. HKDF with the current root key as the salt, so the new root
 * depends on the whole history of the conversation and not just on the fresh
 * DH output. An attacker who learns one DH output still cannot walk the chain
 * forward without every earlier one.
 */
export function kdfRoot(rootKey: Uint8Array, dhOutput: Uint8Array): { rootKey: Uint8Array; chainKey: Uint8Array } {
  const prk = extract(sha256, dhOutput, rootKey);
  const out = expand(sha256, prk, utf8ToBytes('OCX1 root ratchet v1'), KEY_LEN * 2);
  return { rootKey: out.slice(0, KEY_LEN), chainKey: out.slice(KEY_LEN) };
}

/**
 * Symmetric chain step. Two different constants under the same chain key give
 * a message key and the next chain key. The step is one-way, which is what
 * makes deleting the message key actually buy forward secrecy: nobody can
 * reconstruct it from any later state.
 */
const MESSAGE_KEY_CONSTANT = Uint8Array.of(0x01);
const CHAIN_KEY_CONSTANT = Uint8Array.of(0x02);

export function kdfChain(chainKey: Uint8Array): { messageKey: Uint8Array; nextChainKey: Uint8Array } {
  return {
    messageKey: hmac(sha256, chainKey, MESSAGE_KEY_CONSTANT),
    nextChainKey: hmac(sha256, chainKey, CHAIN_KEY_CONSTANT),
  };
}

/**
 * Handshake mixer. All three secrets go in as one input keying material blob
 * so the result is only as weak as the strongest surviving component, which is
 * the entire point of a hybrid: X25519 and ML-KEM must both fall.
 */
export function kdfHandshake(ikm: Uint8Array, conversationId: string): Uint8Array {
  const prk = extract(sha256, ikm, utf8ToBytes('OCX1 hybrid handshake v1'));
  return expand(sha256, prk, utf8ToBytes(conversationId), KEY_LEN);
}
