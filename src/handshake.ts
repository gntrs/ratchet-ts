import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { randomBytes } from '@noble/hashes/utils.js';

import type { AcceptPayload, EnvelopeToken, IdentityKeyPair, InvitePayload, PendingSession, SessionState } from './contract.js';
import { concat, toHex, wipe } from './bytes.js';
import { x25519Keygen, x25519SharedSecret } from './curves.js';
import { encodeEnvelope } from './envelope.js';
import { fail } from './errors.js';
import {
  MLKEM768_CIPHERTEXT_LEN,
  MLKEM768_PUBLIC_LEN,
  X25519_PUBLIC_LEN,
  publicOf,
} from './identity.js';
import { kdfHandshake, kdfRoot } from './kdf.js';

/**
 * PQXDH-shaped hybrid handshake.
 *
 * Two round trips would be the textbook shape. We get away with one and a half
 * because the invite carries a long term identity rather than a prekey bundle:
 * the responder can encapsulate to the initiator's ML-KEM key and derive the
 * root immediately, and the initiator finishes on receiving the accept.
 *
 * The price of that shortcut is stated plainly in the README: the initiator's
 * contribution to the handshake is a long term key, not an ephemeral one, so
 * the handshake secret has no initiator-side forward secrecy until the first
 * ratchet step. The Double Ratchet takes over from message one, which is why
 * this is acceptable rather than merely convenient.
 */

/** 128 bits of conversation id. Not secret, it just has to not collide. */
function newConversationId(): string {
  return toHex(randomBytes(16));
}

export function beginInvite(self: IdentityKeyPair): { token: EnvelopeToken; pending: PendingSession } {
  const conversationId = newConversationId();
  const sender = publicOf(self);
  return {
    token: encodeEnvelope({ kind: 'invite', sender, conversationId }),
    pending: {
      conversationId,
      role: 'initiator',
      // Snapshot so that a later accept can be checked against the identity
      // that actually sent the invite, not whatever identity is loaded now.
      selfIdentitySnapshot: sender,
      createdAt: new Date().toISOString(),
    },
  };
}

/** Lengths are checked before the primitives see the bytes, so a hostile token
 * produces `malformed_token` rather than a library-level throw we would have to
 * guess the meaning of. */
function requireLength(value: Uint8Array, expected: number, what: string): void {
  if (value.length !== expected) fail('malformed_token', `${what} must be ${expected} bytes, got ${value.length}`);
}

/**
 * Responder side. Consumes an invite, produces the accept token to send back
 * and a live session that can already receive.
 *
 * The responder cannot send yet: it has no send chain until the initiator's
 * first message reveals an initiator ratchet key. Same asymmetry as Signal.
 */
export function acceptInvite(self: IdentityKeyPair, invite: InvitePayload): { token: EnvelopeToken; session: SessionState } {
  requireLength(invite.sender.classicalPublic, X25519_PUBLIC_LEN, 'invite classical public key');
  requireLength(invite.sender.pqPublic, MLKEM768_PUBLIC_LEN, 'invite ML-KEM public key');

  const ratchet = x25519Keygen();
  const kem = ml_kem768.encapsulate(invite.sender.pqPublic);

  // DH1 binds the responder's identity, DH2 binds the responder's fresh ratchet
  // key. Without DH2 the whole handshake would be replayable by anyone holding
  // a recorded invite.
  const dh1 = x25519SharedSecret(self.classicalSecret, invite.sender.classicalPublic);
  const dh2 = x25519SharedSecret(ratchet.secretKey, invite.sender.classicalPublic);
  const ikm = concat(dh1, dh2, kem.sharedSecret);
  const rootKey = kdfHandshake(ikm, invite.conversationId);
  wipe(dh1, dh2, ikm, kem.sharedSecret);

  const session: SessionState = {
    conversationId: invite.conversationId,
    role: 'responder',
    peer: invite.sender,
    rootKey,
    selfRatchetPublic: ratchet.publicKey,
    selfRatchetSecret: ratchet.secretKey,
    sendCount: 0,
    recvCount: 0,
    previousSendCount: 0,
    skippedKeys: {},
  };

  const token = encodeEnvelope({
    kind: 'accept',
    sender: publicOf(self),
    conversationId: invite.conversationId,
    kemCiphertext: kem.cipherText,
    ratchetPublic: ratchet.publicKey,
  });

  return { token, session };
}

/**
 * Initiator side. Derives the same root key from the accept, then immediately
 * takes one DH ratchet step so that message zero is already sent under a chain
 * the responder has never seen a private key for.
 */
export function completeInvite(self: IdentityKeyPair, pending: PendingSession, accept: AcceptPayload): SessionState {
  if (accept.conversationId !== pending.conversationId) {
    fail('no_session', 'accept does not match the pending conversation');
  }
  requireLength(accept.sender.classicalPublic, X25519_PUBLIC_LEN, 'accept classical public key');
  requireLength(accept.sender.pqPublic, MLKEM768_PUBLIC_LEN, 'accept ML-KEM public key');
  requireLength(accept.ratchetPublic, X25519_PUBLIC_LEN, 'accept ratchet public key');
  requireLength(accept.kemCiphertext, MLKEM768_CIPHERTEXT_LEN, 'accept ML-KEM ciphertext');

  const dh1 = x25519SharedSecret(self.classicalSecret, accept.sender.classicalPublic);
  const dh2 = x25519SharedSecret(self.classicalSecret, accept.ratchetPublic);
  // ML-KEM decapsulation is implicitly rejecting: a corrupted ciphertext yields
  // a wrong-but-well-formed secret rather than an error, so the mismatch only
  // surfaces when the first message fails its AEAD tag. That is by design.
  const pq = ml_kem768.decapsulate(accept.kemCiphertext, self.pqSecret);
  const ikm = concat(dh1, dh2, pq);
  const handshakeRoot = kdfHandshake(ikm, accept.conversationId);
  wipe(dh1, dh2, pq, ikm);

  const ratchet = x25519Keygen();
  const dh = x25519SharedSecret(ratchet.secretKey, accept.ratchetPublic);
  const stepped = kdfRoot(handshakeRoot, dh);
  wipe(dh, handshakeRoot);

  return {
    conversationId: accept.conversationId,
    role: 'initiator',
    peer: accept.sender,
    rootKey: stepped.rootKey,
    selfRatchetPublic: ratchet.publicKey,
    selfRatchetSecret: ratchet.secretKey,
    peerRatchetPublic: accept.ratchetPublic,
    sendChainKey: stepped.chainKey,
    sendCount: 0,
    recvCount: 0,
    previousSendCount: 0,
    skippedKeys: {},
  };
}
