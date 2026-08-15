import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from '@noble/hashes/utils.js';

import type {
  AcceptPayload,
  EnvelopeToken,
  IdentityKeyPair,
  InvitePayload,
  PendingSession,
  PublicIdentity,
  SessionState,
} from './contract.js';
import { concat, toHex, utf8ToBytes, wipe } from './bytes.js';
import { x25519Keygen, x25519SharedSecret } from './curves.js';
import { encodeEnvelope } from './envelope.js';
import { fail } from './errors.js';
import {
  MLDSA65_PUBLIC_LEN,
  MLDSA65_SIGNATURE_LEN,
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
 *
 * ---------------------------------------------------------------------------
 * WHAT 0.6.0 ADDED, AND WHY IT COST NO EXTRA FLIGHTS
 * ---------------------------------------------------------------------------
 *
 * Until 0.6.0 the only thing tying a handshake to an identity was X25519. DH1
 * on both sides is computed from a long term X25519 key, so an adversary who
 * can solve discrete log on Curve25519 can compute it too, which means they can
 * sit in the middle of a live handshake and be both parties. ML-KEM protects a
 * RECORDED session and does nothing about that. The library therefore shipped
 * post-quantum confidentiality next to classical authenticity, which is a
 * strange pair to promise together.
 *
 * Both handshake frames now carry an ML-DSA-65 signature over a transcript, and
 * this needed no third flight because each side already sends exactly one frame
 * that can carry one.
 *
 *   invite   signs the conversation id and the initiator's own identity, so an
 *            adversary cannot rewrite whose invite it is.
 *   accept   signs the conversation id, the initiator's WHOLE identity as the
 *            responder received it, and both public values the responder
 *            contributes. Covering the initiator identity is the load bearing
 *            part: it is what stops an adversary from taking a real invite,
 *            accepting it in its own name to the initiator, and separately
 *            opening its own conversation with the responder.
 *
 * REPLAY IS NOT WHAT THESE SIGNATURES SOLVE and they are not weakened by that.
 * An invite was always replayable, before and after: it is a static offer, and
 * anyone who records one can hand it to a responder later. What that gets an
 * attacker is a session with an initiator who is not listening, which is a way
 * to waste a responder's CPU rather than a way to read anything. The signature
 * fixes attribution, not freshness. Freshness comes from the conversation id
 * and from the fact that the initiator has to complete with a key only it holds.
 *
 * THE COST IS REAL AND IS NOT HIDDEN. ML-DSA-65 signing is about 7.4 ms on the
 * reference machine and verification about 1.4 ms, against a whole pre-0.6.0
 * handshake of 0.88 ms. So authenticated handshakes are roughly an order of
 * magnitude more expensive than unauthenticated ones. The identity grows by the
 * 1952 byte verifying key and each handshake frame by a 3309 byte signature.
 * The README carries the measured figures rather than these estimates.
 */

const INVITE_DOMAIN = utf8ToBytes('OCX2 invite transcript v1');
const ACCEPT_DOMAIN = utf8ToBytes('OCX2 accept transcript v1');

/**
 * Length prefixes on every variable field, and a domain string in front.
 *
 * Without the prefixes an attacker with freedom over any two adjacent fields
 * could shift bytes across the boundary between them and produce one signed
 * message that means two different things, which is the classic canonicalisation
 * break and it is cheap to prevent. The domain string keeps an invite transcript
 * from ever being a valid accept transcript: they cover overlapping fields, and
 * a signature that could be lifted from one frame to the other would undo the
 * point of signing either.
 *
 * The conversation id goes in as its ASCII hex, which is the form it travels in
 * and the form both sides already hold, so neither side has to agree about a
 * second encoding of it.
 */
function transcript(domain: Uint8Array, parts: readonly Uint8Array[]): Uint8Array {
  const lengths = new Uint8Array(4 * parts.length);
  const view = new DataView(lengths.buffer);
  parts.forEach((part, i) => view.setUint32(i * 4, part.length, false));
  return concat(domain, lengths, ...parts);
}

function inviteTranscript(conversationId: string, sender: PublicIdentity): Uint8Array {
  return transcript(INVITE_DOMAIN, [
    utf8ToBytes(conversationId),
    sender.classicalPublic,
    sender.pqPublic,
    sender.sigPublic,
  ]);
}

/**
 * The initiator identity in here is the one the RESPONDER saw, and the initiator
 * checks the signature against the identity it actually sent. A mismatch means
 * somebody rewrote the invite in flight, and it fails as a bad signature.
 */
function acceptTranscript(
  conversationId: string,
  initiator: PublicIdentity,
  responder: PublicIdentity,
  kemCiphertext: Uint8Array,
  ratchetPublic: Uint8Array,
): Uint8Array {
  return transcript(ACCEPT_DOMAIN, [
    utf8ToBytes(conversationId),
    initiator.classicalPublic,
    initiator.pqPublic,
    initiator.sigPublic,
    responder.classicalPublic,
    responder.pqPublic,
    responder.sigPublic,
    kemCiphertext,
    ratchetPublic,
  ]);
}

/** 128 bits of conversation id. Not secret, it just has to not collide. */
function newConversationId(): string {
  return toHex(randomBytes(16));
}

export function beginInvite(self: IdentityKeyPair): { token: EnvelopeToken; pending: PendingSession } {
  const conversationId = newConversationId();
  const sender = publicOf(self);
  const signature = ml_dsa65.sign(inviteTranscript(conversationId, sender), self.sigSecret);
  return {
    token: encodeEnvelope({ kind: 'invite', sender, conversationId, signature }),
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
  requireLength(invite.sender.sigPublic, MLDSA65_PUBLIC_LEN, 'invite ML-DSA public key');
  requireLength(invite.signature, MLDSA65_SIGNATURE_LEN, 'invite signature');

  // Before any key agreement runs. Encapsulating to an unauthenticated public
  // key and only then asking who it belonged to would mean the expensive half
  // of the handshake is reachable by anyone who can send bytes.
  if (!ml_dsa65.verify(invite.signature, inviteTranscript(invite.conversationId, invite.sender), invite.sender.sigPublic)) {
    fail('bad_signature', 'the invite is not signed by the identity it claims');
  }

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

  const responder = publicOf(self);
  const signature = ml_dsa65.sign(
    acceptTranscript(invite.conversationId, invite.sender, responder, kem.cipherText, ratchet.publicKey),
    self.sigSecret,
  );

  const token = encodeEnvelope({
    kind: 'accept',
    sender: responder,
    conversationId: invite.conversationId,
    kemCiphertext: kem.cipherText,
    ratchetPublic: ratchet.publicKey,
    signature,
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
  requireLength(accept.sender.sigPublic, MLDSA65_PUBLIC_LEN, 'accept ML-DSA public key');
  requireLength(accept.signature, MLDSA65_SIGNATURE_LEN, 'accept signature');
  requireLength(accept.ratchetPublic, X25519_PUBLIC_LEN, 'accept ratchet public key');
  requireLength(accept.kemCiphertext, MLKEM768_CIPHERTEXT_LEN, 'accept ML-KEM ciphertext');

  // Verified against the identity snapshot taken when the invite was sent, NOT
  // against whatever identity is loaded now and not against anything the accept
  // asserts about us. That is what makes this catch a rewritten invite: if the
  // responder signed a different initiator identity, the transcript this side
  // rebuilds does not match the one that was signed.
  if (
    !ml_dsa65.verify(
      accept.signature,
      acceptTranscript(
        accept.conversationId,
        pending.selfIdentitySnapshot,
        accept.sender,
        accept.kemCiphertext,
        accept.ratchetPublic,
      ),
      accept.sender.sigPublic,
    )
  ) {
    fail('bad_signature', 'the accept is not signed by the identity it claims, or the invite was rewritten in flight');
  }

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
