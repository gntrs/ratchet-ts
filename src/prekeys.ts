import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from '@noble/hashes/utils.js';

import type {
  EnvelopeToken,
  IdentityKeyPair,
  IntroPayload,
  PrekeyBundle,
  PrekeySecrets,
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
 * Offline delivery: sending to somebody whose laptop is shut.
 *
 * ---------------------------------------------------------------------------
 * WHY THE THREE FLIGHT HANDSHAKE COULD NOT DO THIS
 * ---------------------------------------------------------------------------
 *
 * beginInvite, acceptInvite, completeInvite need both people running the
 * software at the same moment, because the responder contributes a fresh
 * ratchet key that the initiator cannot predict. That is fine for a tool where
 * two people agree to transfer a file and it is the single largest limitation
 * of the tool for everything else.
 *
 * A prekey bundle removes the round trips by having the recipient publish, in
 * advance, the values the responder would otherwise have contributed live. The
 * sender pulls the bundle, derives the root key alone, and sends one frame that
 * carries both the handshake and the first message. The recipient can open it
 * whenever it next runs. This is X3DH with a post-quantum arm, which is what
 * Signal ships as PQXDH.
 *
 * ---------------------------------------------------------------------------
 * WHAT GOES INTO THE ROOT, AND WHAT EACH PART IS FOR
 * ---------------------------------------------------------------------------
 *
 * Four secrets, concatenated in this order and fed to the same kdfHandshake the
 * live handshake uses:
 *
 *   DH1 = X25519(sender ephemeral, recipient IDENTITY key)
 *         Binds the recipient's long term identity, so the message is readable
 *         only by the identity the sender meant, not merely by whoever holds a
 *         prekey.
 *
 *   DH2 = X25519(sender IDENTITY key, recipient prekey)
 *         Binds the sender's long term identity. This is what makes the message
 *         attributable at all, and it is why an unauthenticated sender cannot
 *         produce one.
 *
 *   DH3 = X25519(sender ephemeral, recipient prekey)
 *         Forward secrecy. Neither long term key appears in it, so compromising
 *         both identities later does not recover this.
 *
 *   SS  = ML-KEM-768 encapsulation to the recipient's PQ prekey
 *         The post-quantum arm. As in the live handshake, the mixture is only
 *         as weak as its strongest surviving component.
 *
 * ---------------------------------------------------------------------------
 * THIS ALSO CLOSES THE GAP THE LIVE HANDSHAKE HAS
 * ---------------------------------------------------------------------------
 *
 * The README has said since 0.1.0 that the live handshake has no initiator side
 * forward secrecy before the first ratchet step, because the initiator's only
 * contribution is a long term key: record the wire today, steal the identity
 * file later, recover the root. The ephemeral above is exactly the missing
 * piece, and it is wiped before the frame leaves this function, so the value
 * that would let a future thief re-derive the root no longer exists anywhere by
 * the time the bytes are on the network.
 *
 * That makes offline delivery, counterintuitively, the stronger of the two
 * paths rather than a convenience with a caveat.
 *
 * ---------------------------------------------------------------------------
 * WHAT A BUNDLE DOES NOT SOLVE
 * ---------------------------------------------------------------------------
 *
 * REPLAY. A bundle is a static offer and one prekey can be used by many senders
 * and by the same sender twice. An attacker who records an intro frame can send
 * it again, and the recipient will derive the same root and open the same
 * message a second time. Signal solves this with one time prekeys, consumed on
 * use, plus a server that hands each out once. There is no server here, so
 * `openIntro` refuses a conversation id it has already opened and the caller has
 * to keep that set. `seenConversationIds` is not optional and not a cache: a
 * caller that passes an empty set every time has no replay protection at all,
 * which is why it is a required argument rather than an option with a default.
 *
 * ROTATION. The prekey is long lived until the caller replaces it. The longer
 * one is published the more messages share its forward secrecy, so
 * `publishPrekeys` is cheap on purpose and is meant to be called on a schedule.
 * Nothing here enforces that, because nothing here knows how the bundle is
 * distributed.
 */

const BUNDLE_DOMAIN = utf8ToBytes('OCX3 prekey bundle v1');
const INTRO_DOMAIN = utf8ToBytes('OCX3 intro transcript v1');

/** Same shape newConversationId produces in the live handshake. */
function newConversationId(): string {
  return toHex(randomBytes(16));
}

function requireLength(value: Uint8Array, expected: number, what: string): void {
  if (value.length !== expected) fail('malformed_token', `${what} must be ${expected} bytes, got ${value.length}`);
}

/** Length prefixed and domain separated, for the same reasons as handshake.ts. */
function transcript(domain: Uint8Array, parts: readonly Uint8Array[]): Uint8Array {
  const lengths = new Uint8Array(4 * parts.length);
  const view = new DataView(lengths.buffer);
  parts.forEach((part, i) => view.setUint32(i * 4, part.length, false));
  return concat(domain, lengths, ...parts);
}

function bundleTranscript(identity: PublicIdentity, classical: Uint8Array, pq: Uint8Array, createdAt: string): Uint8Array {
  return transcript(BUNDLE_DOMAIN, [
    utf8ToBytes(createdAt),
    identity.classicalPublic,
    identity.pqPublic,
    identity.sigPublic,
    classical,
    pq,
  ]);
}

function introTranscript(payload: {
  conversationId: string;
  sender: PublicIdentity;
  recipient: PublicIdentity;
  ephemeralPublic: Uint8Array;
  kemCiphertext: Uint8Array;
  ratchetPublic: Uint8Array;
  prekeyClassical: Uint8Array;
  prekeyPq: Uint8Array;
}): Uint8Array {
  return transcript(INTRO_DOMAIN, [
    utf8ToBytes(payload.conversationId),
    payload.sender.classicalPublic,
    payload.sender.pqPublic,
    payload.sender.sigPublic,
    payload.recipient.classicalPublic,
    payload.recipient.pqPublic,
    payload.recipient.sigPublic,
    payload.ephemeralPublic,
    payload.kemCiphertext,
    payload.ratchetPublic,
    // The prekeys the sender actually used. Without these an attacker holding
    // two of the recipient's published bundles could swap one for the other and
    // the signature would still verify, which would let them steer a sender
    // onto a prekey whose secret they had recovered.
    payload.prekeyClassical,
    payload.prekeyPq,
  ]);
}

/**
 * Mint a publishable bundle and the secrets that open messages sent to it.
 *
 * The two halves go to different places and that separation is the whole API:
 * `bundle` is meant to be published anywhere, `secrets` never leaves the device
 * and is what `openIntro` needs. Returning them as one object would invite a
 * caller to serialise the wrong half.
 *
 * `createdAt` is inside the signature so that a bundle cannot be silently
 * back-dated by whoever is hosting it. Nothing in this file enforces a maximum
 * age, because only the caller knows its own rotation policy, but the value is
 * signed so that a caller which does enforce one cannot be lied to.
 */
export function publishPrekeys(self: IdentityKeyPair, createdAt?: string): {
  bundle: PrekeyBundle;
  secrets: PrekeySecrets;
} {
  const classical = x25519Keygen();
  const pq = ml_kem768.keygen();
  const stamp = createdAt ?? new Date().toISOString();
  const identity = publicOf(self);

  const signature = ml_dsa65.sign(
    bundleTranscript(identity, classical.publicKey, pq.publicKey, stamp),
    self.sigSecret,
  );

  return {
    bundle: {
      identity,
      prekeyClassical: classical.publicKey,
      prekeyPq: pq.publicKey,
      createdAt: stamp,
      signature,
    },
    secrets: {
      prekeyClassicalSecret: classical.secretKey,
      prekeyPqSecret: pq.secretKey,
      prekeyClassicalPublic: classical.publicKey,
      prekeyPqPublic: pq.publicKey,
      createdAt: stamp,
    },
  };
}

/**
 * Check a bundle before using it, and say why if it is refused.
 *
 * Exported because a caller that fetches bundles from somewhere untrusted wants
 * to reject them at fetch time rather than at send time, and because a bundle
 * that fails here is a fact worth surfacing to a user: it means whoever served
 * it is not who they claim, or the file is corrupt.
 */
export function verifyBundle(bundle: PrekeyBundle): boolean {
  if (bundle.identity.classicalPublic.length !== X25519_PUBLIC_LEN) return false;
  if (bundle.identity.pqPublic.length !== MLKEM768_PUBLIC_LEN) return false;
  if (bundle.identity.sigPublic.length !== MLDSA65_PUBLIC_LEN) return false;
  if (bundle.prekeyClassical.length !== X25519_PUBLIC_LEN) return false;
  if (bundle.prekeyPq.length !== MLKEM768_PUBLIC_LEN) return false;
  if (bundle.signature.length !== MLDSA65_SIGNATURE_LEN) return false;
  return ml_dsa65.verify(
    bundle.signature,
    bundleTranscript(bundle.identity, bundle.prekeyClassical, bundle.prekeyPq, bundle.createdAt),
    bundle.identity.sigPublic,
  );
}

/**
 * Send to a bundle. One frame, no round trip, recipient may be asleep.
 *
 * Returns the intro token and a live session. The caller seals its own messages
 * with that session through the normal `engine.seal`, which is why this takes no
 * plaintext and never sees one: the intro frame carries the handshake, not the
 * message, and keeping them as two tokens means the offline path uses the same
 * message envelope as everything else rather than a second sealed format that
 * would need its own AAD argument.
 *
 * The session comes back already stepped past the handshake root, exactly as
 * completeInvite leaves it, so the first seal is an ordinary send.
 */
export function sealIntro(
  self: IdentityKeyPair,
  bundle: PrekeyBundle,
): { token: EnvelopeToken; session: SessionState; conversationId: string } {
  if (!verifyBundle(bundle)) {
    fail('bad_signature', 'the prekey bundle is not signed by the identity it claims');
  }

  const conversationId = newConversationId();
  const ephemeral = x25519Keygen();
  const kem = ml_kem768.encapsulate(bundle.prekeyPq);

  const dh1 = x25519SharedSecret(ephemeral.secretKey, bundle.identity.classicalPublic);
  const dh2 = x25519SharedSecret(self.classicalSecret, bundle.prekeyClassical);
  const dh3 = x25519SharedSecret(ephemeral.secretKey, bundle.prekeyClassical);
  const ikm = concat(dh1, dh2, dh3, kem.sharedSecret);
  const handshakeRoot = kdfHandshake(ikm, conversationId);
  wipe(dh1, dh2, dh3, ikm, kem.sharedSecret);

  // One ratchet step before the first message, mirroring completeInvite, so
  // message zero is already under a chain the recipient has never held a
  // private key for.
  const ratchet = x25519Keygen();
  const dh = x25519SharedSecret(ratchet.secretKey, bundle.prekeyClassical);
  const stepped = kdfRoot(handshakeRoot, dh);
  wipe(dh, handshakeRoot);

  const sender = publicOf(self);
  const signature = ml_dsa65.sign(
    introTranscript({
      conversationId,
      sender,
      recipient: bundle.identity,
      ephemeralPublic: ephemeral.publicKey,
      kemCiphertext: kem.cipherText,
      ratchetPublic: ratchet.publicKey,
      prekeyClassical: bundle.prekeyClassical,
      prekeyPq: bundle.prekeyPq,
    }),
    self.sigSecret,
  );

  const session: SessionState = {
    conversationId,
    role: 'initiator',
    peer: bundle.identity,
    rootKey: stepped.rootKey,
    selfRatchetPublic: ratchet.publicKey,
    selfRatchetSecret: ratchet.secretKey,
    peerRatchetPublic: bundle.prekeyClassical,
    sendChainKey: stepped.chainKey,
    sendCount: 0,
    recvCount: 0,
    previousSendCount: 0,
    skippedKeys: {},
  };

  // The ephemeral secret dies here, before the token exists. This is the line
  // that closes the initiator forward secrecy gap, so it is deliberately not at
  // the end of the function where a later edit could drift past it.
  wipe(ephemeral.secretKey);

  const token = encodeEnvelope({
    kind: 'intro',
    conversationId,
    sender,
    ephemeralPublic: ephemeral.publicKey,
    kemCiphertext: kem.cipherText,
    ratchetPublic: ratchet.publicKey,
    prekeyClassical: bundle.prekeyClassical,
    prekeyPq: bundle.prekeyPq,
    signature,
  });

  return { token, session, conversationId };
}

/**
 * Recipient side. Derives the same root from stored prekey secrets.
 *
 * `seenConversationIds` is required and is mutated on success. See the replay
 * paragraph in the header: without a server handing out one time prekeys, this
 * set is the only thing standing between a recorded intro and a message that
 * opens twice. A caller that cannot persist it does not have replay protection,
 * and should know that rather than discover it.
 */
export function openIntro(
  self: IdentityKeyPair,
  secrets: PrekeySecrets,
  intro: IntroPayload,
  seenConversationIds: Set<string>,
): SessionState {
  requireLength(intro.sender.classicalPublic, X25519_PUBLIC_LEN, 'intro classical public key');
  requireLength(intro.sender.pqPublic, MLKEM768_PUBLIC_LEN, 'intro ML-KEM public key');
  requireLength(intro.sender.sigPublic, MLDSA65_PUBLIC_LEN, 'intro ML-DSA public key');
  requireLength(intro.signature, MLDSA65_SIGNATURE_LEN, 'intro signature');
  requireLength(intro.ephemeralPublic, X25519_PUBLIC_LEN, 'intro ephemeral public key');
  requireLength(intro.kemCiphertext, MLKEM768_CIPHERTEXT_LEN, 'intro ML-KEM ciphertext');
  requireLength(intro.ratchetPublic, X25519_PUBLIC_LEN, 'intro ratchet public key');

  if (seenConversationIds.has(intro.conversationId)) {
    fail('replay_detected', 'this intro has already been opened');
  }

  // Before the KEM decapsulation, so an unauthenticated sender cannot make this
  // side do the expensive work, and before the prekey check so the error names
  // the more serious problem when both are wrong.
  if (
    !ml_dsa65.verify(
      intro.signature,
      introTranscript({
        conversationId: intro.conversationId,
        sender: intro.sender,
        recipient: publicOf(self),
        ephemeralPublic: intro.ephemeralPublic,
        kemCiphertext: intro.kemCiphertext,
        ratchetPublic: intro.ratchetPublic,
        prekeyClassical: intro.prekeyClassical,
        prekeyPq: intro.prekeyPq,
      }),
      intro.sender.sigPublic,
    )
  ) {
    fail('bad_signature', 'the intro is not signed by the identity it claims, or it was addressed to somebody else');
  }

  // Which prekey the sender used. A sender on a stale bundle is a normal thing
  // that happens whenever a bundle is rotated, and it has to be a named failure
  // rather than a silent wrong key that only shows up as an AEAD tag mismatch
  // three layers later.
  if (
    toHex(intro.prekeyClassical) !== toHex(secrets.prekeyClassicalPublic) ||
    toHex(intro.prekeyPq) !== toHex(secrets.prekeyPqPublic)
  ) {
    fail('no_session', 'this intro was sent to a prekey this device no longer holds');
  }

  const dh1 = x25519SharedSecret(self.classicalSecret, intro.ephemeralPublic);
  const dh2 = x25519SharedSecret(secrets.prekeyClassicalSecret, intro.sender.classicalPublic);
  const dh3 = x25519SharedSecret(secrets.prekeyClassicalSecret, intro.ephemeralPublic);
  const pq = ml_kem768.decapsulate(intro.kemCiphertext, secrets.prekeyPqSecret);
  const ikm = concat(dh1, dh2, dh3, pq);
  const handshakeRoot = kdfHandshake(ikm, intro.conversationId);
  wipe(dh1, dh2, dh3, pq, ikm);

  const session: SessionState = {
    conversationId: intro.conversationId,
    role: 'responder',
    peer: intro.sender,
    rootKey: handshakeRoot,
    // The recipient's ratchet key for this conversation IS the prekey, because
    // that is the public value the sender stepped against. It is a long lived
    // key doing a per conversation job for exactly one step, and the first
    // reply replaces it like any other ratchet step.
    selfRatchetPublic: secrets.prekeyClassicalPublic,
    selfRatchetSecret: secrets.prekeyClassicalSecret,
    sendCount: 0,
    recvCount: 0,
    previousSendCount: 0,
    skippedKeys: {},
  };

  seenConversationIds.add(intro.conversationId);
  return session;
}
