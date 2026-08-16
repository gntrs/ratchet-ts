/**
 * ratchet-ts public contract.
 *
 * Type-only. The crypto core and any consumer import from here so none of them
 * depend on each other's internals.
 *
 * ---------------------------------------------------------------------------
 * ARCHITECTURE, AND WHY IT IS THIS SHAPE
 * ---------------------------------------------------------------------------
 *
 * Two layers, borrowed from Signal because Signal is the design that survived
 * twelve years of people trying to break it:
 *
 *   1. HANDSHAKE (PQXDH-style). A hybrid of X25519 and ML-KEM-768. Both must
 *      be broken to recover the root key, so a future quantum computer that
 *      kills X25519 still faces ML-KEM, and a flaw found in ML-KEM (it is
 *      young) still faces X25519. This runs once per conversation.
 *
 *   2. DOUBLE RATCHET. After the handshake, every message advances a key
 *      chain, and every reply rotates a fresh X25519 pair. It buys two
 *      properties:
 *
 *        - Forward secrecy: stealing the device today does not decrypt
 *          yesterday's messages, because those keys were deleted after use.
 *        - Post-compromise security: if an attacker steals current keys but
 *          then goes quiet, the next reply rotates them back out.
 *
 * Being precise about the post-quantum claim, because overclaiming here is how
 * crypto products lose credibility: the PQ protection is in the HANDSHAKE.
 * The ratchet that follows is classical X25519. That is exactly what Signal's
 * PQXDH does today. It defeats harvest-now-decrypt-later, which is the actual
 * threat. It does not make every ratchet step quantum-safe, and no shipping
 * messenger currently does.
 *
 * ---------------------------------------------------------------------------
 * THE "NO CEREMONY" CLAIM, STATED HONESTLY
 * ---------------------------------------------------------------------------
 *
 * You cannot encrypt to someone whose public key you do not have. That is not
 * an engineering gap, it is what asymmetric crypto means. So the ceremony is
 * not eliminated, it is HIDDEN: folded into the first two messages of the
 * conversation and performed by the software rather than the human.
 *
 *   msg 1  Alice -> Bob    Invite   carries Alice's public keys. Not secret.
 *   msg 2  Bob   -> Alice  Accept   carries Bob's keys + ML-KEM ciphertext.
 *                                   Bob's client sends this automatically.
 *   msg 3+ both ways       Message  ratcheted, forward-secret.
 */

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/**
 * Long-term identity. Generated once per device, never leaves it.
 *
 * Secret halves are `Uint8Array` and are expected to be zeroed after use where
 * the runtime allows it. They must never be serialised into anything that
 * crosses the network or lands in a log.
 */
export interface IdentityKeyPair {
  /** X25519 classical half. */
  readonly classicalPublic: Uint8Array;
  readonly classicalSecret: Uint8Array;
  /** ML-KEM-768 post-quantum half, for confidentiality. */
  readonly pqPublic: Uint8Array;
  readonly pqSecret: Uint8Array;
  /**
   * ML-DSA-65 signing half, for authenticity. Added in 0.6.0.
   *
   * The KEM half above defeats harvest-now-decrypt-later: a recorded session
   * cannot be read once a quantum computer exists. It does nothing about an
   * adversary standing in the middle of a LIVE handshake, because until 0.6.0
   * the only thing binding a handshake to an identity was X25519, and an
   * adversary who can break X25519 can produce both sides of that binding. So
   * confidentiality was post-quantum and authenticity was not, which is a
   * strange pair of promises to ship together and the README said so.
   */
  readonly sigPublic: Uint8Array;
  readonly sigSecret: Uint8Array;
  /**
   * This identity, signed by its own signing key, computed once at creation.
   *
   * It is what an invite carries instead of a fresh signature per handshake.
   * See `certifyIdentity` in identity.ts for why a per invite signature was
   * costing 8 ms and proving nothing the fingerprint and the accept transcript
   * did not already prove.
   */
  readonly certificate: Uint8Array;
}

/** The publishable half of an identity. Safe to paste anywhere. */
export interface PublicIdentity {
  readonly classicalPublic: Uint8Array;
  readonly pqPublic: Uint8Array;
  /** ML-DSA-65 verifying key. See IdentityKeyPair.sigPublic. */
  readonly sigPublic: Uint8Array;
}

/**
 * Short human-checkable fingerprint of a `PublicIdentity`, for out-of-band
 * verification ("read me your six words").
 *
 * This is the honest answer to man-in-the-middle. The invisible handshake
 * means nobody verified anything, so a hostile transport could swap keys on
 * message one. Fingerprint comparison is what closes that hole, and the UI
 * must offer it rather than pretending the problem does not exist.
 */
export interface Fingerprint {
  /** Six words from a fixed wordlist. Easy to read aloud. */
  readonly words: readonly string[];
  /** Hex form, for people who prefer it. */
  readonly hex: string;
}

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

export type EnvelopeKind = 'invite' | 'accept' | 'message' | 'intro';

/**
 * What actually gets pasted into a chat, or anywhere else.
 *
 * Encoded as `OCX1.<kind>.<base64url payload>`. Deliberately marked rather
 * than disguised. A visible marker means the recipient without the library
 * sees something explicable instead of line noise.
 */
export type EnvelopeToken = string;

/**
 * The same three payloads in self-describing binary form.
 *
 * `EnvelopeToken` exists to be pasted into a chat box, and base64url is what
 * makes that possible. It also costs a third of the body on every frame. Where
 * the transport is already binary (a socket, a file, a BLOB column) that third
 * buys nothing, so `encodeEnvelopeBytes` writes the same fields with a one byte
 * version and a one byte kind in front instead. The kind travels in the bytes,
 * so decoding needs no out-of-band hint.
 *
 * The two forms are alternative encodings of one payload, not two protocols.
 * Neither is a wrapper over the other: converting means decode then re-encode.
 */
export type EnvelopeBytes = Uint8Array;

export interface InvitePayload {
  readonly kind: 'invite';
  readonly sender: PublicIdentity;
  /** Random id tying an accept back to its invite. */
  readonly conversationId: string;
  /**
   * The sender's identity certificate: ML-DSA-65 over its own three public
   * keys, signed once when the identity was created and reused for every
   * invite it ever sends.
   *
   * It says "these three keys are one identity, asserted by the holder of the
   * signing key". It deliberately does NOT cover the conversation id, because
   * that bound an invite to one conversation while invites stayed replayable
   * verbatim anyway, and it never proved possession of the X25519 or ML-KEM
   * halves in either shape. The protection against a machine in the middle is
   * the accept transcript, which is per handshake and stays that way.
   */
  readonly certificate: Uint8Array;
}

export interface AcceptPayload {
  readonly kind: 'accept';
  readonly sender: PublicIdentity;
  readonly conversationId: string;
  /** ML-KEM-768 encapsulation to the inviter's PQ public key. */
  readonly kemCiphertext: Uint8Array;
  /** Responder's first ratchet public key. */
  readonly ratchetPublic: Uint8Array;
  /**
   * ML-DSA-65 over the accept transcript, which includes the initiator's whole
   * identity. That binding is what stops a quantum adversary from accepting an
   * invite in somebody else's name.
   */
  readonly signature: Uint8Array;
}

/**
 * A sealed message on the wire.
 *
 * WHAT CHANGED IN 0.4.0, AND WHY THE FIELDS LOOK THIN. 0.3.x put the whole
 * conversation id, the whole ratchet public key, both counters and a 24 byte
 * nonce on every message, for 122 bytes of overhead. This carries a 4 byte
 * session tag, a varint counter, a 12 byte nonce, and the ratchet key only on
 * the first few messages of a chain, for 34 bytes in the common case.
 *
 * The fields that left the wire did not leave the AEAD. The full 16 byte
 * conversation id and the full 32 byte ratchet public key are still bound as
 * associated data, rebuilt on the receiving side from session state. Binding
 * data that is not transmitted is exactly what associated data is for, and the
 * alternative would have been a real loss of cross-conversation binding.
 */
export interface MessagePayload {
  readonly kind: 'message';
  /**
   * First 4 bytes of the 16 byte conversation id, raw.
   *
   * Enough to route an inbound frame to the right session on a host with a
   * plausible number of conversations, and not enough to be the security
   * binding. The receiver checks it against its own session, then binds all 16
   * bytes into the AEAD, so a tag collision routes to the wrong session and then
   * fails to open rather than opening as the wrong conversation.
   */
  readonly sessionTag: Uint8Array;
  /** Index within the current sending chain. */
  readonly messageNumber: number;
  /**
   * Sender's current ratchet public key, present only when the sender chose to
   * repeat it. See RATCHET_KEY_RESEND in the ratchet for how often that is and
   * what it costs when it is not.
   */
  readonly ratchetPublic?: Uint8Array;
  /**
   * Length of the previous sending chain. Travels with the ratchet key, because
   * it is only actionable by a receiver that is being asked to step the ratchet.
   */
  readonly previousChainLength?: number;
  /**
   * The 12 byte RFC 8439 nonce this message was sealed under, random per seal.
   *
   * It is on the wire because it has to be: the receiver cannot derive it, which
   * is the entire point. A derived nonce was built and rejected, and the
   * NONCE_LEN comment in the ratchet is where that argument lives. Last field
   * before the ciphertext, and bound into the AEAD like every other header
   * field, so flipping a bit of it is an authentication failure rather than a
   * garbled decrypt.
   */
  readonly nonce: Uint8Array;
  /** Sealed body, including the 16 byte Poly1305 tag. */
  readonly ciphertext: Uint8Array;
}

/**
 * The offline path, added in 0.6.0. One frame that carries a whole handshake,
 * so the recipient does not have to be running anything when it is sent.
 *
 * It is large: identity, ephemeral, KEM ciphertext, ratchet key, both prekeys
 * it was addressed to, and a signature. That is the price of not having a round
 * trip, it is paid once per conversation, and the messages after it are the
 * same 34 byte envelopes as any other conversation.
 */
export interface IntroPayload {
  readonly kind: 'intro';
  readonly conversationId: string;
  readonly sender: PublicIdentity;
  /**
   * Single use X25519 key whose secret is wiped before the frame is built.
   *
   * This is what gives the offline path the initiator side forward secrecy the
   * live handshake does not have. Recording this frame and stealing the
   * sender's identity file afterwards does not recover the root key, because
   * the other half of DH1 and DH3 stopped existing before the bytes were sent.
   */
  readonly ephemeralPublic: Uint8Array;
  /** ML-KEM-768 encapsulation to the recipient's PQ prekey. */
  readonly kemCiphertext: Uint8Array;
  /** Sender's first ratchet public key. */
  readonly ratchetPublic: Uint8Array;
  /**
   * The prekeys this frame was addressed to, echoed back.
   *
   * Signed, so an attacker holding two of a recipient's published bundles
   * cannot swap one for the other and steer a sender onto a prekey whose secret
   * they have recovered. Also what lets the recipient say "that is a prekey I
   * have rotated away from" instead of failing an AEAD tag three layers later.
   */
  readonly prekeyClassical: Uint8Array;
  readonly prekeyPq: Uint8Array;
  readonly signature: Uint8Array;
}

/**
 * What a recipient publishes so that people can write to them while they are
 * offline. Safe to put anywhere: it is all public keys and a signature over
 * them.
 */
export interface PrekeyBundle {
  readonly identity: PublicIdentity;
  /** X25519 prekey. Rotate by calling publishPrekeys again. */
  readonly prekeyClassical: Uint8Array;
  /** ML-KEM-768 prekey, the post-quantum arm of the offline handshake. */
  readonly prekeyPq: Uint8Array;
  /** ISO 8601. Inside the signature, so a host cannot back-date a bundle. */
  readonly createdAt: string;
  /** ML-DSA-65 over the identity, both prekeys and the timestamp. */
  readonly signature: Uint8Array;
}

/**
 * The half of a published bundle that never leaves the device.
 *
 * Carries the public halves too, so that `openIntro` can tell "addressed to a
 * prekey I have rotated away from" apart from "addressed to me and corrupt",
 * without the caller having to keep the bundle alongside it.
 */
export interface PrekeySecrets {
  readonly prekeyClassicalSecret: Uint8Array;
  readonly prekeyClassicalPublic: Uint8Array;
  readonly prekeyPqSecret: Uint8Array;
  readonly prekeyPqPublic: Uint8Array;
  readonly createdAt: string;
}

export type EnvelopePayload = InvitePayload | AcceptPayload | MessagePayload | IntroPayload;

// ---------------------------------------------------------------------------
// AEAD backend
// ---------------------------------------------------------------------------

/**
 * Which XChaCha20-Poly1305 implementation is doing the work.
 *
 * `native` is node:crypto's ChaCha20-Poly1305 with the nonce extended in
 * TypeScript; `noble` is @noble/ciphers. They are selected automatically and
 * produce byte-identical output for every input, so this is reporting, not
 * configuration. It is exported because "why is this slow" is answerable only
 * if a caller can see which one it got, and a browser or a locked-down runtime
 * legitimately gets `noble`.
 */
export type AeadBackend = 'native' | 'noble';

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

/**
 * One conversation's ratchet state.
 *
 * Persisted per conversation. Losing it means losing the ability to read that
 * conversation, which is the intended tradeoff: there is no server-side
 * escrow, so there is nothing for anyone to hand over.
 */
export interface SessionState {
  readonly conversationId: string;
  /**
   * The same 16 bytes as `conversationId`, unhexed, cached.
   *
   * `conversationId` stays the canonical hex form because it is what the
   * handshake generates, what the invite and accept envelopes carry, and what
   * every caller has been printing and comparing since 0.1.0. But the message
   * path now needs the raw bytes on every seal and every open, to slice a
   * session tag off the front and to bind all 16 into the AEAD, and parsing 32
   * hex characters per message to get them is a cost with no reason to exist.
   *
   * Optional so that a session built by the handshake, which does not know about
   * this field, is still a valid SessionState. The ratchet fills it in on the
   * first message and every session it returns carries it, so the parse happens
   * at most once per session rather than once per message.
   */
  readonly conversationIdBytes?: Uint8Array;
  readonly role: 'initiator' | 'responder';
  /** Peer identity, pinned at handshake. A change here is a MITM signal. */
  readonly peer: PublicIdentity;
  /** Root key, advanced on every DH ratchet step. */
  readonly rootKey: Uint8Array;
  /** Our current ratchet keypair. */
  readonly selfRatchetPublic: Uint8Array;
  readonly selfRatchetSecret: Uint8Array;
  /** Peer's latest ratchet public, once seen. */
  readonly peerRatchetPublic?: Uint8Array;
  /**
   * The peer ratchet public from the chain before the current one.
   *
   * Needed only because the ratchet key left the wire. A message that does not
   * carry the key is attributed to the current receive chain, and a message that
   * was in flight across a direction change belongs to the one before it. Its
   * AAD binds that older key, so without this field there is nothing to rebuild
   * the AAD from and a late message from the previous chain could not be opened
   * at all. One chain back is the whole window; see `parkedCandidates`.
   */
  readonly previousPeerRatchetPublic?: Uint8Array;
  /**
   * Counts DH ratchet steps taken on the receive side. Purely local, never on
   * the wire, and its only job is to key `skippedKeys` with a small integer
   * instead of a base64 encoding of a 32 byte public key. Optional so a session
   * built by the handshake, which has taken no steps, is still valid.
   */
  readonly peerChainEpoch?: number;
  /** Sending chain. Undefined until the first DH step completes. */
  readonly sendChainKey?: Uint8Array;
  readonly sendCount: number;
  /** Receiving chain. */
  readonly recvChainKey?: Uint8Array;
  readonly recvCount: number;
  /** Length of our previous sending chain, reported in each message. */
  readonly previousSendCount: number;
  /**
   * Message keys for messages that arrived out of order, or not yet at all.
   * Keyed `${peerChainEpoch}:${messageNumber}`.
   *
   * The key used to be `${base64(ratchetPublic)}:${messageNumber}`, which meant
   * base64 encoding 32 bytes on every open just to probe a map that is empty in
   * the common case. The epoch is a small integer that identifies the same chain
   * for the same purpose, and it is local state, so nothing on the wire moved.
   *
   * Bounded, and must stay bounded: an attacker who can make us skip forever
   * would otherwise have a memory exhaustion primitive. See MAX_SKIP in the
   * implementation.
   */
  readonly skippedKeys: Readonly<Record<string, Uint8Array>>;
}

/** A session that has been started but not yet answered. */
export interface PendingSession {
  readonly conversationId: string;
  readonly role: 'initiator';
  readonly selfIdentitySnapshot: PublicIdentity;
  readonly createdAt: string;
}

// ---------------------------------------------------------------------------
// Engine surface
// ---------------------------------------------------------------------------

/** Result of opening an envelope: either plaintext, or a state transition. */
export type OpenResult =
  | {
      readonly outcome: 'message';
      readonly plaintext: string;
      readonly session: SessionState;
    }
  | {
      /** An invite arrived. Caller should send `reply` back automatically. */
      readonly outcome: 'invite';
      readonly reply: EnvelopeToken;
      readonly session: SessionState;
      readonly peerFingerprint: Fingerprint;
    }
  | {
      /** Our invite was accepted. Session is now live. */
      readonly outcome: 'accepted';
      readonly session: SessionState;
      readonly peerFingerprint: Fingerprint;
    }
  | {
      /**
       * An offline intro arrived: a whole handshake in one frame, sent while
       * this device was not running. The session is live and can already
       * receive, and the message that came with it is a separate token the
       * caller opens with this session.
       *
       * Deliberately a different outcome from 'invite'. They look similar and
       * they are not: an invite is a request to reply, an intro is a completed
       * handshake somebody performed without us, and a UI that treated them the
       * same would offer to send an accept that nobody is waiting for.
       */
      readonly outcome: 'intro';
      readonly session: SessionState;
      readonly peerFingerprint: Fingerprint;
    };

/**
 * Why an open failed. Distinguished because a caller must say different things:
 * a replay is suspicious, a missing session is ordinary, a tampered ciphertext
 * is alarming.
 */
export type CryptoFailureReason =
  | 'malformed_token'
  | 'unknown_version'
  | 'no_session'
  | 'authentication_failed'
  | 'replay_detected'
  | 'skip_limit_exceeded'
  | 'identity_mismatch'
  | 'bad_signature';

export interface CryptoFailure {
  readonly reason: CryptoFailureReason;
  readonly message: string;
}

/**
 * The whole public API of the crypto core. Everything else is an
 * implementation detail and must not be imported across the boundary.
 */
export interface MessagingEngine {
  createIdentity(): Promise<IdentityKeyPair>;
  publicOf(identity: IdentityKeyPair): PublicIdentity;
  fingerprint(identity: PublicIdentity): Fingerprint;

  /** Begin a conversation. Returns the invite to paste, plus pending state. */
  invite(self: IdentityKeyPair): Promise<{
    token: EnvelopeToken;
    pending: PendingSession;
  }>;

  /** Encrypt into an existing session. Returns token and advanced state. */
  seal(
    session: SessionState,
    plaintext: string,
  ): Promise<{ token: EnvelopeToken; session: SessionState }>;

  /**
   * Encrypt raw bytes into an existing session. Same wire format as `seal`:
   * the string API is a UTF-8 view over this one, so tokens from either API
   * open under both.
   */
  sealBytes(
    session: SessionState,
    plaintext: Uint8Array,
  ): Promise<{ token: EnvelopeToken; session: SessionState }>;

  /**
   * Handle any inbound token. Dispatches on kind, so callers do not have to
   * know which stage of the handshake they are in.
   */
  open(
    self: IdentityKeyPair,
    token: EnvelopeToken,
    context: {
      session?: SessionState;
      pending?: PendingSession;
      /**
       * Needed only to open an offline `intro`. Both prekey fields are required
       * together: without the secrets there is nothing to decapsulate with, and
       * without the seen set there is no replay protection, so neither has a
       * default and leaving either out is an error that says which.
       */
      prekeys?: PrekeySecrets;
      /** Conversation ids already opened. Mutated on success. */
      seenConversationIds?: Set<string>;
    },
  ): Promise<OpenResult>;

  /**
   * Decrypt a message token to raw bytes. Message tokens only: handshake
   * tokens go through `open`, which owns the state machine.
   */
  openBytes(
    session: SessionState,
    token: EnvelopeToken,
  ): Promise<{ plaintext: Uint8Array; session: SessionState }>;

  /**
   * Byte-native counterpart of `sealBytes`: plaintext bytes in, envelope bytes
   * out, with no token built at any point. The name spells the envelope side
   * out because `sealBytes` already holds the short name for the plaintext
   * side, and a caller who confused the two would base64 a binary frame onto a
   * binary transport, which is the exact waste this method deletes.
   *
   * The frame is byte identical to `encodeEnvelopeBytes` of the token
   * `sealBytes` would have produced for the same session and plaintext, so a
   * peer on an older release cannot tell which method the sender used.
   *
   * `options.reserve` leaves that many zero bytes in front of the envelope,
   * inside the same allocation, for a transport that prefixes each frame with
   * its own length. Filling them in place is the difference between one buffer
   * per frame and two, and it is the last full-size copy on the send path. The
   * envelope bytes themselves are unchanged, so the wire is unchanged: the
   * reserved head is the caller's, and the caller decides what goes in it.
   */
  sealToEnvelopeBytes(
    session: SessionState,
    plaintext: Uint8Array,
    options?: { readonly reserve?: number },
  ): Promise<{ envelope: EnvelopeBytes; session: SessionState }>;

  /**
   * Byte-native counterpart of `openBytes`, narrow for the same reason:
   * message envelopes only, because invite and accept are protocol steps that
   * produce a session rather than a payload, and a caller pulling chunks off a
   * socket has nothing to do with one.
   */
  openFromEnvelopeBytes(
    session: SessionState,
    envelope: EnvelopeBytes,
  ): Promise<{ plaintext: Uint8Array; session: SessionState }>;
}

// ---------------------------------------------------------------------------
// Instrumentation
// ---------------------------------------------------------------------------

/**
 * Types so a UI can render key state without reaching into session internals.
 * Truncated fingerprints only, never real key material, so that screenshots
 * are safe.
 */
export interface RatchetSnapshot {
  readonly label: string;
  readonly sendCount: number;
  readonly recvCount: number;
  /** First 8 hex chars of the current root key. Display only. */
  readonly rootKeyPreview: string;
  readonly selfRatchetPreview: string;
  readonly peerRatchetPreview?: string;
  /** Keys destroyed so far. The forward-secrecy number worth showing. */
  readonly keysBurned: number;
}

export interface TranscriptEntry {
  readonly id: string;
  readonly from: 'alice' | 'bob';
  readonly plaintext: string;
  readonly token: EnvelopeToken;
  readonly kind: EnvelopeKind;
  readonly at: string;
}
