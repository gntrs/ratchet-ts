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
  /** ML-KEM-768 post-quantum half. */
  readonly pqPublic: Uint8Array;
  readonly pqSecret: Uint8Array;
}

/** The publishable half of an identity. Safe to paste anywhere. */
export interface PublicIdentity {
  readonly classicalPublic: Uint8Array;
  readonly pqPublic: Uint8Array;
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

export type EnvelopeKind = 'invite' | 'accept' | 'message';

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
}

export interface AcceptPayload {
  readonly kind: 'accept';
  readonly sender: PublicIdentity;
  readonly conversationId: string;
  /** ML-KEM-768 encapsulation to the inviter's PQ public key. */
  readonly kemCiphertext: Uint8Array;
  /** Responder's first ratchet public key. */
  readonly ratchetPublic: Uint8Array;
}

export interface MessagePayload {
  readonly kind: 'message';
  readonly conversationId: string;
  /** Current ratchet public key of the sender. Drives the DH ratchet. */
  readonly ratchetPublic: Uint8Array;
  /** Index within the current sending chain. */
  readonly messageNumber: number;
  /** Length of the previous sending chain, so gaps can be reconstructed. */
  readonly previousChainLength: number;
  /** XChaCha20-Poly1305 nonce. */
  readonly nonce: Uint8Array;
  /** Sealed body, including Poly1305 tag. */
  readonly ciphertext: Uint8Array;
}

export type EnvelopePayload = InvitePayload | AcceptPayload | MessagePayload;

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
   * Keyed `${base64(ratchetPublic)}:${messageNumber}`.
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
  | 'identity_mismatch';

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
