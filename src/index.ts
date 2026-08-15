/**
 * The public face of the crypto core.
 *
 * The UI imports this module and nothing else under src/. Every other file is
 * an implementation detail, and keeping the boundary at one module is what
 * lets the internals move (a different AEAD, a different skip policy) without
 * a single change on the React side.
 *
 * The methods are async even though nothing here awaits. The contract declares
 * them that way so this can move into a worker or a WASM backend later without
 * breaking every call site, and an async signature is the cheapest possible
 * option on that future.
 */

import type {
  PrekeySecrets,
  EnvelopeBytes,
  EnvelopeToken,
  Fingerprint,
  IdentityKeyPair,
  MessagingEngine,
  OpenResult,
  PendingSession,
  RatchetSnapshot,
  SessionState,
} from './contract.js';
import { toHex } from './bytes.js';
import type { EncodeEnvelopeBytesOptions } from './envelope.js';
import { decodeEnvelope, encodeEnvelope } from './envelope.js';
import { fail } from './errors.js';
import { acceptInvite, beginInvite, completeInvite } from './handshake.js';
import { createIdentity, fingerprint, publicOf, sameIdentity } from './identity.js';
import { openIntro } from './prekeys.js';
import {
  ratchetDecrypt,
  ratchetDecryptBytes,
  ratchetDecryptFromEnvelopeBytes,
  ratchetEncrypt,
  ratchetEncryptBytes,
  ratchetEncryptToEnvelopeBytes,
} from './ratchet.js';

async function engineCreateIdentity(): Promise<IdentityKeyPair> {
  return createIdentity();
}

async function engineInvite(
  self: IdentityKeyPair,
): Promise<{ token: EnvelopeToken; pending: PendingSession }> {
  return beginInvite(self);
}

async function engineSeal(
  session: SessionState,
  plaintext: string,
): Promise<{ token: EnvelopeToken; session: SessionState }> {
  const sealed = ratchetEncrypt(session, plaintext);
  return { token: encodeEnvelope(sealed.payload), session: sealed.session };
}

/**
 * Byte counterpart of `seal`. Same session advance, same token format: the
 * wire carries raw bytes either way, so a token from `sealBytes` opens under
 * `open` (as the UTF-8 decoding of the bytes) and a token from `seal` opens
 * under `openBytes` (as the exact UTF-8 encoding of the string). Use this
 * path for anything not guaranteed to be valid UTF-8: files, images,
 * protobuf.
 */
async function engineSealBytes(
  session: SessionState,
  plaintext: Uint8Array,
): Promise<{ token: EnvelopeToken; session: SessionState }> {
  const sealed = ratchetEncryptBytes(session, plaintext);
  return { token: encodeEnvelope(sealed.payload), session: sealed.session };
}

/**
 * Byte counterpart of `open`, deliberately narrower: message tokens only.
 * Handshake tokens (invite, accept) are protocol, not payload, and already
 * have a home in `open`, so a binary-payload caller is never forced to handle
 * handshake outcomes it cannot receive. No identity parameter for the same
 * reason: decrypting a ratcheted message needs only the session.
 */
async function engineOpenBytes(
  session: SessionState,
  token: EnvelopeToken,
): Promise<{ plaintext: Uint8Array; session: SessionState }> {
  const payload = decodeEnvelope(token);
  if (payload.kind !== 'message') {
    fail('malformed_token', `expected a message token, got ${payload.kind}`);
  }
  return ratchetDecryptBytes(session, payload);
}

/**
 * Envelope-bytes counterpart of `sealBytes`, for callers whose transport is
 * already binary. `sealBytes` hands back a pasteable token, which such a caller
 * then has to un-base64 straight back into the bytes it already had; this skips
 * that and emits the identical frame directly.
 *
 * `options.reserve` asks for N zero bytes in front of the envelope in the same
 * allocation, for a transport that prefixes a length and would otherwise have
 * to concatenate. The envelope itself is unchanged and starts at index N.
 */
async function engineSealToEnvelopeBytes(
  session: SessionState,
  plaintext: Uint8Array,
  options?: EncodeEnvelopeBytesOptions,
): Promise<{ envelope: EnvelopeBytes; session: SessionState }> {
  return ratchetEncryptToEnvelopeBytes(session, plaintext, options);
}

/**
 * Envelope-bytes counterpart of `openBytes`, message envelopes only, for the
 * same reason `openBytes` gives.
 */
async function engineOpenFromEnvelopeBytes(
  session: SessionState,
  envelope: EnvelopeBytes,
): Promise<{ plaintext: Uint8Array; session: SessionState }> {
  return ratchetDecryptFromEnvelopeBytes(session, envelope);
}

/**
 * One entry point for every inbound token, because the UI genuinely does not
 * know which stage it is in: a pasted blob could be a stranger's invite, the
 * accept it has been waiting for, or the next line of an ongoing chat. Making
 * the caller guess would push protocol state machine logic into a component.
 */
async function engineOpen(
  self: IdentityKeyPair,
  token: EnvelopeToken,
  context: {
    session?: SessionState;
    pending?: PendingSession;
    prekeys?: PrekeySecrets;
    seenConversationIds?: Set<string>;
  },
): Promise<OpenResult> {
  const payload = decodeEnvelope(token);

  switch (payload.kind) {
    case 'invite': {
      const accepted = acceptInvite(self, payload);
      return {
        outcome: 'invite',
        reply: accepted.token,
        session: accepted.session,
        peerFingerprint: fingerprint(payload.sender),
      };
    }

    case 'accept': {
      const pending = context.pending;
      if (!pending) fail('no_session', 'no pending invite for this accept');
      // The accept is only decryptable with the ML-KEM secret of the identity
      // that sent the invite. Checking first turns a confusing decapsulation
      // failure into an accurate "wrong account" message.
      if (!sameIdentity(pending.selfIdentitySnapshot, publicOf(self))) {
        fail('identity_mismatch', 'this accept answers an invite from a different identity');
      }
      const session = completeInvite(self, pending, payload);
      return {
        outcome: 'accepted',
        session,
        peerFingerprint: fingerprint(session.peer),
      };
    }

    case 'intro': {
      // Both are required, and neither has a default. Without the secrets there
      // is nothing to decapsulate with; without the seen set there is no replay
      // protection at all, and quietly substituting an empty one would make the
      // second delivery of a recorded intro open exactly like the first.
      const prekeys = context.prekeys;
      if (!prekeys) fail('no_session', 'no prekey secrets loaded, so an offline intro cannot be opened');
      const seen = context.seenConversationIds;
      if (!seen) {
        fail('no_session', 'openIntro needs the set of conversation ids already opened, to refuse a replayed intro');
      }
      const session = openIntro(self, prekeys, payload, seen);
      return { outcome: 'intro', session, peerFingerprint: fingerprint(payload.sender) };
    }

    case 'message': {
      const session = context.session;
      if (!session) fail('no_session', 'no session for this conversation');
      const opened = ratchetDecrypt(session, payload);
      return { outcome: 'message', plaintext: opened.plaintext, session: opened.session };
    }
  }
}

export const engine: MessagingEngine = {
  createIdentity: engineCreateIdentity,
  publicOf,
  fingerprint,
  invite: engineInvite,
  seal: engineSeal,
  sealBytes: engineSealBytes,
  open: engineOpen,
  openBytes: engineOpenBytes,
  sealToEnvelopeBytes: engineSealToEnvelopeBytes,
  openFromEnvelopeBytes: engineOpenFromEnvelopeBytes,
};

// ---------------------------------------------------------------------------
// Helpers the UI needs
// ---------------------------------------------------------------------------

/**
 * Six words on one line, spaced. Users compare these out loud over a channel
 * the app does not control, so the rendering has to be identical on both
 * devices or the comparison is worthless.
 */
export function formatFingerprint(value: Fingerprint): string {
  return value.words.join(' ');
}

/**
 * Display-only view of a live session.
 *
 * Forward secrecy is invisible by nature, so the demo has to render it. Only
 * truncated previews leave this function: a screenshot of the app must not be
 * a key disclosure.
 */
export function ratchetSnapshot(session: SessionState, label: string): RatchetSnapshot {
  const snapshot: RatchetSnapshot = {
    label,
    sendCount: session.sendCount,
    recvCount: session.recvCount,
    rootKeyPreview: toHex(session.rootKey.subarray(0, 4)),
    selfRatchetPreview: toHex(session.selfRatchetPublic.subarray(0, 4)),
    // Message keys are derived once, used once, and dropped. The count is the
    // honest number of keys that no longer exist anywhere.
    keysBurned: session.sendCount + session.recvCount,
    ...(session.peerRatchetPublic
      ? { peerRatchetPreview: toHex(session.peerRatchetPublic.subarray(0, 4)) }
      : {}),
  };
  return snapshot;
}

export { isCryptoFailure, CryptoFailureError } from './errors.js';
export { fingerprint, publicOf, sameIdentity } from './identity.js';
/**
 * The offline path. Deliberately not folded into `engine`, for the same reason
 * the binary codec is not: `engine` is the state machine two live peers drive,
 * and these three are about a conversation that starts with only one person
 * present. Keeping them separate means a caller that never wants offline
 * delivery does not have to think about prekey rotation or a replay set.
 *
 * `engine.open` still handles an inbound intro token, because a caller receiving
 * a token genuinely cannot know which kind it is until it decodes it, which is
 * the whole argument for `open` having one entry point.
 */
export { openIntro, publishPrekeys, sealIntro, verifyBundle } from './prekeys.js';
export { MAX_SKIP } from './ratchet.js';
export { ENVELOPE_VERSION, decodeEnvelope, encodeEnvelope } from './envelope.js';
/**
 * Binary envelope codec, additive in 0.3.0.
 *
 * Deliberately not folded into `engine`: these two do no crypto, they only
 * rewrite an already-sealed payload from one spelling into another. Everything
 * on `engine` advances a ratchet.
 *
 * THREE NAMES WITH "BYTES" IN THEM, AND WHICH LAYER EACH ONE MEANS. The word is
 * doing different work in each, and a caller who reads it as one word will pick
 * the wrong one, so the map is here rather than left to be inferred:
 *
 *   engine.sealBytes           the PLAINTEXT is bytes. Out comes a token, i.e.
 *                              base64url text, because the caller is going to
 *                              paste it or log it.
 *   encodeEnvelopeBytes        the ENVELOPE is bytes. In goes a payload that is
 *                              already sealed; no key is touched.
 *   engine.sealToEnvelopeBytes both at once, which is why it is the only one of
 *                              the three that has to say both. Plaintext bytes
 *                              in, envelope bytes out, no token in between.
 *
 * The third exists because composing the first two was the common case and the
 * composition was absurd: a caller on a binary transport base64ed the envelope
 * into a token and immediately decoded it straight back into the bytes it
 * already had. `openFromEnvelopeBytes` is the same story inbound.
 *
 * Rule of thumb for picking one. If the transport is a human, `seal` or
 * `sealBytes` and keep the token. If the transport is a socket or a file,
 * `sealToEnvelopeBytes` and never build a token at all. Reach for the codec
 * directly only when you have a payload from somewhere else and want the other
 * spelling of it.
 */
export { decodeEnvelopeBytes, encodeEnvelopeBytes } from './envelope.js';
export type {
  DecodeEnvelopeBytesOptions,
  EncodeEnvelopeBytesOptions,
} from './envelope.js';
/**
 * Reporting only. `aeadBackend()` says which implementation the next seal will
 * use so a slow run can be explained rather than guessed at. `sealAead` and
 * `openAead` are exposed because a caller already trusting this library for
 * XChaCha20-Poly1305 should not have to add a second cipher dependency to use
 * it outside a ratchet.
 */
export { aeadBackend, aeadReady, openAead, sealAead } from './aead.js';
/**
 * Same deal for the curves, and for the same reason: a handshake that takes
 * 27 ms instead of 5 ms is a backend question, not a mystery. `curveBackend()`
 * says which x25519 implementation the next key exchange will use.
 *
 * The raw curve operations are deliberately NOT exported the way `sealAead`
 * and `openAead` are. Nobody needs a bare x25519 from this package, and every
 * public primitive is one more thing that can be reached for and misused.
 */
export { curveBackend, curvesReady } from './curves.js';
/**
 * And the hashes, which matter more than the other two look like they should.
 * The chain step is two HMAC-SHA256 per message in each direction, so it runs
 * more often than any other primitive here, and on the JavaScript path it was
 * measured at about a third of the cost of sealing a chat sized message. If
 * this reports 'noble' on a machine that has node:crypto, the probe rejected
 * the native path and every message is paying for it.
 *
 * Raw `hmacSha256` and `hkdfSha256` stay unexported for the same reason the
 * curve operations do.
 */
export { hashBackend, hashReady } from './hash.js';
export {
  serializeSession,
  deserializeSession,
  serializePending,
  deserializePending,
  exportIdentity,
  importIdentity,
} from './serialize.js';
export type * from './contract.js';
