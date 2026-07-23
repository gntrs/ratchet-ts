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
import { decodeEnvelope, encodeEnvelope } from './envelope.js';
import { fail } from './errors.js';
import { acceptInvite, beginInvite, completeInvite } from './handshake.js';
import { createIdentity, fingerprint, publicOf, sameIdentity } from './identity.js';
import { ratchetDecrypt, ratchetEncrypt } from './ratchet.js';

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
 * One entry point for every inbound token, because the UI genuinely does not
 * know which stage it is in: a pasted blob could be a stranger's invite, the
 * accept it has been waiting for, or the next line of an ongoing chat. Making
 * the caller guess would push protocol state machine logic into a component.
 */
async function engineOpen(
  self: IdentityKeyPair,
  token: EnvelopeToken,
  context: { session?: SessionState; pending?: PendingSession },
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
  open: engineOpen,
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
export { MAX_SKIP } from './ratchet.js';
export { ENVELOPE_VERSION, decodeEnvelope, encodeEnvelope } from './envelope.js';
export type * from './contract.js';
