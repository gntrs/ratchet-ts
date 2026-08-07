import type {
  AcceptPayload,
  EnvelopeKind,
  EnvelopePayload,
  EnvelopeToken,
  InvitePayload,
  MessagePayload,
} from './contract.js';
import { bytesToUtf8, fromBase64Url, toBase64Url, utf8ToBytes } from './bytes.js';
import { fail } from './errors.js';

export const ENVELOPE_VERSION = 'OCX1';

/**
 * A compact binary body rather than JSON.
 *
 * An ML-KEM-768 public key is 1184 bytes on its own. JSON with base64 fields
 * inside a base64 token would inflate the accept envelope by roughly a third
 * for no benefit, and these tokens get pasted into chat apps by hand. Binary
 * also makes the encode/decode round trip trivially byte exact, which is a
 * property the message AAD depends on.
 *
 * Every variable length field is length prefixed and the reader refuses
 * trailing bytes, so there is exactly one encoding of any given payload.
 */

const KINDS: readonly EnvelopeKind[] = ['invite', 'accept', 'message'];

class Writer {
  private readonly parts: Uint8Array[] = [];
  private size = 0;

  u32(value: number): void {
    const buf = new Uint8Array(4);
    new DataView(buf.buffer).setUint32(0, value, false);
    this.raw(buf);
  }

  /** u16 length prefix covers every field we have, the largest being 2400. */
  blob(value: Uint8Array): void {
    if (value.length > 0xffff) throw new RangeError('field too long for a u16 length prefix');
    const buf = new Uint8Array(2);
    new DataView(buf.buffer).setUint16(0, value.length, false);
    this.raw(buf);
    this.raw(value);
  }

  text(value: string): void {
    this.blob(utf8ToBytes(value));
  }

  raw(value: Uint8Array): void {
    this.parts.push(value);
    this.size += value.length;
  }

  finish(): Uint8Array {
    const out = new Uint8Array(this.size);
    let at = 0;
    for (const p of this.parts) {
      out.set(p, at);
      at += p.length;
    }
    return out;
  }
}

class Reader {
  private at = 0;

  constructor(private readonly buf: Uint8Array) {}

  u32(): number {
    if (this.at + 4 > this.buf.length) fail('malformed_token', 'truncated integer field');
    const value = new DataView(this.buf.buffer, this.buf.byteOffset + this.at, 4).getUint32(0, false);
    this.at += 4;
    return value;
  }

  blob(): Uint8Array {
    if (this.at + 2 > this.buf.length) fail('malformed_token', 'truncated length prefix');
    const len = new DataView(this.buf.buffer, this.buf.byteOffset + this.at, 2).getUint16(0, false);
    this.at += 2;
    if (this.at + len > this.buf.length) fail('malformed_token', 'length prefix overruns the payload');
    // Copy rather than subarray: callers keep these around inside session state
    // and must not share a backing buffer with the decoded token.
    const out = this.buf.slice(this.at, this.at + len);
    this.at += len;
    return out;
  }

  text(): string {
    return bytesToUtf8(this.blob());
  }

  end(): void {
    if (this.at !== this.buf.length) fail('malformed_token', 'trailing bytes after the payload');
  }
}

function encodeBody(payload: EnvelopePayload): Uint8Array {
  const w = new Writer();
  switch (payload.kind) {
    case 'invite':
      w.text(payload.conversationId);
      w.blob(payload.sender.classicalPublic);
      w.blob(payload.sender.pqPublic);
      return w.finish();
    case 'accept':
      w.text(payload.conversationId);
      w.blob(payload.sender.classicalPublic);
      w.blob(payload.sender.pqPublic);
      w.blob(payload.kemCiphertext);
      w.blob(payload.ratchetPublic);
      return w.finish();
    case 'message':
      w.text(payload.conversationId);
      w.blob(payload.ratchetPublic);
      w.u32(payload.messageNumber);
      w.u32(payload.previousChainLength);
      w.blob(payload.nonce);
      // Ciphertext is last and still length prefixed, so a truncated paste is
      // caught by the reader rather than silently decrypting a shorter body.
      w.blob(payload.ciphertext);
      return w.finish();
  }
}

function decodeBody(kind: EnvelopeKind, body: Uint8Array): EnvelopePayload {
  const r = new Reader(body);
  switch (kind) {
    case 'invite': {
      const conversationId = r.text();
      const classicalPublic = r.blob();
      const pqPublic = r.blob();
      r.end();
      const out: InvitePayload = { kind, conversationId, sender: { classicalPublic, pqPublic } };
      return out;
    }
    case 'accept': {
      const conversationId = r.text();
      const classicalPublic = r.blob();
      const pqPublic = r.blob();
      const kemCiphertext = r.blob();
      const ratchetPublic = r.blob();
      r.end();
      const out: AcceptPayload = {
        kind,
        conversationId,
        sender: { classicalPublic, pqPublic },
        kemCiphertext,
        ratchetPublic,
      };
      return out;
    }
    case 'message': {
      const conversationId = r.text();
      const ratchetPublic = r.blob();
      const messageNumber = r.u32();
      const previousChainLength = r.u32();
      const nonce = r.blob();
      const ciphertext = r.blob();
      r.end();
      const out: MessagePayload = {
        kind,
        conversationId,
        ratchetPublic,
        messageNumber,
        previousChainLength,
        nonce,
        ciphertext,
      };
      return out;
    }
  }
}

export function encodeEnvelope(payload: EnvelopePayload): EnvelopeToken {
  return `${ENVELOPE_VERSION}.${payload.kind}.${toBase64Url(encodeBody(payload))}`;
}

/**
 * Binary envelope form, for transports that carry bytes rather than text.
 *
 * The string form spends 4 bytes of wire on every 3 bytes of payload because
 * base64 is 4/3 inflation. On a socket that is pure waste: the framing layer
 * already delimits messages, so there is nothing for base64 to protect against.
 * This form is the same body, unencoded, which is exactly 3/4 of the size once
 * the fixed prefix stops mattering.
 *
 * Two header bytes make it self describing, because unlike the string form
 * there is no `OCX1.<kind>.` prefix to carry that out of band:
 *
 *   [0] version marker, BINARY_ENVELOPE_VERSION
 *   [1] kind tag, see BINARY_KIND_TAGS
 *   [2..] the same body bytes the string form base64s
 *
 * The version marker is deliberately a value no OCX1 string token can start
 * with, so a token pasted into the byte path is rejected as a version problem
 * rather than being misread as a kind tag and a body.
 */
const BINARY_ENVELOPE_VERSION = 0x01;

const BINARY_KIND_TAGS: Readonly<Record<EnvelopeKind, number>> = {
  invite: 0x01,
  accept: 0x02,
  message: 0x03,
};

/** Index is the tag byte. Sparse on purpose: an unlisted byte is a hard reject. */
const BINARY_KIND_BY_TAG: readonly (EnvelopeKind | undefined)[] = [
  undefined,
  'invite',
  'accept',
  'message',
];

export function encodeEnvelopeBytes(payload: EnvelopePayload): Uint8Array {
  const body = encodeBody(payload);
  const out = new Uint8Array(2 + body.length);
  out[0] = BINARY_ENVELOPE_VERSION;
  out[1] = BINARY_KIND_TAGS[payload.kind];
  out.set(body, 2);
  return out;
}

export function decodeEnvelopeBytes(bytes: Uint8Array): EnvelopePayload {
  if (bytes.length < 2) fail('malformed_token', 'binary envelope is shorter than its two byte header');
  // Version before kind, same order as the string form, so a future OCX2 byte
  // stream reports "update your client" rather than "unknown kind".
  if (bytes[0] !== BINARY_ENVELOPE_VERSION) {
    fail('unknown_version', `unsupported binary envelope version ${bytes[0]}`);
  }
  const kind = BINARY_KIND_BY_TAG[bytes[1]!];
  if (kind === undefined) fail('malformed_token', `unknown envelope kind tag ${bytes[1]}`);
  // subarray, not slice: Reader copies every field it hands back, so nothing
  // that escapes this function shares a buffer with the caller's frame anyway,
  // and copying the whole body here would double the cost of the fast path.
  return decodeBody(kind, bytes.subarray(2));
}

export function decodeEnvelope(token: EnvelopeToken): EnvelopePayload {
  const trimmed = token.trim();
  const parts = trimmed.split('.');
  if (parts.length !== 3) fail('malformed_token', 'expected OCX1.<kind>.<payload>');
  const [version, kind, body] = parts as [string, string, string];
  // Version is checked before kind so a future OCX2 token reports the useful
  // "update your client" reason instead of "we do not know that kind".
  if (version !== ENVELOPE_VERSION) fail('unknown_version', `unsupported envelope version ${version}`);
  if (!KINDS.includes(kind as EnvelopeKind)) fail('malformed_token', `unknown envelope kind ${kind}`);
  const raw = fromBase64Url(body);
  if (raw === null) fail('malformed_token', 'payload is not valid base64url');
  return decodeBody(kind as EnvelopeKind, raw);
}

/**
 * Associated data for the AEAD.
 *
 * Everything in the header except the ciphertext is bound here. That is what
 * stops an attacker lifting a valid ciphertext out of one message and pasting
 * it into another envelope with a different conversation id, ratchet key, or
 * message number: the tag is computed over those fields, so any swap fails the
 * Poly1305 check instead of decrypting into the wrong chain position.
 */
export function messageAad(header: {
  conversationId: string;
  ratchetPublic: Uint8Array;
  messageNumber: number;
  previousChainLength: number;
  nonce: Uint8Array;
}): Uint8Array {
  const w = new Writer();
  w.raw(utf8ToBytes(ENVELOPE_VERSION));
  w.text(header.conversationId);
  w.blob(header.ratchetPublic);
  w.u32(header.messageNumber);
  w.u32(header.previousChainLength);
  w.blob(header.nonce);
  return w.finish();
}
