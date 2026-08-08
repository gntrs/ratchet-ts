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

/**
 * Accumulates the pieces of a body and then writes them out exactly once.
 *
 * The point of keeping the pieces rather than growing a buffer is that the
 * total is known before a single byte moves, so the caller can allocate the
 * final destination, header and all, and have the body land straight into it.
 * That is why `writeInto` exists alongside `finish`: `finish` is the
 * convenience for the string path, which needs a standalone body to base64,
 * and `writeInto` is what `encodeEnvelopeBytes` uses to avoid building a body
 * buffer only to immediately copy it somewhere two bytes to the right.
 */
class Writer {
  private readonly parts: Uint8Array[] = [];
  private size = 0;

  /** Bytes the accumulated parts will occupy. Known before anything is copied. */
  get length(): number {
    return this.size;
  }

  u32(value: number): void {
    // Written by hand rather than through a DataView: same big endian bytes,
    // same ToUint32 truncation, one fewer object allocated per field.
    const buf = new Uint8Array(4);
    buf[0] = (value >>> 24) & 0xff;
    buf[1] = (value >>> 16) & 0xff;
    buf[2] = (value >>> 8) & 0xff;
    buf[3] = value & 0xff;
    this.raw(buf);
  }

  /** u16 length prefix covers every field we have, the largest being 2400. */
  blob(value: Uint8Array): void {
    if (value.length > 0xffff) throw new RangeError('field too long for a u16 length prefix');
    const buf = new Uint8Array(2);
    buf[0] = (value.length >>> 8) & 0xff;
    buf[1] = value.length & 0xff;
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

  /** Copies the parts into `out` starting at `at`. Returns the end offset. */
  writeInto(out: Uint8Array, at: number): number {
    let cursor = at;
    for (const p of this.parts) {
      out.set(p, cursor);
      cursor += p.length;
    }
    return cursor;
  }

  finish(): Uint8Array {
    const out = new Uint8Array(this.size);
    this.writeInto(out, 0);
    return out;
  }
}

class Reader {
  private at = 0;

  constructor(private readonly buf: Uint8Array) {}

  u32(): number {
    if (this.at + 4 > this.buf.length) fail('malformed_token', 'truncated integer field');
    const b = this.buf;
    const i = this.at;
    // Same big endian read a DataView would do, without allocating one.
    const value = ((b[i]! << 24) | (b[i + 1]! << 16) | (b[i + 2]! << 8) | b[i + 3]!) >>> 0;
    this.at += 4;
    return value;
  }

  /** Bounds checked u16 length prefix. Leaves `at` on the first field byte. */
  private fieldLength(): number {
    if (this.at + 2 > this.buf.length) fail('malformed_token', 'truncated length prefix');
    const len = (this.buf[this.at]! << 8) | this.buf[this.at + 1]!;
    this.at += 2;
    if (this.at + len > this.buf.length) fail('malformed_token', 'length prefix overruns the payload');
    return len;
  }

  /**
   * A copy. This is the default and it is the right default.
   *
   * Callers keep these around inside session state and must not share a backing
   * buffer with the decoded token. A socket reader that pools or reuses its
   * read buffer would otherwise watch a stored ratchet key or nonce change
   * underneath it, which is a bug that reproduces only under load.
   *
   * Constructing a fresh Uint8Array rather than calling `this.buf.slice()`,
   * because slice only copies for a plain Uint8Array. Node's Buffer inherits
   * from Uint8Array but overrides slice as a deprecated alias of subarray,
   * which shares memory. A Buffer is exactly what a socket hands the CLI on
   * every frame, so the one input shape this guarantee mattered most for was
   * the one shape that silently did not get it. This also normalises the
   * output: a decoded field is a Uint8Array whatever the caller passed in.
   */
  blob(): Uint8Array {
    const len = this.fieldLength();
    const out = new Uint8Array(this.buf.subarray(this.at, this.at + len));
    this.at += len;
    return out;
  }

  /**
   * A view, opt in, and only ever used for the ciphertext.
   *
   * READ THE PARAGRAPH ABOVE BEFORE REACHING FOR THIS. The copy that `blob`
   * makes is not paranoia and it must not be "simplified away" for
   * `ratchetPublic` or `nonce`: those two land in long lived session state, and
   * the whole reason `blob` copies is that they must outlive a transient
   * network buffer.
   *
   * The ciphertext is the one field with a different life. It is handed
   * straight to the AEAD, read once, and dropped; nothing that survives the
   * call retains it. Copying 64 KiB per chunk so that it can be read once and
   * discarded was measured at more than a tenth of the whole receive path.
   *
   * Still opt in rather than automatic, because the caller is the only one who
   * knows whether it is going to reuse the frame buffer. `decodeEnvelopeBytes`
   * defaults to copying, so the default behaviour of the public API is
   * unchanged and no existing caller can be surprised by this.
   *
   * A plain Uint8Array over the same memory rather than `subarray`, because
   * Buffer.prototype.subarray hands back a Buffer, and a decoded field being a
   * Uint8Array whatever came in is a promise the copying path already makes.
   */
  blobView(): Uint8Array {
    const len = this.fieldLength();
    const out = new Uint8Array(this.buf.buffer, this.buf.byteOffset + this.at, len);
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

/**
 * The field order, and nothing else. Returns the Writer rather than its bytes
 * so a caller that already knows where the body belongs can have it written
 * there directly instead of into a temporary.
 */
function bodyWriter(payload: EnvelopePayload): Writer {
  const w = new Writer();
  switch (payload.kind) {
    case 'invite':
      w.text(payload.conversationId);
      w.blob(payload.sender.classicalPublic);
      w.blob(payload.sender.pqPublic);
      return w;
    case 'accept':
      w.text(payload.conversationId);
      w.blob(payload.sender.classicalPublic);
      w.blob(payload.sender.pqPublic);
      w.blob(payload.kemCiphertext);
      w.blob(payload.ratchetPublic);
      return w;
    case 'message':
      w.text(payload.conversationId);
      w.blob(payload.ratchetPublic);
      w.u32(payload.messageNumber);
      w.u32(payload.previousChainLength);
      w.blob(payload.nonce);
      // Ciphertext is last and still length prefixed, so a truncated paste is
      // caught by the reader rather than silently decrypting a shorter body.
      w.blob(payload.ciphertext);
      return w;
  }
}

function encodeBody(payload: EnvelopePayload): Uint8Array {
  return bodyWriter(payload).finish();
}

function decodeBody(
  kind: EnvelopeKind,
  body: Uint8Array,
  borrowCiphertext = false,
): EnvelopePayload {
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
      // The only field that is ever a view, and only when the caller asked.
      // See Reader.blobView for why this one and not the two above it.
      const ciphertext = borrowCiphertext ? r.blobView() : r.blob();
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

export interface EncodeEnvelopeBytesOptions {
  /**
   * Leave this many untouched bytes in front of the envelope.
   *
   * The returned array is `reserve + envelopeLength` long, the reserved bytes
   * are zero, and the envelope starts at index `reserve`. It exists so a
   * transport with a fixed size header can write that header into the buffer it
   * was handed rather than allocating a second buffer and copying a whole
   * envelope into it one byte later. Length prefixed framing is the case that
   * motivated it, and at 64 KiB a chunk that copy was the single largest
   * avoidable cost on the send path.
   *
   * Zero, absent, and the whole options object being absent all mean the same
   * thing: an envelope starting at index 0, exactly as before.
   */
  readonly reserve?: number;
}

/**
 * One allocation, one pass.
 *
 * The body length is known from the field sizes before any byte moves, so the
 * header, the optional reserved prefix and the body all land in the same array
 * on the first and only copy. The previous shape built the body into its own
 * buffer and then copied that buffer two bytes to the right, which meant every
 * envelope was written twice.
 *
 * Options are an object rather than a bare number on purpose: this function is
 * exactly the shape people pass to `Array.prototype.map`, which would hand a
 * bare second parameter the element index. An object bag reads `undefined` out
 * of a stray number and behaves as if nothing was passed.
 */
export function encodeEnvelopeBytes(
  payload: EnvelopePayload,
  options?: EncodeEnvelopeBytesOptions,
): Uint8Array {
  const reserve = options?.reserve ?? 0;
  if (!Number.isInteger(reserve) || reserve < 0) {
    throw new RangeError(`reserve must be a non-negative integer, got ${String(options?.reserve)}`);
  }
  const w = bodyWriter(payload);
  const out = new Uint8Array(reserve + 2 + w.length);
  out[reserve] = BINARY_ENVELOPE_VERSION;
  out[reserve + 1] = BINARY_KIND_TAGS[payload.kind];
  w.writeInto(out, reserve + 2);
  return out;
}

export interface DecodeEnvelopeBytesOptions {
  /**
   * Return `ciphertext` as a view into `bytes` instead of a copy.
   *
   * Only the ciphertext is ever borrowed. `ratchetPublic` and `nonce` are
   * copied whatever this says, because they land in long lived session state
   * and must not alias a transient network buffer. See `Reader.blobView`.
   *
   * Only safe when the caller will not reuse or overwrite `bytes` until it has
   * finished with the returned ciphertext, which in practice means handing it
   * straight to the AEAD and dropping it. Off by default, so the behaviour of
   * this function is unchanged for every caller that does not ask.
   */
  readonly borrowCiphertext?: boolean;
}

export function decodeEnvelopeBytes(
  bytes: Uint8Array,
  options?: DecodeEnvelopeBytesOptions,
): EnvelopePayload {
  // TypeScript says this is a Uint8Array. JavaScript callers, and anything that
  // reached here through a JSON round trip or an await that resolved to
  // undefined, say otherwise. Without this line `null` and `undefined` escape
  // as a raw TypeError from `.length`, which breaks the one promise this
  // module makes: every bad input comes back as a CryptoFailureError carrying a
  // reason. Buffer passes, because Buffer extends Uint8Array.
  if (!(bytes instanceof Uint8Array)) {
    fail('malformed_token', `binary envelope must be a Uint8Array, received ${bytes === null ? 'null' : typeof bytes}`);
  }
  if (bytes.length < 2) fail('malformed_token', 'binary envelope is shorter than its two byte header');
  // Version before kind, same order as the string form, so a future OCX2 byte
  // stream reports "update your client" rather than "unknown kind".
  if (bytes[0] !== BINARY_ENVELOPE_VERSION) {
    fail('unknown_version', `unsupported binary envelope version ${bytes[0]}`);
  }
  const kind = BINARY_KIND_BY_TAG[bytes[1]!];
  if (kind === undefined) fail('malformed_token', `unknown envelope kind tag ${bytes[1]}`);
  // subarray, not slice: by default Reader copies every field it hands back, so
  // nothing that escapes this function shares a buffer with the caller's frame,
  // and copying the whole body here would double the cost of the fast path. The
  // one exception is an explicitly borrowed ciphertext, which the option above
  // spells out.
  return decodeBody(kind, bytes.subarray(2), options?.borrowCiphertext === true);
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
