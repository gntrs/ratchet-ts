import type {
  AcceptPayload,
  EnvelopeKind,
  EnvelopePayload,
  EnvelopeToken,
  IntroPayload,
  InvitePayload,
  MessagePayload,
} from './contract.js';
import { bytesToUtf8, fromBase64Url, toBase64Url, utf8ToBytes } from './bytes.js';
import { fail } from './errors.js';

export const ENVELOPE_VERSION = 'OCX3';

/**
 * A compact binary body rather than JSON.
 *
 * An ML-KEM-768 public key is 1184 bytes on its own. JSON with base64 fields
 * inside a base64 token would inflate the accept envelope by roughly a third
 * for no benefit, and these tokens get pasted into chat apps by hand. Binary
 * also makes the encode/decode round trip trivially byte exact, which is a
 * property the message AAD depends on.
 *
 * The two handshake kinds length prefix every variable field and the reader
 * refuses trailing bytes, so there is exactly one encoding of any given invite
 * or accept. The message kind gets that same uniqueness a different way, from
 * canonical varints and a ciphertext that runs to the end of the buffer, which
 * `readVarint` below enforces rather than assumes.
 *
 * ---------------------------------------------------------------------------
 * OCX2, AND WHAT BROKE
 * ---------------------------------------------------------------------------
 *
 * OCX1 spent 122 bytes of envelope on a 256 byte message. OCX2 spends 34, or 67
 * on the messages that carry a ratchet key. The savings, in order of size:
 *
 *   -32  the conversation id travels as 4 binary bytes rather than 32 ASCII hex
 *        characters with a u16 length prefix. The receiver already knows which
 *        conversation this is; four bytes are enough to say "this one" and the
 *        AEAD binds all sixteen.
 *   -34  the ratchet public key is on the wire only for the first
 *        RATCHET_KEY_RESEND messages of a sending chain, not all of them. The
 *        AEAD binds it on every message either way, reconstructed from state.
 *   -14  the nonce is 12 bytes rather than 24 and loses its u16 length prefix.
 *        It is still random and still transmitted. See the NONCE_LEN comment in
 *        ratchet.ts for why a derived counter was built, measured and rejected.
 *    -8  message number and previous chain length are varints, not u32, and the
 *        previous chain length only appears beside a ratchet key.
 *    -2  no ciphertext length prefix. It is the rest of the buffer.
 *    -1  version and kind share one byte with the ratchet key flag.
 *
 * An OCX1 peer meeting these bytes reads 0x2? where it demanded 0x01 and reports
 * `unknown_version`, which is the whole reason the version moved.
 *
 * ---------------------------------------------------------------------------
 * OCX3, AND WHY IT COSTS THE MESSAGE PATH NOTHING
 * ---------------------------------------------------------------------------
 *
 * 0.6.0 put an ML-DSA-65 verifying key in every identity and a signature on
 * both handshake frames, so the invite and the accept grew by 1952 and 5261
 * bytes respectively. That is a large addition and it lands entirely on the two
 * frames that happen once per conversation. The message envelope is unchanged,
 * byte for byte: still 34 bytes of overhead, or 67 when a ratchet key rides
 * along. A conversation pays for authentication once, not per message.
 *
 * The version still moved, because an OCX2 peer handed an OCX3 invite would
 * read the identity fields it expects, then find two more length prefixed
 * blobs where it expected the end of the body, and `r.end()` would report
 * `malformed_token`. That is a correct refusal but a confusing one, and a peer
 * that cannot check a signature must not silently proceed as though there were
 * none to check. `unknown_version` says the real thing.
 */

const KINDS: readonly EnvelopeKind[] = ['invite', 'accept', 'message', 'intro'];

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
   * read buffer would otherwise watch a stored ratchet key change underneath
   * it, which is a bug that reproduces only under load.
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
   * `ratchetPublic`: that field lands in long lived session state, and the whole
   * reason `blob` copies is that it must outlive a transient network buffer.
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
function bodyWriter(payload: InvitePayload | AcceptPayload | IntroPayload): Writer {
  const w = new Writer();
  switch (payload.kind) {
    case 'invite':
      w.text(payload.conversationId);
      w.blob(payload.sender.classicalPublic);
      w.blob(payload.sender.pqPublic);
      w.blob(payload.sender.sigPublic);
      w.blob(payload.certificate);
      return w;
    case 'accept':
      w.text(payload.conversationId);
      w.blob(payload.sender.classicalPublic);
      w.blob(payload.sender.pqPublic);
      w.blob(payload.sender.sigPublic);
      w.blob(payload.kemCiphertext);
      w.blob(payload.ratchetPublic);
      w.blob(payload.signature);
      return w;
    case 'intro':
      w.text(payload.conversationId);
      w.blob(payload.sender.classicalPublic);
      w.blob(payload.sender.pqPublic);
      w.blob(payload.sender.sigPublic);
      w.blob(payload.ephemeralPublic);
      w.blob(payload.kemCiphertext);
      w.blob(payload.ratchetPublic);
      w.blob(payload.prekeyClassical);
      w.blob(payload.prekeyPq);
      w.blob(payload.signature);
      return w;
  }
}

function decodeHandshakeBody(kind: 'invite' | 'accept' | 'intro', body: Uint8Array): EnvelopePayload {
  const r = new Reader(body);
  switch (kind) {
    case 'invite': {
      const conversationId = r.text();
      const classicalPublic = r.blob();
      const pqPublic = r.blob();
      const sigPublic = r.blob();
      const certificate = r.blob();
      r.end();
      const out: InvitePayload = {
        kind,
        conversationId,
        sender: { classicalPublic, pqPublic, sigPublic },
        certificate,
      };
      return out;
    }
    case 'accept': {
      const conversationId = r.text();
      const classicalPublic = r.blob();
      const pqPublic = r.blob();
      const sigPublic = r.blob();
      const kemCiphertext = r.blob();
      const ratchetPublic = r.blob();
      const signature = r.blob();
      r.end();
      const out: AcceptPayload = {
        kind,
        conversationId,
        sender: { classicalPublic, pqPublic, sigPublic },
        kemCiphertext,
        ratchetPublic,
        signature,
      };
      return out;
    }
    case 'intro': {
      const conversationId = r.text();
      const classicalPublic = r.blob();
      const pqPublic = r.blob();
      const sigPublic = r.blob();
      const ephemeralPublic = r.blob();
      const kemCiphertext = r.blob();
      const ratchetPublic = r.blob();
      const prekeyClassical = r.blob();
      const prekeyPq = r.blob();
      const signature = r.blob();
      r.end();
      const out: IntroPayload = {
        kind,
        conversationId,
        sender: { classicalPublic, pqPublic, sigPublic },
        ephemeralPublic,
        kemCiphertext,
        ratchetPublic,
        prekeyClassical,
        prekeyPq,
        signature,
      };
      return out;
    }
  }
}

// ---------------------------------------------------------------------------
// The message header
// ---------------------------------------------------------------------------

/**
 * Canonical unsigned varint, seven bits a byte, low group first, high bit set on
 * every byte but the last. LEB128, and the same shape protobuf and DWARF use.
 *
 * CANONICAL IS THE WHOLE POINT, not a nicety. Two byte strings must never decode
 * to one message, because the AEAD binds the header bytes and the receiver
 * rebuilds them: an encoding that admits 0x00 and 0x80 0x00 for the same zero
 * would let an attacker rewrite a header into a second spelling that means the
 * same thing, and any code that later hashed, deduplicated or compared frames
 * would see two distinct messages carrying one plaintext. So the reader refuses
 * any encoding that is not the shortest one for its value, and refuses a value
 * past VARINT_MAX rather than accepting a longer form for a bigger number.
 *
 * The bound is 2^32-1 because that is what the u32 fields it replaces carried,
 * and because MAX_SKIP in ratchet.ts means no honest message number gets near it.
 */
const VARINT_MAX = 0xffffffff;
const VARINT_MAX_BYTES = 5;

function varintLength(value: number): number {
  if (value < 0x80) return 1;
  if (value < 0x4000) return 2;
  if (value < 0x200000) return 3;
  if (value < 0x10000000) return 4;
  return 5;
}

function writeVarint(out: Uint8Array, at: number, value: number): number {
  let remaining = value;
  let cursor = at;
  while (remaining >= 0x80) {
    out[cursor++] = (remaining & 0x7f) | 0x80;
    remaining >>>= 7;
  }
  out[cursor++] = remaining;
  return cursor;
}

function readVarint(buf: Uint8Array, at: number): { value: number; next: number } {
  let value = 0;
  // Multiplied rather than shifted: a 32 bit value needs bit 31, and `|` in
  // JavaScript is a signed 32 bit operator that would turn it negative.
  let scale = 1;
  let cursor = at;
  for (let i = 0; i < VARINT_MAX_BYTES; i++) {
    if (cursor >= buf.length) fail('malformed_token', 'truncated varint');
    const byte = buf[cursor++]!;
    value += (byte & 0x7f) * scale;
    if ((byte & 0x80) === 0) {
      // A final group of zero after at least one continuation byte is the
      // padded, non-minimal spelling. There is no other way to write a
      // non-canonical varint, so this one check is the whole rule.
      if (i > 0 && byte === 0) fail('malformed_token', 'non-canonical varint, trailing zero group');
      if (value > VARINT_MAX) fail('malformed_token', `varint ${value} is past the ${VARINT_MAX} bound`);
      return { value, next: cursor };
    }
    scale *= 128;
  }
  fail('malformed_token', `varint is longer than ${VARINT_MAX_BYTES} bytes`);
}

/**
 * Byte 0 of a message envelope, bit by bit: [ver:4][kind:2][hasRatchetKey:1][reserved:1].
 *
 * The version lives in the high nibble so a 0.3.x peer, which reads byte 0 as a
 * bare version marker equal to 1, sees 0x2c or 0x2e and reports "unsupported
 * binary envelope version" instead of walking off into a body it cannot parse.
 * That was the whole reason for bumping rather than reusing the byte.
 *
 * The reserved bit is required to be zero on decode. It is the only room left for
 * a compatible extension, and an implementation that sets it and expects to be
 * ignored is a worse outcome than a clean reject.
 */
const BINARY_ENVELOPE_VERSION = 0x03;
const KIND_BITS: Readonly<Record<EnvelopeKind, number>> = { invite: 1, accept: 2, message: 3, intro: 4 };
/** Index is the two bit kind field. 0 is unassigned and is a hard reject. */
const KIND_BY_BITS: readonly (EnvelopeKind | undefined)[] = [undefined, 'invite', 'accept', 'message', 'intro'];
const FLAG_RATCHET_KEY = 0x02;
const FLAG_RESERVED = 0x01;
/** Poly1305. Spelled out rather than imported so this file reads standalone. */
const MESSAGE_TAG_LEN = 16;

/** Bytes of conversation id on the wire. The other 12 are in the AAD only. */
export const SESSION_TAG_LEN = 4;
/** Bytes of conversation id the AEAD binds, whatever the wire carries. */
export const CONVERSATION_ID_LEN = 16;
/** X25519 public key. Spelled out here rather than imported from identity.ts so
 * the wire layout is readable in one file. */
export const RATCHET_PUBLIC_LEN = 32;
/**
 * RFC 8439 ChaCha20-Poly1305 nonce. Random per seal, and transmitted.
 *
 * The layout owns this number because the layout is what a decoder has to agree
 * with; `ratchet.ts` aliases it rather than declaring its own, so there is one
 * place where the length can be wrong. The argument for random over derived, and
 * for 12 over 24, is in the NONCE_LEN comment in ratchet.ts.
 */
export const MESSAGE_NONCE_LEN = 12;
/** Conversation id bytes that never travel: 4 on the wire, 16 in the AAD. */
const AAD_ID_TAIL_LEN = CONVERSATION_ID_LEN - SESSION_TAG_LEN;

/**
 * The 16 raw bytes behind a conversation id's 32 hex characters.
 *
 * Lives here rather than in bytes.ts because the wire is the only thing that
 * wants them: everywhere else a conversation id is the hex string the handshake
 * minted. Strict about both length and alphabet, because a session whose id does
 * not parse would otherwise seal messages under a silently truncated AAD.
 */
export function conversationIdToBytes(conversationId: string): Uint8Array {
  if (conversationId.length !== CONVERSATION_ID_LEN * 2) {
    fail('malformed_token', `conversation id must be ${CONVERSATION_ID_LEN * 2} hex characters, got ${conversationId.length}`);
  }
  const out = new Uint8Array(CONVERSATION_ID_LEN);
  for (let i = 0; i < CONVERSATION_ID_LEN; i += 1) {
    // Digit by digit rather than parseInt on a two character slice, because
    // parseInt accepts prefixes: it reads "0x" as 0 and "5 " as 5, so a
    // malformed id would parse to plausible bytes instead of failing.
    const hi = hexDigit(conversationId.charCodeAt(i * 2));
    const lo = hexDigit(conversationId.charCodeAt(i * 2 + 1));
    if (hi < 0 || lo < 0) fail('malformed_token', 'conversation id is not hex');
    out[i] = (hi << 4) | lo;
  }
  return out;
}

function hexDigit(code: number): number {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10;
  if (code >= 0x41 && code <= 0x46) return code - 0x41 + 10;
  return -1;
}

/**
 * Everything in a message envelope except the sealed body.
 *
 * `ratchetPublic` and `previousChainLength` are present together or not at all,
 * and their presence is the `hasRatchetKey` bit of byte 0. A `MessagePayload`
 * satisfies this structurally, so the encoder, the decoder and the AAD builder
 * all read the same shape.
 *
 * `nonce` is last, immediately in front of the ciphertext, and it is the only
 * header field with no fixed offset from the front of the frame: it sits after
 * two varints and an optional 32 byte key. It is last on purpose. The AAD is the
 * header prefix of the output buffer, so putting the one field that changes on
 * every seal at the end keeps the whole rest of the header identical from one
 * message to the next, which is what makes the single-writer arrangement in
 * `sealMessageEnvelope` cheap.
 */
export interface MessageHeader {
  readonly sessionTag: Uint8Array;
  readonly messageNumber: number;
  readonly nonce: Uint8Array;
  readonly ratchetPublic?: Uint8Array;
  readonly previousChainLength?: number;
}

export function messageHeaderLength(header: MessageHeader): number {
  const base = 1 + SESSION_TAG_LEN + varintLength(header.messageNumber) + MESSAGE_NONCE_LEN;
  if (header.ratchetPublic === undefined) return base;
  return base + varintLength(header.previousChainLength ?? 0) + RATCHET_PUBLIC_LEN;
}

/**
 * Writes the header into `out` at `at` and returns the offset just past it.
 *
 * This function is the single definition of the message wire layout. The seal
 * path calls it once, straight into the envelope it is building, and then hands
 * the bytes it wrote to the AEAD as associated data; the open path calls it to
 * rebuild those same bytes for verification. One writer means the two can never
 * disagree about what was signed, which the old shape could, because it built
 * the AAD out of one serialiser and the envelope out of another.
 */
export function writeMessageHeader(out: Uint8Array, at: number, header: MessageHeader): number {
  if (header.sessionTag.length !== SESSION_TAG_LEN) {
    fail('malformed_token', `session tag must be ${SESSION_TAG_LEN} bytes, got ${header.sessionTag.length}`);
  }
  if (header.messageNumber < 0 || header.messageNumber > VARINT_MAX || !Number.isInteger(header.messageNumber)) {
    fail('malformed_token', `message number ${header.messageNumber} is not a u32`);
  }
  const carriesKey = header.ratchetPublic !== undefined;
  out[at] = (BINARY_ENVELOPE_VERSION << 4) | (KIND_BITS.message << 2) | (carriesKey ? FLAG_RATCHET_KEY : 0);
  out.set(header.sessionTag, at + 1);
  let cursor = writeVarint(out, at + 1 + SESSION_TAG_LEN, header.messageNumber);
  if (header.ratchetPublic !== undefined) {
    const previous = header.previousChainLength ?? 0;
    if (previous < 0 || previous > VARINT_MAX || !Number.isInteger(previous)) {
      fail('malformed_token', `previous chain length ${previous} is not a u32`);
    }
    if (header.ratchetPublic.length !== RATCHET_PUBLIC_LEN) {
      fail('malformed_token', `ratchet public key must be ${RATCHET_PUBLIC_LEN} bytes, got ${header.ratchetPublic.length}`);
    }
    cursor = writeVarint(out, cursor, previous);
    out.set(header.ratchetPublic, cursor);
    cursor += RATCHET_PUBLIC_LEN;
  }
  // Checked rather than assumed. A 24 byte value here would still encode, still
  // decode, and still round trip against another build of this library, while
  // quietly being XChaCha20-Poly1305 instead of the RFC 8439 construction the
  // rest of the stack agrees on. The length is the only thing distinguishing
  // the two, so it is the thing to assert.
  if (header.nonce.length !== MESSAGE_NONCE_LEN) {
    fail('malformed_token', `message nonce must be ${MESSAGE_NONCE_LEN} bytes, got ${header.nonce.length}`);
  }
  out.set(header.nonce, cursor);
  cursor += MESSAGE_NONCE_LEN;
  return cursor;
}

/**
 * The bytes the AEAD binds that the wire does not carry.
 *
 * Twelve bytes of conversation id always, plus the 32 byte ratchet public key on
 * the messages that omit it. THIS IS A SECURITY PROPERTY, NOT A FORMATTING
 * DETAIL. The receiver reconstructs both from session state, so binding them
 * costs nothing on the wire and keeps every guarantee the old fully transmitted
 * header had: a ciphertext lifted out of one conversation, or out of one chain,
 * cannot be pasted into another, because the tag was computed over the id and
 * the key of the conversation and chain it was sealed in. Drop this and the
 * saving stops being free.
 *
 * `ratchetPublic` is the key to append, or undefined when the header already
 * carries it and appending would bind it twice.
 */
export function aadExtensionLength(header: MessageHeader): number {
  return AAD_ID_TAIL_LEN + (header.ratchetPublic === undefined ? RATCHET_PUBLIC_LEN : 0);
}

export function writeAadExtension(
  out: Uint8Array,
  at: number,
  conversationId: Uint8Array,
  ratchetPublic: Uint8Array | undefined,
): number {
  if (conversationId.length !== CONVERSATION_ID_LEN) {
    fail('malformed_token', `conversation id must be ${CONVERSATION_ID_LEN} bytes, got ${conversationId.length}`);
  }
  out.set(conversationId.subarray(SESSION_TAG_LEN), at);
  let cursor = at + AAD_ID_TAIL_LEN;
  if (ratchetPublic !== undefined) {
    if (ratchetPublic.length !== RATCHET_PUBLIC_LEN) {
      fail('malformed_token', `ratchet public key must be ${RATCHET_PUBLIC_LEN} bytes, got ${ratchetPublic.length}`);
    }
    out.set(ratchetPublic, cursor);
    cursor += RATCHET_PUBLIC_LEN;
  }
  return cursor;
}

/**
 * Associated data for one message, built standalone.
 *
 * The seal path does NOT call this: it writes the header into the envelope it is
 * already allocating and hands the AEAD that subarray, which is the double
 * serialisation this release exists to delete. This is the open path, where the
 * header bytes arrive inside a buffer the caller owns and must not be written
 * into, so the only option is a small scratch copy.
 *
 * `chainRatchetPublic` is the sending chain's key as the receiver knows it, and
 * is ignored when the header carries the key itself.
 */
export function messageAad(
  header: MessageHeader,
  conversationId: Uint8Array,
  chainRatchetPublic: Uint8Array,
): Uint8Array {
  const headerLength = messageHeaderLength(header);
  const aad = new Uint8Array(headerLength + aadExtensionLength(header));
  writeMessageHeader(aad, 0, header);
  writeAadExtension(
    aad,
    headerLength,
    conversationId,
    header.ratchetPublic === undefined ? chainRatchetPublic : undefined,
  );
  return aad;
}

function decodeMessage(bytes: Uint8Array, flags: number, borrowCiphertext: boolean): MessagePayload {
  const carriesKey = (flags & FLAG_RATCHET_KEY) !== 0;
  if (bytes.length < 1 + SESSION_TAG_LEN) fail('malformed_token', 'truncated message header');
  // A copy, for the reason Reader.blob gives: this lands in nothing long lived
  // today, but it is compared against session state and a socket that reuses its
  // read buffer must not be able to change it underneath the comparison.
  const sessionTag = new Uint8Array(bytes.subarray(1, 1 + SESSION_TAG_LEN));
  const number = readVarint(bytes, 1 + SESSION_TAG_LEN);
  let cursor = number.next;

  let ratchetPublic: Uint8Array | undefined;
  let previousChainLength: number | undefined;
  if (carriesKey) {
    const previous = readVarint(bytes, cursor);
    previousChainLength = previous.value;
    cursor = previous.next;
    if (cursor + RATCHET_PUBLIC_LEN > bytes.length) fail('malformed_token', 'truncated ratchet public key');
    ratchetPublic = new Uint8Array(bytes.subarray(cursor, cursor + RATCHET_PUBLIC_LEN));
    cursor += RATCHET_PUBLIC_LEN;
  }

  if (cursor + MESSAGE_NONCE_LEN > bytes.length) fail('malformed_token', 'truncated message nonce');
  // A copy, for the same reason as the session tag above. This one is handed
  // straight to the AEAD, so a reader that recycles its buffer between decode
  // and open would change the nonce out from under the tag check.
  const nonce = new Uint8Array(bytes.subarray(cursor, cursor + MESSAGE_NONCE_LEN));
  cursor += MESSAGE_NONCE_LEN;

  // Everything left is the sealed body. There is no length prefix to check it
  // against, which is exactly the point: the frame already knows where it ends.
  // The floor is the Poly1305 tag, because a body shorter than its own tag
  // cannot be a sealed anything and there is no reason to hand it to the AEAD.
  const remaining = bytes.length - cursor;
  if (remaining < MESSAGE_TAG_LEN) {
    fail('malformed_token', `sealed body is ${remaining} bytes, shorter than its ${MESSAGE_TAG_LEN} byte tag`);
  }
  const ciphertext = borrowCiphertext
    ? new Uint8Array(bytes.buffer, bytes.byteOffset + cursor, remaining)
    : new Uint8Array(bytes.subarray(cursor));

  return {
    kind: 'message',
    sessionTag,
    messageNumber: number.value,
    nonce,
    ciphertext,
    ...(ratchetPublic !== undefined ? { ratchetPublic } : {}),
    ...(previousChainLength !== undefined ? { previousChainLength } : {}),
  };
}

export function encodeEnvelope(payload: EnvelopePayload): EnvelopeToken {
  return `${ENVELOPE_VERSION}.${payload.kind}.${toBase64Url(encodeEnvelopeBytes(payload))}`;
}

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
  if (payload.kind === 'message') {
    const headerLength = messageHeaderLength(payload);
    const out = new Uint8Array(reserve + headerLength + payload.ciphertext.length);
    writeMessageHeader(out, reserve, payload);
    out.set(payload.ciphertext, reserve + headerLength);
    return out;
  }
  const w = bodyWriter(payload);
  const out = new Uint8Array(reserve + 2 + w.length);
  out[reserve] = BINARY_ENVELOPE_VERSION;
  out[reserve + 1] = KIND_BITS[payload.kind];
  w.writeInto(out, reserve + 2);
  return out;
}

/**
 * Seal a message straight into its envelope buffer, with the header doubling as
 * the AEAD's associated data.
 *
 * THIS FUNCTION IS THE POINT OF THE 0.4.0 REWRITE. 0.3.x built a `messageAad`
 * Writer over one field set, then built the envelope body over an overlapping
 * field set, so every send serialised the conversation id, the ratchet key, the
 * counters and the nonce twice. Here the header is written once, at its final
 * resting place in the output buffer, and that exact subarray is handed to the
 * AEAD. There is no second spelling of the layout that could drift from the
 * first, and no second allocation. The nonce is part of that single write: it
 * is a header field like any other, so it is transmitted and bound by the same
 * line of code, and there is no way to bind it without sending it or to send it
 * without binding it.
 *
 * The buffer is laid out as
 *
 *   [0, reserve)                     caller's framing space, untouched
 *   [reserve, +headerLength)         the header, and the AAD's first part
 *   [+headerLength, +aadExtension)   the AAD tail, overwritten by the ciphertext
 *   [+headerLength, +ciphertext)     the sealed body once `seal` returns
 *
 * The AAD tail and the ciphertext deliberately share space. The tail carries the
 * 12 conversation id bytes that are not on the wire, plus the 32 ratchet key
 * bytes when the header omits them, and it exists only for the duration of the
 * `seal` call. Overwriting it afterwards is safe because the receiver rebuilds
 * those bytes from its own session state rather than reading them off the wire,
 * which is the whole reason they can be omitted in the first place.
 *
 * `seal` receives the AAD and returns the ciphertext including its tag. It is a
 * callback rather than a direct AEAD call so this file keeps owning the layout
 * and nothing else, and so the ratchet keeps owning key and nonce selection.
 */
export function sealMessageEnvelope(
  header: MessageHeader,
  conversationId: Uint8Array,
  chainRatchetPublic: Uint8Array,
  plaintextLength: number,
  seal: (aad: Uint8Array) => Uint8Array,
  reserve = 0,
): Uint8Array {
  const headerLength = messageHeaderLength(header);
  const extensionLength = aadExtensionLength(header);
  const sealedLength = plaintextLength + MESSAGE_TAG_LEN;
  // Whichever of the two tenants of the region after the header is larger. The
  // extension wins only for plaintexts under about 30 bytes, where the few
  // wasted bytes are cheaper than a second allocation to avoid them.
  const tail = Math.max(extensionLength, sealedLength);
  const out = new Uint8Array(reserve + headerLength + tail);

  writeMessageHeader(out, reserve, header);
  writeAadExtension(
    out,
    reserve + headerLength,
    conversationId,
    header.ratchetPublic === undefined ? chainRatchetPublic : undefined,
  );
  const ciphertext = seal(out.subarray(reserve, reserve + headerLength + extensionLength));
  out.set(ciphertext, reserve + headerLength);
  const total = reserve + headerLength + ciphertext.length;
  return total === out.length ? out : out.subarray(0, total);
}

export interface DecodeEnvelopeBytesOptions {
  /**
   * Return `ciphertext` as a view into `bytes` instead of a copy.
   *
   * Only the ciphertext is ever borrowed. `sessionTag` and `ratchetPublic` are
   * copied whatever this says, because they are compared against, and in the
   * ratchet key's case stored in, long lived session state and must not alias a
   * transient network buffer. See `Reader.blobView`.
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
  if (bytes.length < 1) fail('malformed_token', 'binary envelope is empty');
  const first = bytes[0]!;

  // A handshake envelope still spends a whole byte on its version and a whole
  // byte on its kind, unpacked, exactly as 0.3.x did. Invites and accepts carry
  // a 1184 byte ML-KEM key; saving a byte there is noise, and leaving the layout
  // alone keeps this rewrite to the one envelope kind it is about.
  if (first === BINARY_ENVELOPE_VERSION) {
    if (bytes.length < 2) fail('malformed_token', 'binary envelope is shorter than its two byte header');
    const kind = KIND_BY_BITS[bytes[1]!];
    if (kind === undefined || kind === 'message') {
      fail('malformed_token', `unknown envelope kind tag ${bytes[1]}`);
    }
    // subarray, not slice: Reader copies every field it hands back, so nothing
    // that escapes this function shares a buffer with the caller's frame, and
    // copying the whole body here would double the cost.
    return decodeHandshakeBody(kind, bytes.subarray(2));
  }

  // Version before kind, so a 0.3.x frame reports "update your client" rather
  // than being misread as some kind we do not know.
  if (first >>> 4 !== BINARY_ENVELOPE_VERSION) {
    fail('unknown_version', `unsupported binary envelope version ${first >>> 4}`);
  }
  const packedKind = KIND_BY_BITS[(first >>> 2) & 0x03];
  if (packedKind !== 'message') {
    fail('malformed_token', `packed envelope header carries kind ${String(packedKind)}, only message is packed`);
  }
  // The one spare bit. Rejecting it rather than ignoring it keeps it usable as
  // a real extension point later instead of something implementations disagree
  // about today.
  if ((first & FLAG_RESERVED) !== 0) fail('malformed_token', 'reserved header bit is set');
  return decodeMessage(bytes, first, options?.borrowCiphertext === true);
}

export function decodeEnvelope(token: EnvelopeToken): EnvelopePayload {
  const trimmed = token.trim();
  const parts = trimmed.split('.');
  if (parts.length !== 3) fail('malformed_token', 'expected OCX2.<kind>.<payload>');
  const [version, kind, body] = parts as [string, string, string];
  // Version is checked before kind so an OCX1 token reports the useful
  // "update your client" reason instead of "we do not know that kind".
  if (version !== ENVELOPE_VERSION) fail('unknown_version', `unsupported envelope version ${version}`);
  if (!KINDS.includes(kind as EnvelopeKind)) fail('malformed_token', `unknown envelope kind ${kind}`);
  const raw = fromBase64Url(body);
  if (raw === null) fail('malformed_token', 'payload is not valid base64url');
  const payload = decodeEnvelopeBytes(raw);
  // The label and the bytes both say what this is. They must agree, or a token
  // could be filed under one kind and parsed as another.
  if (payload.kind !== kind) {
    fail('malformed_token', `token labelled ${kind} decodes as ${payload.kind}`);
  }
  return payload;
}
