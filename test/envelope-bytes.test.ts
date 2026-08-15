import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { randomBytes } from '@noble/hashes/utils.js';

import type { AcceptPayload, EnvelopePayload, InvitePayload, MessagePayload } from '../src/contract.js';
import {
  CONVERSATION_ID_LEN,
  MESSAGE_NONCE_LEN,
  RATCHET_PUBLIC_LEN,
  SESSION_TAG_LEN,
  conversationIdToBytes,
  decodeEnvelope,
  decodeEnvelopeBytes,
  encodeEnvelope,
  encodeEnvelopeBytes,
  messageAad,
} from '../src/envelope.js';
import { isCryptoFailure } from '../src/errors.js';

/**
 * The binary envelope form, 0.4.0 layout.
 *
 * WHAT THIS FILE PINS, AND WHY IT WAS REWRITTEN. Through 0.3.x a message
 * envelope was a version byte, a kind byte and six length prefixed fields, and
 * this file pinned that shape byte for byte. 0.4.0 replaces the message layout
 * outright: the version and kind now share byte 0 with a presence flag, the
 * conversation id is four binary bytes instead of thirty-two ASCII ones, the
 * counters are canonical varints, the nonce shrank from 24 bytes to 12 and moved
 * to the end of the header, the ratchet key is on the wire only when the flag
 * says so, and the ciphertext has no length prefix because it runs to the end of
 * the frame. Every assertion below was rewritten against the new layout rather
 * than relaxed: the byte-exact pins are still byte exact, the hostile-input
 * rejects are still exhaustive, and there are more of both than there were.
 *
 * The pins in this file survive a random nonce because the encoder does not
 * generate one. It writes the twelve bytes it is handed, so a fixed NONCE
 * constant makes the whole frame a literal again. The randomness lives one layer
 * up in ratchet.ts and is tested in test/message-chain.test.ts.
 *
 * Invite and accept envelopes did NOT change. They still spend a whole byte on
 * the version and a whole byte on the kind, because those frames carry a 1184
 * byte ML-KEM key and saving a byte inside one is noise.
 *
 * Loading vectors.json: @types/node is deliberately absent from this package,
 * so fs is reached through a dynamic specifier the compiler does not resolve.
 * Same trick, same reason, as test/vectors.test.ts.
 */
interface FsLike {
  readonly readFileSync: (path: URL, options: { encoding: 'utf8' }) => string;
}
const fsModule = 'node:' + 'fs';
const fs = (await import(fsModule)) as FsLike;

interface VectorTokens {
  readonly tokens: {
    readonly invite: string;
    readonly accept: string;
    readonly message0: string;
    readonly reply0: string;
  };
}

const vectors = JSON.parse(
  fs.readFileSync(new URL('./vectors.json', import.meta.url), { encoding: 'utf8' }),
) as VectorTokens;

// Real field sizes, not round numbers: 32 hex chars of conversation id from
// handshake.ts, a 32 byte X25519 public, a 1184 byte ML-KEM-768 public, a 1088
// byte ML-KEM-768 ciphertext. The size assertions below are exact, so a wrong
// constant here shows up as a failure rather than as a test that quietly
// measures the wrong shape.
const CONVERSATION_ID = 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf';
const SESSION_TAG = conversationIdToBytes(CONVERSATION_ID).subarray(0, SESSION_TAG_LEN);

/** Byte 0 of a message envelope with and without the ratchet key. */
const HEADER_PLAIN = 0x3c;
const HEADER_STEP = 0x3e;
/** Byte 0 and byte 1 of a handshake envelope, which kept the 0.3.x shape. */
const HANDSHAKE_VERSION = 0x03;
const TAG_INVITE = 0x01;
const TAG_ACCEPT = 0x02;
/** Poly1305, the floor under any sealed body. */
const MESSAGE_TAG_LEN = 16;

/**
 * A body larger than one call to randomBytes will give you.
 *
 * noble's randomBytes refuses anything over 65536, which never mattered while
 * the ciphertext carried a u16 length prefix that capped it below that anyway.
 * Without the prefix the ceiling is gone, and the extremes test has to be able
 * to build something past it. Nothing here needs unpredictable bytes, only
 * distinguishable ones.
 */
function filler(length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) out[i] = (i * 31 + (i >>> 8)) & 0xff;
  return out;
}

function hex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

function unhex(text: string): Uint8Array {
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** 0x00..0x1f. Sixteen bytes of body plus a sixteen byte tag, deterministically. */
const CIPHERTEXT_32 = Uint8Array.from({ length: 32 }, (_, i) => i);
/** 0x40..0x5f, so a stray ciphertext byte in the key slot is obvious in a hex dump. */
const RATCHET_PUBLIC = Uint8Array.from({ length: 32 }, (_, i) => 0x40 + i);

function sampleInvite(): InvitePayload {
  return {
    kind: 'invite',
    conversationId: CONVERSATION_ID,
    sender: { classicalPublic: randomBytes(32), pqPublic: randomBytes(1184), sigPublic: randomBytes(1952) },
    signature: randomBytes(3309),
  };
}

function sampleAccept(): AcceptPayload {
  return {
    kind: 'accept',
    conversationId: CONVERSATION_ID,
    sender: { classicalPublic: randomBytes(32), pqPublic: randomBytes(1184), sigPublic: randomBytes(1952) },
    kemCiphertext: randomBytes(1088),
    ratchetPublic: randomBytes(32),
    signature: randomBytes(3309),
  };
}

/**
 * A fixed nonce, so the byte pins below have something to pin.
 *
 * The real seal draws this from the CSPRNG on every message. These are encoder
 * tests rather than ratchet tests: the encoder's job is to put whatever twelve
 * bytes it is handed at the right offset, and a fixed value is the only way to
 * assert that against a literal. `test/message-chain.test.ts` is where the
 * randomness itself is checked.
 */
const NONCE = Uint8Array.from([0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb]);

/** The common case: no ratchet key, 34 bytes of overhead. */
function samplePlain(plaintextLength: number): MessagePayload {
  return {
    kind: 'message',
    sessionTag: Uint8Array.from(SESSION_TAG),
    messageNumber: 7,
    nonce: Uint8Array.from(NONCE),
    // Ciphertext is plaintext plus the 16 byte Poly1305 tag.
    ciphertext: randomBytes(plaintextLength + 16),
  };
}

/**
 * The chain-step case: key and previous chain length present together.
 *
 * Both counters are deliberately small enough for a one byte varint, because
 * the 67 byte step overhead in the header table is quoted for exactly that
 * case. Chains longer than 127 messages pay one more byte per counter, and the
 * extremes test below pins what that costs.
 */
function sampleStep(plaintextLength: number): MessagePayload {
  return {
    kind: 'message',
    sessionTag: Uint8Array.from(SESSION_TAG),
    messageNumber: 0,
    previousChainLength: 5,
    ratchetPublic: randomBytes(32),
    nonce: Uint8Array.from(NONCE),
    ciphertext: randomBytes(plaintextLength + 16),
  };
}

function samples(): EnvelopePayload[] {
  return [sampleInvite(), sampleAccept(), samplePlain(256), sampleStep(256)];
}

/** Runs `fn` and returns the CryptoFailure it must have thrown. */
function failureOf(fn: () => unknown): { reason: string; message: string } {
  try {
    fn();
  } catch (error) {
    if (!isCryptoFailure(error)) {
      assert.fail(`expected a CryptoFailureError, got ${String(error)}`);
    }
    return { reason: error.reason, message: error.message };
  }
  assert.fail('expected a failure, got a value');
}

function join(...parts: readonly (number | Uint8Array)[]): Uint8Array {
  const arrays = parts.map((p) => (typeof p === 'number' ? new Uint8Array([p]) : p));
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let at = 0;
  for (const a of arrays) {
    out.set(a, at);
    at += a.length;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Byte-exact pins
// ---------------------------------------------------------------------------

/**
 * The non-step message envelope, in full.
 *
 *   offset  size  field
 *   0       1     0x3c = [ver 0011][kind 11][hasRatchetKey 0][reserved 0]
 *   1       4     session tag, first 4 bytes of the 16 byte conversation id
 *   5       1     message number as a canonical varint, 7 fits in one byte
 *   6       12    RFC 8439 nonce, random per seal, no length prefix
 *   18      n     ciphertext, no length prefix, runs to the end of the frame
 *
 * Overhead is 1 + 4 + 1 + 12 + the 16 byte Poly1305 tag inside the ciphertext,
 * which is 34.
 */
const PIN_PLAIN =
  '3c' +
  'a0a1a2a3' +
  '07' +
  'b0b1b2b3b4b5b6b7b8b9babb' +
  '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';

test('a non-step message envelope is byte identical to its pin', () => {
  const payload: MessagePayload = {
    kind: 'message',
    sessionTag: Uint8Array.from(SESSION_TAG),
    messageNumber: 7,
    nonce: Uint8Array.from(NONCE),
    ciphertext: CIPHERTEXT_32,
  };
  const encoded = encodeEnvelopeBytes(payload);
  assert.equal(hex(encoded), PIN_PLAIN);
  // 18 bytes of header, 32 of sealed body. Sixteen of that body is the tag, so
  // the overhead a 16 byte plaintext actually pays is 18 + 16 = 34.
  assert.equal(encoded.length, 50);
  assert.equal(encoded.length - (CIPHERTEXT_32.length - 16), 34);
  // The nonce field is exactly twelve bytes at a fixed offset. A build that
  // went back to XChaCha20 would put twenty-four here and fail.
  assert.deepEqual(encoded.subarray(6, 18), NONCE);
  assert.equal(encoded.subarray(6, 18).length, 12);
  assert.deepEqual(decodeEnvelopeBytes(unhex(PIN_PLAIN)), payload);
});

/**
 * The step message envelope, in full.
 *
 *   offset  size  field
 *   0       1     0x3e = [ver 0011][kind 11][hasRatchetKey 1][reserved 0]
 *   1       4     session tag
 *   5       2     message number 300 as a varint: 0xac 0x02
 *   7       1     previous chain length 5 as a varint
 *   8       32    ratchet public key
 *   40      12    RFC 8439 nonce
 *   52      n     ciphertext
 *
 * Overhead is 1 + 4 + 1 + 1 + 32 + 12 + 16 = 67 when both counters fit in one
 * varint byte, which is every message number below 128.
 */
const PIN_STEP =
  '3e' +
  'a0a1a2a3' +
  'ac02' +
  '05' +
  '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f' +
  'b0b1b2b3b4b5b6b7b8b9babb' +
  '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';

test('a step message envelope is byte identical to its pin', () => {
  const payload: MessagePayload = {
    kind: 'message',
    sessionTag: Uint8Array.from(SESSION_TAG),
    messageNumber: 300,
    previousChainLength: 5,
    ratchetPublic: RATCHET_PUBLIC,
    nonce: Uint8Array.from(NONCE),
    ciphertext: CIPHERTEXT_32,
  };
  const encoded = encodeEnvelopeBytes(payload);
  assert.equal(hex(encoded), PIN_STEP);
  assert.equal(encoded.length, 84);
  assert.deepEqual(decodeEnvelopeBytes(unhex(PIN_STEP)), payload);

  // Message number 0 with a one byte previous chain length is the 67 byte case
  // the header table promises.
  const first = encodeEnvelopeBytes({
    kind: 'message',
    sessionTag: Uint8Array.from(SESSION_TAG),
    messageNumber: 0,
    previousChainLength: 0,
    ratchetPublic: RATCHET_PUBLIC,
    nonce: Uint8Array.from(NONCE),
    ciphertext: CIPHERTEXT_32,
  });
  assert.equal(first.length - (CIPHERTEXT_32.length - 16), 67);
});

test('byte 0 says version, kind and key presence, and nothing else', () => {
  assert.equal(encodeEnvelopeBytes(samplePlain(0))[0], HEADER_PLAIN);
  assert.equal(encodeEnvelopeBytes(sampleStep(0))[0], HEADER_STEP);
  for (const first of [HEADER_PLAIN, HEADER_STEP]) {
    assert.equal(first >>> 4, 3, 'version nibble moved');
    assert.equal((first >>> 2) & 0x03, 3, 'kind bits moved');
    assert.equal(first & 0x01, 0, 'reserved bit is not zero');
  }
  // Handshake envelopes kept the two byte header.
  assert.equal(encodeEnvelopeBytes(sampleInvite())[0], HANDSHAKE_VERSION);
  assert.equal(encodeEnvelopeBytes(sampleInvite())[1], TAG_INVITE);
  assert.equal(encodeEnvelopeBytes(sampleAccept())[1], TAG_ACCEPT);
});

// ---------------------------------------------------------------------------
// Round trip
// ---------------------------------------------------------------------------

test('every envelope kind round trips through the binary form exactly', () => {
  for (const payload of samples()) {
    assert.deepEqual(decodeEnvelopeBytes(encodeEnvelopeBytes(payload)), payload);
  }
});

test('binary round trip survives the extremes of every field', () => {
  // Smallest legal message: no key, number 0, a body that is nothing but its tag.
  const smallest: MessagePayload = {
    kind: 'message',
    sessionTag: Uint8Array.from(SESSION_TAG),
    messageNumber: 0,
    nonce: Uint8Array.from(NONCE),
    ciphertext: new Uint8Array(16),
  };
  // Largest counters the varint bound admits, and a body far past the 65535 the
  // old u16 length prefix could describe. That ceiling is gone: the ciphertext
  // has no prefix, so the frame length is the only limit.
  const full: MessagePayload = {
    kind: 'message',
    sessionTag: Uint8Array.from(SESSION_TAG),
    messageNumber: 0xffffffff,
    previousChainLength: 0xffffffff,
    ratchetPublic: randomBytes(32),
    nonce: Uint8Array.from(NONCE),
    ciphertext: filler(200_000),
  };
  assert.deepEqual(decodeEnvelopeBytes(encodeEnvelopeBytes(smallest)), smallest);
  assert.deepEqual(decodeEnvelopeBytes(encodeEnvelopeBytes(full)), full);
  // Five byte varints at both ends: 1 + 4 + 5 + 5 + 32 + 12 = 59 of header.
  assert.equal(encodeEnvelopeBytes(full).length - full.ciphertext.length, 59);
});

test('the binary form and the string form of one payload decode to the same object', () => {
  for (const payload of samples()) {
    const fromText = decodeEnvelope(encodeEnvelope(payload));
    const fromBytes = decodeEnvelopeBytes(encodeEnvelopeBytes(payload));
    assert.deepEqual(fromBytes, fromText);
    assert.deepEqual(fromBytes, payload);
  }
});

test('the string form is exactly base64url over the binary form', () => {
  for (const payload of samples()) {
    const token = encodeEnvelope(payload);
    const binary = encodeEnvelopeBytes(payload);
    assert.ok(token.startsWith(`OCX3.${payload.kind}.`), `token ${token.slice(0, 20)} has the wrong prefix`);
    // Re-encoding what the string form decodes must land on the same bytes the
    // binary form emits. If these ever diverge, one of the two encoders has
    // grown a field the other has not.
    assert.deepEqual(encodeEnvelopeBytes(decodeEnvelope(token)), binary);
  }
});

test('reserve leaves untouched space in front and changes nothing after it', () => {
  for (const payload of samples()) {
    const plain = encodeEnvelopeBytes(payload);
    const reserved = encodeEnvelopeBytes(payload, { reserve: 4 });
    assert.equal(reserved.length, plain.length + 4);
    assert.deepEqual(reserved.subarray(0, 4), new Uint8Array(4));
    assert.deepEqual(reserved.subarray(4), plain);
  }
});

// ---------------------------------------------------------------------------
// The AAD binds what the wire does not carry
// ---------------------------------------------------------------------------

/**
 * The security property that pays for the 34 byte header.
 *
 * Four of the sixteen conversation id bytes are on the wire, and on a non-step
 * message none of the ratchet key is. Both are bound into the AEAD's associated
 * data all the same, reconstructed by the receiver from session state. This test
 * is the unit-level statement of that; the end to end version, which mutates a
 * live session and asserts the open fails, is in test/wire-binding.test.ts.
 */
test('the AAD carries the full conversation id and the full ratchet key', () => {
  const conversationId = conversationIdToBytes(CONVERSATION_ID);
  const chainKey = RATCHET_PUBLIC;

  const plain = samplePlain(64);
  const plainAad = messageAad(plain, conversationId, chainKey);
  // 18 byte header, nonce included, then the 12 id bytes the wire never saw,
  // then the 32 key bytes the wire never saw. The nonce is inside the header
  // slice rather than appended, because it travels: binding it is a matter of
  // covering the bytes that are already on the wire.
  assert.equal(plainAad.length, 18 + (CONVERSATION_ID_LEN - SESSION_TAG_LEN) + RATCHET_PUBLIC_LEN);
  assert.deepEqual(plainAad.subarray(0, 18), encodeEnvelopeBytes(plain).subarray(0, 18));
  assert.deepEqual(plainAad.subarray(6, 18), plain.nonce);
  assert.deepEqual(plainAad.subarray(18, 30), conversationId.subarray(SESSION_TAG_LEN));
  assert.deepEqual(plainAad.subarray(30), chainKey);

  // One bit of the nonce changes the AAD, so a relay cannot swap the nonce of a
  // captured frame and have the tag still check out.
  const otherNonce = { ...plain, nonce: Uint8Array.from(plain.nonce) };
  otherNonce.nonce[0] = otherNonce.nonce[0]! ^ 0x01;
  assert.notDeepEqual(messageAad(otherNonce, conversationId, chainKey), plainAad);

  // On a step message the key is already in the header, so appending it again
  // would bind it twice and buy nothing.
  const step = sampleStep(64);
  const stepAad = messageAad(step, conversationId, chainKey);
  assert.equal(stepAad.length, encodeEnvelopeBytes(step).length - step.ciphertext.length + 12);
  assert.deepEqual(stepAad.subarray(stepAad.length - 12), conversationId.subarray(SESSION_TAG_LEN));

  // One bit of the id that never travels changes the AAD. This is what stops a
  // ciphertext being lifted into a conversation that shares a session tag.
  const nudged = Uint8Array.from(conversationId);
  nudged[15] = nudged[15]! ^ 0x01;
  assert.notDeepEqual(messageAad(plain, nudged, chainKey), plainAad);
  // And one bit of the key that never travels.
  const otherKey = Uint8Array.from(chainKey);
  otherKey[31] = otherKey[31]! ^ 0x01;
  assert.notDeepEqual(messageAad(plain, conversationId, otherKey), plainAad);
});

test('an AAD built from a wrong length id or key is refused rather than truncated', () => {
  const conversationId = conversationIdToBytes(CONVERSATION_ID);
  const plain = samplePlain(16);
  assert.equal(
    failureOf(() => messageAad(plain, conversationId.subarray(0, 15), RATCHET_PUBLIC)).reason,
    'malformed_token',
  );
  assert.equal(
    failureOf(() => messageAad(plain, conversationId, RATCHET_PUBLIC.subarray(0, 31))).reason,
    'malformed_token',
  );
});

test('conversation ids that are not 32 hex characters are refused', () => {
  for (const bad of ['', 'a0a1', `${CONVERSATION_ID}00`, 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz', ' '.repeat(32)]) {
    assert.equal(failureOf(() => conversationIdToBytes(bad)).reason, 'malformed_token');
  }
  // parseInt would read "0x" as zero, so the hex alphabet check has to be per
  // digit rather than per byte pair.
  assert.equal(failureOf(() => conversationIdToBytes('0x'.repeat(16))).reason, 'malformed_token');
  assert.deepEqual(
    conversationIdToBytes('A0A1A2A3A4A5A6A7A8A9AAABACADAEAF'),
    conversationIdToBytes(CONVERSATION_ID),
    'upper case hex must parse to the same bytes',
  );
});

// ---------------------------------------------------------------------------
// Canonical varints
// ---------------------------------------------------------------------------

/**
 * Two wire byte strings must never decode to one message.
 *
 * The AEAD binds the header bytes and the receiver rebuilds them, so a varint
 * encoding that admitted 0x07 and 0x87 0x00 for the same seven would let an
 * attacker rewrite a frame into a second spelling of the same message. Anything
 * downstream that hashed or deduplicated frames would then see two messages
 * carrying one plaintext. The reader refuses every non-minimal encoding.
 */
test('a non-minimal varint is rejected', () => {
  // The honest frame: message number 7 in one byte.
  const honest = unhex(PIN_PLAIN);
  assert.equal(honest[5], 0x07);
  assert.equal((decodeEnvelopeBytes(honest) as MessagePayload).messageNumber, 7);

  // The same value padded to two bytes: 0x87 0x00. Byte for byte a longer frame
  // that a lenient reader would call message 7.
  const padded = join(honest.subarray(0, 5), unhex('8700'), honest.subarray(6));
  const failure = failureOf(() => decodeEnvelopeBytes(padded));
  assert.equal(failure.reason, 'malformed_token');
  assert.equal(failure.message, 'non-canonical varint, trailing zero group');

  // Every padding length, up to the five byte ceiling.
  for (const tail of ['8700', '878000', '87808000', '8780808000']) {
    const bad = join(honest.subarray(0, 5), unhex(tail), honest.subarray(6));
    assert.equal(failureOf(() => decodeEnvelopeBytes(bad)).reason, 'malformed_token');
  }

  // Zero padded is the same bug with the smallest value.
  const zero = join(unhex('3ca0a1a2a3'), unhex('8000'), CIPHERTEXT_32);
  assert.equal(
    failureOf(() => decodeEnvelopeBytes(zero)).message,
    'non-canonical varint, trailing zero group',
  );

  // And the previous chain length, which is the second varint and needs its own
  // check because it is read by a second call site.
  const stepped = unhex(PIN_STEP);
  const paddedPrevious = join(stepped.subarray(0, 7), unhex('8500'), stepped.subarray(8));
  assert.equal(failureOf(() => decodeEnvelopeBytes(paddedPrevious)).reason, 'malformed_token');
});

test('a varint longer than five bytes or past 2^32-1 is rejected', () => {
  // Six continuation bytes: the reader gives up at five rather than growing an
  // unbounded integer out of attacker bytes.
  const long = join(unhex('3ca0a1a2a3'), unhex('808080808001'), CIPHERTEXT_32);
  assert.equal(failureOf(() => decodeEnvelopeBytes(long)).message, 'varint is longer than 5 bytes');

  // Five bytes, minimal, but 2^35 - a value the u32 counters it replaced could
  // never hold. Accepting it would mean the wire admits numbers the encoder
  // cannot produce.
  const huge = join(unhex('3ca0a1a2a3'), unhex('8080808080'), CIPHERTEXT_32);
  const failure = failureOf(() => decodeEnvelopeBytes(huge));
  assert.equal(failure.reason, 'malformed_token');

  // 0xffffffff is the largest that must still work, and it is exactly five bytes.
  const max = join(unhex('3ca0a1a2a3'), unhex('ffffffff0f'), CIPHERTEXT_32);
  assert.equal((decodeEnvelopeBytes(max) as MessagePayload).messageNumber, 0xffffffff);

  // The encoder refuses the same values from the other side, so a caller cannot
  // mint a frame the decoder would then reject.
  for (const number of [-1, 1.5, 0x100000000, Number.NaN]) {
    assert.equal(
      failureOf(() =>
        encodeEnvelopeBytes({
          kind: 'message',
          sessionTag: Uint8Array.from(SESSION_TAG),
          messageNumber: number,
          nonce: Uint8Array.from(NONCE),
          ciphertext: CIPHERTEXT_32,
        }),
      ).reason,
      'malformed_token',
    );
  }
});

test('a truncated varint is refused before it is read', () => {
  // Header byte, session tag, then a continuation byte with nothing after it.
  const bad = unhex('3ca0a1a2a380');
  const failure = failureOf(() => decodeEnvelopeBytes(bad));
  assert.equal(failure.reason, 'malformed_token');
  assert.equal(failure.message, 'truncated varint');
});

// ---------------------------------------------------------------------------
// Size
// ---------------------------------------------------------------------------

test('message overhead is 34 bytes without a key and 67 with one', () => {
  for (const plaintext of [20, 256, 4000]) {
    const plain = encodeEnvelopeBytes(samplePlain(plaintext));
    const step = encodeEnvelopeBytes(sampleStep(plaintext));
    assert.equal(plain.length - plaintext, 34, `non-step overhead moved at ${plaintext} bytes`);
    assert.equal(step.length - plaintext, 67, `step overhead moved at ${plaintext} bytes`);
  }
});

test('the binary form is strictly smaller than the string form, ratio near 3/4', () => {
  for (const payload of samples()) {
    const text = encodeEnvelope(payload);
    const binary = encodeEnvelopeBytes(payload);
    assert.ok(
      binary.length < text.length,
      `binary ${binary.length} is not smaller than text ${text.length}`,
    );
    // 3/4 is the base64 ratio. The fixed "OCX3.<kind>." prefix drags it below
    // that, and the smaller the frame the more it drags, which is why the tight
    // bound lives in the next test instead of here.
    const ratio = binary.length / text.length;
    assert.ok(ratio > 0.71 && ratio < 0.76, `ratio ${ratio} is not near 3/4 for ${payload.kind}`);
  }
});

test('the ratio converges on 3/4 as the payload grows', () => {
  const big = samplePlain(65_519);
  const ratio = encodeEnvelopeBytes(big).length / encodeEnvelope(big).length;
  // The fixed 13 char "OCX3.message." prefix is the only thing keeping this off
  // 0.75 exactly, and at 64 KiB it is worth four ten thousandths.
  assert.ok(ratio > 0.7495 && ratio < 0.7505, `ratio ${ratio} did not converge on 3/4`);
});

/**
 * The 0.3.4 overhead, and where the 100 bytes went.
 *
 * 0.3.4 spent 122 bytes of binary envelope on a message that carried 256 bytes
 * of plaintext:
 *
 *      1  binary envelope version
 *      1  kind tag
 *      2  conversation id length prefix
 *     32  conversation id, as 32 ASCII hex characters
 *      2  ratchet public length prefix
 *     32  ratchet public
 *      4  message number, u32
 *      4  previous chain length, u32
 *      2  nonce length prefix
 *     24  nonce
 *      2  ciphertext length prefix
 *     16  Poly1305 tag
 *    ---
 *    122
 *
 * 0.4.0 spends 34, or 67 on the first three messages of a chain. The id lost 30
 * bytes to binary and truncation, the key and its prefix lost 34 on most
 * messages, the nonce lost 14 by dropping its length prefix and halving from 24
 * bytes to 12, the counters lost 6 to varints, and the two remaining length
 * prefixes lost 3 more.
 *
 * The nonce is still on the wire and still random. A mid-0.4.0 build derived it
 * from the message number and sent nothing, which would have made this line read
 * 26 instead of 14. That build was rejected: a state rollback replays the
 * message key, and a derived nonce replays the keystream with it, so two
 * ciphertexts under one rewound counter hand an observer the XOR of the two
 * plaintexts. Random costs 12 bytes a frame and turns that back into a forgery
 * risk rather than a plaintext disclosure.
 */
test('the 0.3.4 message overhead is decomposed and beaten', () => {
  const OLD_OVERHEAD = 122;
  const plain = encodeEnvelopeBytes(samplePlain(256));
  const step = encodeEnvelopeBytes(sampleStep(256));

  assert.equal(plain.length - 256, 34);
  assert.equal(step.length - 256, 67);
  assert.equal(OLD_OVERHEAD - 34, 88, 'the non-step saving moved');
  assert.equal(OLD_OVERHEAD - 67, 55, 'the step saving moved');

  // Constant, not proportional: the overhead is the same at 64 KiB as at 20 B.
  assert.equal(encodeEnvelopeBytes(samplePlain(65_519)).length - 65_519, 34);
  assert.equal(encodeEnvelopeBytes(samplePlain(20)).length - 20, 34);
});

// ---------------------------------------------------------------------------
// The string form must not have moved
// ---------------------------------------------------------------------------

test('known answer tokens still encode byte identically through the string path', () => {
  const known = [
    vectors.tokens.invite,
    vectors.tokens.accept,
    vectors.tokens.message0,
    vectors.tokens.reply0,
  ];
  for (const token of known) {
    assert.ok(token.length > 0, 'vectors.json is missing a token');
    const payload = decodeEnvelope(token);
    // Byte identical, not merely equivalent. These strings are frozen wire
    // output: any drift here is a breaking change for every peer already
    // running the same major.
    assert.equal(encodeEnvelope(payload), token);
    // And the byte path agrees with the frozen vectors on the payload.
    assert.deepEqual(decodeEnvelopeBytes(encodeEnvelopeBytes(payload)), payload);
  }
});

// ---------------------------------------------------------------------------
// Hostile input
// ---------------------------------------------------------------------------

test('empty and stub input fails closed', () => {
  // Empty: nothing to read at all.
  assert.equal(failureOf(() => decodeEnvelopeBytes(new Uint8Array(0))).reason, 'malformed_token');
  // A lone handshake version byte with no kind after it.
  assert.equal(
    failureOf(() => decodeEnvelopeBytes(Uint8Array.of(HANDSHAKE_VERSION))).reason,
    'malformed_token',
  );
  // A zero byte is a packed header claiming version 0, which is the reason a
  // version check has to come before anything else: it is a version problem,
  // not a shape problem, and the caller should hear "update your client".
  assert.equal(failureOf(() => decodeEnvelopeBytes(new Uint8Array(1))).reason, 'unknown_version');
});

test('input that is not a byte array at all fails closed rather than throwing', () => {
  // The types say Uint8Array. A JavaScript caller, a JSON round trip, or an
  // await that quietly resolved to undefined all say otherwise, and this is the
  // library boundary where that stops being the caller's problem. null and
  // undefined used to escape as a raw TypeError out of `.length`, which broke
  // the promise the rest of this file spends 400 lines proving.
  for (const notBytes of [null, undefined, 'OCX3.message.AAAA', 42, {}, [1, 2, 3]]) {
    const failure = failureOf(() => decodeEnvelopeBytes(notBytes as unknown as Uint8Array));
    assert.equal(failure.reason, 'malformed_token', `wrong reason for ${String(notBytes)}`);
  }

  // Buffer is the one shape that must still pass, because that is exactly what
  // a socket hands the CLI on every single frame.
  const payload = samplePlain(32);
  const asBuffer = Buffer.from(encodeEnvelopeBytes(payload));
  assert.ok(asBuffer instanceof Uint8Array, 'Buffer stopped extending Uint8Array');
  // deepEqual compares prototypes, so this also pins that decoded fields come
  // back as plain Uint8Arrays and do not inherit the shape of the input.
  assert.deepEqual(decodeEnvelopeBytes(asBuffer), payload);
});

test('an older frame fails as unknown_version, not as a mystery auth failure', () => {
  // This is the entire reason the version was bumped from 0x01 to 0x02, and
  // again to 0x03 when the handshake frames grew signatures. A 0.3.x message
  // envelope starts with 0x01 0x03; a 0.3.x handshake with 0x01 0x01; a 0.5.x
  // handshake with 0x02 0x01. All must land on "update your client".
  //
  // 0x03 used to be in this list as an obviously foreign byte and cannot be any
  // more: it IS the current handshake version marker, so a frame starting with
  // it is dispatched as a current handshake and refused on its kind tag
  // instead. 0x02 replaced it, which is the more useful case anyway, because it
  // is a real version somebody is running rather than a number nobody shipped.
  for (const first of [0x00, 0x01, 0x02, 0x0f]) {
    const stale = join(first, 0x03, new Uint8Array(120));
    assert.equal(failureOf(() => decodeEnvelopeBytes(stale)).reason, 'unknown_version');
  }
  // And a version nibble from the future.
  const future = unhex(PIN_PLAIN).slice();
  future[0] = (0x0f << 4) | 0x0c;
  assert.equal(failureOf(() => decodeEnvelopeBytes(future)).reason, 'unknown_version');
});

test('an OCX1 string token fails as unknown_version', () => {
  assert.equal(failureOf(() => decodeEnvelope('OCX1.message.AAAA')).reason, 'unknown_version');
  assert.equal(failureOf(() => decodeEnvelope('OCX9.invite.AAAA')).reason, 'unknown_version');
});

test('the reserved header bit is rejected rather than ignored', () => {
  const bad = unhex(PIN_PLAIN).slice();
  bad[0] = HEADER_PLAIN | 0x01;
  const failure = failureOf(() => decodeEnvelopeBytes(bad));
  assert.equal(failure.reason, 'malformed_token');
  assert.equal(failure.message, 'reserved header bit is set');
});

test('a packed header claiming a handshake kind is refused', () => {
  for (const kindBits of [0, 1, 2]) {
    const bad = unhex(PIN_PLAIN).slice();
    bad[0] = (0x03 << 4) | (kindBits << 2);
    const failure = failureOf(() => decodeEnvelopeBytes(bad));
    assert.equal(failure.reason, 'malformed_token');
  }
});

test('an unknown handshake kind tag fails closed', () => {
  const good = encodeEnvelopeBytes(sampleInvite());
  for (const tag of [0x00, 0x03, 0x04, 0x80, 0xff]) {
    const bad = good.slice();
    bad[1] = tag;
    assert.equal(failureOf(() => decodeEnvelopeBytes(bad)).reason, 'malformed_token');
  }
});

test('a string form token handed to the byte decoder fails closed', () => {
  const token = encodeEnvelope(samplePlain(64));
  // "O" of OCX3 is 0x4f, whose version nibble is 4, so this trips the version
  // check rather than being misread as a kind followed by a body.
  assert.equal(failureOf(() => decodeEnvelopeBytes(new TextEncoder().encode(token))).reason, 'unknown_version');
});

/**
 * Truncation, and the one place 0.4.0 answers differently from 0.3.x.
 *
 * A handshake body is a chain of length prefixed fields, so any cut lands in the
 * middle of a declared field and the decoder rejects it. Every cut, no
 * exceptions.
 *
 * A message body is not like that, and pretending otherwise would be the wrong
 * test. The ciphertext has no length prefix and runs to the end of the frame, so
 * once the header is complete and at least a tag's worth of body survives, a
 * truncated frame is a WELL FORMED frame carrying a shorter ciphertext. There is
 * nothing in the bytes for a parser to object to. What rejects it is the
 * Poly1305 tag, one layer up, and `test/hardening.test.ts` pins that: a
 * truncated ciphertext fails `authentication_failed`.
 *
 * So the message case splits. Cuts that land in the header, or leave a body
 * under sixteen bytes, are decode failures. Cuts past that decode, and must
 * decode to a strictly shorter ciphertext, which is the property that keeps the
 * tag able to see the damage.
 */
test('every truncation of a handshake envelope fails closed', () => {
  for (const payload of [sampleInvite(), sampleAccept()]) {
    const good = encodeEnvelopeBytes(payload);
    for (let cut = 0; cut < good.length; cut += 1) {
      const failure = failureOf(() => decodeEnvelopeBytes(good.subarray(0, cut)));
      assert.ok(
        failure.reason === 'malformed_token' || failure.reason === 'unknown_version',
        `unexpected reason ${failure.reason} at cut ${cut}`,
      );
    }
  }
});

test('a truncated message frame either fails to decode or decodes shorter', () => {
  for (const payload of [samplePlain(64), sampleStep(64)]) {
    const good = encodeEnvelopeBytes(payload);
    const headerLength = good.length - payload.ciphertext.length;
    for (let cut = 0; cut < good.length; cut += 1) {
      const cutBytes = good.subarray(0, cut);
      if (cut < headerLength + MESSAGE_TAG_LEN) {
        // Inside the header, or a body too short to be a tag: a shape error.
        const failure = failureOf(() => decodeEnvelopeBytes(cutBytes));
        assert.ok(
          failure.reason === 'malformed_token' || failure.reason === 'unknown_version',
          `unexpected reason ${failure.reason} at cut ${cut}`,
        );
        continue;
      }
      // Past that, it decodes, and the loss must be visible in the ciphertext
      // rather than swallowed. The tag is what turns this into a rejection.
      const decoded = decodeEnvelopeBytes(cutBytes) as MessagePayload;
      assert.equal(decoded.ciphertext.length, cut - headerLength);
      assert.ok(decoded.ciphertext.length < payload.ciphertext.length);
    }
  }
});

/**
 * Trailing bytes, and why the answer differs by kind now.
 *
 * A handshake body is a sequence of length prefixed fields, so anything after
 * the last one is a hard reject exactly as before. A message body ends with a
 * ciphertext that has no length prefix and runs to the end of the frame, so
 * there is no such thing as a trailing byte: extra bytes are extra ciphertext,
 * and the Poly1305 tag is what rejects them. That is a deliberate trade, and it
 * is safe only because the tag covers the whole body.
 */
test('trailing bytes after a handshake payload are refused', () => {
  for (const payload of [sampleInvite(), sampleAccept()]) {
    const good = encodeEnvelopeBytes(payload);
    for (const extra of [[0x00], [0xff], [0x01, 0x02, 0x03]]) {
      const bad = join(good, new Uint8Array(extra));
      const failure = failureOf(() => decodeEnvelopeBytes(bad));
      assert.equal(failure.reason, 'malformed_token');
      assert.equal(failure.message, 'trailing bytes after the payload');
    }
  }
});

test('extra bytes after a message body become ciphertext for the tag to reject', () => {
  const payload = samplePlain(64);
  const good = encodeEnvelopeBytes(payload);
  const extended = join(good, Uint8Array.of(0xff, 0xff));
  const decoded = decodeEnvelopeBytes(extended) as MessagePayload;
  // The decoder does not reject it, and must not pretend it did not happen
  // either: the two bytes are visible in the ciphertext, where the AEAD sees
  // them.
  assert.equal(decoded.ciphertext.length, payload.ciphertext.length + 2);
  assert.notDeepEqual(decoded.ciphertext, payload.ciphertext);
});

test('a sealed body shorter than its own tag is refused', () => {
  // The header is a literal rather than an encode call, so the test still fails
  // if the encoder starts producing something else. Six bytes of prefix and then
  // the twelve nonce bytes: the body begins at offset 18.
  const header = join(unhex('3ca0a1a2a307'), NONCE);
  for (let bodyLength = 0; bodyLength < 16; bodyLength += 1) {
    const bad = join(header, new Uint8Array(bodyLength));
    const failure = failureOf(() => decodeEnvelopeBytes(bad));
    assert.equal(failure.reason, 'malformed_token');
    assert.ok(failure.message.includes('shorter than its 16 byte tag'), failure.message);
  }
  // Sixteen exactly is a legal, empty plaintext.
  assert.equal((decodeEnvelopeBytes(join(header, new Uint8Array(16))) as MessagePayload).ciphertext.length, 16);
});

/**
 * The nonce is a fixed width field, so a frame that stops inside it is refused
 * before anything downstream sees a short nonce.
 *
 * This test did not exist before 0.4.0 shipped a nonce on the wire, and it is
 * the reason the decoder checks the length rather than letting `subarray` clamp
 * silently. A clamped nonce would reach the AEAD as a shorter value and the tag
 * check would fail with the wrong reason, which is the sort of thing that reads
 * as a decryption bug when it is really a framing bug.
 */
test('a truncated message nonce is refused', () => {
  const prefix = unhex('3ca0a1a2a307');
  for (let present = 0; present < MESSAGE_NONCE_LEN; present += 1) {
    const bad = join(prefix, NONCE.subarray(0, present));
    const failure = failureOf(() => decodeEnvelopeBytes(bad));
    assert.equal(failure.reason, 'malformed_token');
    assert.equal(failure.message, 'truncated message nonce');
  }
});

test('a truncated ratchet key is refused', () => {
  const stepped = unhex(PIN_STEP);
  // Header says the key is there, frame stops thirty bytes into it.
  const bad = stepped.subarray(0, 8 + 30);
  const failure = failureOf(() => decodeEnvelopeBytes(bad));
  assert.equal(failure.reason, 'malformed_token');
  assert.equal(failure.message, 'truncated ratchet public key');
});

/**
 * No allocation on an unvalidated length.
 *
 * This one changed shape with the format. 0.3.x had u16 length prefixes an
 * attacker could inflate, and the test measured that inflating one did not cost
 * a heap request. 0.4.0 has no length prefix on the message body at all, so the
 * attack surface is the varint counters instead: they are read as numbers and
 * must never be treated as sizes. A five byte varint can express 2^35, and the
 * only correct response is to reject the value, not to reserve anything.
 */
test('a huge counter is rejected as a number and never treated as a size', () => {
  const rounds = 20_000;
  const small = join(unhex('3ca0a1a2a3'), unhex('07'), new Uint8Array(4));
  const huge = join(unhex('3ca0a1a2a3'), unhex('ffffffff0f'), new Uint8Array(4));

  // Both reject, one for a short body and one for the same reason after reading
  // a four billion message number. Neither may allocate.
  assert.equal(failureOf(() => decodeEnvelopeBytes(small)).reason, 'malformed_token');
  assert.equal(failureOf(() => decodeEnvelopeBytes(huge)).reason, 'malformed_token');

  const smallStart = Date.now();
  for (let i = 0; i < rounds; i += 1) {
    try {
      decodeEnvelopeBytes(small);
    } catch {
      // expected
    }
  }
  const smallMs = Date.now() - smallStart;

  const bigStart = Date.now();
  for (let i = 0; i < rounds; i += 1) {
    try {
      decodeEnvelopeBytes(huge);
    } catch {
      // expected
    }
  }
  const bigMs = Date.now() - bigStart;

  // Generous, because this is a scheduler-sensitive measurement and a flaky
  // test is worse than no test. The wall clock is dominated by Error
  // construction, so only the ratio means anything.
  assert.ok(
    bigMs <= smallMs * 3 + 250,
    `a 2^32 counter cost ${bigMs} ms against ${smallMs} ms for a small one, which looks like allocation`,
  );
});

test('decoding does not alias the caller buffer', () => {
  const payload = samplePlain(64);
  const frame = join(Uint8Array.of(0xaa, 0xbb), encodeEnvelopeBytes(payload));
  const decoded = decodeEnvelopeBytes(frame.subarray(2));
  assert.deepEqual(decoded, payload);
  // Reusing the frame buffer is normal for a socket reader. The decoded payload
  // goes into session state and must not change underneath it.
  frame.fill(0);
  assert.deepEqual(decoded, payload);
});

test('decoding does not alias a Buffer either, which is what a socket delivers', () => {
  // The Uint8Array case above passed for years while this one did not, because
  // Buffer overrides slice as an alias of subarray. Every frame the CLI reads
  // off a socket arrives as a Buffer, so a caller that pools or reuses its read
  // buffer would have watched session state change underneath it.
  for (const payload of [samplePlain(64), sampleStep(64), sampleInvite()]) {
    const frame = Buffer.from(encodeEnvelopeBytes(payload));
    const decoded = decodeEnvelopeBytes(frame);
    assert.deepEqual(decoded, payload);
    frame.fill(0xaa);
    assert.deepEqual(decoded, payload, 'decoded fields aliased the caller Buffer');
  }
});

test('borrowCiphertext borrows only the ciphertext', () => {
  const payload = sampleStep(64);
  const frame = Buffer.from(encodeEnvelopeBytes(payload));
  const decoded = decodeEnvelopeBytes(frame, { borrowCiphertext: true }) as MessagePayload;
  assert.deepEqual(decoded, payload);
  frame.fill(0xaa);
  // The ciphertext is a view, so it moved with the buffer. That is the whole
  // point of the option and the reason it is off by default.
  assert.notDeepEqual(decoded.ciphertext, payload.ciphertext);
  // Everything that lands in session state is still a copy.
  assert.deepEqual(decoded.sessionTag, payload.sessionTag);
  assert.deepEqual(decoded.ratchetPublic, payload.ratchetPublic);
});
