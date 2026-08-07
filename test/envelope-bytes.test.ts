import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from '@noble/hashes/utils.js';

import type { AcceptPayload, EnvelopePayload, InvitePayload, MessagePayload } from '../src/contract.js';
import {
  decodeEnvelope,
  decodeEnvelopeBytes,
  encodeEnvelope,
  encodeEnvelopeBytes,
} from '../src/envelope.js';
import { isCryptoFailure } from '../src/errors.js';

/**
 * The binary envelope form.
 *
 * Two jobs here. First, prove the byte path is a faithful mirror of the string
 * path: same payloads in, same payloads out, and the string path itself is
 * untouched down to the byte. Second, prove the byte path fails closed on
 * hostile input, because a socket hands it attacker-controlled bytes with no
 * base64 alphabet check in front of it. The string form got a free filter from
 * base64url decoding; the binary form has none, so every reject below is load
 * bearing.
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
// handshake.ts, a 32 byte X25519 public, a 24 byte XChaCha20 nonce, a 1184 byte
// ML-KEM-768 public, a 1088 byte ML-KEM-768 ciphertext. The size assertions
// below are exact, so a wrong constant here shows up as a failure rather than
// as a test that quietly measures the wrong shape.
const CONVERSATION_ID = 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf';

function sampleInvite(): InvitePayload {
  return {
    kind: 'invite',
    conversationId: CONVERSATION_ID,
    sender: { classicalPublic: randomBytes(32), pqPublic: randomBytes(1184) },
  };
}

function sampleAccept(): AcceptPayload {
  return {
    kind: 'accept',
    conversationId: CONVERSATION_ID,
    sender: { classicalPublic: randomBytes(32), pqPublic: randomBytes(1184) },
    kemCiphertext: randomBytes(1088),
    ratchetPublic: randomBytes(32),
  };
}

function sampleMessage(plaintextLength: number): MessagePayload {
  return {
    kind: 'message',
    conversationId: CONVERSATION_ID,
    ratchetPublic: randomBytes(32),
    messageNumber: 4_000_000_000,
    previousChainLength: 65_537,
    nonce: randomBytes(24),
    // Ciphertext is plaintext plus the 16 byte Poly1305 tag.
    ciphertext: randomBytes(plaintextLength + 16),
  };
}

function samples(): EnvelopePayload[] {
  return [sampleInvite(), sampleAccept(), sampleMessage(256)];
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

function u16be(value: number): Uint8Array {
  return new Uint8Array([(value >>> 8) & 0xff, value & 0xff]);
}

function u32be(value: number): Uint8Array {
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
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

const VERSION_BYTE = 0x01;
const TAG_INVITE = 0x01;
const TAG_ACCEPT = 0x02;
const TAG_MESSAGE = 0x03;

// ---------------------------------------------------------------------------
// Round trip
// ---------------------------------------------------------------------------

test('every envelope kind round trips through the binary form exactly', () => {
  for (const payload of samples()) {
    assert.deepEqual(decodeEnvelopeBytes(encodeEnvelopeBytes(payload)), payload);
  }
});

test('binary round trip survives empty and maximum length blobs', () => {
  const empty: MessagePayload = {
    kind: 'message',
    conversationId: '',
    ratchetPublic: new Uint8Array(0),
    messageNumber: 0,
    previousChainLength: 0,
    nonce: new Uint8Array(0),
    ciphertext: new Uint8Array(0),
  };
  const full: MessagePayload = {
    kind: 'message',
    conversationId: CONVERSATION_ID,
    ratchetPublic: randomBytes(32),
    messageNumber: 0xffffffff,
    previousChainLength: 0xffffffff,
    nonce: randomBytes(24),
    // 65535 is the largest a u16 length prefix can describe. One more byte and
    // the encoder refuses, which is the documented ceiling the CLI chunks to.
    ciphertext: randomBytes(65_535),
  };
  assert.deepEqual(decodeEnvelopeBytes(encodeEnvelopeBytes(empty)), empty);
  assert.deepEqual(decodeEnvelopeBytes(encodeEnvelopeBytes(full)), full);
});

test('the binary form and the string form of one payload decode to the same object', () => {
  for (const payload of samples()) {
    const fromText = decodeEnvelope(encodeEnvelope(payload));
    const fromBytes = decodeEnvelopeBytes(encodeEnvelopeBytes(payload));
    assert.deepEqual(fromBytes, fromText);
    assert.deepEqual(fromBytes, payload);
  }
});

test('binary body is byte identical to the base64 the string form carries', () => {
  for (const payload of samples()) {
    const token = encodeEnvelope(payload);
    const binary = encodeEnvelopeBytes(payload);
    // Re-encoding what the string form decodes must land on the same bytes the
    // binary form emits after its two byte header. If these ever diverge, one
    // of the two encoders has grown a field the other has not.
    const reEncoded = encodeEnvelopeBytes(decodeEnvelope(token));
    assert.deepEqual(reEncoded, binary);
    assert.equal(binary[0], VERSION_BYTE);
    assert.equal(binary[1], { invite: TAG_INVITE, accept: TAG_ACCEPT, message: TAG_MESSAGE }[payload.kind]);
  }
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
    // output from v0.1: any drift here is a breaking change for every peer
    // already running an older build.
    assert.equal(encodeEnvelope(payload), token);
    // And the new byte path agrees with the frozen vectors on the payload.
    assert.deepEqual(decodeEnvelopeBytes(encodeEnvelopeBytes(payload)), payload);
  }
});

// ---------------------------------------------------------------------------
// Size
// ---------------------------------------------------------------------------

test('the binary form is strictly smaller than the string form, ratio near 3/4', () => {
  for (const payload of [sampleInvite(), sampleAccept(), sampleMessage(256), sampleMessage(65_519)]) {
    const text = encodeEnvelope(payload);
    const binary = encodeEnvelopeBytes(payload);
    assert.ok(
      binary.length < text.length,
      `binary ${binary.length} is not smaller than text ${text.length}`,
    );
    // 3/4 is the base64 ratio. The fixed "OCX1.<kind>." prefix drags it a
    // little below that, and the smaller the payload the more it drags, which
    // is why the tight bound lives in the next test instead of here.
    const ratio = binary.length / text.length;
    assert.ok(ratio > 0.73 && ratio < 0.76, `ratio ${ratio} is not near 3/4 for ${payload.kind}`);
  }
});

test('the ratio converges on 3/4 as the payload grows', () => {
  const big = sampleMessage(65_519);
  const ratio = encodeEnvelopeBytes(big).length / encodeEnvelope(big).length;
  // The fixed 13 char "OCX1.message." prefix is the only thing keeping this off
  // 0.75 exactly, and at 64 KiB it is worth four ten thousandths.
  assert.ok(ratio > 0.7495 && ratio < 0.7505, `ratio ${ratio} did not converge on 3/4`);
});

/**
 * The 259 byte figure in the README, decomposed.
 *
 * bench/bench.mjs measures overhead as `token.length - plaintext.length` on a
 * 256 byte message, which folds three separate costs into one number:
 *
 *     13  "OCX1.message." prefix, literal ASCII, not base64
 *    160  base64 of the 120 byte binary header and tag (120 * 4/3)
 *     85  base64 inflation of the 256 byte plaintext itself (256 / 3)
 *      1  rounding up to the next base64 quantum
 *    ---
 *    259
 *
 * Only 120 of that is protocol. The third line is the one that scales with the
 * file, and it is the one the binary form deletes outright.
 */
test('the 259 byte string overhead decomposes as documented', () => {
  const payload = sampleMessage(256);
  const text = encodeEnvelope(payload);
  const binary = encodeEnvelopeBytes(payload);

  assert.equal(text.length - 256, 259, 'the README figure moved');

  // 104 bytes of header: 2+32 conversation id, 2+32 ratchet public, 4 message
  // number, 4 previous chain length, 2+24 nonce, 2 ciphertext length prefix.
  // The 16 byte Poly1305 tag lives inside the ciphertext, so 104 + 16 = the
  // 120 byte body constant.
  assert.equal(binary.length - 2 - (256 + 16), 104);
  assert.equal(binary.length - 256, 122, 'binary overhead is 120 body constant plus 2 header bytes');

  // Same message, same crypto, less than half the wire overhead, and the part
  // that grew with the payload is gone entirely.
  assert.ok(binary.length - 256 < text.length - 256);
  assert.equal(encodeEnvelopeBytes(sampleMessage(65_519)).length - 65_519, 122);
});

// ---------------------------------------------------------------------------
// Hostile input
// ---------------------------------------------------------------------------

test('empty and stub input fails closed', () => {
  for (const bytes of [new Uint8Array(0), new Uint8Array(1), new Uint8Array([VERSION_BYTE])]) {
    const failure = failureOf(() => decodeEnvelopeBytes(bytes));
    assert.equal(failure.reason, 'malformed_token');
  }
});

test('a wrong version byte fails as unknown_version', () => {
  const good = encodeEnvelopeBytes(sampleMessage(16));
  for (const version of [0x00, 0x02, 0x7f, 0xff]) {
    const bad = good.slice();
    bad[0] = version;
    const failure = failureOf(() => decodeEnvelopeBytes(bad));
    assert.equal(failure.reason, 'unknown_version');
  }
});

test('an unknown kind tag fails closed', () => {
  const good = encodeEnvelopeBytes(sampleMessage(16));
  for (const tag of [0x00, 0x04, 0x05, 0x80, 0xff]) {
    const bad = good.slice();
    bad[1] = tag;
    const failure = failureOf(() => decodeEnvelopeBytes(bad));
    assert.equal(failure.reason, 'malformed_token');
  }
});

test('a string form token handed to the byte decoder fails closed', () => {
  const token = encodeEnvelope(sampleMessage(64));
  const asBytes = new TextEncoder().encode(token);
  const failure = failureOf(() => decodeEnvelopeBytes(asBytes));
  // "O" of OCX1 is 0x4f, so this trips the version check rather than being
  // misread as a kind tag followed by a body. That is the whole reason the
  // version marker is 0x01 and not a printable byte.
  assert.equal(failure.reason, 'unknown_version');

  // Same for the raw base64url body with no prefix, which starts with an
  // alphabet byte and can never be 0x01.
  const bodyOnly = new TextEncoder().encode(token.slice('OCX1.message.'.length));
  assert.equal(failureOf(() => decodeEnvelopeBytes(bodyOnly)).reason, 'unknown_version');
});

test('every truncation of a valid binary envelope fails closed', () => {
  for (const payload of samples()) {
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

test('trailing bytes after a complete payload are refused', () => {
  for (const payload of samples()) {
    const good = encodeEnvelopeBytes(payload);
    for (const extra of [[0x00], [0xff], [0x01, 0x02, 0x03]]) {
      const bad = join(good, new Uint8Array(extra));
      const failure = failureOf(() => decodeEnvelopeBytes(bad));
      assert.equal(failure.reason, 'malformed_token');
      assert.equal(failure.message, 'trailing bytes after the payload');
    }
  }
});

test('a length prefix that overruns the payload is refused', () => {
  // A message envelope whose conversation id claims 4096 bytes inside a buffer
  // that holds four.
  const bad = join(VERSION_BYTE, TAG_MESSAGE, u16be(4096), new Uint8Array([0x61, 0x62, 0x63, 0x64]));
  const failure = failureOf(() => decodeEnvelopeBytes(bad));
  assert.equal(failure.reason, 'malformed_token');
  assert.equal(failure.message, 'length prefix overruns the payload');

  // And an overrun on the last field, where a lenient reader would be most
  // tempted to just take what is there.
  const payload = sampleMessage(32);
  const good = encodeEnvelopeBytes(payload);
  const inflated = good.slice();
  // Rewrite the ciphertext length prefix, which sits immediately before the
  // final blob, to claim 200 bytes more than the buffer holds.
  const prefixAt = good.length - (32 + 16) - 2;
  inflated.set(u16be(32 + 16 + 200), prefixAt);
  const second = failureOf(() => decodeEnvelopeBytes(inflated));
  assert.equal(second.reason, 'malformed_token');
  assert.equal(second.message, 'length prefix overruns the payload');
});

/**
 * No allocation on an unvalidated length.
 *
 * The reader compares the claimed length against the remaining buffer BEFORE it
 * slices, so a hostile prefix costs one comparison rather than a heap request.
 * Worth stating plainly: this format caps every length prefix at u16, so the
 * largest claim an attacker can even express is 65535 bytes, not 4 GB. The 4 GB
 * shape is still exercised below, in the only place a 32 bit number appears in
 * the wire format, to confirm those fields are counters and never lengths.
 */
test('a hostile length prefix fails immediately without allocating', () => {
  // Maximum expressible claim, 65535 bytes, inside a four byte buffer.
  const maxClaim = join(VERSION_BYTE, TAG_MESSAGE, u16be(0xffff));
  const failure = failureOf(() => decodeEnvelopeBytes(maxClaim));
  assert.equal(failure.message, 'length prefix overruns the payload');

  // 4 GiB claimed in the u32 slots. Those are the message counters, so the
  // decoder reads them as numbers and moves on: it must not treat any of them
  // as a size, and the following truncated field is what stops it.
  const fourGiB = join(
    VERSION_BYTE,
    TAG_MESSAGE,
    u16be(0),
    u16be(0),
    u32be(0xffffffff),
    u32be(0xffffffff),
    u16be(0xffff),
  );
  const huge = failureOf(() => decodeEnvelopeBytes(fourGiB));
  assert.equal(huge.reason, 'malformed_token');
  assert.equal(huge.message, 'length prefix overruns the payload');

  // Differential timing, which is the part an absolute bound cannot show. Both
  // loops reject the same number of envelopes; the only difference is that one
  // claims 16 bytes and the other claims 65535. If the length were trusted
  // before the bounds check, the second loop would push 4096 times more through
  // the heap and the ratio would blow out. The wall clock here is dominated by
  // Error construction (V8 captures a stack on every throw), so the absolute
  // numbers say nothing on their own and only the ratio is meaningful.
  const smallClaim = join(VERSION_BYTE, TAG_MESSAGE, u16be(16));
  const rounds = 20_000;

  const smallStart = Date.now();
  for (let i = 0; i < rounds; i += 1) {
    try {
      decodeEnvelopeBytes(smallClaim);
    } catch {
      // expected
    }
  }
  const smallMs = Date.now() - smallStart;

  const bigStart = Date.now();
  for (let i = 0; i < rounds; i += 1) {
    try {
      decodeEnvelopeBytes(maxClaim);
    } catch {
      // expected
    }
  }
  const bigMs = Date.now() - bigStart;

  // Generous, because this is a scheduler-sensitive measurement and a flaky
  // test is worse than no test. A trusting decoder would not be near this.
  assert.ok(
    bigMs <= smallMs * 3 + 250,
    `a 65535 byte claim cost ${bigMs} ms against ${smallMs} ms for a 16 byte claim, which looks like allocation`,
  );
});

test('a truncated integer field is refused before it is read', () => {
  // Message envelope, empty conversation id and ratchet public, then only two
  // of the four bytes the message number needs.
  const bad = join(VERSION_BYTE, TAG_MESSAGE, u16be(0), u16be(0), new Uint8Array([0x00, 0x00]));
  const failure = failureOf(() => decodeEnvelopeBytes(bad));
  assert.equal(failure.reason, 'malformed_token');
  assert.equal(failure.message, 'truncated integer field');
});

test('decoding does not alias the caller buffer', () => {
  const payload = sampleMessage(64);
  const frame = join(new Uint8Array([0xaa, 0xbb]), encodeEnvelopeBytes(payload), new Uint8Array(0));
  const decoded = decodeEnvelopeBytes(frame.subarray(2));
  assert.deepEqual(decoded, payload);
  // Reusing the frame buffer is normal for a socket reader. The decoded payload
  // goes into session state and must not change underneath it.
  frame.fill(0);
  assert.deepEqual(decoded, payload);
});
