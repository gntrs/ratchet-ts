// Wire benchmark for ratchet-ts. Everything in one process, over real loopback
// sockets, through a relay that counts the bytes as they pass.
//
//   npm run bench:wire                 3 runs, the default
//   npm run bench:wire -- --runs 5     5 runs
//
// This is the sibling of bench/bench.mjs. That script times primitives; this one
// times the things a 0.3.0 release note would claim: how many bytes leave the
// machine per byte of payload, how fast each AEAD backend actually is, and how
// much of a handshake is this library versus the network between the two peers.
//
// Read bench/README.md before quoting any number out of here. The short version:
// only the crypto columns say anything about this library. Every throughput
// number is a property of the transport it was measured on, and the transport
// here is a loopback socket with an extra hop in it.
import os from 'node:os';
import net from 'node:net';
import { createHash, randomBytes } from 'node:crypto';

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';

import { connect, listen } from '../cli/frame.mjs';
import { humanBytes } from '../cli/format.mjs';
import * as lib from '../dist/index.js';

const engine = lib.engine;

// ---------------------------------------------------------------------------
// The 0.2.1 baseline
// ---------------------------------------------------------------------------

/**
 * NOT A FRESH MEASUREMENT.
 *
 * These numbers were measured once, on ratchet-ts 0.2.1, moving a 763.5 kB
 * screenshot from a Windows laptop to a WSL box on a different network, over a
 * Tailscale DERP relay rather than a direct route. They are the sender side of
 * that transfer's --stats table and they are also the numbers printed in the
 * README.
 *
 * Nothing in this file reproduces them and nothing in this file can. The relay
 * was the bottleneck, so the 3.00 MB/s figure is a fact about somebody else's
 * network on one afternoon. It is hard coded here so the comparison table has a
 * before column, and it is labelled loudly so nobody reads it as this machine.
 *
 * The two rows worth comparing are the byte counts and the crypto time. Those
 * are protocol and CPU, so they mean the same thing on any link.
 */
const BASELINE_0_2_1 = Object.freeze({
  label: '0.2.1 over a Tailscale DERP relay',
  plainBytes: 763500,
  wireBytes: 1020500,
  overheadBytes: 257000,
  overheadPct: 33.7,
  chunks: 12,
  senderCryptoMs: 52,
  throughputMBs: 3.0,
});

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const RUNS = (() => {
  const i = process.argv.indexOf('--runs');
  const n = i === -1 ? 3 : Number.parseInt(process.argv[i + 1] ?? '', 10);
  return Number.isFinite(n) && n >= 1 && n <= 50 ? n : 3;
})();

// The chunk size a real transfer gets, restated rather than imported.
//
// cli/protocol.mjs computes min(64 KiB, 0xffff - 16) and exports it as
// DEFAULT_CHUNK_BYTES, and importing it from there would be the tidier thing.
// It is copied instead because that module also imports names from dist that
// may not exist while the release is being assembled, and a benchmark that
// cannot start because an unrelated file is half converted is useless. If the
// envelope ever gets a u32 length prefix, this number moves and so does the
// one in cli/protocol.mjs, and nothing here will notice: check both.
const CHUNK = Math.min(64 * 1024, 0xffff - 16);

// Two decades of payload size, because envelope overhead is a fixed cost per
// chunk and a percentage only looks meaningful at one end of that range.
const SIZES = [20, 1024, 64 * 1024, 1024 * 1024, 10 * 1024 * 1024];

// The size the 0.2.1 baseline was measured at, so the comparison row is the same
// payload and the same chunk count rather than an interpolation.
const BASELINE_SIZE = BASELINE_0_2_1.plainBytes;
const BASELINE_NAME = 'screenshot.png';

// Protocol version byte from cli/protocol.mjs. Restated rather than imported
// because it is a private constant there, and the header JSON below has to be
// byte identical to the one a real transfer sends or the wire totals are wrong.
const PROTOCOL_VERSION = 1;

const HOST = '127.0.0.1';

// The base64url token form pads three bytes into four characters and every
// frame used to carry one trailing newline. That is the wire this release is
// replacing, and it is reconstructed rather than measured, so it is exact
// arithmetic on a real envelope rather than a guess.
const TOKEN_FRAME_OVERHEAD = 1;

// Header of the self describing binary envelope: one version byte, one kind
// tag. Only used when dist does not export encodeEnvelopeBytes, in which case
// the binary column is derived from the base64 length instead of measured, and
// says so.
const BINARY_ENVELOPE_HEADER = 2;
const BINARY_FRAME_PREFIX = 4;

// ---------------------------------------------------------------------------
// What this build actually gives us
// ---------------------------------------------------------------------------

const HAS_ENVELOPE_BYTES =
  typeof lib.encodeEnvelopeBytes === 'function' && typeof lib.decodeEnvelopeBytes === 'function';

const HAS_LIB_AEAD =
  typeof lib.sealAead === 'function' &&
  typeof lib.openAead === 'function' &&
  typeof lib.aeadBackend === 'function';

const LIB_AEAD_BACKEND = HAS_LIB_AEAD ? lib.aeadBackend() : null;

const WIRE_MODE = HAS_ENVELOPE_BYTES ? 'binary' : 'token';

const notes = [];
if (!HAS_ENVELOPE_BYTES) {
  notes.push(
    'dist does not export encodeEnvelopeBytes, so frames carry the base64url token and the binary column is arithmetic, not measurement. Re-export it from src/index.ts and rebuild to fix this.',
  );
}
if (!HAS_LIB_AEAD) {
  notes.push(
    'dist does not export sealAead/openAead/aeadBackend, so only the @noble/ciphers column in section 2 is real.',
  );
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const enc = new TextEncoder();
const dec = new TextDecoder();

const pct = (n) => `${n.toFixed(1)}%`;
const ms = (n) => n.toFixed(2);

function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function median(xs) {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}

/**
 * Median of the per-run values plus the spread between the best and worst run,
 * as a share of the median. Same construction and same meaning as bench.mjs:
 * under 10 percent the machine was quiet, over 25 percent something else was
 * competing for the CPU and the numbers are worth less.
 */
function agg(runs, pick) {
  const xs = runs.map(pick).filter((n) => Number.isFinite(n));
  if (xs.length === 0) return { median: NaN, best: NaN, worst: NaN, spread: NaN };
  const s = [...xs].sort((a, b) => a - b);
  const m = s[Math.floor(s.length / 2)];
  const best = s[0];
  const worst = s[s.length - 1];
  return { median: m, best, worst, spread: m === 0 ? 0 : ((worst - best) / m) * 100 };
}

function spreadOf(runs, pick) {
  const a = agg(runs, pick);
  return Number.isFinite(a.spread) ? pct(a.spread) : 'n/a';
}

/** Charge one call's duration to a named clock and nothing else. */
async function charge(clock, fn) {
  const t0 = performance.now();
  try {
    return await fn();
  } finally {
    clock.ms += performance.now() - t0;
  }
}

/** Base64url without padding: three payload bytes become four characters. */
function base64urlLength(byteLength) {
  return Math.ceil((byteLength * 4) / 3);
}

/** Inverse of the above, for recovering a body length from a token. */
function bodyLengthFromBase64url(chars) {
  return Math.floor((chars * 3) / 4);
}

// ---------------------------------------------------------------------------
// Frame transcoding
// ---------------------------------------------------------------------------
//
// engine.seal returns a token string and engine.open takes one, so putting the
// binary envelope on the wire means transcoding at both ends. A binary native
// implementation would not pay that, so it is charged to its own clock and
// printed in its own column instead of being folded into the crypto number.
// Do not read the transcode column as a cost of this release; read it as the
// cost of this harness not having a bytes-in bytes-out seal API to call.

function frameFromToken(token, clock) {
  if (WIRE_MODE === 'binary') {
    const t0 = performance.now();
    const bytes = lib.encodeEnvelopeBytes(lib.decodeEnvelope(token));
    clock.ms += performance.now() - t0;
    return bytes;
  }
  return enc.encode(token);
}

function tokenFromFrame(frame, clock) {
  if (WIRE_MODE === 'binary') {
    const t0 = performance.now();
    const token = lib.encodeEnvelope(lib.decodeEnvelopeBytes(frame));
    clock.ms += performance.now() - t0;
    return token;
  }
  return dec.decode(frame);
}

/**
 * What one envelope costs on each of the two wires, from the same token.
 *
 * The token number is always exact. The binary number is exact when dist
 * exports encodeEnvelopeBytes and is otherwise reconstructed from the base64
 * length, which is correct arithmetic over a documented two byte header but is
 * not a measurement, and the printed output says so.
 */
function sizeBothWays(token) {
  const tokenBytes = Buffer.byteLength(token, 'utf8');
  if (HAS_ENVELOPE_BYTES) {
    return { tokenBytes, envelopeBytes: lib.encodeEnvelopeBytes(lib.decodeEnvelope(token)).length };
  }
  // OCX1.<kind>.<base64url>: everything before the last dot is ASCII overhead.
  const bodyChars = token.length - (token.lastIndexOf('.') + 1);
  return {
    tokenBytes,
    envelopeBytes: bodyLengthFromBase64url(bodyChars) + BINARY_ENVELOPE_HEADER,
  };
}

// ---------------------------------------------------------------------------
// Loopback plumbing
// ---------------------------------------------------------------------------

/**
 * A TCP relay that forwards everything and counts it on the way past.
 *
 * This is the only honest way to answer "bytes on the wire" from inside one
 * process: not the length of the thing we handed to send(), but the number of
 * bytes the kernel actually carried, framing prefixes included. It costs one
 * extra hop and one extra copy per direction, which is why the throughput
 * numbers here are a floor rather than a best case.
 */
async function countingRelay(targetPort) {
  const counters = { up: 0, down: 0 };
  const live = new Set();

  const server = net.createServer((inbound) => {
    const outbound = net.connect({ host: HOST, port: targetPort });
    live.add(inbound);
    live.add(outbound);
    inbound.on('data', (c) => {
      counters.up += c.length;
    });
    outbound.on('data', (c) => {
      counters.down += c.length;
    });
    inbound.pipe(outbound);
    outbound.pipe(inbound);
    // Either half hanging up first is normal at the end of a transfer, so a
    // relay must never turn that into an unhandled error event.
    inbound.on('error', () => outbound.destroy());
    outbound.on('error', () => inbound.destroy());
  });

  server.on('error', () => {});

  await new Promise((resolve) => server.listen(0, HOST, resolve));

  return {
    port: server.address().port,
    counters,
    snapshot: () => ({ up: counters.up, down: counters.down }),
    close: () =>
      new Promise((resolve) => {
        for (const s of live) s.destroy();
        server.close(() => resolve());
      }),
  };
}

async function firstChannel(server) {
  for await (const channel of server) return channel;
  throw new Error('the loopback server closed before a connection arrived');
}

/**
 * Both ends of one framed loopback connection, with a byte counter in between.
 *
 * `relay` is optional because the handshake measurement does not want the extra
 * hop in its latency, and the byte counts it would produce are already covered
 * by section 1.
 */
async function loopbackPair({ counted = true } = {}) {
  const server = await listen({ host: HOST, port: 0 });
  const relay = counted ? await countingRelay(server.port) : null;
  const accepting = firstChannel(server);
  const client = await connect({ host: HOST, port: relay ? relay.port : server.port });
  const accepted = await accepting;
  return {
    // The receiver is the listener, matching the CLI: it has the stable address
    // and it is the party that invites.
    receiver: accepted,
    sender: client,
    relay,
    close: async () => {
      await client.close();
      await accepted.close();
      await server.close();
      if (relay) await relay.close();
    },
  };
}

/** A frame adapter, so the same code works whether frames are bytes or a token. */
function wireFor(channel, transcodeClock) {
  return {
    async send(token) {
      await channel.send(frameFromToken(token, transcodeClock));
    },
    async recv(what) {
      const frame = await channel.receive();
      if (frame === null || frame === undefined) {
        throw new Error(`the channel closed while waiting for ${what}`);
      }
      return tokenFromFrame(frame, transcodeClock);
    },
  };
}

// ---------------------------------------------------------------------------
// Section 1: one real transfer, measured
// ---------------------------------------------------------------------------
//
// This reimplements the cli/protocol.mjs frame sequence rather than calling it,
// so the bench keeps working while that file is mid refactor. The accounting is
// deliberately identical: "on the wire" is the sealed header plus the sealed
// chunks, sender to receiver. Handshake frames are counted separately and
// reported in section 3, exactly as --stats does it.
//
// The consequence, stated plainly: a divergence introduced in cli/protocol.mjs
// will not show up in these numbers.

function headerJson({ name, size, sha256, chunks }) {
  return JSON.stringify({
    v: PROTOCOL_VERSION,
    name,
    size,
    sha256,
    chunks,
    chunkSize: CHUNK,
  });
}

function chunkCount(size) {
  return size === 0 ? 0 : Math.ceil(size / CHUNK);
}

async function benchSender({ wire, identity, name, bytes, clock, relay }) {
  const size = bytes.length;
  const chunks = chunkCount(size);

  const handshakeStart = performance.now();

  const invite = await wire.recv('the peer invite');
  let opened = await charge(clock, () => engine.open(identity, invite, {}));
  if (opened.outcome !== 'invite') throw new Error(`expected an invite, got ${opened.outcome}`);
  let session = opened.session;
  await wire.send(opened.reply);

  // The responder has no send chain until the initiator speaks, so the receiver
  // has to say something before this side can send at all. See cli/protocol.mjs
  // step 3b: the handshake is not finished until this frame lands.
  const ready = await wire.recv('the receiver ready frame');
  const readyOpen = await charge(clock, () => engine.open(identity, ready, { session }));
  if (readyOpen.outcome !== 'message') throw new Error('expected a ready frame');
  session = readyOpen.session;

  const handshakeMs = performance.now() - handshakeStart;
  // Every handshake byte has necessarily crossed the relay by now: the receiver
  // could not have produced this frame without consuming our reply first.
  const afterHandshake = relay ? relay.snapshot() : null;

  const sha256 = sha256Hex(bytes);
  const header = headerJson({ name, size, sha256, chunks });

  // What the same envelopes would have cost on the 0.2.1 base64 wire, and on
  // the binary wire, computed frame by frame from the tokens we are sending.
  let tokenWire = 0;
  let binaryWire = 0;

  const wallStart = performance.now();

  const sealedHeader = await charge(clock, () => engine.seal(session, header));
  session = sealedHeader.session;
  {
    const both = sizeBothWays(sealedHeader.token);
    tokenWire += both.tokenBytes + TOKEN_FRAME_OVERHEAD;
    binaryWire += both.envelopeBytes + BINARY_FRAME_PREFIX;
  }
  await wire.send(sealedHeader.token);

  for (let i = 0; i < chunks; i += 1) {
    const start = i * CHUNK;
    const slice = bytes.subarray(start, Math.min(start + CHUNK, size));
    const sealed = await charge(clock, () => engine.sealBytes(session, slice));
    session = sealed.session;
    const both = sizeBothWays(sealed.token);
    tokenWire += both.tokenBytes + TOKEN_FRAME_OVERHEAD;
    binaryWire += both.envelopeBytes + BINARY_FRAME_PREFIX;
    await wire.send(sealed.token);
  }

  const ackFrame = await wire.recv('the receiver acknowledgement');
  const ack = await charge(clock, () => engine.open(identity, ackFrame, { session }));
  if (ack.outcome !== 'message') throw new Error('expected an acknowledgement');
  const wallMs = performance.now() - wallStart;
  const afterPayload = relay ? relay.snapshot() : null;

  const ackBody = JSON.parse(ack.plaintext);
  if (ackBody.ok !== true || ackBody.sha256 !== sha256) {
    throw new Error('the receiver did not verify the payload');
  }

  return {
    plainBytes: size,
    chunks,
    handshakeMs,
    wallMs,
    sha256,
    tokenWire,
    binaryWire,
    handshakeWireUp: afterHandshake ? afterHandshake.up : NaN,
    handshakeWireDown: afterHandshake ? afterHandshake.down : NaN,
    // The measured answer: bytes the kernel carried from sender to receiver
    // between the end of the handshake and the acknowledgement.
    measuredWire: afterHandshake && afterPayload ? afterPayload.up - afterHandshake.up : NaN,
  };
}

async function benchReceiver({ wire, identity, clock }) {
  const invited = await charge(clock, () => engine.invite(identity));
  await wire.send(invited.token);

  const replyFrame = await wire.recv('the sender reply');
  const accepted = await charge(clock, () =>
    engine.open(identity, replyFrame, { pending: invited.pending }),
  );
  if (accepted.outcome !== 'accepted') throw new Error(`expected an accept, got ${accepted.outcome}`);
  let session = accepted.session;

  const ready = await charge(clock, () =>
    engine.seal(session, JSON.stringify({ v: PROTOCOL_VERSION, ready: true })),
  );
  session = ready.session;
  await wire.send(ready.token);

  const headerFrame = await wire.recv('the payload header');
  const headerOpen = await charge(clock, () => engine.open(identity, headerFrame, { session }));
  if (headerOpen.outcome !== 'message') throw new Error('expected a payload header');
  session = headerOpen.session;
  const header = JSON.parse(headerOpen.plaintext);

  const assembled = new Uint8Array(header.size);
  let done = 0;
  for (let i = 0; i < header.chunks; i += 1) {
    const frame = await wire.recv(`chunk ${i + 1}`);
    const chunk = await charge(clock, () => engine.openBytes(session, frame));
    session = chunk.session;
    assembled.set(chunk.plaintext, done);
    done += chunk.plaintext.length;
  }
  if (done !== header.size) throw new Error(`assembled ${done} of ${header.size} bytes`);

  // Belt and braces over the AEAD, same reasoning as the CLI: each chunk
  // authenticates only itself, so only a whole payload hash catches an
  // assembly fault. A bench that silently moved the wrong bytes would be worse
  // than no bench.
  const sha256 = sha256Hex(assembled);
  if (sha256 !== header.sha256) throw new Error('payload hash mismatch after assembly');

  const ack = await charge(clock, () => engine.seal(session, JSON.stringify({ ok: true, sha256 })));
  await wire.send(ack.token);

  return { plainBytes: header.size, sha256 };
}

async function measureTransfer({ size, name }) {
  const bytes = randomBytes(size);
  const pair = await loopbackPair({ counted: true });
  const senderCrypto = { ms: 0 };
  const receiverCrypto = { ms: 0 };
  const transcode = { ms: 0 };

  try {
    const senderWire = wireFor(pair.sender, transcode);
    const receiverWire = wireFor(pair.receiver, transcode);
    const alice = await engine.createIdentity();
    const bob = await engine.createIdentity();

    const [sent] = await Promise.all([
      benchSender({
        wire: senderWire,
        identity: alice,
        name,
        bytes,
        clock: senderCrypto,
        relay: pair.relay,
      }),
      benchReceiver({ wire: receiverWire, identity: bob, clock: receiverCrypto }),
    ]);

    return {
      ...sent,
      senderCryptoMs: senderCrypto.ms,
      receiverCryptoMs: receiverCrypto.ms,
      transcodeMs: transcode.ms,
      // MB is 1e6 bytes here, not 1048576, matching cli/protocol.mjs so the two
      // throughput numbers can sit in the same table without a footnote.
      throughputMBs: sent.wallMs > 0 ? size / 1e6 / (sent.wallMs / 1000) : 0,
    };
  } finally {
    await pair.close();
  }
}

// ---------------------------------------------------------------------------
// Section 2: AEAD throughput, both backends, explicitly
// ---------------------------------------------------------------------------
//
// Two call paths are measured side by side. @noble/ciphers is called directly,
// so that column exists on every build and is the reference. src/aead.ts is
// called through its public seal/open, whichever backend it picked, so that
// column is whatever this Node happens to select. If aeadBackend() says 'noble'
// then both columns are the same primitive and the difference is wrapper cost,
// which is worth knowing but is not a backend comparison.

const AEAD_CASES = [
  // 256 B is the message size bench/bench.mjs times, so the two scripts talk
  // about the same thing. At this size per call setup dominates and the number
  // is closer to a call rate than a stream rate, which is why the chunk sized
  // row is there too: that one is the honest bulk figure.
  { label: '256 B', size: 256, iters: 8000 },
  { label: `${CHUNK} B`, size: CHUNK, iters: 400 },
];

function nobleSeal(key, nonce, plaintext, aad) {
  return xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
}

function nobleOpen(key, nonce, ciphertext, aad) {
  return xchacha20poly1305(key, nonce, aad).decrypt(ciphertext);
}

async function throughputMBs(iters, bytesPerIter, fn) {
  const t0 = performance.now();
  for (let i = 0; i < iters; i += 1) await fn(i);
  const elapsed = performance.now() - t0;
  if (elapsed <= 0) return Infinity;
  return (iters * bytesPerIter) / 1e6 / (elapsed / 1000);
}

async function measureAead({ warm = false } = {}) {
  const out = {};
  for (const testCase of AEAD_CASES) {
    // A tenth of the iterations is enough to get the JIT past the interpreter,
    // which is all the warm pass is for.
    const iters = warm ? Math.max(1, Math.floor(testCase.iters / 10)) : testCase.iters;
    const key = randomBytes(32);
    // 48 bytes is close to what messageAad() produces for a real message
    // header, so the Poly1305 input length is realistic rather than zero.
    const aad = randomBytes(48);
    const plaintext = randomBytes(testCase.size);
    const nonces = Array.from({ length: iters }, () => randomBytes(24));
    // Ciphertexts for the open measurement are built outside the timer, so the
    // open column times decryption and not encryption plus decryption.
    const sealedNoble = nonces.map((n) => nobleSeal(key, n, plaintext, aad));

    out[`noble seal ${testCase.label}`] = await throughputMBs(iters, testCase.size, (i) =>
      nobleSeal(key, nonces[i], plaintext, aad),
    );
    out[`noble open ${testCase.label}`] = await throughputMBs(iters, testCase.size, (i) =>
      nobleOpen(key, nonces[i], sealedNoble[i], aad),
    );

    if (HAS_LIB_AEAD) {
      out[`lib seal ${testCase.label}`] = await throughputMBs(iters, testCase.size, (i) =>
        lib.sealAead(key, nonces[i], plaintext, aad),
      );
      out[`lib open ${testCase.label}`] = await throughputMBs(iters, testCase.size, (i) =>
        lib.openAead(key, nonces[i], sealedNoble[i], aad),
      );
    }
  }
  return out;
}

/**
 * The pinned contract says src/aead.ts must be byte identical to
 * @noble/ciphers for every input. A benchmark that reported a faster backend
 * without checking that would be reporting a faster wrong answer, so this runs
 * first and its result is printed above the throughput table.
 */
async function verifyAeadIdentity(samples = 200) {
  if (!HAS_LIB_AEAD) return null;
  let sealMatches = 0;
  let openMatches = 0;
  let firstFailure = null;

  for (let i = 0; i < samples; i += 1) {
    const key = randomBytes(32);
    const nonce = randomBytes(24);
    // Zero length plaintext and zero length aad are both legal and both are
    // where a hand written backend usually goes wrong, so they are in the mix.
    const plaintext = randomBytes(i % 17 === 0 ? 0 : 1 + (i * 37) % 4096);
    const aad = randomBytes(i % 11 === 0 ? 0 : 1 + (i * 13) % 128);

    const reference = nobleSeal(key, nonce, plaintext, aad);
    const mine = await lib.sealAead(key, nonce, plaintext, aad);
    if (Buffer.compare(Buffer.from(mine), Buffer.from(reference)) === 0) sealMatches += 1;
    else if (!firstFailure) firstFailure = `seal differs at sample ${i} (plaintext ${plaintext.length} B, aad ${aad.length} B)`;

    const roundTrip = await lib.openAead(key, nonce, reference, aad);
    if (Buffer.compare(Buffer.from(roundTrip), Buffer.from(plaintext)) === 0) openMatches += 1;
    else if (!firstFailure) firstFailure = `open differs at sample ${i}`;
  }

  return { samples, sealMatches, openMatches, firstFailure };
}

// ---------------------------------------------------------------------------
// Section 3: handshake, crypto time versus round trips
// ---------------------------------------------------------------------------
//
// Three frames cross the wire before either side can send a payload:
//
//   receiver -> sender   invite
//   sender   -> receiver accept
//   receiver -> sender   ready
//
// That is three one way flights, so one and a half round trips. The crypto
// column is one ML-KEM-768 keygen, encapsulation and decapsulation plus two
// X25519 exchanges, and it is the same on any link. The transport column is
// wall minus crypto and it is entirely a fact about the network.

const HANDSHAKE_FLIGHTS = 3;
const HANDSHAKE_ROUND_TRIPS = HANDSHAKE_FLIGHTS / 2;

async function oneHandshake() {
  const pair = await loopbackPair({ counted: false });
  const senderCrypto = { ms: 0 };
  const receiverCrypto = { ms: 0 };
  const transcode = { ms: 0 };

  try {
    const senderWire = wireFor(pair.sender, transcode);
    const receiverWire = wireFor(pair.receiver, transcode);
    const alice = await engine.createIdentity();
    const bob = await engine.createIdentity();

    let senderWall = 0;
    let receiverWall = 0;

    const senderSide = (async () => {
      // The clock starts before the first read, matching cli/protocol.mjs: from
      // this side, waiting for the peer to produce an invite is part of the
      // handshake whether or not the CPU was busy.
      const t0 = performance.now();
      const invite = await senderWire.recv('the peer invite');
      const opened = await charge(senderCrypto, () => engine.open(alice, invite, {}));
      await senderWire.send(opened.reply);
      const ready = await senderWire.recv('the receiver ready frame');
      await charge(senderCrypto, () => engine.open(alice, ready, { session: opened.session }));
      senderWall = performance.now() - t0;
    })();

    const receiverSide = (async () => {
      const t0 = performance.now();
      const invited = await charge(receiverCrypto, () => engine.invite(bob));
      await receiverWire.send(invited.token);
      const reply = await receiverWire.recv('the sender reply');
      const accepted = await charge(receiverCrypto, () =>
        engine.open(bob, reply, { pending: invited.pending }),
      );
      const ready = await charge(receiverCrypto, () =>
        engine.seal(accepted.session, JSON.stringify({ v: PROTOCOL_VERSION, ready: true })),
      );
      await receiverWire.send(ready.token);
      receiverWall = performance.now() - t0;
    })();

    await Promise.all([senderSide, receiverSide]);

    return {
      senderWallMs: senderWall,
      receiverWallMs: receiverWall,
      senderCryptoMs: senderCrypto.ms,
      receiverCryptoMs: receiverCrypto.ms,
      transcodeMs: transcode.ms,
    };
  } finally {
    await pair.close();
  }
}

/**
 * Loopback round trip, measured with the same framing the handshake uses.
 *
 * Printed next to the handshake so a reader can subtract. On this machine a
 * round trip is tens of microseconds; on the DERP relay the 0.2.1 baseline was
 * measured over it was tens of milliseconds, and that difference is the whole
 * gap between the two handshake numbers.
 */
async function measureRoundTrip(iterations = 200) {
  const pair = await loopbackPair({ counted: false });
  try {
    const probe = randomBytes(32);
    const echo = (async () => {
      for (let i = 0; i < iterations; i += 1) {
        const frame = await pair.receiver.receive();
        if (frame === null || frame === undefined) return;
        await pair.receiver.send(frame);
      }
    })();

    const samples = [];
    for (let i = 0; i < iterations; i += 1) {
      const t0 = performance.now();
      await pair.sender.send(probe);
      await pair.sender.receive();
      samples.push(performance.now() - t0);
    }
    await echo;
    return median(samples);
  } finally {
    await pair.close();
  }
}

// ---------------------------------------------------------------------------
// One run
// ---------------------------------------------------------------------------

async function oneRun() {
  const out = { sizes: {}, aead: null, handshake: null, rttMs: NaN, baseline: null };

  for (const size of SIZES) {
    out.sizes[size] = await measureTransfer({ size, name: 'bench.bin' });
  }

  out.baseline = await measureTransfer({ size: BASELINE_SIZE, name: BASELINE_NAME });
  out.aead = await measureAead();

  // A handful of handshakes per run, because one handshake is a single sample
  // and this is the noisiest thing in the file.
  const handshakes = [];
  for (let i = 0; i < 15; i += 1) handshakes.push(await oneHandshake());
  out.handshake = {
    senderWallMs: median(handshakes.map((h) => h.senderWallMs)),
    receiverWallMs: median(handshakes.map((h) => h.receiverWallMs)),
    senderCryptoMs: median(handshakes.map((h) => h.senderCryptoMs)),
    receiverCryptoMs: median(handshakes.map((h) => h.receiverCryptoMs)),
  };

  out.rttMs = await measureRoundTrip(200);
  return out;
}

// ---------------------------------------------------------------------------
// Warm up
// ---------------------------------------------------------------------------
//
// The JIT and the noble precomputed tables both cost real milliseconds the
// first time through. Timing a cold engine measures the compiler.

for (let i = 0; i < 20; i += 1) {
  const a = await engine.createIdentity();
  const b = await engine.createIdentity();
  const inv = await engine.invite(a);
  const bo = await engine.open(b, inv.token, {});
  await engine.open(a, bo.reply, { pending: inv.pending });
}
await measureTransfer({ size: 256 * 1024, name: 'warmup.bin' });
await measureAead({ warm: true });

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

const aeadCheck = await verifyAeadIdentity(200);

console.log(`\nratchet-ts wire benchmark`);
console.log(`${process.version}  |  ${(os.cpus()[0] || {}).model}  |  ${os.platform()}/${os.arch()}`);
console.log(
  `${RUNS} run${RUNS === 1 ? '' : 's'}  |  loopback ${HOST} through a counting relay  |  chunk ${CHUNK} B`,
);
console.log(
  `wire: ${WIRE_MODE === 'binary' ? 'self describing binary envelope' : 'OCX1 base64url token'}, u32 length prefixed frames`,
);
console.log(
  `aead: @noble/ciphers direct${HAS_LIB_AEAD ? `, and src/aead.ts reporting backend "${LIB_AEAD_BACKEND}"` : ', src/aead.ts not exported from dist'}`,
);
// src/aead.ts may or may not read an environment variable to pick a backend.
// If it does, echoing it here is the difference between a reader trusting the
// table and a reader wondering which build they just measured.
if (process.env.RATCHET_AEAD) console.log(`env: RATCHET_AEAD=${process.env.RATCHET_AEAD}`);
console.log('');

for (const note of notes) console.log(`  note: ${note}`);
if (notes.length) console.log('');

const runs = [];
for (let r = 1; r <= RUNS; r += 1) {
  process.stdout.write(`  running ${r}/${RUNS}\r`);
  runs.push(await oneRun());
}
process.stdout.write('                    \r');

// --- 1. bytes on the wire ---------------------------------------------------

console.log('1. bytes on the wire');
console.log('   Sealed header plus sealed chunks, sender to receiver, counted by a relay');
console.log('   sitting between the two sockets. Handshake frames are in section 3, which');
console.log('   is the same split cli/protocol.mjs uses when it prints --stats.\n');

console.table(
  SIZES.map((size) => {
    const first = runs[0].sizes[size];
    const measured = Number.isFinite(first.measuredWire) ? first.measuredWire : first.binaryWire;
    const overhead = measured - first.plainBytes;
    return {
      payload: humanBytes(first.plainBytes),
      chunks: first.chunks,
      'on the wire': humanBytes(measured),
      overhead: humanBytes(overhead),
      'overhead %': pct((overhead / first.plainBytes) * 100),
      'per chunk': `${Math.round(overhead / Math.max(first.chunks, 1))} B`,
      'byte count': new Set(runs.map((r) => r.sizes[size].measuredWire)).size === 1 ? 'stable' : 'MOVED',
    };
  }),
);

console.log('   the same envelopes costed against each wire format\n');
console.log('   0.2.1: OCX1 base64url token plus a newline delimiter.');
console.log(
  `   binary: self describing envelope plus a u32 length prefix${HAS_ENVELOPE_BYTES ? ', measured' : ', DERIVED from the base64 length because dist lacks encodeEnvelopeBytes'}.`,
);
console.log(
  `   the "on the wire" column above is whichever of these this build actually sent (${WIRE_MODE}).\n`,
);

console.table(
  SIZES.map((size) => {
    const first = runs[0].sizes[size];
    const old = first.tokenWire;
    const next = first.binaryWire;
    return {
      payload: humanBytes(first.plainBytes),
      '0.2.1 wire': humanBytes(old),
      '0.2.1 overhead %': pct(((old - first.plainBytes) / first.plainBytes) * 100),
      'binary wire': humanBytes(next),
      'binary overhead %': pct(((next - first.plainBytes) / first.plainBytes) * 100),
      saved: pct(((old - next) / old) * 100),
    };
  }),
);
console.log('');

// Byte counts are deterministic, so a disagreement across runs means something
// non deterministic got into the frame sizes and the table above is a lie.
const unstable = SIZES.filter(
  (size) => new Set(runs.map((r) => r.sizes[size].measuredWire)).size > 1,
);
if (unstable.length) {
  console.log(
    `   WARNING: wire byte counts moved between runs at ${unstable.map(humanBytes).join(', ')}. Treat section 1 as unreliable.\n`,
  );
}

console.log('   time for the same transfers, median of runs\n');
console.table(
  SIZES.map((size) => ({
    payload: humanBytes(runs[0].sizes[size].plainBytes),
    'sender crypto ms': ms(agg(runs, (r) => r.sizes[size].senderCryptoMs).median),
    'receiver crypto ms': ms(agg(runs, (r) => r.sizes[size].receiverCryptoMs).median),
    'transcode ms': ms(agg(runs, (r) => r.sizes[size].transcodeMs).median),
    'wall ms': ms(agg(runs, (r) => r.sizes[size].wallMs).median),
    'MB/s': agg(runs, (r) => r.sizes[size].throughputMBs).median.toFixed(2),
    spread: spreadOf(runs, (r) => r.sizes[size].wallMs),
  })),
);
console.log(
  '   transcode is this harness converting between the token and binary forms because',
);
console.log(
  '   engine.seal returns a token. A binary native call path would not pay it.\n',
);

// --- 2. AEAD throughput -----------------------------------------------------

console.log('2. AEAD throughput, MB/s, MB is 1e6 bytes');
if (aeadCheck) {
  const ok = aeadCheck.sealMatches === aeadCheck.samples && aeadCheck.openMatches === aeadCheck.samples;
  console.log(
    `   byte identity vs @noble/ciphers: seal ${aeadCheck.sealMatches}/${aeadCheck.samples}, open ${aeadCheck.openMatches}/${aeadCheck.samples} ${ok ? 'PASS' : 'FAIL'}`,
  );
  if (aeadCheck.firstFailure) console.log(`   FIRST FAILURE: ${aeadCheck.firstFailure}`);
} else {
  console.log('   byte identity vs @noble/ciphers: not checked, src/aead.ts is not in dist');
}
console.log('');

const aeadKeys = Object.keys(runs[0].aead);
console.table(
  AEAD_CASES.flatMap((testCase) =>
    ['seal', 'open'].map((op) => {
      const nobleKey = `noble ${op} ${testCase.label}`;
      const libKey = `lib ${op} ${testCase.label}`;
      const noble = agg(runs, (r) => r.aead[nobleKey]).median;
      const hasLib = aeadKeys.includes(libKey);
      const libValue = hasLib ? agg(runs, (r) => r.aead[libKey]).median : NaN;
      return {
        op: `${op} ${testCase.label}`,
        '@noble/ciphers': noble.toFixed(1),
        [`src/aead.ts (${LIB_AEAD_BACKEND ?? 'absent'})`]: hasLib ? libValue.toFixed(1) : 'n/a',
        ratio: hasLib ? `${(libValue / noble).toFixed(2)}x` : 'n/a',
        spread: spreadOf(runs, (r) => r.aead[nobleKey]),
      };
    }),
  ),
);
if (HAS_LIB_AEAD && LIB_AEAD_BACKEND === 'noble') {
  console.log(
    '   src/aead.ts selected the noble backend on this Node, so both columns are the same',
  );
  console.log('   primitive and the ratio is wrapper overhead, not a backend comparison.\n');
} else {
  console.log('');
}

// --- 3. handshake -----------------------------------------------------------

console.log('3. handshake cost, crypto versus transport');
console.log(
  `   ${HANDSHAKE_FLIGHTS} one way flights, so ${HANDSHAKE_ROUND_TRIPS} round trips before a payload byte can move.\n`,
);

const rtt = agg(runs, (r) => r.rttMs).median;
console.table(
  [
    {
      side: 'sender',
      wall: (r) => r.handshake.senderWallMs,
      crypto: (r) => r.handshake.senderCryptoMs,
    },
    {
      side: 'receiver',
      wall: (r) => r.handshake.receiverWallMs,
      crypto: (r) => r.handshake.receiverCryptoMs,
    },
  ].map((row) => {
    const wall = agg(runs, row.wall).median;
    const crypto = agg(runs, row.crypto).median;
    return {
      side: row.side,
      'wall ms': ms(wall),
      'crypto ms': ms(crypto),
      'transport ms': ms(wall - crypto),
      'crypto share': pct((crypto / wall) * 100),
      spread: spreadOf(runs, row.wall),
    };
  }),
);

console.log(`   loopback round trip: ${ms(rtt)} ms median over 200 probes.`);
console.log(
  `   ${HANDSHAKE_ROUND_TRIPS} round trips of that is ${ms(rtt * HANDSHAKE_ROUND_TRIPS)} ms, which is what the transport column`,
);
console.log('   is made of on this machine. Substitute your own link:');
console.log(
  `   at 40 ms RTT the same handshake costs about ${ms(40 * HANDSHAKE_ROUND_TRIPS)} ms of transport and the`,
);
console.log('   crypto column does not move at all.\n');

// --- 4. versus the 0.2.1 baseline -------------------------------------------

const base = runs[0].baseline;
const baseMeasured = Number.isFinite(base.measuredWire) ? base.measuredWire : base.binaryWire;
const baseOverhead = baseMeasured - base.plainBytes;
const baseCrypto = agg(runs, (r) => r.baseline.senderCryptoMs).median;
const baseThroughput = agg(runs, (r) => r.baseline.throughputMBs).median;

console.log('4. versus the 0.2.1 baseline');
console.log(`   Baseline column: ${BASELINE_0_2_1.label}. Measured once, on other hardware,`);
console.log('   on somebody else\'s network, and hard coded in this file. It is not a fresh');
console.log('   measurement and re-running this script will not reproduce it.\n');

console.table([
  {
    metric: 'plaintext',
    '0.2.1 (relay)': humanBytes(BASELINE_0_2_1.plainBytes),
    'this build (loopback)': humanBytes(base.plainBytes),
    change: 'same payload by construction',
  },
  {
    metric: 'on the wire',
    '0.2.1 (relay)': humanBytes(BASELINE_0_2_1.wireBytes),
    'this build (loopback)': humanBytes(baseMeasured),
    change: pct(((baseMeasured - BASELINE_0_2_1.wireBytes) / BASELINE_0_2_1.wireBytes) * 100),
  },
  {
    metric: 'overhead',
    '0.2.1 (relay)': `${humanBytes(BASELINE_0_2_1.overheadBytes)} (${pct(BASELINE_0_2_1.overheadPct)})`,
    'this build (loopback)': `${humanBytes(baseOverhead)} (${pct((baseOverhead / base.plainBytes) * 100)})`,
    change: `${(BASELINE_0_2_1.overheadPct - (baseOverhead / base.plainBytes) * 100).toFixed(1)} points`,
  },
  {
    metric: 'chunks',
    '0.2.1 (relay)': String(BASELINE_0_2_1.chunks),
    'this build (loopback)': String(base.chunks),
    change: base.chunks === BASELINE_0_2_1.chunks ? 'same' : 'DIFFERENT, sizes do not line up',
  },
  {
    metric: 'sender crypto',
    '0.2.1 (relay)': `${BASELINE_0_2_1.senderCryptoMs} ms`,
    'this build (loopback)': `${ms(baseCrypto)} ms`,
    change: 'different CPU, comparable in kind',
  },
  {
    metric: 'throughput',
    '0.2.1 (relay)': `${BASELINE_0_2_1.throughputMBs.toFixed(2)} MB/s`,
    'this build (loopback)': `${baseThroughput.toFixed(2)} MB/s`,
    change: 'NOT COMPARABLE, relay versus loopback',
  },
]);

console.log('   The only two rows that mean anything across those two columns are the byte');
console.log('   counts and, loosely, the crypto time. Throughput is a property of the link.');
console.log(
  `   Same payload on the binary envelope wire: ${humanBytes(base.binaryWire)}, ${pct(((base.binaryWire - base.plainBytes) / base.plainBytes) * 100)} overhead, ${pct(((BASELINE_0_2_1.wireBytes - base.binaryWire) / BASELINE_0_2_1.wireBytes) * 100)} fewer bytes than 0.2.1${HAS_ENVELOPE_BYTES ? '.' : ' (derived, see the note at the top).'}\n`,
);
