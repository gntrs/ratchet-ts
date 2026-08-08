// Wire benchmark for ratchet-ts. Everything in one process, over real loopback
// sockets, through a relay that counts the bytes as they pass.
//
//   npm run bench:wire                 3 runs, the default
//   npm run bench:wire -- --runs 5     5 runs
//
// This is the sibling of bench/bench.mjs. That script times primitives; this one
// times the things a release note would claim: how many bytes leave the machine
// per byte of payload, how fast each AEAD backend actually is, and how much of a
// handshake is this library versus the network between the two peers.
//
// Read bench/README.md before quoting any number out of here. The short version:
// only the crypto columns say anything about this library. Every throughput
// number is a property of the transport it was measured on, and the transport
// here is a loopback socket with an extra hop in it.
//
// ---------------------------------------------------------------------------
// WHY THIS FILE CALLS cli/protocol.mjs INSTEAD OF COPYING IT
// ---------------------------------------------------------------------------
//
// Until 0.3.2 this script reimplemented the CLI's frame sequence so it would
// keep running while that file was mid refactor. It admitted as much in a
// comment and then did exactly what the comment warned about: cli/protocol.mjs
// moved its payload path onto engine.sealToEnvelopeBytes and
// engine.openFromEnvelopeBytes in 0.3.1, the copy here stayed on
// engine.sealBytes and engine.openBytes, and for two releases this benchmark
// measured base64url work that the shipping code no longer performs. On a
// 10.5 MB transfer the copy spent hundreds of milliseconds turning a 65535 byte
// ciphertext into an 87532 character token and parsing it straight back out,
// per frame, at both ends. The reported throughput was roughly a tenth of the
// real one. The tell was sitting in plain sight: the copy declared protocol
// version 1 while cli/protocol.mjs had been on version 2 since the binary frame
// format landed.
//
// So the copy is gone. Sections 1 and 4 now call sendPayload and receivePayload
// from cli/protocol.mjs over a real socket pair. Those two functions take a
// channel and return a stats object; they touch no globals, no stdout and no
// process state, so there was never a reason they could not be driven from
// here. Every constant that used to be restated is now imported. This class of
// drift cannot recur, because there is no second copy left to drift from.
//
// One reimplementation survives, in section 3, and it is guarded rather than
// trusted. See the comment above oneHandshake for what it is and what checks it.
import os from 'node:os';
import net from 'node:net';
import { createHash, randomBytes } from 'node:crypto';

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';

import { connect, listen } from '../cli/frame.mjs';
import { humanBytes } from '../cli/format.mjs';
import {
  DEFAULT_CHUNK_BYTES,
  PROTOCOL_VERSION,
  receivePayload,
  sendPayload,
} from '../cli/protocol.mjs';
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
 *
 * A genuine before and after over the same link does now exist, and it is not
 * in this file. The repository README, under "The same file over a real
 * network", moves this same 763.5 kB file over the same relayed VPN on 0.2.1
 * and again on 0.3.0, minutes apart. That pair is comparable to itself, at one
 * run each, and it is still not comparable to anything measured here on
 * loopback, so the NOT COMPARABLE cell in section 4 stays exactly where it is.
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

// The chunk size a real transfer gets, imported rather than restated.
//
// It used to be recomputed here as min(64 KiB, 0xffff - 16), with a comment
// explaining that copying it was safer than importing it. That reasoning is
// dead: this file now imports sendPayload from the same module, so if
// cli/protocol.mjs cannot load then the benchmark cannot run either way, and
// the copy bought nothing except a second place for the number to be wrong.
const CHUNK = DEFAULT_CHUNK_BYTES;

// Two decades of payload size, because envelope overhead is a fixed cost per
// chunk and a percentage only looks meaningful at one end of that range.
const SIZES = [20, 1024, 64 * 1024, 1024 * 1024, 10 * 1024 * 1024];

// The size the 0.2.1 baseline was measured at, so the comparison row is the same
// payload and the same chunk count rather than an interpolation.
const BASELINE_SIZE = BASELINE_0_2_1.plainBytes;
const BASELINE_NAME = 'screenshot.png';

const HOST = '127.0.0.1';

// The base64url token form pads three bytes into four characters and every
// frame used to carry one trailing newline. That is the wire 0.3.0 replaced,
// and it is reconstructed rather than measured, so it is exact arithmetic on
// real envelopes rather than a guess.
const TOKEN_FRAME_OVERHEAD = 1;

/** u32 big endian length prefix per frame, set by cli/frame.mjs. */
const FRAME_PREFIX_BYTES = 4;

// ---------------------------------------------------------------------------
// What this build has to give us
// ---------------------------------------------------------------------------
//
// There used to be a fallback here: when dist did not export encodeEnvelopeBytes
// the script put base64url tokens on the wire and derived the binary column
// arithmetically. That branch is unreachable now. cli/protocol.mjs imports
// encodeEnvelopeBytes at module load, so a dist without it fails this file's
// import before any of this runs. Rather than keep a dead branch that claims to
// handle a case it cannot reach, the requirements are asserted once, loudly.

const REQUIRED_MODULE = ['encodeEnvelope', 'decodeEnvelope', 'encodeEnvelopeBytes', 'decodeEnvelopeBytes'];
const REQUIRED_ENGINE = ['createIdentity', 'invite', 'seal', 'sealBytes', 'open', 'sealToEnvelopeBytes', 'openFromEnvelopeBytes'];

for (const name of REQUIRED_MODULE) {
  if (typeof lib[name] !== 'function') {
    throw new Error(`dist does not export ${name}, which this benchmark and cli/protocol.mjs both need`);
  }
}
for (const name of REQUIRED_ENGINE) {
  if (typeof engine[name] !== 'function') {
    throw new Error(`dist exports no engine.${name}, which this benchmark and cli/protocol.mjs both need`);
  }
}

const HAS_LIB_AEAD =
  typeof lib.sealAead === 'function' &&
  typeof lib.openAead === 'function' &&
  typeof lib.aeadBackend === 'function';

const LIB_AEAD_BACKEND = HAS_LIB_AEAD ? lib.aeadBackend() : null;

const notes = [];
if (!HAS_LIB_AEAD) {
  notes.push(
    'dist does not export sealAead/openAead, so only the @noble/ciphers column in section 2 is real.',
  );
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const enc = new TextEncoder();

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

/** The two conversions cli/protocol.mjs calls toWire and fromWire. */
function toWire(token) {
  return lib.encodeEnvelopeBytes(lib.decodeEnvelope(token));
}

function fromWire(frame) {
  return lib.encodeEnvelope(lib.decodeEnvelopeBytes(frame));
}

/**
 * What the frames a transfer actually sent would have cost as 0.2.1 tokens.
 *
 * Exact, not derived: each frame is decoded and re-encoded as the OCX1 token it
 * would have been, and the token's real byte length is added up. Every call
 * happens after the transfer has finished and no timer is running, so this
 * cannot leak into any measured number. It is the one place in this file that
 * still builds a token from a chunk, and it does it deliberately, to price a
 * wire format nothing here speaks any more.
 */
function tokenWireCost(frames) {
  let total = 0;
  for (const frame of frames) {
    total += Buffer.byteLength(fromWire(frame), 'utf8') + TOKEN_FRAME_OVERHEAD;
  }
  return total;
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

/**
 * A channel that keeps a reference to every frame it was asked to send.
 *
 * cli/protocol.mjs returns one wireBytes total and nothing per frame, but the
 * 0.2.1 comparison table needs the individual envelopes, and the frame sequence
 * check needs their kinds and their order. Recording them at the channel is the
 * only place both are available without reaching inside the module.
 *
 * The recorded array is the real thing the socket carried, not a copy made by
 * this file, so nothing here can disagree with what was sent. The only work
 * added to the send path is one array push, which is nanoseconds against a
 * socket write, and everything derived from the recording happens after the
 * transfer has completed and every clock has stopped.
 */
function recordingChannel(channel) {
  const sent = [];
  return {
    remote: channel.remote,
    sent,
    async send(bytes) {
      sent.push(bytes);
      return channel.send(bytes);
    },
    receive: () => channel.receive(),
    next: () => channel.receive(),
    close: () => channel.close(),
  };
}

// ---------------------------------------------------------------------------
// Section 1: one real transfer, measured
// ---------------------------------------------------------------------------
//
// Not a reimplementation. sendPayload and receivePayload from cli/protocol.mjs
// run against the two ends of a loopback pair with the counting relay between
// them, and every number below is either returned by those two functions or
// counted by the relay.
//
// The accounting therefore is the CLI's accounting rather than a copy of it:
// "on the wire" is the sealed header plus the sealed chunks, sender to
// receiver, and the handshake frames are counted separately and reported in
// section 3. That is what --stats prints because it is literally the same code.

function chunkCount(size) {
  return size === 0 ? 0 : Math.ceil(size / CHUNK);
}

/**
 * The frame sequence a healthy transfer produces, checked rather than assumed.
 *
 * This is what replaced the old "the bench copies the CLI and a divergence will
 * not show up here" comment. If cli/protocol.mjs ever sends a different number
 * of frames, or sends something that is not a self describing binary envelope,
 * the benchmark stops instead of quietly reporting the wrong thing.
 *
 * The check that would have caught the 0.3.1 drift is the round trip one: a
 * frame carrying a base64url token cannot survive decodeEnvelopeBytes followed
 * by encodeEnvelopeBytes unchanged, because it is not an envelope, it is a
 * string describing one.
 */
function checkFrameSequence({ senderFrames, receiverFrames, chunks }) {
  const problems = [];

  const wantSender = 2 + chunks; // accept, header, one per chunk
  const wantReceiver = 3; // invite, ready, acknowledgement
  if (senderFrames.length !== wantSender) {
    problems.push(`the sender put ${senderFrames.length} frames on the socket, expected ${wantSender}`);
  }
  if (receiverFrames.length !== wantReceiver) {
    problems.push(`the receiver put ${receiverFrames.length} frames on the socket, expected ${wantReceiver}`);
  }

  const kindOf = (frame) => {
    try {
      return lib.decodeEnvelopeBytes(frame).kind;
    } catch {
      return null;
    }
  };

  const senderKinds = senderFrames.map(kindOf);
  const receiverKinds = receiverFrames.map(kindOf);
  if (senderKinds[0] !== 'accept') problems.push(`the sender's first frame is ${senderKinds[0]}, expected accept`);
  if (receiverKinds[0] !== 'invite') problems.push(`the receiver's first frame is ${receiverKinds[0]}, expected invite`);
  for (let i = 1; i < senderKinds.length; i += 1) {
    if (senderKinds[i] !== 'message') {
      problems.push(`sender frame ${i + 1} is ${senderKinds[i]}, expected message`);
      break;
    }
  }
  for (let i = 1; i < receiverKinds.length; i += 1) {
    if (receiverKinds[i] !== 'message') {
      problems.push(`receiver frame ${i + 1} is ${receiverKinds[i]}, expected message`);
      break;
    }
  }

  // Every frame has to be an envelope in binary form. A token would fail here.
  let roundTripped = 0;
  for (const frame of [...senderFrames, ...receiverFrames]) {
    let same = false;
    try {
      const again = lib.encodeEnvelopeBytes(lib.decodeEnvelopeBytes(frame));
      same = Buffer.compare(Buffer.from(again), Buffer.from(frame)) === 0;
    } catch {
      same = false;
    }
    if (same) roundTripped += 1;
  }
  const total = senderFrames.length + receiverFrames.length;
  if (roundTripped !== total) {
    problems.push(`${total - roundTripped} of ${total} frames are not self describing binary envelopes`);
  }

  return { total, roundTripped, problems };
}

async function measureTransfer({ size, name }) {
  const bytes = randomBytes(size);
  const pair = await loopbackPair({ counted: true });

  try {
    const senderChannel = recordingChannel(pair.sender);
    const receiverChannel = recordingChannel(pair.receiver);
    const alice = await engine.createIdentity();
    const bob = await engine.createIdentity();

    // Snapshotted from inside onHandshake, which cli/protocol.mjs fires the
    // instant the handshake settles and before the first payload frame is
    // sealed. Every handshake byte has necessarily crossed the relay by then:
    // the receiver could not have produced the ready frame without consuming
    // the accept first.
    let afterHandshake = null;

    const [sent, received] = await Promise.all([
      sendPayload({
        channel: senderChannel,
        identity: alice,
        name,
        bytes,
        chunkSize: CHUNK,
        onHandshake: () => {
          afterHandshake = pair.relay.snapshot();
        },
      }),
      receivePayload({ channel: receiverChannel, identity: bob }),
    ]);

    const afterPayload = pair.relay.snapshot();

    if (received.stats.sha256 !== sent.sha256) {
      throw new Error('the two ends disagree about the payload hash');
    }
    if (sha256Hex(bytes) !== sent.sha256) {
      throw new Error('the sender hashed something other than the payload it was given');
    }

    // The accept is a handshake frame. Everything after it is the payload
    // phase, which is the split --stats uses and the split section 1 reports.
    const payloadFrames = senderChannel.sent.slice(1);
    const sequence = checkFrameSequence({
      senderFrames: senderChannel.sent,
      receiverFrames: receiverChannel.sent,
      chunks: sent.chunks,
    });

    const framedBytes = payloadFrames.reduce((n, f) => n + FRAME_PREFIX_BYTES + f.length, 0);
    const measuredWire = afterHandshake ? afterPayload.up - afterHandshake.up : NaN;

    return {
      plainBytes: sent.plainBytes,
      chunks: sent.chunks,
      handshakeMs: sent.handshakeMs,
      receiverHandshakeMs: received.stats.handshakeMs,
      wallMs: sent.wallMs,
      sha256: sent.sha256,
      backend: sent.backend,
      // What the same envelopes would have cost on the 0.2.1 base64 wire,
      // computed frame by frame from the frames that really went out.
      tokenWire: tokenWireCost(payloadFrames),
      // What cli/protocol.mjs says it put on the socket.
      binaryWire: sent.wireBytes,
      // What the relay saw. Three independent counts of the same thing, and
      // the three of them agreeing is worth more than any one of them.
      measuredWire,
      framedBytes,
      wireAgrees: measuredWire === sent.wireBytes && framedBytes === sent.wireBytes,
      handshakeWireUp: afterHandshake ? afterHandshake.up : NaN,
      handshakeWireDown: afterHandshake ? afterHandshake.down : NaN,
      senderCryptoMs: sent.cryptoMs,
      receiverCryptoMs: received.stats.cryptoMs,
      sequence,
      // MB is 1e6 bytes here, not 1048576, and the figure comes out of
      // cli/protocol.mjs rather than being recomputed, so the two throughput
      // numbers cannot disagree about the base.
      throughputMBs: sent.throughputMBs,
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
//
// THIS IS THE ONE PLACE THE BENCH STILL DRIVES THE ENGINE ITSELF, and it is
// worth saying why, because everything else in this file stopped doing that.
//
// cli/protocol.mjs reports one cumulative cryptoMs per transfer. It has no
// handshake-only crypto figure and the onHandshake callback does not carry the
// clock, so the crypto and transport split this section exists to show cannot
// be read out of a real transfer: the smallest transfer that module will do
// still seals a header and opens an acknowledgement after handshakeMs has
// stopped, which would make transport go negative on loopback. Rather than
// change what section 3 measures, the five engine calls are driven here.
//
// It is a timing harness for five calls, not a second copy of the wire
// protocol: no chunk loop, no header JSON, no framing arithmetic, and the
// protocol version comes from the import. The accounting deliberately matches
// cli/protocol.mjs call for call. In that module the invite and the accept are
// converted outside timed(), because both fall inside the window handshakeMs
// already reports, while the ready frame's seal and every open are inside it
// with their conversion included. This does the same.
//
// And it is checked rather than trusted: every counted transfer in section 1
// hands back the real handshakeMs from cli/protocol.mjs, both sides, and those
// medians are printed next to the harness's own. If the two ever diverge by
// more than a factor of two the report says DRIFT and names it.

const HANDSHAKE_FLIGHTS = 3;
const HANDSHAKE_ROUND_TRIPS = HANDSHAKE_FLIGHTS / 2;

/** Loud enough to be noticed, loose enough not to fire on a busy laptop. */
const HANDSHAKE_DRIFT_FACTOR = 2;

async function expectFrame(channel, what) {
  const frame = await channel.receive();
  if (frame === null || frame === undefined) {
    throw new Error(`the channel closed while waiting for ${what}`);
  }
  return frame;
}

async function oneHandshake() {
  const pair = await loopbackPair({ counted: false });
  const senderCrypto = { ms: 0 };
  const receiverCrypto = { ms: 0 };

  try {
    const alice = await engine.createIdentity();
    const bob = await engine.createIdentity();

    let senderWall = 0;
    let receiverWall = 0;

    const senderSide = (async () => {
      // The clock starts before the first read, matching cli/protocol.mjs: from
      // this side, waiting for the peer to produce an invite is part of the
      // handshake whether or not the CPU was busy.
      const t0 = performance.now();
      const inviteFrame = await expectFrame(pair.sender, 'the peer invite');
      const opened = await charge(senderCrypto, () =>
        engine.open(alice, fromWire(inviteFrame), {}),
      );
      if (opened.outcome !== 'invite') throw new Error(`expected an invite, got ${opened.outcome}`);
      // Outside the clock, exactly as handshakeFrame is in cli/protocol.mjs.
      await pair.sender.send(toWire(opened.reply));
      const readyFrame = await expectFrame(pair.sender, 'the receiver ready frame');
      const readyOpen = await charge(senderCrypto, () =>
        engine.open(alice, fromWire(readyFrame), { session: opened.session }),
      );
      if (readyOpen.outcome !== 'message') throw new Error('expected a ready frame');
      const readyBody = JSON.parse(readyOpen.plaintext);
      if (readyBody.v !== PROTOCOL_VERSION) {
        throw new Error(`receiver speaks protocol v${readyBody.v}, this is v${PROTOCOL_VERSION}`);
      }
      senderWall = performance.now() - t0;
    })();

    const receiverSide = (async () => {
      const t0 = performance.now();
      const invited = await charge(receiverCrypto, () => engine.invite(bob));
      await pair.receiver.send(toWire(invited.token));
      const replyFrame = await expectFrame(pair.receiver, 'the sender reply');
      const accepted = await charge(receiverCrypto, () =>
        engine.open(bob, fromWire(replyFrame), { pending: invited.pending }),
      );
      if (accepted.outcome !== 'accepted') {
        throw new Error(`expected an accept, got ${accepted.outcome}`);
      }
      const ready = await charge(receiverCrypto, async () => {
        const sealed = await engine.seal(
          accepted.session,
          JSON.stringify({ v: PROTOCOL_VERSION, ready: true }),
        );
        return { frame: toWire(sealed.token), session: sealed.session };
      });
      await pair.receiver.send(ready.frame);
      receiverWall = performance.now() - t0;
    })();

    await Promise.all([senderSide, receiverSide]);

    return {
      senderWallMs: senderWall,
      receiverWallMs: receiverWall,
      senderCryptoMs: senderCrypto.ms,
      receiverCryptoMs: receiverCrypto.ms,
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
// Section 5: representation cost, token versus bytes
// ---------------------------------------------------------------------------
//
// Nothing else in this file measures the thing 0.3.1 is about, so this section
// does, and it measures it on this machine rather than quoting anybody.
//
// engine.seal and engine.sealBytes hand back an OCX1 token, which is base64url
// over the envelope body, and engine.open and engine.openBytes take one. The
// wire is binary. Up to and including 0.3.0 that meant every chunk frame got
// base64 encoded and then immediately decoded again on each side, purely to
// cross an API that speaks strings:
//
//   sender    engine.sealBytes -> encodeEnvelope        encode
//             cli toWire       -> decodeEnvelope        decode
//   receiver  cli fromWire     -> encodeEnvelope        encode
//             engine.openBytes -> decodeEnvelope        decode
//
// Each of those pairs is a round trip that ends where it began, which is why
// this section reports round trips and not single calls: one per endpoint, two
// per frame, and not one byte on the socket differed either way.
//
// 0.3.1 deleted both of them for chunk frames. engine.sealToEnvelopeBytes goes
// from plaintext bytes to envelope bytes and engine.openFromEnvelopeBytes comes
// back, so the token is never built. The measurement below is therefore the
// size of what was removed, and it stays in the file because a saving nobody
// can re-measure is a claim, not a result.
//
// The bytes rows are not the alternative to subtract. They are what a transfer
// paid inside toWire and fromWire before and goes on paying now, since
// something still has to write the envelope out and read it back in. What
// disappeared is the token round trip, whole, twice. That is why the arithmetic
// below subtracts nothing from it.

/**
 * Both endpoints paid one full base64 round trip per chunk frame in 0.3.0, so a
 * frame that crossed the wire cost two. Counted from the four call sites listed
 * above rather than assumed. As of 0.3.1 the chunk path pays neither, so this
 * is a historical figure: it sizes what the release removed, and it is not a
 * description of what cli/protocol.mjs does now.
 */
const CLI_BASE64_ROUND_TRIPS_PER_FRAME_0_3_0 = 2;

/** One file's worth of chunks, at the size the section 4 baseline uses. */
const REPR_FILE_BYTES = BASELINE_SIZE;
const REPR_CHUNKS = chunkCount(REPR_FILE_BYTES);

// Each rep is 12 encodes plus 12 decodes, so a rep is already an average over
// the workload. 21 of them is enough for a median to stop moving between runs
// while keeping the whole section under a second.
const REPR_REPS = 21;

/**
 * One settled session pair, driven through the engine with no sockets.
 *
 * Used by the workload builder and by the seal path interop check. It is the
 * receiver that invites and the sender that accepts, matching the CLI, so the
 * sender is the Double Ratchet responder and cannot seal anything until the
 * receiver has spoken once. That is what the ready frame is for.
 */
async function settledPair() {
  const alice = await engine.createIdentity();
  const bob = await engine.createIdentity();

  const invited = await engine.invite(bob);
  const senderOpen = await engine.open(alice, invited.token, {});
  const receiverOpen = await engine.open(bob, senderOpen.reply, { pending: invited.pending });
  const ready = await engine.seal(
    receiverOpen.session,
    JSON.stringify({ v: PROTOCOL_VERSION, ready: true }),
  );
  const readyOpen = await engine.open(alice, ready.token, { session: senderOpen.session });

  return {
    senderIdentity: alice,
    receiverIdentity: bob,
    senderSession: readyOpen.session,
    receiverSession: ready.session,
  };
}

/**
 * The claim cli/protocol.mjs rests on, checked at the seal rather than at the
 * codec: the bytes native calls are an internal shortcut and not a wire change.
 *
 * A frame sealed by engine.sealToEnvelopeBytes has to open through the token
 * entry point, and a frame sealed by engine.sealBytes has to open through
 * engine.openFromEnvelopeBytes. If either direction fails then the two halves
 * of the seam are speaking different wires and the whole comparison below is
 * about a format change rather than a shortcut.
 *
 * Nonces are random, so the two seals cannot be compared byte for byte against
 * each other. Interoperability is the property that actually matters and it is
 * the one being asserted.
 */
async function verifySealPathsInterop() {
  const pair = await settledPair();
  // ASCII so the token entry point's UTF-8 decode of the plaintext is lossless.
  // Binary would come back mangled through engine.open and prove nothing.
  const text = 'ratchet-ts seal path interop check. '.repeat(64);
  const plaintext = enc.encode(text);
  const problems = [];

  const bytesSealed = await engine.sealToEnvelopeBytes(pair.senderSession, plaintext);
  const openedAsToken = await engine.open(
    pair.receiverIdentity,
    fromWire(bytesSealed.envelope),
    { session: pair.receiverSession },
  );
  if (openedAsToken.outcome !== 'message' || openedAsToken.plaintext !== text) {
    problems.push('a frame from engine.sealToEnvelopeBytes did not open through engine.open');
  }

  // The original receiver session is untouched by the open above, because
  // sessions are immutable and every open returns a new one. Both messages are
  // number 0 in the same chain, so each opens cleanly against the base session.
  const tokenSealed = await engine.sealBytes(pair.senderSession, plaintext);
  const openedAsBytes = await engine.openFromEnvelopeBytes(
    pair.receiverSession,
    toWire(tokenSealed.token),
  );
  if (Buffer.compare(Buffer.from(openedAsBytes.plaintext), Buffer.from(plaintext)) !== 0) {
    problems.push('a frame from engine.sealBytes did not open through engine.openFromEnvelopeBytes');
  }

  return { problems };
}

/**
 * Real sealed chunks, not synthetic ones.
 *
 * The envelopes are produced by driving an actual handshake and then sealing
 * actual chunks, so the ratchet key, nonce, message numbers and ciphertext
 * length are what a transfer really carries. A hand built payload would time
 * the same code but would let a wrong field length go unnoticed.
 */
async function representationWorkload() {
  const pair = await settledPair();

  let session = pair.senderSession;
  const bytes = randomBytes(REPR_FILE_BYTES);
  const tokens = [];
  for (let i = 0; i < REPR_CHUNKS; i += 1) {
    const start = i * CHUNK;
    const slice = bytes.subarray(start, Math.min(start + CHUNK, REPR_FILE_BYTES));
    const sealed = await engine.sealBytes(session, slice);
    session = sealed.session;
    tokens.push(sealed.token);
  }

  const payloads = tokens.map((t) => lib.decodeEnvelope(t));
  const frames = payloads.map((p) => lib.encodeEnvelopeBytes(p));
  return { payloads, tokens, frames };
}

/**
 * The claim this whole section rests on: the shortcut is a shortcut.
 *
 * A bytes native path is only allowed to exist if the payload that comes back
 * out of either codec re-encodes to the same token and the same frame the long
 * way round produced. If that ever stops holding, the saved milliseconds were
 * bought by changing the wire, which is a different and much worse release.
 */
function verifyRepresentationIdentity({ payloads, tokens, frames }) {
  let tokenMatches = 0;
  let frameMatches = 0;
  let firstFailure = null;

  for (let i = 0; i < payloads.length; i += 1) {
    // Payload out of the byte codec, back to a token: this is what cli fromWire
    // did, followed by whatever the engine would have handed the caller.
    const viaBytes = lib.encodeEnvelope(lib.decodeEnvelopeBytes(frames[i]));
    if (viaBytes === tokens[i]) tokenMatches += 1;
    else if (!firstFailure) firstFailure = `token differs after a byte round trip at chunk ${i}`;

    // Payload out of the token codec, back to a frame: this is what cli
    // toWire did.
    const viaToken = lib.encodeEnvelopeBytes(lib.decodeEnvelope(tokens[i]));
    if (Buffer.compare(Buffer.from(viaToken), Buffer.from(frames[i])) === 0) frameMatches += 1;
    else if (!firstFailure) firstFailure = `frame differs after a token round trip at chunk ${i}`;
  }

  return { samples: payloads.length, tokenMatches, frameMatches, firstFailure, firstToken: tokens[0] };
}

async function measureRepresentation({ reps = REPR_REPS } = {}) {
  const workload = await representationWorkload();
  const { payloads, tokens, frames } = workload;

  const samples = {
    encodeToken: [],
    encodeBytes: [],
    decodeToken: [],
    decodeBytes: [],
    roundTripToken: [],
    roundTripBytes: [],
  };

  // Every loop feeds a length into this. Not paranoia about correctness, which
  // verifyRepresentationIdentity handles: it is here so the optimiser cannot
  // delete a loop whose result nothing reads and hand back a zero.
  let sink = 0;

  for (let r = 0; r < reps; r += 1) {
    let t0 = performance.now();
    for (const p of payloads) sink += lib.encodeEnvelope(p).length;
    samples.encodeToken.push(performance.now() - t0);

    t0 = performance.now();
    for (const t of tokens) sink += lib.decodeEnvelope(t).ciphertext.length;
    samples.decodeToken.push(performance.now() - t0);

    // Encode then decode the result, which is exactly the pair of calls the
    // sender made per chunk in 0.3.0: seal produced the token, toWire took it
    // apart again.
    t0 = performance.now();
    for (const p of payloads) sink += lib.decodeEnvelope(lib.encodeEnvelope(p)).ciphertext.length;
    samples.roundTripToken.push(performance.now() - t0);

    t0 = performance.now();
    for (const p of payloads) sink += lib.encodeEnvelopeBytes(p).length;
    samples.encodeBytes.push(performance.now() - t0);

    t0 = performance.now();
    for (const f of frames) sink += lib.decodeEnvelopeBytes(f).ciphertext.length;
    samples.decodeBytes.push(performance.now() - t0);

    t0 = performance.now();
    for (const p of payloads) sink += lib.decodeEnvelopeBytes(lib.encodeEnvelopeBytes(p)).ciphertext.length;
    samples.roundTripBytes.push(performance.now() - t0);
  }

  return { ...samples, sink, workload };
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

  // The real module's own handshake numbers, pooled from every counted transfer
  // this run performed. These are the anti-drift reference for section 3.
  const cliTransfers = [...SIZES.map((s) => out.sizes[s]), out.baseline];
  out.cliHandshake = {
    senderMs: median(cliTransfers.map((t) => t.handshakeMs)),
    receiverMs: median(cliTransfers.map((t) => t.receiverHandshakeMs)),
    wireUp: median(cliTransfers.map((t) => t.handshakeWireUp)),
    wireDown: median(cliTransfers.map((t) => t.handshakeWireDown)),
  };

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
  out.repr = await measureRepresentation();
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
// base64url has two implementations behind it on Node, the string path and the
// Buffer path, and both are cold on the first envelope. Timing that would make
// section 5 a compiler benchmark.
await measureRepresentation({ reps: 3 });

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

const aeadCheck = await verifyAeadIdentity(200);
const interopCheck = await verifySealPathsInterop();

console.log(`\nratchet-ts wire benchmark`);
console.log(`${process.version}  |  ${(os.cpus()[0] || {}).model}  |  ${os.platform()}/${os.arch()}`);
console.log(
  `${RUNS} run${RUNS === 1 ? '' : 's'}  |  loopback ${HOST} through a counting relay  |  chunk ${CHUNK} B`,
);
console.log('wire: self describing binary envelope, u32 length prefixed frames');
console.log(
  `payload path: cli/protocol.mjs sendPayload and receivePayload, protocol v${PROTOCOL_VERSION}, called not copied`,
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

// --- 0. the bench agrees with the CLI ---------------------------------------
//
// Printed first and printed even when it passes, because a guard nobody sees is
// a guard nobody trusts. Everything below section 0 is only worth reading if
// this says PASS.

const sequences = [...SIZES.map((s) => runs[0].sizes[s]), runs[0].baseline].map((t) => t.sequence);
const sequenceProblems = sequences.flatMap((s) => s.problems);
const framesChecked = sequences.reduce((n, s) => n + s.total, 0);
const framesBinary = sequences.reduce((n, s) => n + s.roundTripped, 0);
const wireDisagreements = [...SIZES.map((s) => runs[0].sizes[s]), runs[0].baseline].filter(
  (t) => !t.wireAgrees,
);

console.log('0. the bench and the CLI are the same code');
console.log(
  `   frame sequence: ${sequenceProblems.length === 0 ? 'PASS' : 'FAIL'}, ${framesBinary}/${framesChecked} frames are self describing binary envelopes`,
);
for (const problem of sequenceProblems) console.log(`   FAIL: ${problem}`);
console.log(
  `   byte counts agree three ways (relay, cli/protocol.mjs, frame arithmetic): ${wireDisagreements.length === 0 ? 'PASS' : 'FAIL'}`,
);
for (const t of wireDisagreements) {
  console.log(
    `   FAIL at ${humanBytes(t.plainBytes)}: relay ${t.measuredWire}, cli ${t.binaryWire}, frames ${t.framedBytes}`,
  );
}
console.log(
  `   seal paths interoperate on one wire: ${interopCheck.problems.length === 0 ? 'PASS' : 'FAIL'}`,
);
for (const problem of interopCheck.problems) console.log(`   FAIL: ${problem}`);
console.log(
  `   protocol version is imported from cli/protocol.mjs, not restated here: v${PROTOCOL_VERSION}.`,
);
console.log(
  '   Both ends of a real transfer reject a peer whose version disagrees, so a completed',
);
console.log('   transfer above is itself the version check.\n');

// --- 1. bytes on the wire ---------------------------------------------------

console.log('1. bytes on the wire');
console.log('   Sealed header plus sealed chunks, sender to receiver, counted by a relay');
console.log('   sitting between the two sockets. Handshake frames are in section 3, which');
console.log('   is the same split cli/protocol.mjs uses when it prints --stats, because it');
console.log('   is cli/protocol.mjs doing the sending.\n');

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
console.log('   0.2.1: OCX1 base64url token plus a newline delimiter. Reconstructed exactly,');
console.log('   frame by frame, from the envelopes this build really sent.');
console.log('   binary: self describing envelope plus a u32 length prefix, measured. This is');
console.log('   what the "on the wire" column above is.\n');

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
    'wall ms': ms(agg(runs, (r) => r.sizes[size].wallMs).median),
    'MB/s': agg(runs, (r) => r.sizes[size].throughputMBs).median.toFixed(2),
    spread: spreadOf(runs, (r) => r.sizes[size].wallMs),
  })),
);
console.log('   THE transcode ms COLUMN IS GONE, and it is not reading zero somewhere off');
console.log('   screen. It measured this harness turning a base64url token into envelope');
console.log('   bytes and back again, which it only ever did because the copy of the CLI it');
console.log('   used to carry called engine.sealBytes and engine.openBytes. cli/protocol.mjs');
console.log('   stopped calling those on the payload path in 0.3.1 and calls');
console.log('   engine.sealToEnvelopeBytes and engine.openFromEnvelopeBytes instead, so no');
console.log('   such conversion happens in the shipping code and there is nothing left to');
console.log('   charge to it. This file now calls that module rather than reimplementing it,');
console.log('   so the column cannot come back by accident.');
console.log('   Nothing was made faster to achieve that. Work the shipping code does not do');
console.log('   was taken out of the measurement. Held against one unchanged build, swapping');
console.log('   the dead token path for the real one moved a 10.5 MB transfer from 4.4 MB/s');
console.log('   to 47.7 MB/s, about eleven times, and a 1.0 MB transfer about five times.');
console.log('   The earlier numbers were wrong, not the library.');
console.log('   If the figures above are larger again than that, do not credit this file for');
console.log('   the difference. src also got faster in the same window, separately measured');
console.log('   at about 1.6x on the real path at 10.5 MB. See bench/README.md, "The 0.3.2');
console.log('   correction", for the two effects held apart.');
console.log('   The crypto columns are cli/protocol.mjs reporting its own clock, the same');
console.log('   cryptoMs that ratchet send --stats prints, not a number computed here.\n');

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

// The drift guard. The table above is the one harness in this file that still
// drives the engine itself; these two numbers come out of the real module
// during the section 1 transfers. They measure the same three flights, so they
// have no business disagreeing.
const cliSender = agg(runs, (r) => r.cliHandshake.senderMs).median;
const cliReceiver = agg(runs, (r) => r.cliHandshake.receiverMs).median;
const benchSender = agg(runs, (r) => r.handshake.senderWallMs).median;
const benchReceiver = agg(runs, (r) => r.handshake.receiverWallMs).median;

console.log('   the same handshake as cli/protocol.mjs measures it, for comparison\n');
console.table([
  {
    side: 'sender',
    'this harness ms': ms(benchSender),
    'cli/protocol.mjs ms': ms(cliSender),
    ratio: `${(benchSender / cliSender).toFixed(2)}x`,
  },
  {
    side: 'receiver',
    'this harness ms': ms(benchReceiver),
    'cli/protocol.mjs ms': ms(cliReceiver),
    ratio: `${(benchReceiver / cliReceiver).toFixed(2)}x`,
  },
]);

const drifted = [
  ['sender', benchSender, cliSender],
  ['receiver', benchReceiver, cliReceiver],
].filter(
  ([, a, b]) =>
    !Number.isFinite(a / b) || a / b > HANDSHAKE_DRIFT_FACTOR || a / b < 1 / HANDSHAKE_DRIFT_FACTOR,
);
if (drifted.length) {
  console.log(
    `   DRIFT: the harness and cli/protocol.mjs disagree by more than ${HANDSHAKE_DRIFT_FACTOR}x on ${drifted.map(([s]) => s).join(' and ')}.`,
  );
  console.log('   One of the two changed and the other did not. Section 3 is not trustworthy');
  console.log('   until they agree again.\n');
} else {
  console.log(
    `   Within ${HANDSHAKE_DRIFT_FACTOR}x, so the harness is still doing what the CLI does. The cli column`,
  );
  console.log('   carries the extra relay hop the harness does not, which is worth about');
  console.log(`   ${ms(rtt)} ms, and it is a whole transfer's handshake rather than fifteen in a row.\n`);
}

const handshakeUp = agg(runs, (r) => r.cliHandshake.wireUp).median;
const handshakeDown = agg(runs, (r) => r.cliHandshake.wireDown).median;
console.log(
  `   handshake bytes, counted by the relay: ${humanBytes(handshakeUp)} sender to receiver,`,
);
console.log(
  `   ${humanBytes(handshakeDown)} receiver to sender. Deliberately outside the section 1 totals: a`,
);
console.log('   fixed post-quantum handshake folded into an overhead percentage defined');
console.log('   against the payload would say more about the file size than the protocol.');
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
  `   Same payload on the binary envelope wire: ${humanBytes(base.binaryWire)}, ${pct(((base.binaryWire - base.plainBytes) / base.plainBytes) * 100)} overhead, ${pct(((BASELINE_0_2_1.wireBytes - base.binaryWire) / BASELINE_0_2_1.wireBytes) * 100)} fewer bytes than 0.2.1.`,
);
console.log('   A before and after over one link does exist, and it is not this table: the');
console.log('   repository README, under "The same file over a real network", moves the same');
console.log('   file on 0.2.1 and on 0.3.0 over the same relayed VPN, one run each. That pair');
console.log('   is comparable to itself. It is still not comparable to the loopback column\n   above, which is why the change cell still says NOT COMPARABLE.\n');

// --- 5. representation cost -------------------------------------------------

const reprCheck = verifyRepresentationIdentity(runs[0].repr.workload);

/**
 * Every timed pass from every run, as one pooled sample, described by
 * percentiles rather than by best and worst.
 *
 * The rest of this file spreads three run level medians, where best to worst is
 * the right summary. Here there are 21 passes per run and the extremes are
 * garbage collection: one pause during one of 63 passes says the machine has a
 * collector, not that the codec is unstable. p10 to p90 is the honest middle
 * and the max column keeps the tail visible instead of hiding it.
 */
function pooled(key) {
  const xs = runs.flatMap((r) => r.repr[key]).filter((n) => Number.isFinite(n));
  if (xs.length === 0) return { median: NaN, p10: NaN, p90: NaN, max: NaN, spread: NaN, n: 0 };
  const s = [...xs].sort((a, b) => a - b);
  const at = (p) => s[Math.min(s.length - 1, Math.floor(p * s.length))];
  const median = at(0.5);
  const p10 = at(0.1);
  const p90 = at(0.9);
  return { median, p10, p90, max: s[s.length - 1], spread: ((p90 - p10) / median) * 100, n: s.length };
}

const encodeToken = pooled('encodeToken');
const decodeToken = pooled('decodeToken');
const roundTripToken = pooled('roundTripToken');
const encodeBytes = pooled('encodeBytes');
const decodeBytes = pooled('decodeBytes');
const roundTripBytes = pooled('roundTripBytes');

console.log('5. representation cost, token versus bytes');
console.log(
  `   ${REPR_CHUNKS} sealed chunks of ${CHUNK} B, one ${humanBytes(REPR_FILE_BYTES)} file's worth, encoded and`,
);
console.log(
  `   decoded ${REPR_REPS} times per run across ${RUNS} run${RUNS === 1 ? '' : 's'}. Every number below is one pass over the`,
);
console.log('   whole workload, not one chunk, and it is measured on this machine.\n');

{
  const ok =
    reprCheck.tokenMatches === reprCheck.samples && reprCheck.frameMatches === reprCheck.samples;
  console.log(
    `   round trip is byte identical: token ${reprCheck.tokenMatches}/${reprCheck.samples}, frame ${reprCheck.frameMatches}/${reprCheck.samples} ${ok ? 'PASS' : 'FAIL'}`,
  );
  console.log(
    '   Nothing on the socket changes when the base64 hop is removed. If that line ever',
  );
  console.log('   says FAIL, the saving was bought by changing the wire and the release is wrong.');
}
if (reprCheck.firstFailure) console.log(`   FIRST FAILURE: ${reprCheck.firstFailure}`);
console.log('');

const reprRow = (operation, a, versus) => ({
  operation,
  ms: ms(a.median),
  p10: ms(a.p10),
  p90: ms(a.p90),
  max: ms(a.max),
  spread: Number.isFinite(a.spread) ? pct(a.spread) : 'n/a',
  'us per chunk': ((a.median * 1000) / REPR_CHUNKS).toFixed(1),
  'vs bytes': versus && Number.isFinite(versus.median) ? `${(a.median / versus.median).toFixed(1)}x` : '',
});

console.table([
  reprRow('encode payload -> token', encodeToken, encodeBytes),
  reprRow('encode payload -> bytes', encodeBytes, null),
  reprRow('decode token -> payload', decodeToken, decodeBytes),
  reprRow('decode bytes -> payload', decodeBytes, null),
  reprRow('round trip via token', roundTripToken, roundTripBytes),
  reprRow('round trip via bytes', roundTripBytes, null),
]);
console.log(
  `   ${encodeToken.n} timed passes per row. Spread here is p10 to p90 over the median, not the best`,
);
console.log(
  '   to worst used elsewhere in this file: at this sample count the extremes are garbage',
);
console.log('   collection pauses, so the max column carries the tail instead of the summary.\n');

{
  const deleted = roundTripToken.median * CLI_BASE64_ROUND_TRIPS_PER_FRAME_0_3_0;
  const survives = encodeBytes.median + decodeBytes.median;

  console.log('   what the chunk path paid in 0.3.0 and stopped paying in 0.3.1\n');
  console.table([
    {
      quantity: 'frames per transfer that carry a chunk',
      value: String(REPR_CHUNKS),
      where: 'sendPayload chunk loop',
    },
    {
      quantity: 'token round trips per frame, 0.3.0',
      value: String(CLI_BASE64_ROUND_TRIPS_PER_FRAME_0_3_0),
      where: 'sealBytes + toWire, fromWire + openBytes',
    },
    {
      quantity: 'token round trips per frame, 0.3.1',
      value: '0',
      where: 'sealToEnvelopeBytes, openFromEnvelopeBytes',
    },
    {
      quantity: 'one token round trip, whole workload',
      value: `${ms(roundTripToken.median)} ms`,
      where: 'the table above',
    },
    {
      quantity: `deleted per endpoint, ${humanBytes(REPR_FILE_BYTES)}`,
      value: `${ms(roundTripToken.median)} ms`,
      where: `1 round trip, that side's ${REPR_CHUNKS} chunks`,
    },
    {
      quantity: `deleted per ${humanBytes(REPR_FILE_BYTES)} transfer`,
      value: `${ms(deleted)} ms`,
      where: `${CLI_BASE64_ROUND_TRIPS_PER_FRAME_0_3_0} round trips, both endpoints`,
    },
    {
      quantity: 'byte codec, paid before and after',
      value: `${ms(survives)} ms`,
      where: 'the envelope still gets written out and read back',
    },
    {
      quantity: 'sender crypto, same payload, section 4',
      value: `${ms(baseCrypto)} ms`,
      where: 'cli/protocol.mjs cryptoMs, the bytes native path',
    },
    {
      quantity: 'deleted as a share of that crypto',
      value: pct((deleted / baseCrypto) * 100),
      where: 'two endpoints over one, read as a shape not a ratio',
    },
  ]);

  console.log(
    '   Nothing is subtracted from the deleted row. The bytes native path still writes the',
  );
  console.log(
    '   envelope out on the sender and reads it back in on the receiver, which is the byte',
  );
  console.log(
    '   codec row, and toWire and fromWire paid exactly that before. The base64 round trip',
  );
  console.log('   on each side was pure detour and all of it went.');
  console.log(
    '   It counts chunk frames only. The invite, the accept, the ready frame, the header',
  );
  console.log(
    '   and the acknowledgement still build a token, so the figure is a floor.',
  );
  console.log(
    '   In 0.3.0 half of it appeared in the cryptoMs the CLI printed and half did not: the',
  );
  console.log(
    '   base64 inside sealBytes and openBytes was timed, the identical base64 in toWire and',
  );
  console.log(
    '   fromWire was not. In 0.3.1 the chunk path pays neither and what is left is inside.',
  );
  console.log(
    '   The share row got bigger when this file started calling cli/protocol.mjs instead of',
  );
  console.log(
    '   copying it, because the crypto figure it divides by lost the base64 that the copy',
  );
  console.log(
    '   was still doing. The deleted milliseconds did not move; the thing they are measured',
  );
  console.log('   against got smaller, which is the correct denominator.\n');
}
