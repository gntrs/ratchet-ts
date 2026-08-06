// Runtime-agnostic smoke test for the built library.
//
// This file is the portability proof, so its constraints are the point:
//   - it imports ../dist/index.js, the published build, not the TypeScript
//     source, because that is what users actually run,
//   - it touches no Node builtin, not even node:assert (see check below),
//   - the only environment it assumes is globalThis.crypto, the WebCrypto
//     standard that Node 20+, Bun, Deno, browsers, and edge workers all ship.
// If this prints PASS under a runtime, the library runs there unmodified.
//
// Build once, then run under anything:
//   npm run build
//   node examples/runtime-smoke.mjs
//   bun examples/runtime-smoke.mjs
//   deno run --allow-read examples/runtime-smoke.mjs
import { engine, formatFingerprint, isCryptoFailure } from '../dist/index.js';

// Identify the host from its own global. Bun and Deno both expose a
// Node-compatible `process`, so they have to be checked before Node is.
const runtime = globalThis.Bun
  ? `bun ${globalThis.Bun.version}`
  : globalThis.Deno
    ? `deno ${globalThis.Deno.version.deno}`
    : globalThis.process?.versions?.node
      ? `node ${globalThis.process.versions.node}`
      : 'unknown runtime';

// Tiny inline assert. Importing node:assert would quietly reintroduce the
// Node dependency this script exists to disprove. A thrown error exits
// nonzero on every runtime, which is all CI needs from a failure.
function check(condition, label) {
  if (!condition) throw new Error(`FAIL ${runtime}: ${label}`);
  console.log(`ok: ${label}`);
}

// The library routes all randomness through the one standard entry point,
// so a missing WebCrypto is the only environment problem worth reporting
// up front with a clear message instead of a deep stack trace.
check(typeof globalThis.crypto?.getRandomValues === 'function', 'globalThis.crypto is available');

// Full handshake: Alice invites, Bob accepts, Alice completes.
const alice = await engine.createIdentity();
const bob = await engine.createIdentity();
const { token: inviteToken, pending } = await engine.invite(alice);
const bobOpen = await engine.open(bob, inviteToken, {});
check(bobOpen.outcome === 'invite', 'invite opens on the receiving side');
let bobSession = bobOpen.session;
const aliceOpen = await engine.open(alice, bobOpen.reply, { pending });
check(aliceOpen.outcome === 'accepted', 'accept completes the handshake');
let aliceSession = aliceOpen.session;

// The six safety words exist to be compared out loud, so Bob's rendering of
// Alice must be byte-for-byte identical to what Alice's own device renders.
const bobSeesAlice = formatFingerprint(bobOpen.peerFingerprint);
const aliceSelf = formatFingerprint(engine.fingerprint(engine.publicOf(alice)));
check(bobSeesAlice === aliceSelf, `fingerprint matches on both sides: ${bobSeesAlice}`);

// One message each way. The direction change on the reply also forces a
// ratchet step, so this exercises the DH ratchet, not just the symmetric one.
const a1 = await engine.seal(aliceSession, 'portable ciphertext, no runtime assumptions');
aliceSession = a1.session;
const b1 = await engine.open(bob, a1.token, { session: bobSession });
bobSession = b1.session;
check(
  b1.outcome === 'message' && b1.plaintext === 'portable ciphertext, no runtime assumptions',
  'alice to bob message decrypts',
);
const b2 = await engine.seal(bobSession, 'confirmed from the other side');
bobSession = b2.session;
const a2 = await engine.open(alice, b2.token, { session: aliceSession });
aliceSession = a2.session;
check(
  a2.outcome === 'message' && a2.plaintext === 'confirmed from the other side',
  'bob to alice reply decrypts',
);

// Tamper: flip one character of a fresh ciphertext. The open must fail
// closed with the library's own deliberate error, never return garbage
// plaintext, and never crash with an unrelated exception type.
const a3 = await engine.seal(aliceSession, 'this line is corrupted in transit');
const chars = a3.token.split('');
chars[chars.length - 3] = chars[chars.length - 3] === 'A' ? 'B' : 'A';
const corrupted = chars.join('');
let rejected = false;
try {
  await engine.open(bob, corrupted, { session: bobSession });
} catch (error) {
  rejected = isCryptoFailure(error);
}
check(rejected, 'tampered token is rejected with a deliberate crypto failure');

console.log(`PASS ${runtime}`);
