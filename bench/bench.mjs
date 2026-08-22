// Micro-benchmark for ratchet-ts. Single thread, no tuning.
//
//   npm run bench                 3 runs, the default
//   npm run bench -- --runs 5     5 runs
//
// One run is already a median over hundreds of operations. Repeating the whole
// run catches the slower thing: a machine that is quiet for two seconds and busy
// for the next two. The spread column is that noise made visible.
import os from 'node:os';
import { engine } from '../dist/index.js';

const RUNS = (() => {
  const i = process.argv.indexOf('--runs');
  const n = i === -1 ? 3 : Number.parseInt(process.argv[i + 1] ?? '', 10);
  return Number.isFinite(n) && n >= 1 && n <= 50 ? n : 3;
})();

const OPS = ['keygen', 'handshake', 'seal (256 B)', 'open (256 B)'];

const stats = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  const mean = s.reduce((a, b) => a + b, 0) / s.length;
  return { mean, median: s[Math.floor(s.length / 2)], p95: s[Math.floor(s.length * 0.95)] };
};

async function timed(n, fn) {
  const ms = [];
  for (let i = 0; i < n; i++) {
    const t0 = performance.now();
    await fn(i);
    ms.push(performance.now() - t0);
  }
  return stats(ms);
}

// Warm up the JIT and the noble precomputed tables once. Timing a cold engine
// measures the compiler, not the cryptography.
for (let i = 0; i < 20; i++) {
  const a = await engine.createIdentity();
  const b = await engine.createIdentity();
  const inv = await engine.invite(a);
  const bo = await engine.open(b, inv.token, {});
  await engine.open(a, bo.reply, { pending: inv.pending });
}

async function oneRun() {
  const out = {};

  // 1. identity keygen: X25519 + ML-KEM-768 keypairs
  out['keygen'] = await timed(300, () => engine.createIdentity());

  // 2. full handshake: invite + accept + open, ML-KEM encaps + decaps + 2x X25519.
  // Identities are built outside the timer so keygen is not counted twice.
  const pairs = [];
  for (let i = 0; i < 300; i++) {
    pairs.push([await engine.createIdentity(), await engine.createIdentity()]);
  }
  let hi = 0;
  out['handshake'] = await timed(300, async () => {
    const [a, b] = pairs[hi++];
    const inv = await engine.invite(a);
    const bo = await engine.open(b, inv.token, {});
    await engine.open(a, bo.reply, { pending: inv.pending });
  });

  // 3 + 4. seal and open on one live session, 256-byte payload, real ratchet advance
  const a = await engine.createIdentity();
  const b = await engine.createIdentity();
  const inv = await engine.invite(a);
  const bo = await engine.open(b, inv.token, {});
  let aliceSession = (await engine.open(a, bo.reply, { pending: inv.pending })).session;
  let bobSession = bo.session;
  const msg = 'x'.repeat(256);
  const sealMs = [];
  const openMs = [];
  // Four numbers, not one, because the old single number was wrong twice over.
  // It reported the base64url TOKEN length while the README talks about the
  // BINARY wire, and it sampled message 0 and called the result constant. The
  // first RATCHET_KEY_RESEND messages of a chain carry a 32 byte ratchet key
  // that later ones omit, so overhead drops after message 2 and stays down.
  // Measuring both forms, on both sides of that step, is the honest version.
  const overhead = { binaryWithKey: 0, binarySteady: 0, tokenWithKey: 0, tokenSteady: 0 };
  for (let i = 0; i < 2000; i++) {
    const t0 = performance.now();
    const sealed = await engine.seal(aliceSession, msg);
    const t1 = performance.now();
    const opened = await engine.open(b, sealed.token, { session: bobSession });
    const t2 = performance.now();
    sealMs.push(t1 - t0);
    openMs.push(t2 - t1);
    aliceSession = sealed.session;
    bobSession = opened.session;
    // Message 0 still carries the ratchet key; message 5 is safely past the
    // resend window, so it is the steady state every later message shares.
    if (i === 0 || i === 5) {
      const wire = await engine.sealToEnvelopeBytes(aliceSession, msg);
      const binary = (wire.bytes ?? wire.envelope).length - Buffer.byteLength(msg, 'utf8');
      const token = Buffer.byteLength(sealed.token, 'utf8') - Buffer.byteLength(msg, 'utf8');
      if (i === 0) {
        overhead.binaryWithKey = binary;
        overhead.tokenWithKey = token;
      } else {
        overhead.binarySteady = binary;
        overhead.tokenSteady = token;
      }
    }
  }
  out['seal (256 B)'] = stats(sealMs);
  out['open (256 B)'] = stats(openMs);
  out.overhead = overhead;
  return out;
}

console.log(`\nratchet-ts benchmark`);
console.log(`${process.version}  |  ${(os.cpus()[0] || {}).model}  |  ${os.platform()}/${os.arch()}`);
console.log(`${RUNS} run${RUNS === 1 ? '' : 's'}\n`);

const runs = [];
for (let r = 1; r <= RUNS; r++) {
  process.stdout.write(`  running ${r}/${RUNS}\r`);
  runs.push(await oneRun());
}
process.stdout.write('                    \r');

if (RUNS > 1) {
  console.log('each run, median ms');
  console.table(
    runs.map((run, i) => {
      const row = { run: i + 1 };
      for (const op of OPS) row[op] = run[op].median.toFixed(3);
      return row;
    }),
  );
  console.log(`across ${RUNS} runs`);
}

// The headline number is the median of the per-run medians. Best and worst are the
// fastest and slowest run. Spread is how far apart those two are, as a share of the
// headline: under 10 percent the machine was quiet, over 25 percent something else
// was competing for the CPU and the numbers are worth less.
console.table(
  OPS.map((op) => {
    const medians = runs.map((r) => r[op].median).sort((a, b) => a - b);
    const means = runs.map((r) => r[op].mean);
    const p95s = runs.map((r) => r[op].p95);
    const median = medians[Math.floor(medians.length / 2)];
    const best = medians[0];
    const worst = medians[medians.length - 1];
    const meanOfMeans = means.reduce((a, b) => a + b, 0) / means.length;
    return {
      op,
      'median ms': median.toFixed(3),
      'best ms': best.toFixed(3),
      'worst ms': worst.toFixed(3),
      spread: `${(((worst - best) / median) * 100).toFixed(1)}%`,
      'p95 ms': Math.max(...p95s).toFixed(3),
      'ops/sec': Math.round(1000 / meanOfMeans).toLocaleString('en-US'),
    };
  }),
);

const ov = runs[0].overhead;
console.log(
  `envelope overhead, binary wire: +${ov.binarySteady} bytes steady, ` +
    `+${ov.binaryWithKey} while the ratchet key rides along (first 3 of a chain)`,
);
console.log(
  `envelope overhead, base64url token: +${ov.tokenSteady} bytes steady, ` +
    `+${ov.tokenWithKey} with the key. Text form costs about a third more.\n`,
);
