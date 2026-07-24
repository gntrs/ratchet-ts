// Micro-benchmark for ratchet-ts. Baseline numbers, single thread, no tuning.
// Run:  npm run build && node bench/bench.mjs
import os from 'node:os';
import { engine } from '../dist/index.js';

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

// warm up the JIT and the noble tables
for (let i = 0; i < 20; i++) {
  const a = await engine.createIdentity();
  const b = await engine.createIdentity();
  const inv = await engine.invite(a);
  const bo = await engine.open(b, inv.token, {});
  await engine.open(a, bo.reply, { pending: inv.pending });
}

const rows = [];
const push = (op, st) =>
  rows.push({
    op,
    'median ms': st.median.toFixed(3),
    'mean ms': st.mean.toFixed(3),
    'p95 ms': st.p95.toFixed(3),
    'ops/sec': Math.round(1000 / st.mean).toLocaleString('en-US'),
  });

// 1. identity keygen: X25519 + ML-KEM-768 keypairs
push('keygen', await timed(300, () => engine.createIdentity()));

// 2. full handshake: invite + accept + open, ML-KEM encaps + decaps + 2x X25519
const pairs = [];
for (let i = 0; i < 300; i++) pairs.push([await engine.createIdentity(), await engine.createIdentity()]);
let hi = 0;
push('handshake', await timed(300, async () => {
  const [a, b] = pairs[hi++];
  const inv = await engine.invite(a);
  const bo = await engine.open(b, inv.token, {});
  await engine.open(a, bo.reply, { pending: inv.pending });
}));

// 3 + 4. seal / open on a live session, 256-byte payload, real ratchet advance
const a = await engine.createIdentity();
const b = await engine.createIdentity();
const inv = await engine.invite(a);
const bo = await engine.open(b, inv.token, {});
let aliceSession = (await engine.open(a, bo.reply, { pending: inv.pending })).session;
let bobSession = bo.session;
const msg = 'x'.repeat(256);
const N = 2000;
const sealMs = [], openMs = [];
let overhead = 0;
for (let i = 0; i < N; i++) {
  const t0 = performance.now();
  const sealed = await engine.seal(aliceSession, msg);
  const t1 = performance.now();
  const opened = await engine.open(b, sealed.token, { session: bobSession });
  const t2 = performance.now();
  sealMs.push(t1 - t0);
  openMs.push(t2 - t1);
  aliceSession = sealed.session;
  bobSession = opened.session;
  if (i === 0) overhead = Buffer.byteLength(sealed.token, 'utf8') - Buffer.byteLength(msg, 'utf8');
}
push('seal (256 B)', stats(sealMs));
push('open (256 B)', stats(openMs));

console.log(`\nratchet-ts benchmark`);
console.log(`${process.version}  |  ${(os.cpus()[0] || {}).model}  |  ${os.platform()}/${os.arch()}\n`);
console.table(rows);
console.log(`ciphertext overhead: +${overhead} bytes per message (constant)\n`);
