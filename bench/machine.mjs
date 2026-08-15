// Produces one machine row for the charts in bench/charts/generate.mjs.
//
//   npm run bench:machine              20 rounds, the default
//   npm run bench:machine -- --rounds 5
//
// This is not `npm run bench`. That script answers "is this build fast on this
// laptop right now" in a few seconds and it is the right tool for that. This one
// answers "what number belongs in a published chart next to seven other
// machines", and those are different questions with different failure modes.
//
// WHY THIS FILE EXISTS. The measured row in the chart was 4.44 ms, and the
// README said it came from "20 rounds of 2000 iterations with a 25 second
// sustained warmup, phase separated". That method was real and it was better
// than the short harness, and it lived nowhere: it was typed once, on one
// laptop, and thrown away. So the one number the chart presents as reproducible
// was the only number in the repository nobody could reproduce, including the
// person who took it. A benchmark whose method is a sentence in a README is a
// benchmark that gets re-derived slightly differently every time, and the whole
// point of that chart is that rows taken different ways are not comparable.
//
// What the method is, and why each part of it:
//
//   Sustained warmup, 25 seconds. A JIT warmup of twenty iterations gets the
//   compiler out of the way. It does not get the CPU into the thermal and clock
//   state it will actually sit in, and on a laptop that difference was 18
//   percent, wider than most of what this project has ever optimised.
//
//   Phase separation. Running the handshake loop immediately before the seal
//   loop leaves ML-KEM's working set in cache and the seal numbers come out
//   flattering. Each phase gets an idle gap so it starts from a comparable
//   state instead of inheriting the previous phase's cache.
//
//   A re-warm burst inside each phase, after that gap. This is not belt and
//   braces, it is the fix for a bug this harness had on its first run. On a
//   heterogeneous CPU, the 250 ms idle gap is long enough for the scheduler to
//   move the process to an efficiency core, and a phase that then times a
//   5 microsecond operation measures the slow core for as long as it takes to
//   migrate back. Seal came out with a 115 percent spread across rounds and the
//   harness blamed CPU contention, which was wrong: the machine was quiet and
//   the harness's own idle gap had caused it. The same seal in one sustained
//   loop is 4.25 us at 7.9 percent spread. So each phase runs untimed work
//   first, long enough to be back on a performance core before the timer starts.
//   The gap still does its job, because it is the cache that has to go cold and
//   not the clock.
//
//   Median of per-round p50, not one long p50. Twenty short rounds make a
//   two-second interruption visible as one bad round instead of dissolving into
//   a single distribution. The spread across rounds is reported for that reason
//   and is the number to read before trusting the median.
//
//   Seal and open on separate session pairs. Thousands of seals with no reply
//   walk the receiving side into MAX_SKIP, so timing both on one pair measures
//   skip handling. The open phase pre-seals its messages untimed and then opens
//   them in order.
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { engine, aeadBackend, aeadReady, curveBackend, curvesReady, hashBackend, hashReady } from '../dist/index.js';

const ROUNDS = (() => {
  const i = process.argv.indexOf('--rounds');
  const n = i === -1 ? 20 : Number.parseInt(process.argv[i + 1] ?? '', 10);
  return Number.isFinite(n) && n >= 1 && n <= 100 ? n : 20;
})();

const WARMUP_MS = 25_000;
const PAYLOAD = 256;
const KEYGEN_ITERS = 300;
const HANDSHAKE_ITERS = 300;
const MESSAGE_ITERS = 2000;

const p50 = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
const msg = 'x'.repeat(PAYLOAD);

/** An idle gap between phases, so one phase does not inherit the last one's cache. */
const settle = () => new Promise((r) => setTimeout(r, 250));

/**
 * Untimed work run after `settle` and before the timer, to get back onto a
 * performance core. See the header: without this the idle gap itself is what
 * makes the microsecond rows unstable. It runs on its own session so it does not
 * advance any chain the measured loop is about to use.
 */
async function rewarm(ms = 120) {
  const { alice } = await freshPair();
  let s = alice;
  const until = performance.now() + ms;
  while (performance.now() < until) s = (await engine.seal(s, msg)).session;
}

async function freshPair() {
  const a = await engine.createIdentity();
  const b = await engine.createIdentity();
  const inv = await engine.invite(a);
  const bo = await engine.open(b, inv.token, {});
  const alice = (await engine.open(a, bo.reply, { pending: inv.pending })).session;
  return { a, b, alice, bob: bo.session };
}

/**
 * The power state is part of the row, and a guessed one is worse than none. This
 * reads the machine where it can and returns the literal string 'not recorded'
 * where it cannot, which is a value the chart generator accepts on purpose.
 */
function powerState() {
  if (process.platform !== 'darwin') return 'not recorded';
  try {
    const ps = execFileSync('pmset', ['-g', 'ps'], { encoding: 'utf8' });
    if (/AC Power/.test(ps)) return 'ac-boost';
    if (/Battery Power/.test(ps)) return 'not recorded';
  } catch {}
  return 'not recorded';
}

await Promise.all([aeadReady(), curvesReady(), hashReady()]);
const backends = `aead ${aeadBackend()}, curve ${curveBackend()}, hash ${hashBackend()}`;

console.log('\nratchet-ts machine row');
console.log(`${process.version}  |  ${os.cpus()[0].model}  |  ${process.platform}/${process.arch}`);
console.log(`${backends}`);
console.log(`${ROUNDS} rounds, ${PAYLOAD} B payload, ${WARMUP_MS / 1000} s sustained warmup\n`);

if (!/native/.test(aeadBackend()) || !/native/.test(curveBackend()) || !/native/.test(hashBackend())) {
  console.log('WARNING: at least one primitive fell back to the pure JavaScript path.');
  console.log('The chart rows are all native native native. This row is not comparable to them.\n');
}

// Sustained warmup. Twenty iterations warms the JIT; twenty-five seconds warms
// the machine. The distinction is the whole reason this harness exists.
process.stdout.write('  warming up');
const warmStart = performance.now();
let lastDot = warmStart;
while (performance.now() - warmStart < WARMUP_MS) {
  const { alice } = await freshPair();
  let s = alice;
  for (let i = 0; i < 200; i++) s = (await engine.seal(s, msg)).session;
  // One dot per second of warmup, not one per pass. The loop runs thousands of
  // passes and a dot each buried the rest of the output.
  if (performance.now() - lastDot >= 1000) {
    process.stdout.write('.');
    lastDot = performance.now();
  }
}
process.stdout.write(' done\n');

const rounds = { keygen: [], handshake: [], seal: [], open: [] };

for (let r = 1; r <= ROUNDS; r++) {
  process.stdout.write(`\r  round ${r}/${ROUNDS}   `);

  // Keygen: X25519 + ML-KEM-768 keypairs.
  await settle();
  await rewarm();
  {
    const ms = [];
    for (let i = 0; i < KEYGEN_ITERS; i++) {
      const t0 = performance.now();
      await engine.createIdentity();
      ms.push(performance.now() - t0);
    }
    rounds.keygen.push(p50(ms));
  }

  // Handshake: invite + accept + complete. Identities are built outside the
  // timer, otherwise this column would be keygen counted three times.
  await settle();
  await rewarm();
  {
    const pairs = [];
    for (let i = 0; i < HANDSHAKE_ITERS; i++) {
      pairs.push([await engine.createIdentity(), await engine.createIdentity()]);
    }
    const ms = [];
    for (let i = 0; i < HANDSHAKE_ITERS; i++) {
      const [a, b] = pairs[i];
      const t0 = performance.now();
      const inv = await engine.invite(a);
      const bo = await engine.open(b, inv.token, {});
      await engine.open(a, bo.reply, { pending: inv.pending });
      ms.push(performance.now() - t0);
    }
    rounds.handshake.push(p50(ms));
  }

  // Seal, on its own pair. The receiver never opens, which is fine: skipping is
  // a receiver problem and the sender just advances its own chain.
  await settle();
  await rewarm();
  {
    const { alice } = await freshPair();
    let s = alice;
    const ms = [];
    for (let i = 0; i < MESSAGE_ITERS; i++) {
      const t0 = performance.now();
      const sealed = await engine.seal(s, msg);
      ms.push(performance.now() - t0);
      s = sealed.session;
    }
    rounds.seal.push(p50(ms));
  }

  // Open, on a different pair, against messages sealed outside the timer and
  // opened in order so nothing is measuring MAX_SKIP.
  //
  // Sealed in chunks rather than all at once. Holding all 2000 tokens live
  // before opening any of them is roughly a megabyte of retained strings, and
  // collecting it landed inside the timed loop on about one round in twenty:
  // open's spread across rounds was 43 percent while every other row was under
  // 10, driven by a single outlier. A chunk is opened and dropped before the
  // next is sealed, so the live set stays flat. The chain still advances in
  // order across chunk boundaries, which is the property that keeps MAX_SKIP
  // out of the measurement.
  await settle();
  await rewarm();
  {
    const { b, alice, bob } = await freshPair();
    const CHUNK = 200;
    let s = alice;
    let rs = bob;
    const ms = [];
    for (let done = 0; done < MESSAGE_ITERS; done += CHUNK) {
      const tokens = [];
      for (let i = 0; i < CHUNK; i++) {
        const sealed = await engine.seal(s, msg);
        tokens.push(sealed.token);
        s = sealed.session;
      }
      for (const token of tokens) {
        const t0 = performance.now();
        const opened = await engine.open(b, token, { session: rs });
        ms.push(performance.now() - t0);
        rs = opened.session;
      }
    }
    rounds.open.push(p50(ms));
  }
}

process.stdout.write('\r                    \r');

/**
 * Two spread columns, because one of them was lying about this harness.
 *
 * `range` is best round to worst round over the median, the definition
 * bench/README.md gives and `npm run bench` prints. On twenty rounds it is a
 * two-sample statistic in disguise: one interrupted round sets it on its own.
 * It put open at 41 percent while eighteen of the twenty rounds sat inside one
 * percent of each other, and that reads as a broken machine when nothing was
 * wrong.
 *
 * `p10-p90` is the same measure with the tails cut, which is what
 * bench/wire.mjs already switched to for the same reason: "at this sample count
 * the extremes are garbage collection pauses". The method here is explicitly
 * median-of-per-round-p50, chosen to be robust to a bad round, so gating the
 * whole run on the least robust statistic available contradicts the method. The
 * gate reads p10-p90. `range` stays on screen because a big gap between the two
 * columns is itself the signal that one round went wrong, and hiding it would
 * be the kind of quiet smoothing this directory exists to avoid.
 */
const pct = (xs, q) => [...xs].sort((a, b) => a - b)[Math.min(xs.length - 1, Math.floor(xs.length * q))];
const rangeSpread = (xs) => ((pct(xs, 1) - pct(xs, 0)) / p50(xs)) * 100;
const robustSpread = (xs) => ((pct(xs, 0.9) - pct(xs, 0.1)) / p50(xs)) * 100;

const summary = Object.entries(rounds).map(([op, xs]) => ({
  op,
  'median ms': p50(xs).toFixed(4),
  'best round': pct(xs, 0).toFixed(4),
  'worst round': pct(xs, 1).toFixed(4),
  range: `${rangeSpread(xs).toFixed(1)}%`,
  'p10-p90': `${robustSpread(xs).toFixed(1)}%`,
}));

console.log(`median of per-round p50, across ${ROUNDS} rounds`);
console.table(summary);

const worstSpread = Math.max(...Object.values(rounds).map(robustSpread));
if (worstSpread > 25) {
  console.log('p10-p90 spread is over 25 percent on at least one row. Something else was');
  console.log('using the CPU. Do not put this run in the chart; run it again on a quiet');
  console.log('machine.\n');
} else if (worstSpread > 10) {
  console.log('p10-p90 spread is over 10 percent on at least one row. The machine was not');
  console.log('fully quiet. Usable, but a cleaner run is worth taking if one is available.\n');
}

const iso = new Date().toISOString().slice(0, 10);
console.log('row for bench/charts/generate.mjs, fill in label and sub:\n');
console.log(`  {
    label: '${os.cpus()[0].model}', sub: 'fill this in',
    handshake: ${p50(rounds.handshake).toFixed(4)}, seal: ${p50(rounds.seal).toFixed(4)}, open: ${p50(rounds.open).toFixed(4)},
    version: 'fill this in', measuredOn: '${iso}',
    power: '${powerState()}',
    backends: '${backends}',
    harness: 'bench/machine.mjs, ${PAYLOAD} B payload, ${ROUNDS} rounds, ${WARMUP_MS / 1000} s sustained warmup, median of per-round p50, phases separated, seal and open on separate session pairs',
  },`);
console.log(`\nkeygen p50 was ${p50(rounds.keygen).toFixed(4)} ms. The chart has no keygen column, so it is`);
console.log('reported here and not in the row.\n');
