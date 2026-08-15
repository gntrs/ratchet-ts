// Generates the benchmark charts embedded in the README.
//
//   node bench/charts/generate.mjs
//
// PROVENANCE IS PART OF THE DATA. Every row below carries the version it was
// measured on, the date, the harness that produced it, and the power state the
// machine was in. That is not decoration: before 2026-08-08 this file held eight
// hand-copied numbers with no version attached, the Ryzen row said 7.6 ms
// handshake, and 0.3.3 had already made that row 1.86 ms. The chart was
// overstating one machine by roughly 4x and nothing in the source said so. A row
// without a `version` and a `measuredOn` is a row that can go stale silently, so
// the renderer refuses to draw one and marks every row older than
// CURRENT_VERSION as stale on the chart itself.
//
// POWER STATE IS ALSO PART OF THE DATA, and it was the second way this file
// lied. On 2026-08-09 the measured laptop produced seal p50 of 16.36 us in the
// morning and 30.0 us the same evening, on identical code. Nothing regressed.
// The machine was on battery on the Balanced plan, reporting a CurrentClockSpeed
// of 1890 MHz against a 4.5 GHz boost ceiling, with total system load at 2
// percent, so it was the clock and not contention. An absolute millisecond
// figure from this machine is meaningless without the power state stamped next
// to it, and ratios are better but not immune, because AES-CBC and HKDF do not
// scale with clock the way ChaCha20 and HMAC do. So `power` is a required field
// on every timing row, and the chart draws a base-clock row in a different
// colour from a boost-clock row, the same way it already hatches a stale one.
//
// TWO of these machines are available to this project, the Ryzen 5 7530U laptop
// and the Apple M4 desktop, and both are re-measured on releases that move the
// measured paths. The other seven are inherited from hardware borrowed once,
// they have NOT been re-measured on 0.3.3 or later, and they are drawn hatched
// so the chart is honest about being a mixed-vintage comparison rather than
// quietly presenting stale numbers as current. None of them recorded a power
// state either, which is a second reason they are not comparable to the measured
// rows and not a reason to guess one for them.
//
// THE TWO MEASURED ROWS ARE NOT COMPARABLE TO EACH OTHER IN ABSOLUTE TERMS, and
// this file draws them in different colours for exactly that reason. One is a
// laptop pinned near its base clock on battery, the other is a desktop on mains
// free to boost. That is a power-state difference stacked on a hardware
// difference, and the section above is about why the first of those cannot be
// factored out after the fact. Read the gap between them as "these are two
// different machines in two different states", not as a chip ranking.
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

/**
 * Rows at this version are current. Anything else is drawn as stale.
 *
 * This says 0.4.0 while package.json says 0.5.0, and that is deliberate rather
 * than a stale constant. 0.5.0 changed only the CLI at-rest story, how the
 * identity file and the peer list are stored on disk. It touched none of the
 * handshake, seal or open paths and did not move the wire format, so 0.5.0 is
 * byte-identical to 0.4.0 in the library and on the wire. 0.4.0 is the version
 * these numbers actually describe, and pretending they were taken on a version
 * that changed nothing about them would be the same class of error the header
 * above is about. Bump this when a release changes the measured paths, not
 * merely when the version number moves.
 */
const CURRENT_VERSION = '0.4.0';

/**
 * `handshake` is the full invite + accept + complete exchange in median ms.
 * `seal` is one steady-state send in median ms. `open` is one receive. The
 * measured row is a 256 byte payload: 256 bytes is this project's working
 * estimate of a chat message, and latency is flat below about 1 kB, so the exact
 * choice barely moves it. The inherited rows below did NOT record their payload
 * size, which is one more reason they are not comparable to the current row.
 *
 * `measuredOn` is the day the row was produced. `version` is the ratchet-ts
 * version under test. `backends` is what aeadBackend() / curveBackend() /
 * hashBackend() printed on that run; the pre-0.3.3 rows predate the native
 * curve and hash backends entirely, which is the single biggest reason their
 * handshake column is not comparable to the current row.
 *
 * `power` is the CPU power state during the run. Use 'ac-boost' for a machine on
 * mains that was free to boost, 'battery-base-<n>mhz' for a machine pinned near
 * its base clock, and 'not recorded' when nobody wrote it down. 'not recorded'
 * is an honest value and the renderer accepts it; a guess is not, and there is
 * no way to recover it after the fact.
 *
 * Only fields that were actually recorded appear here. The inherited rows carry
 * no `open` number because none was ever written down for them, and inventing
 * one to fill the column would be exactly the failure this header is about.
 * That is also why there is no open chart: one bar is not a comparison.
 */
const MACHINES = [
  {
    label: 'Apple M4', sub: 'Mac mini 2024, macOS 26, Node 22',
    handshake: 0.8818, seal: 0.0046, open: 0.0042,
    version: '0.4.0', measuredOn: '2026-08-15',
    power: 'ac-boost',
    backends: 'aead native, curve native, hash native',
    harness: 'bench/machine.mjs, 256 B payload, 20 rounds, 25 s sustained warmup, median of per-round p50, phases separated, seal and open on separate session pairs. Run from the 0.5.0 tree, which is byte-identical to 0.4.0 in the library and on the wire. The three medians reproduced to within 2.4 percent across three independent 20-round runs. The open row is the one to read with care: its p10-p90 spread across rounds was 27 percent on this machine, so the median is solid but the per-round distribution has a slow mode that is not yet explained.',
  },
  {
    label: 'Ryzen 5 7530U', sub: 'laptop, Windows 11, Node 25',
    handshake: 4.444, seal: 0.0355, open: 0.0292,
    version: '0.4.0', measuredOn: '2026-08-09',
    power: 'battery-base-1890mhz',
    backends: 'aead native, curve native, hash native',
    harness: '256 B payload, 20 rounds of 2000 iterations, 25 s sustained warmup, median of per-round p50, seal and open timed in isolation',
  },
  {
    label: 'Apple M1', sub: 'laptop 2020, macOS',
    handshake: 6.2, seal: 0.019,
    version: '0.1.0', measuredOn: 'not recorded',
    power: 'not recorded',
    backends: 'pre-0.3.3, no native curve or hash backend',
    harness: 'npm run bench, payload size not recorded',
  },
  {
    label: 'Core i5-12500H', sub: 'laptop 2022, Windows, Node 24',
    handshake: 6.5, seal: 0.025,
    version: '0.2.0', measuredOn: 'not recorded',
    power: 'not recorded',
    backends: 'pre-0.3.3, no native curve or hash backend',
    harness: 'npm run bench, payload size not recorded',
  },
  {
    label: 'Core i5-12450H', sub: 'laptop 2022, Windows, Node 24',
    handshake: 7.0, seal: 0.023,
    version: '0.2.0', measuredOn: 'not recorded',
    power: 'not recorded',
    backends: 'pre-0.3.3, no native curve or hash backend',
    harness: 'npm run bench, payload size not recorded',
  },
  {
    label: 'Ryzen 7 5800X3D', sub: 'desktop, Windows, Node 24',
    handshake: 7.3, seal: 0.028,
    version: '0.2.0', measuredOn: 'not recorded',
    power: 'not recorded',
    backends: 'pre-0.3.3, no native curve or hash backend',
    harness: 'npm run bench, payload size not recorded',
  },
  {
    label: 'EPYC 9354P 32-core', sub: 'VPS, Linux, Node 22',
    handshake: 8.9, seal: 0.050,
    version: '0.2.0', measuredOn: 'not recorded',
    power: 'not recorded',
    backends: 'pre-0.3.3, no native curve or hash backend',
    harness: 'npm run bench, payload size not recorded',
  },
  {
    label: 'Core i5-10400F', sub: 'desktop 2020, WSL, Node 22',
    handshake: 10.9, seal: 0.053,
    version: '0.2.0', measuredOn: 'not recorded',
    power: 'not recorded',
    backends: 'pre-0.3.3, no native curve or hash backend',
    harness: 'npm run bench, payload size not recorded',
  },
  {
    label: 'Core i5-10400F', sub: 'same box, Windows, Node 24',
    handshake: 11.5, seal: 0.042,
    version: '0.2.0', measuredOn: 'not recorded',
    power: 'not recorded',
    backends: 'pre-0.3.3, no native curve or hash backend',
    harness: 'npm run bench, payload size not recorded',
  },
];

/**
 * 1 KiB of random bytes, measured on one machine with 0.1.0 installed from npm
 * and 0.2.0 installed from the packed tarball. 0.1.0 has no bytes API, so the
 * old row is the workaround people actually write: latin1 into a string. That
 * round trips, but every byte above 0x7f becomes two UTF-8 bytes on the wire.
 *
 * These two rows are byte counts, not timings. They are exact, they reproduce
 * against the published tarballs, and they do not go stale the way a latency
 * row does: no release since has changed either number. They still carry the
 * provenance fields, because a number without provenance is how the handshake
 * chart got four times wrong. They carry no `power` field, and that is the one
 * exemption: a byte count does not change with the CPU clock, so demanding a
 * power state here would force an invented value onto a row that cannot have a
 * meaningful one.
 */
const WIRE = [
  {
    label: '0.1.0', sub: 'latin1 string workaround', bytes: 2227, tone: 'old',
    version: '0.1.0', measuredOn: '2026-07', harness: 'npm run bench:wire, exact byte count',
  },
  {
    label: '0.2.0', sub: 'sealBytes, native Uint8Array', bytes: 1539, tone: 'new',
    version: '0.2.0', measuredOn: '2026-07', harness: 'npm run bench:wire, exact byte count',
  },
];

// Timing rows must carry a power state. Byte-count rows must not be forced to
// invent one. Same refusal, two different field lists.
for (const row of MACHINES) {
  for (const field of ['version', 'measuredOn', 'harness', 'power']) {
    if (typeof row[field] !== 'string' || row[field] === '') {
      throw new Error(`row "${row.label}" is missing ${field}; refusing to draw an unattributed number`);
    }
  }
}
for (const row of WIRE) {
  for (const field of ['version', 'measuredOn', 'harness']) {
    if (typeof row[field] !== 'string' || row[field] === '') {
      throw new Error(`row "${row.label}" is missing ${field}; refusing to draw an unattributed number`);
    }
  }
}

const isStale = (m) => m.version !== CURRENT_VERSION;

/**
 * Three buckets, because they get three different treatments on the chart:
 * a row measured while the CPU could boost, a row measured at base clock, and a
 * row where nobody recorded it. Anything unparseable falls into 'unknown' rather
 * than being quietly treated as boost.
 */
function powerClass(m) {
  const p = m.power;
  if (typeof p !== 'string' || p === 'not recorded') return 'unknown';
  if (p.startsWith('ac-')) return 'boost';
  if (p.startsWith('battery-')) return 'base';
  return 'unknown';
}

/** Turns the machine-readable power tag into something a reader can use. */
function powerText(p) {
  if (typeof p !== 'string' || p === 'not recorded') return 'power state not recorded';
  const base = /^battery-base-(\d+)mhz$/.exec(p);
  if (base) return `on battery at ${base[1]} MHz base clock`;
  if (p === 'ac-boost') return 'on AC, free to boost';
  return p;
}

/** The tag drawn to the right of every bar, and reused verbatim in the alt text. */
function rowTag(m) {
  return `v${m.version}, ${isStale(m) ? 'pre-0.3.3' : 'measured'}, ${powerText(m.power)}`;
}

const CURRENT_ROWS = MACHINES.filter((m) => !isStale(m));

/** "the Apple M4 row" / "the Apple M4 and Ryzen 5 7530U rows". */
function rowList(rows) {
  const labels = rows.map((m) => m.label);
  if (labels.length === 0) return 'measured';
  if (labels.length === 1) return labels[0];
  return `${labels.slice(0, -1).join(', ')} and ${labels[labels.length - 1]}`;
}

const THEMES = {
  light: {
    surface: '#ffffff', bar: '#2563eb', base: '#bf8700', stale: '#8c959f',
    ink: '#1f2328', muted: '#59636e', track: '#d1d9e0',
    old: '#bc4c00', new: '#1a7f37',
  },
  dark: {
    surface: '#0d1117', bar: '#4493f8', base: '#d29922', stale: '#6e7781',
    ink: '#e6edf3', muted: '#9198a1', track: '#3d444d',
    old: '#db6d28', new: '#3fb950',
  },
};

const FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif";
// The tag column is at a fixed x rather than trailing the bar. Trailing it meant
// the longest bar pushed its own tag off the right edge of the SVG, which is how
// the old layout hid the version marker on exactly the row most worth doubting.
// The canvas is wider than the bars need because the tag column has to fit the
// longest tag without clipping. The longest is the measured row, whose power
// state makes it the wordiest: "v0.4.0, measured, on battery at 1890 MHz base
// clock". Widening here rather than abbreviating the tag keeps the drawn tag and
// the alt text the same single string, so they cannot drift apart.
const W = 1000, LABEL_X = 244, BAR_X = 256, BAR_MAX = 300, TAG_X = 640;
const BAR_H = 20, ROW_H = 46, TOP = 112;

const fmt = (n, decimals) => n.toFixed(decimals);

/**
 * The chart's alt text is generated from the same array the bars are, so the
 * two cannot drift. The README embeds the string this returns; regenerate the
 * charts and paste it back, and `node bench/charts/generate.mjs` prints it for
 * exactly that reason.
 *
 * Every number in here is a number the chart actually draws. The old version of
 * this function name-checked a 1.85 ms handshake that no bar showed, which is
 * the alt-text form of the same problem: a screen reader user was told a figure
 * they could not have found on the chart.
 */
function altText({ title, unit, key, decimals }) {
  const rows = [...MACHINES].sort((a, b) => a[key] - b[key]);
  const parts = rows.map((m) => `${m.label} ${fmt(m[key], decimals)} (${rowTag(m)})`);
  const caveat = key === 'handshake'
    ? 'Every inherited row predates the native curve and hash backends added in 0.3.3 and none recorded a power state, so the distance between them and the measured rows mixes version, backend and CPU clock together and is not a clean hardware ranking.'
    : 'The inherited rows recorded neither their payload size nor their power state, so they are not directly comparable to the 256 B measured rows.';
  const baseRows = CURRENT_ROWS.filter((m) => powerClass(m) === 'base');
  const powerNote = baseRows.length
    ? `Absolute milliseconds on the ${rowList(baseRows)} row are power-state dependent: it was taken ${powerText(baseRows[0].power)} against a 4.5 GHz boost ceiling, so the same code on mains power is considerably quicker.`
    : '';
  // Two measured rows in different power states are not a hardware ranking, and
  // saying so is the whole reason the power field is required.
  const crossNote = CURRENT_ROWS.length > 1 && new Set(CURRENT_ROWS.map(powerClass)).size > 1
    ? `The measured rows are not comparable to each other either: ${CURRENT_ROWS.map((m) => `${m.label} ${powerText(m.power)}`).join(', ')}, so the distance between them is a power state stacked on a difference in hardware.`
    : '';
  const measuredCount = CURRENT_ROWS.length === 1 ? 'row is' : 'rows are';
  return `${title}, median ${unit} per machine, lower is better: ${parts.join(', ')}. Only the ${rowList(CURRENT_ROWS)} ${measuredCount} measured on ${CURRENT_VERSION}. ${caveat} ${crossNote} ${powerNote}`.replace(/\s+/g, ' ').trim();
}

function hatch(t) {
  return `
  <defs>
    <pattern id="stale" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
      <rect width="6" height="6" fill="${t.surface}"/>
      <rect width="3" height="6" fill="${t.stale}"/>
    </pattern>
  </defs>`;
}

/**
 * The legend is built from what the chart actually contains. A swatch for a
 * category with no bars in it is its own small lie, so a colour only appears
 * here if something on the chart is drawn in it.
 */
function legend(t) {
  const items = [];
  const current = MACHINES.filter((m) => !isStale(m));
  const boost = current.filter((m) => powerClass(m) === 'boost');
  const base = current.filter((m) => powerClass(m) === 'base');
  const unknownPower = current.filter((m) => powerClass(m) === 'unknown');
  const stale = MACHINES.filter(isStale);

  if (boost.length) {
    items.push([t.bar, null, `measured on ${CURRENT_VERSION}, on AC and free to boost, 256 B payload, ${boost[0].measuredOn}`]);
  }
  if (base.length) {
    items.push([t.base, null, `measured on ${CURRENT_VERSION}, ${powerText(base[0].power)} against a 4.5 GHz ceiling, 256 B payload, ${base[0].measuredOn}`]);
  }
  if (unknownPower.length) {
    items.push([t.bar, null, `measured on ${CURRENT_VERSION}, power state not recorded, 256 B payload, ${unknownPower[0].measuredOn}`]);
  }
  if (stale.length) {
    items.push(['url(#stale)', t.stale, 'inherited, pre-0.3.3, not re-measured, power state not recorded']);
  }

  return items.map(([fill, edge, text], i) => {
    const y = 62 + i * 18;
    const stroke = edge ? ` stroke="${edge}" stroke-width="1"` : '';
    return `
  <rect x="16" y="${y - 9}" width="12" height="12" rx="2" fill="${fill}"${stroke}/>
  <text x="34" y="${y + 1}" font-family="${FONT}" font-size="11" fill="${t.muted}">${text}</text>`;
  }).join('');
}

function barFill(m, t) {
  if (isStale(m)) return 'url(#stale)';
  return powerClass(m) === 'base' ? t.base : t.bar;
}

function chart(spec, theme) {
  const { title, unit, key, decimals } = spec;
  const t = THEMES[theme];
  const rows = [...MACHINES].sort((a, b) => a[key] - b[key]);
  const max = Math.max(...rows.map((m) => m[key]));
  const legendLines = legend(t).split('<rect').length - 1;
  const top = Math.max(TOP, 62 + legendLines * 18 + 22);
  const H = top + rows.length * ROW_H + 16;
  const body = rows.map((m, i) => {
    const y = top + i * ROW_H;
    const w = Math.round((m[key] / max) * BAR_MAX);
    const edge = isStale(m) ? ` stroke="${t.stale}" stroke-width="1"` : '';
    return `
  <text x="${LABEL_X}" y="${y + 9}" text-anchor="end" font-family="${FONT}" font-size="13" font-weight="600" fill="${t.ink}">${m.label}</text>
  <text x="${LABEL_X}" y="${y + 25}" text-anchor="end" font-family="${FONT}" font-size="11" fill="${t.muted}">${m.sub}</text>
  <rect x="${BAR_X}" y="${y}" width="${w}" height="${BAR_H}" rx="3" fill="${barFill(m, t)}"${edge}/>
  <text x="${BAR_X + w + 8}" y="${y + 14}" font-family="${FONT}" font-size="12" font-weight="600" fill="${t.ink}">${fmt(m[key], decimals)} ${unit}</text>
  <text x="${TAG_X}" y="${y + 14}" font-family="${FONT}" font-size="11" fill="${t.muted}">${rowTag(m)}</text>`;
  }).join('\n');

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="${altText(spec)}">
  <rect width="${W}" height="${H}" fill="${t.surface}"/>${hatch(t)}
  <text x="16" y="28" font-family="${FONT}" font-size="15" font-weight="700" fill="${t.ink}">${title}</text>
  <text x="16" y="46" font-family="${FONT}" font-size="12" fill="${t.muted}">median ms · lower is better · single thread, no tuning · mixed versions and mixed power states, read the legend</text>
${legend(t)}
  <line x1="${BAR_X}" y1="${top - 8}" x2="${BAR_X}" y2="${H - 12}" stroke="${t.track}" stroke-width="1"/>
${body}
</svg>
`;
}

const WIRE_TOP = 78;

function wireAlt() {
  const [base, now] = WIRE;
  const saved = Math.round(((base.bytes - now.bytes) / base.bytes) * 100);
  return `Bytes on the wire for a 1 KiB binary payload: ${base.label} ${base.sub} ${base.bytes} bytes, ${now.label} ${now.sub} ${now.bytes} bytes, ${saved} percent fewer. Exact byte counts, not timings, measured against the published tarballs, so they do not depend on CPU clock or power state.`;
}

// Two bars, one per version, for the one number the release actually moved.
function wireChart(theme) {
  const t = THEMES[theme];
  const max = Math.max(...WIRE.map((v) => v.bytes));
  const saved = Math.round(((WIRE[0].bytes - WIRE[1].bytes) / WIRE[0].bytes) * 100);
  const H = WIRE_TOP + WIRE.length * ROW_H + 16;
  const rows = WIRE.map((v, i) => {
    const y = WIRE_TOP + i * ROW_H;
    const w = Math.round((v.bytes / max) * BAR_MAX);
    const note = i === 0 ? '' : `  (${saved}% fewer)`;
    return `
  <text x="${LABEL_X}" y="${y + 9}" text-anchor="end" font-family="${FONT}" font-size="13" font-weight="600" fill="${t.ink}">${v.label}</text>
  <text x="${LABEL_X}" y="${y + 25}" text-anchor="end" font-family="${FONT}" font-size="11" fill="${t.muted}">${v.sub}</text>
  <rect x="${BAR_X}" y="${y}" width="${w}" height="${BAR_H}" rx="3" fill="${t[v.tone]}"/>
  <text x="${BAR_X + w + 8}" y="${y + 14}" font-family="${FONT}" font-size="12" font-weight="600" fill="${t.ink}">${v.bytes} B${note}</text>`;
  }).join('\n');

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="${wireAlt()}">
  <rect width="${W}" height="${H}" fill="${t.surface}"/>
  <text x="16" y="28" font-family="${FONT}" font-size="15" font-weight="700" fill="${t.ink}">Bytes on the wire, 1 KiB binary payload</text>
  <text x="16" y="48" font-family="${FONT}" font-size="12" fill="${t.muted}">same machine, same message · exact byte counts · lower is better · clock independent</text>
  <line x1="${BAR_X}" y1="${WIRE_TOP - 8}" x2="${BAR_X}" y2="${H - 12}" stroke="${t.track}" stroke-width="1"/>
${rows}
</svg>
`;
}

// `open` is recorded on both measured rows but still has no chart: seven of the
// nine machines never recorded an open number, so the chart would be two bars in
// two different power states with seven blanks behind them, which is a worse
// picture than no picture. It becomes worth drawing when a third machine is
// measured, or when the two measured rows are ever taken in the same power
// state. The field stays in the data until then.
const CHARTS = [
  { file: 'handshake', title: 'Full handshake (invite + accept + open)', unit: 'ms', key: 'handshake', decimals: 2 },
  { file: 'seal', title: 'seal, one steady-state send', unit: 'ms', key: 'seal', decimals: 4 },
];

for (const c of CHARTS) {
  for (const theme of Object.keys(THEMES)) {
    const path = join(here, `${c.file}-${theme}.svg`);
    writeFileSync(path, chart(c, theme));
    console.log('wrote', path);
  }
}

for (const theme of Object.keys(THEMES)) {
  const path = join(here, `wire-${theme}.svg`);
  writeFileSync(path, wireChart(theme));
  console.log('wrote', path);
}

// The README <img> alt attributes have to carry the same numbers as the bars.
// Printing them here is what stops the two from drifting apart again.
console.log('\n=== paste these into the README <img alt="..."> attributes ===');
for (const c of CHARTS) {
  console.log(`\n----- ${c.file} -----`);
  console.log(altText(c));
}
console.log('\n----- wire -----');
console.log(wireAlt());
console.log('\n=== end alt text ===');
