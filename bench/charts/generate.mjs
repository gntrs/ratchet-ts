// Generates the benchmark charts embedded in the README.
//
//   node bench/charts/generate.mjs
//
// PROVENANCE IS PART OF THE DATA. Every row below carries the version it was
// measured on, the date, and the harness that produced it. That is not
// decoration: before 2026-08-08 this file held eight hand-copied numbers with
// no version attached, the Ryzen row said 7.6 ms handshake, and 0.3.3 had
// already made that row 1.86 ms. The chart was overstating one machine by
// roughly 4x and nothing in the source said so. A row without a `version` and a
// `measuredOn` is a row that can go stale silently, so the renderer now refuses
// to draw one and marks every row older than CURRENT_VERSION as stale on the
// chart itself.
//
// Only ONE of these machines is available to this project. The Ryzen 5 7530U
// row is re-measured on every release. The other seven are inherited from
// hardware borrowed once, they have NOT been re-measured on 0.3.3 or later, and
// they are drawn hatched so the chart is honest about being a mixed-vintage
// comparison rather than quietly presenting stale numbers as current.
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

/** Rows at this version are current. Anything else is drawn as stale. */
const CURRENT_VERSION = '0.3.4';

/**
 * `handshake` is the full invite + accept + complete exchange in median ms.
 * `seal` is one steady-state send in median ms. The measured row is a 256 byte
 * payload: 256 bytes is this project's working estimate of a chat message, and
 * latency is flat below about 1 kB, so the exact choice barely moves it. The
 * inherited rows below did NOT record their payload size, which is one more
 * reason they are not comparable to the current row.
 *
 * `measuredOn` is the day the row was produced. `version` is the ratchet-ts
 * version under test. `backends` is what aeadBackend() / curveBackend() /
 * hashBackend() printed on that run; the pre-0.3.3 rows predate the native
 * curve and hash backends entirely, which is the single biggest reason their
 * handshake column is not comparable to the current row.
 *
 * Only fields that were actually recorded appear here. The inherited rows carry
 * no `open` number because none was ever written down for them, and inventing
 * one to fill the column would be exactly the failure this header is about.
 */
const MACHINES = [
  {
    label: 'Ryzen 5 7530U', sub: 'laptop, Windows 11, Node 25',
    handshake: 1.85, seal: 0.0201, open: 0.0180,
    version: '0.3.4', measuredOn: '2026-08-08',
    backends: 'aead native, curve native, hash native',
    harness: '256 B payload, 4000 iterations, 500 warmup, median of 9 process runs',
  },
  {
    label: 'Apple M1', sub: 'laptop 2020, macOS',
    handshake: 6.2, seal: 0.019,
    version: '0.1.0', measuredOn: 'not recorded',
    backends: 'pre-0.3.3, no native curve or hash backend',
    harness: 'npm run bench, payload size not recorded',
  },
  {
    label: 'Core i5-12500H', sub: 'laptop 2022, Windows, Node 24',
    handshake: 6.5, seal: 0.025,
    version: '0.2.0', measuredOn: 'not recorded',
    backends: 'pre-0.3.3, no native curve or hash backend',
    harness: 'npm run bench, payload size not recorded',
  },
  {
    label: 'Core i5-12450H', sub: 'laptop 2022, Windows, Node 24',
    handshake: 7.0, seal: 0.023,
    version: '0.2.0', measuredOn: 'not recorded',
    backends: 'pre-0.3.3, no native curve or hash backend',
    harness: 'npm run bench, payload size not recorded',
  },
  {
    label: 'Ryzen 7 5800X3D', sub: 'desktop, Windows, Node 24',
    handshake: 7.3, seal: 0.028,
    version: '0.2.0', measuredOn: 'not recorded',
    backends: 'pre-0.3.3, no native curve or hash backend',
    harness: 'npm run bench, payload size not recorded',
  },
  {
    label: 'EPYC 9354P 32-core', sub: 'VPS, Linux, Node 22',
    handshake: 8.9, seal: 0.050,
    version: '0.2.0', measuredOn: 'not recorded',
    backends: 'pre-0.3.3, no native curve or hash backend',
    harness: 'npm run bench, payload size not recorded',
  },
  {
    label: 'Core i5-10400F', sub: 'desktop 2020, WSL, Node 22',
    handshake: 10.9, seal: 0.053,
    version: '0.2.0', measuredOn: 'not recorded',
    backends: 'pre-0.3.3, no native curve or hash backend',
    harness: 'npm run bench, payload size not recorded',
  },
  {
    label: 'Core i5-10400F', sub: 'same box, Windows, Node 24',
    handshake: 11.5, seal: 0.042,
    version: '0.2.0', measuredOn: 'not recorded',
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
 * chart got four times wrong.
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

for (const row of [...MACHINES, ...WIRE]) {
  for (const field of ['version', 'measuredOn', 'harness']) {
    if (typeof row[field] !== 'string' || row[field] === '') {
      throw new Error(`row "${row.label}" is missing ${field}; refusing to draw an unattributed number`);
    }
  }
}

const isStale = (m) => m.version !== CURRENT_VERSION;

const THEMES = {
  light: {
    surface: '#ffffff', bar: '#2563eb', stale: '#8c959f', ink: '#1f2328', muted: '#59636e', track: '#d1d9e0',
    old: '#bc4c00', new: '#1a7f37',
  },
  dark: {
    surface: '#0d1117', bar: '#4493f8', stale: '#6e7781', ink: '#e6edf3', muted: '#9198a1', track: '#3d444d',
    old: '#db6d28', new: '#3fb950',
  },
};

const FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif";
const W = 760, LABEL_X = 244, BAR_X = 256, BAR_MAX = 380, BAR_H = 20, ROW_H = 46, TOP = 112;

const fmt = (n, decimals) => n.toFixed(decimals);

/**
 * The chart's alt text is generated from the same array the bars are, so the
 * two cannot drift. The README embeds the string this returns; regenerate the
 * charts and paste it back, and `node bench/charts/generate.mjs` prints it for
 * exactly that reason.
 */
function altText({ title, unit, key, decimals }) {
  const rows = [...MACHINES].sort((a, b) => a[key] - b[key]);
  const parts = rows.map(m => `${m.label} ${fmt(m[key], decimals)}${isStale(m) ? ` (v${m.version}, pre-0.3.3)` : ` (v${m.version}, measured)`}`);
  const caveat = key === 'handshake'
    ? `The same laptop measured 7.6 ms on 0.2.0 and 1.85 ms on ${CURRENT_VERSION}, so the inherited rows overstate the handshake by roughly 4x.`
    : `The inherited rows did not record their payload size, so they are not directly comparable to the 256 B measured row.`;
  return `${title}, median ${unit} per machine, lower is better: ${parts.join(', ')}. Only the Ryzen 5 7530U row is measured on ${CURRENT_VERSION}; the rest predate the native curve and hash backends added in 0.3.3. ${caveat}`;
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

function legend(t, y) {
  return `
  <rect x="16" y="${y - 9}" width="12" height="12" rx="2" fill="${t.bar}"/>
  <text x="34" y="${y + 1}" font-family="${FONT}" font-size="11" fill="${t.muted}">measured on ${CURRENT_VERSION}, one machine, 256 B payload, 2026-08-08</text>
  <rect x="300" y="${y - 9}" width="12" height="12" rx="2" fill="url(#stale)" stroke="${t.stale}" stroke-width="1"/>
  <text x="318" y="${y + 1}" font-family="${FONT}" font-size="11" fill="${t.muted}">inherited, pre-0.3.3, not re-measured</text>`;
}

function chart(spec, theme) {
  const { title, unit, key, decimals } = spec;
  const t = THEMES[theme];
  const rows = [...MACHINES].sort((a, b) => a[key] - b[key]);
  const max = Math.max(...rows.map(m => m[key]));
  const H = TOP + rows.length * ROW_H + 16;
  const body = rows.map((m, i) => {
    const y = TOP + i * ROW_H;
    const w = Math.round((m[key] / max) * BAR_MAX);
    const stale = isStale(m);
    const fill = stale ? 'url(#stale)' : t.bar;
    const edge = stale ? ` stroke="${t.stale}" stroke-width="1"` : '';
    const tag = stale ? `<text x="${BAR_X + w + 8 + 52}" y="${y + 14}" font-family="${FONT}" font-size="11" fill="${t.muted}">v${m.version}, pre-0.3.3</text>` : `<text x="${BAR_X + w + 8 + 52}" y="${y + 14}" font-family="${FONT}" font-size="11" fill="${t.muted}">v${m.version}, measured</text>`;
    return `
  <text x="${LABEL_X}" y="${y + 9}" text-anchor="end" font-family="${FONT}" font-size="13" font-weight="600" fill="${t.ink}">${m.label}</text>
  <text x="${LABEL_X}" y="${y + 25}" text-anchor="end" font-family="${FONT}" font-size="11" fill="${t.muted}">${m.sub}</text>
  <rect x="${BAR_X}" y="${y}" width="${w}" height="${BAR_H}" rx="3" fill="${fill}"${edge}/>
  <text x="${BAR_X + w + 8}" y="${y + 14}" font-family="${FONT}" font-size="12" font-weight="600" fill="${t.ink}">${fmt(m[key], decimals)} ${unit}</text>
  ${tag}`;
  }).join('\n');

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="${altText(spec)}">
  <rect width="${W}" height="${H}" fill="${t.surface}"/>${hatch(t)}
  <text x="16" y="28" font-family="${FONT}" font-size="15" font-weight="700" fill="${t.ink}">${title}</text>
  <text x="16" y="48" font-family="${FONT}" font-size="12" fill="${t.muted}">median ms · lower is better · single thread, no tuning · mixed versions, read the legend</text>
${legend(t, 72)}
  <line x1="${BAR_X}" y1="${TOP - 8}" x2="${BAR_X}" y2="${H - 12}" stroke="${t.track}" stroke-width="1"/>
${body}
</svg>
`;
}

const WIRE_TOP = 78;

function wireAlt() {
  const [base, now] = WIRE;
  const saved = Math.round(((base.bytes - now.bytes) / base.bytes) * 100);
  return `Bytes on the wire for a 1 KiB binary payload: ${base.label} ${base.sub} ${base.bytes} bytes, ${now.label} ${now.sub} ${now.bytes} bytes, ${saved} percent fewer. Exact byte counts, not timings, measured against the published tarballs.`;
}

// Two bars, one per version, for the one number the release actually moved.
function wireChart(theme) {
  const t = THEMES[theme];
  const max = Math.max(...WIRE.map(v => v.bytes));
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
  <text x="16" y="48" font-family="${FONT}" font-size="12" fill="${t.muted}">same machine, same message · exact byte counts · lower is better</text>
  <line x1="${BAR_X}" y1="${WIRE_TOP - 8}" x2="${BAR_X}" y2="${H - 12}" stroke="${t.track}" stroke-width="1"/>
${rows}
</svg>
`;
}

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
console.log('\n--- paste these into the README <img alt="..."> attributes ---');
for (const c of CHARTS) console.log(`\n${c.file}:\n${altText(c)}`);
console.log(`\nwire:\n${wireAlt()}`);
