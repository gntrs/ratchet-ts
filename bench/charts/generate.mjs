// Generates the benchmark charts embedded in the README.
// Data = median ms from `npm run bench` runs on real machines (see README table).
// Usage: node bench/charts/generate.mjs
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

const MACHINES = [
  { label: 'Core i5-12500H', sub: 'laptop 2022, Windows · Node 24', handshake: 6.5, seal: 0.025 },
  { label: 'Ryzen 7 5800X3D', sub: 'desktop, Windows · Node 24', handshake: 7.3, seal: 0.028 },
  { label: 'EPYC 9354P 32-core', sub: 'VPS, Linux · Node 22', handshake: 8.9, seal: 0.050 },
  { label: 'Core i5-10400F', sub: 'desktop 2020, WSL · Node 22', handshake: 10.9, seal: 0.053 },
  { label: 'Core i5-10400F', sub: 'same box, Windows · Node 24', handshake: 11.5, seal: 0.042 },
  { label: 'Ryzen 5 7530U', sub: 'laptop, Windows · Node 25', handshake: 13.8, seal: 0.061 },
];

const THEMES = {
  light: { surface: '#ffffff', bar: '#2563eb', ink: '#1f2328', muted: '#59636e', track: '#d1d9e0' },
  dark: { surface: '#0d1117', bar: '#4493f8', ink: '#e6edf3', muted: '#9198a1', track: '#3d444d' },
};

const FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif";
const W = 760, LABEL_X = 244, BAR_X = 256, BAR_MAX = 420, BAR_H = 20, ROW_H = 46, TOP = 78;

function chart({ title, unit, key, decimals }, theme) {
  const t = THEMES[theme];
  const max = Math.max(...MACHINES.map(m => m[key]));
  const H = TOP + MACHINES.length * ROW_H + 16;
  const rows = MACHINES.map((m, i) => {
    const y = TOP + i * ROW_H;
    const w = Math.round((m[key] / max) * BAR_MAX);
    const val = m[key].toFixed(decimals);
    return `
  <text x="${LABEL_X}" y="${y + 9}" text-anchor="end" font-family="${FONT}" font-size="13" font-weight="600" fill="${t.ink}">${m.label}</text>
  <text x="${LABEL_X}" y="${y + 25}" text-anchor="end" font-family="${FONT}" font-size="11" fill="${t.muted}">${m.sub}</text>
  <rect x="${BAR_X}" y="${y}" width="${w}" height="${BAR_H}" rx="3" fill="${t.bar}"/>
  <text x="${BAR_X + w + 8}" y="${y + 14}" font-family="${FONT}" font-size="12" font-weight="600" fill="${t.ink}">${val} ${unit}</text>`;
  }).join('\n');

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="${title}, median milliseconds per machine, lower is better">
  <rect width="${W}" height="${H}" fill="${t.surface}"/>
  <text x="16" y="28" font-family="${FONT}" font-size="15" font-weight="700" fill="${t.ink}">${title}</text>
  <text x="16" y="48" font-family="${FONT}" font-size="12" fill="${t.muted}">median ms · lower is better · single thread, no tuning</text>
  <line x1="${BAR_X}" y1="${TOP - 8}" x2="${BAR_X}" y2="${H - 12}" stroke="${t.track}" stroke-width="1"/>
${rows}
</svg>
`;
}

const CHARTS = [
  { file: 'handshake', title: 'Full handshake (invite + accept + open)', unit: 'ms', key: 'handshake', decimals: 1 },
  { file: 'seal', title: 'seal, 256 B message (steady-state send)', unit: 'ms', key: 'seal', decimals: 3 },
];

for (const c of CHARTS) {
  for (const theme of Object.keys(THEMES)) {
    const path = join(here, `${c.file}-${theme}.svg`);
    writeFileSync(path, chart(c, theme));
    console.log('wrote', path);
  }
}
