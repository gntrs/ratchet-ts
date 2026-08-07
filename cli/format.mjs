// Pure formatting helpers for the ratchet-ts CLI. No I/O, no imports from
// other cli modules, no import of ratchet-ts itself: every function here
// takes data in and returns a string, nothing else.

// Decided once at load, not per call, so a script that redirects stdout
// mid-run (or a test harness that mutates env after the module is live)
// does not get a colour flip halfway through a render.
const USE_COLOR =
  Boolean(process.stdout.isTTY) &&
  !process.env.NO_COLOR &&
  process.env.TERM !== 'dumb';

// 16-colour codes only, deliberately. 256-colour and truecolor escapes are
// the ones that turn into garbage on a legacy Windows console or a dumb
// SSH pty, and this tool needs to survive both.
const CODES = {
  green: 32,
  red: 31,
  yellow: 33,
  cyan: 36,
  dim: 2,
  bold: 1,
};

function wrap(code) {
  return (s) => (USE_COLOR ? `\x1b[${code}m${s}\x1b[0m` : String(s));
}

export const color = {
  green: wrap(CODES.green),
  red: wrap(CODES.red),
  yellow: wrap(CODES.yellow),
  cyan: wrap(CODES.cyan),
  dim: wrap(CODES.dim),
  bold: wrap(CODES.bold),
};

// Matches any SGR escape sequence. Needed everywhere we measure a string
// someone might have already colourised, because the escape bytes are not
// visible columns and padding against their raw length draws a crooked box.
const ANSI_RE = /\x1b\[[0-9;]*m/g;

function stripAnsi(s) {
  return s.replace(ANSI_RE, '');
}

function visibleWidth(s) {
  return stripAnsi(s).length;
}

// Splits a string into a flat list where each entry is either one escape
// sequence (zero visible columns) or one visible character. Truncating by raw
// string index would cut an escape in half and spray the rest of the sequence
// across the terminal as literal text.
function ansiTokens(s) {
  const out = [];
  const re = new RegExp(ANSI_RE.source, 'g');
  let i = 0;
  let m;
  while ((m = re.exec(s)) !== null) {
    for (const ch of s.slice(i, m.index)) out.push({ esc: false, t: ch });
    out.push({ esc: true, t: m[0] });
    i = m.index + m[0].length;
  }
  for (const ch of s.slice(i)) out.push({ esc: false, t: ch });
  return out;
}

const ELLIPSIS = '...';

// Drops characters out of the middle rather than the end. Every line we box is
// a short label followed by a long value, and for a filesystem path the two
// parts worth keeping are the label at the front and the filename at the back.
// Chopping the tail would leave "identity  C:\Users\you\AppData\Local\Te",
// which names no file the reader can act on.
export function ellipsize(s, budget) {
  const text = String(s);
  if (budget < ELLIPSIS.length + 2) return text;
  if (visibleWidth(text) <= budget) return text;

  const toks = ansiTokens(text);
  const keep = budget - ELLIPSIS.length;
  const headWidth = Math.ceil(keep / 2);
  const tailWidth = keep - headWidth;

  const head = [];
  let seen = 0;
  let coloured = false;
  for (const tok of toks) {
    if (tok.esc) { head.push(tok.t); coloured = true; continue; }
    if (seen >= headWidth) break;
    head.push(tok.t);
    seen++;
  }

  const tail = [];
  seen = 0;
  for (let i = toks.length - 1; i >= 0; i--) {
    const tok = toks[i];
    if (tok.esc) { tail.unshift(tok.t); coloured = true; continue; }
    if (seen >= tailWidth) break;
    tail.unshift(tok.t);
    seen++;
  }

  // Escapes from the dropped middle are gone, so an opener kept in the head can
  // outlive its reset. Close explicitly rather than bleed colour down the page.
  const reset = coloured ? '\x1b[0m' : '';
  return head.join('') + reset + ELLIPSIS + tail.join('');
}

// Boxes are drawn to the terminal, so the terminal decides how wide they get.
// Capped at 100 because a full width box on an ultrawide monitor is a worse
// read than a narrow one, and floored at 80 when stdout is a pipe or a file,
// where there is no width to ask about.
function terminalWidth() {
  const c = process.stdout.columns;
  if (Number.isInteger(c) && c >= 40) return Math.min(c, 100);
  return 80;
}

// Base 1000, not 1024: this sits next to throughputMBs, which is already
// decimal megabytes, and mixing bases in the same table is how you get a
// support ticket asking why the percentages don't add up.
const BYTE_UNITS = ['B', 'kB', 'MB', 'GB', 'TB', 'PB'];

export function humanBytes(n) {
  const v = Number(n);
  if (!Number.isFinite(v) || v === 0) return '0 B';
  const sign = v < 0 ? '-' : '';
  let abs = Math.abs(v);
  if (abs < 1000) return `${sign}${Math.round(abs)} B`;
  let unit = 0;
  while (abs >= 1000 && unit < BYTE_UNITS.length - 1) {
    abs /= 1000;
    unit++;
  }
  return `${sign}${abs.toFixed(1)} ${BYTE_UNITS[unit]}`;
}

// Three regimes because one fixed decimal count is wrong at both ends: a
// sub-millisecond crypto op needs precision to look like anything other than
// "0 ms", and a multi-second transfer does not need fifteen digits of noise.
export function humanMs(ms) {
  const v = Number(ms);
  if (!Number.isFinite(v)) return '0 ms';
  const abs = Math.abs(v);
  if (abs < 1) return `${v.toFixed(2)} ms`;
  if (abs < 1000) return `${Math.round(v)} ms`;
  return `${(v / 1000).toFixed(1)} s`;
}

export function statsTable(stats, { direction } = {}) {
  const verb = direction === 'received' ? 'received' : 'sent';
  const overheadBytes = stats.wireBytes - stats.plainBytes;
  const overheadPct = stats.plainBytes > 0 ? (overheadBytes / stats.plainBytes) * 100 : 0;

  const rows = [
    [`Plaintext ${verb}`, humanBytes(stats.plainBytes)],
    ['On the wire', humanBytes(stats.wireBytes)],
    ['Overhead', `${humanBytes(overheadBytes)} (${overheadPct.toFixed(1)}%)`],
    ['Chunks', `${stats.chunks} x ${humanBytes(stats.chunkSize)}`],
    ['Handshake', humanMs(stats.handshakeMs)],
    ['Crypto', humanMs(stats.cryptoMs)],
    // A 0.2.x stats object has no backend field, so the row disappears
    // instead of printing undefined.
    ...(stats.backend ? [['AEAD backend', String(stats.backend)]] : []),
    ['Wall time', humanMs(stats.wallMs)],
    ['Throughput', color.cyan(`${stats.throughputMBs.toFixed(2)} MB/s`)],
    ['SHA-256', color.dim(String(stats.sha256).slice(0, 16))],
  ];

  const labelWidth = Math.max(...rows.map(([label]) => label.length));
  const valueWidth = Math.max(...rows.map(([, value]) => visibleWidth(value)));

  return rows
    .map(([label, value]) => {
      const labelPad = ' '.repeat(labelWidth - label.length);
      const valuePad = ' '.repeat(valueWidth - visibleWidth(value));
      return `${label}${labelPad}  ${valuePad}${value}`;
    })
    .join('\n');
}

// Six safety words are meant to be read aloud and eyeballed against another
// screen, so they get styling that makes them impossible to skim past.
export function words(str) {
  return String(str)
    .trim()
    .split(/\s+/)
    .map((w) => color.bold(color.cyan(w)))
    .join('  ');
}

const BAR_WIDTH = 24;

export function progressLine({ done, total, label }) {
  const t = Number(total) > 0 ? Number(total) : 0;
  const d = Math.max(0, Math.min(Number(done) || 0, t || Number(done) || 0));
  const pct = t > 0 ? d / t : 0;
  const filled = Math.round(pct * BAR_WIDTH);
  const bar = `[${'='.repeat(filled)}${' '.repeat(BAR_WIDTH - filled)}]`;
  const pctStr = `${Math.round(pct * 100)}%`.padStart(4);
  const sizes = `${humanBytes(d)}/${humanBytes(t)}`;

  // 78 columns total, fixed parts first, whatever is left goes to the label
  // and gets clipped rather than let a long payload name wrap the line.
  const fixed = `${bar} ${pctStr} ${sizes}`;
  if (!label) return fixed.slice(0, 78);

  const budget = 78 - fixed.length - 1; // 1 for the separating space
  if (budget <= 0) return fixed.slice(0, 78);
  const clipped = label.length > budget ? `${label.slice(0, Math.max(0, budget - 1))}…` : label;
  return `${fixed} ${clipped}`.slice(0, 78);
}

export function box(title, lines) {
  // Two border columns each side, so this is what a body line may occupy. The
  // title sits inside "|- " and " -", two columns more than a body line, so it
  // gets the tighter budget or a long title pushes the box past the terminal.
  const budget = terminalWidth() - 4;
  const titleText = ellipsize(title, budget - 2);
  const bodyLines = lines.map((l) => ellipsize(l, budget));

  const inner = Math.max(visibleWidth(titleText), ...bodyLines.map(visibleWidth), 0);
  // Room for "- title -" on the top edge plus at least one trailing dash,
  // in addition to whatever the body already needs.
  const contentWidth = Math.max(inner + 2, visibleWidth(titleText) + 4);

  const dashCount = Math.max(contentWidth - 3 - visibleWidth(titleText), 0);
  const top = `┌─ ${titleText} ${'─'.repeat(dashCount)}┐`;
  const bottom = `└${'─'.repeat(contentWidth)}┘`;
  const body = bodyLines.map((l) => {
    const pad = ' '.repeat(contentWidth - 2 - visibleWidth(l));
    return `│ ${l}${pad} │`;
  });

  return [top, ...body, bottom].join('\n');
}
