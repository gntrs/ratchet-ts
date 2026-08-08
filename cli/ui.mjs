/**
 * The chat screen, as a pure function.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS FILE HAS NO I/O IN IT
 * ---------------------------------------------------------------------------
 *
 * renderFrame(state, { cols, rows }) takes a plain object and hands back an
 * array of strings, one per terminal row. It never writes, never reads a
 * terminal size, never looks at the clock and never asks whether stdout is a
 * tty. Everything that has to know about a real terminal lives in
 * cli/chat.mjs, on the other side of that seam.
 *
 * That split is the whole reason this file exists as its own module. A TUI
 * that paints as it thinks can only be checked by a human staring at it, and
 * the screens that matter most here are the ones a human almost never sees:
 * the changed-key alarm, an authentication failure mid conversation, the same
 * screen with every colour stripped out, the same screen again on a terminal
 * that cannot draw a box. Those are exactly the screens where a rendering bug
 * turns into a security problem, because a warning that is off the bottom of
 * the viewport is a warning that was never shown. As a pure function every one
 * of them is a snapshot in `node --test` with no terminal anywhere in sight.
 * See test/ui.test.mjs.
 *
 * cli/format.mjs is the same idea one level down and says so in its first
 * comment. This is that property extended to the whole screen.
 *
 * ---------------------------------------------------------------------------
 * WHAT IT WILL NOT DO
 * ---------------------------------------------------------------------------
 *
 * No diffing. A full repaint at 80x24 is 1920 cells, about 4 kB once escapes
 * are counted, and at 30 frames a second that is 120 kB/s into a local pty.
 * A diffing renderer would save most of that and cost a second model of the
 * screen that can disagree with the first one, which is the class of bug that
 * leaves half an alarm on screen.
 *
 * No colour as the only signal. Every state that means something also carries
 * a glyph and a word, so NO_COLOR loses styling and loses no information.
 * Blue and magenta are absent on purpose: they are the two ANSI colours that
 * routinely come out unreadable on a dark background.
 *
 * No emoji. Their width is a guess on Windows, and a guess in a layout is a
 * broken box.
 */

// ---------------------------------------------------------------------------
// MEASUREMENT
// ---------------------------------------------------------------------------

/**
 * A local copy of the escape matcher, deliberately.
 *
 * cli/format.mjs has one, and it does not export it, or ansiTokens, or
 * visibleWidth. Nothing in this file may edit that module, so the choice was
 * between duplicating five lines and doing without. It duplicates them, and it
 * would have had to anyway: format.visibleWidth measures in JavaScript string
 * length, which is right for the ASCII banners that module draws and wrong for
 * a transcript that a human can paste anything into. Everything below counts
 * terminal cells, so `CJK` costs two and a combining accent costs nothing.
 */
const ANSI_RE = /\x1b\[[0-9;]*m/g;

export function stripAnsi(s) {
  return String(s).replace(new RegExp(ANSI_RE.source, 'g'), '');
}

/**
 * Code points that occupy no column at all: combining marks that stack onto
 * the character before them, and the format characters that steer bidi or
 * join emoji together.
 *
 * Ranges are half of an honest wcwidth and no more. The combining marks of the
 * Indic and South East Asian scripts are NOT here, so Devanagari, Bengali,
 * Tamil, Thai and Khmer text measures wider than it draws. That is the wrong
 * direction to be wrong in but it is the safe one: over-measuring wraps a line
 * early, under-measuring runs it off the right edge and corrupts every row
 * below. Adding those blocks is a contained change, and it is a change that
 * has to be made from a real Unicode data file rather than from memory.
 */
const ZERO_WIDTH = [
  [0x0300, 0x036f], // combining diacritical marks
  [0x0483, 0x0489], // combining Cyrillic
  [0x0591, 0x05bd], // Hebrew points
  [0x05bf, 0x05bf],
  [0x05c1, 0x05c2],
  [0x05c4, 0x05c5],
  [0x05c7, 0x05c7],
  [0x0610, 0x061a], // Arabic marks
  [0x064b, 0x065f],
  [0x0670, 0x0670],
  [0x06d6, 0x06dc],
  [0x06df, 0x06e4],
  [0x06e7, 0x06e8],
  [0x06ea, 0x06ed],
  [0x0711, 0x0711], // Syriac
  [0x0730, 0x074a],
  [0x07a6, 0x07b0], // Thaana
  [0x07eb, 0x07f3], // NKo
  [0x0816, 0x082d], // Samaritan
  [0x0859, 0x085b], // Mandaic
  [0x135d, 0x135f], // Ethiopic
  [0x1ab0, 0x1aff], // combining diacritical marks extended
  [0x1dc0, 0x1dff], // combining diacritical marks supplement
  [0x200b, 0x200f], // zero width space, ZWNJ, ZWJ, LRM, RLM
  [0x202a, 0x202e], // bidi embedding and override
  [0x2060, 0x2064], // word joiner and the invisible operators
  [0x206a, 0x206f], // deprecated format characters
  [0x20d0, 0x20f0], // combining marks for symbols
  [0xfe00, 0xfe0f], // variation selectors
  [0xfe20, 0xfe2f], // combining half marks
  [0xfeff, 0xfeff], // byte order mark
  [0xfff9, 0xfffb], // interlinear annotation
  [0x1d167, 0x1d169], // musical symbol combining marks
  [0x1d17b, 0x1d182],
  [0x1d185, 0x1d18b],
  [0x1d1aa, 0x1d1ad],
  [0xe0001, 0xe0001], // language tag
  [0xe0020, 0xe007f], // tag characters, the tail of a flag sequence
  [0xe0100, 0xe01ef], // variation selectors supplement
];

/**
 * Code points a terminal draws two columns wide: the East Asian Wide and
 * Fullwidth classes, plus the emoji that Unicode gave Wide status when it
 * folded them into the standard.
 *
 * The known error is emoji sequences rather than emoji characters. A family
 * built out of four people joined by zero width joiners is one glyph on a
 * modern terminal and measures as four here, and a flag written as two
 * regional indicators measures as four columns rather than two. Both
 * over-measure, which wraps early instead of running off the edge, and both
 * are the reason the header above says no emoji in the chrome: the chrome has
 * to be exact, the transcript only has to be safe.
 */
const WIDE = [
  [0x1100, 0x115f], // Hangul Jamo initial consonants
  [0x231a, 0x231b],
  [0x2329, 0x232a],
  [0x23e9, 0x23ec],
  [0x23f0, 0x23f0],
  [0x23f3, 0x23f3],
  [0x25fd, 0x25fe],
  [0x2614, 0x2615],
  [0x2648, 0x2653],
  [0x267f, 0x267f],
  [0x2693, 0x2693],
  [0x26a1, 0x26a1],
  [0x26aa, 0x26ab],
  [0x26bd, 0x26be],
  [0x26c4, 0x26c5],
  [0x26ce, 0x26ce],
  [0x26d4, 0x26d4],
  [0x26ea, 0x26ea],
  [0x26f2, 0x26f3],
  [0x26f5, 0x26f5],
  [0x26fa, 0x26fa],
  [0x26fd, 0x26fd],
  [0x2705, 0x2705],
  [0x270a, 0x270b],
  [0x2728, 0x2728],
  [0x274c, 0x274c],
  [0x274e, 0x274e],
  [0x2753, 0x2755],
  [0x2757, 0x2757],
  [0x2795, 0x2797],
  [0x27b0, 0x27b0],
  [0x27bf, 0x27bf],
  [0x2b1b, 0x2b1c],
  [0x2b50, 0x2b50],
  [0x2b55, 0x2b55],
  [0x2e80, 0x2e99], // CJK radicals
  [0x2e9b, 0x2ef3],
  [0x2f00, 0x2fd5], // Kangxi radicals
  [0x2ff0, 0x2ffb], // ideographic description
  [0x3000, 0x303e], // CJK symbols and punctuation
  [0x3041, 0x3096], // Hiragana
  [0x3099, 0x30ff], // Katakana
  [0x3105, 0x312f], // Bopomofo
  [0x3131, 0x318e], // Hangul compatibility Jamo
  [0x3190, 0x31e3],
  [0x31f0, 0x321e],
  [0x3220, 0x3247],
  [0x3250, 0x4dbf],
  [0x4e00, 0xa48c], // CJK unified ideographs
  [0xa490, 0xa4c6],
  [0xa960, 0xa97c], // Hangul Jamo extended A
  [0xac00, 0xd7a3], // Hangul syllables
  [0xf900, 0xfaff], // CJK compatibility ideographs
  [0xfe10, 0xfe19], // vertical forms
  [0xfe30, 0xfe52], // CJK compatibility forms
  [0xfe54, 0xfe66],
  [0xfe68, 0xfe6b],
  [0xff01, 0xff60], // fullwidth forms
  [0xffe0, 0xffe6],
  [0x16fe0, 0x16fe4],
  [0x17000, 0x187f7], // Tangut
  [0x18800, 0x18cd5],
  [0x1b000, 0x1b152], // Kana supplement
  [0x1b164, 0x1b167],
  [0x1b170, 0x1b2fb], // Nushu
  [0x1f004, 0x1f004],
  [0x1f0cf, 0x1f0cf],
  [0x1f18e, 0x1f18e],
  [0x1f191, 0x1f19a],
  [0x1f200, 0x1f320],
  [0x1f32d, 0x1f335],
  [0x1f337, 0x1f37c],
  [0x1f37e, 0x1f393],
  [0x1f3a0, 0x1f3ca],
  [0x1f3cf, 0x1f3d3],
  [0x1f3e0, 0x1f3f0],
  [0x1f3f4, 0x1f3f4],
  [0x1f3f8, 0x1f43e],
  [0x1f440, 0x1f440],
  [0x1f442, 0x1f4fc],
  [0x1f4ff, 0x1f53d],
  [0x1f54b, 0x1f54e],
  [0x1f550, 0x1f567],
  [0x1f57a, 0x1f57a],
  [0x1f595, 0x1f596],
  [0x1f5a4, 0x1f5a4],
  [0x1f5fb, 0x1f64f],
  [0x1f680, 0x1f6c5],
  [0x1f6cc, 0x1f6cc],
  [0x1f6d0, 0x1f6d2],
  [0x1f6d5, 0x1f6d7],
  [0x1f6eb, 0x1f6ec],
  [0x1f6f4, 0x1f6fc],
  [0x1f7e0, 0x1f7eb],
  [0x1f90c, 0x1f93a],
  [0x1f93c, 0x1f945],
  [0x1f947, 0x1f978],
  [0x1f97a, 0x1f9cb],
  [0x1f9cd, 0x1f9ff],
  [0x1fa70, 0x1fa74],
  [0x1fa78, 0x1fa7a],
  [0x1fa80, 0x1fa86],
  [0x1fa90, 0x1faa8],
  [0x1fab0, 0x1fab6],
  [0x1fac0, 0x1fac2],
  [0x1fad0, 0x1fad6],
  [0x20000, 0x2fffd], // CJK extension B and beyond
  [0x30000, 0x3fffd],
];

function inRanges(cp, table) {
  let lo = 0;
  let hi = table.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (cp < table[mid][0]) hi = mid - 1;
    else if (cp > table[mid][1]) lo = mid + 1;
    else return true;
  }
  return false;
}

/**
 * Columns one code point occupies. Accepts a number or a single character,
 * because half the callers hold one and half hold the other.
 *
 * Control characters are zero rather than one. They should never reach a
 * rendered line, and counting them as a column would mean a stray \r silently
 * shortened every line after it by one cell.
 */
export function charWidth(input) {
  const cp = typeof input === 'number' ? input : String(input).codePointAt(0);
  if (!Number.isInteger(cp) || cp < 0) return 0;
  if (cp === 0) return 0;
  if (cp < 32) return 0;
  if (cp >= 0x7f && cp < 0xa0) return 0;
  if (inRanges(cp, ZERO_WIDTH)) return 0;
  if (inRanges(cp, WIDE)) return 2;
  return 1;
}

/** Terminal cells a string occupies, escape sequences counted as nothing. */
export function stringWidth(s) {
  let total = 0;
  for (const ch of stripAnsi(s)) total += charWidth(ch.codePointAt(0));
  return total;
}

/**
 * Splits into a flat list where each entry is one escape sequence or one
 * visible character with its width already measured. Cutting a string by
 * JavaScript index would slice an escape in half and spray the remainder
 * across the screen as literal text.
 */
function tokens(s) {
  const out = [];
  const re = new RegExp(ANSI_RE.source, 'g');
  const text = String(s);
  let i = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    for (const ch of text.slice(i, m.index)) out.push({ esc: false, t: ch, w: charWidth(ch.codePointAt(0)) });
    out.push({ esc: true, t: m[0], w: 0 });
    i = m.index + m[0].length;
  }
  for (const ch of text.slice(i)) out.push({ esc: false, t: ch, w: charWidth(ch.codePointAt(0)) });
  return out;
}

/**
 * Cuts from the END at a cell budget, which is the opposite of what
 * format.ellipsize does and right for a different job. That one truncates a
 * label-plus-path, where the front and the back are the useful halves. These
 * are chrome rows where the left is the content and the right is padding, and
 * a middle ellipsis in a title bar reads as damage.
 */
export function clip(s, budget) {
  if (budget <= 0) return '';
  if (stringWidth(s) <= budget) return String(s);
  let out = '';
  let used = 0;
  let coloured = false;
  for (const tok of tokens(s)) {
    if (tok.esc) {
      out += tok.t;
      coloured = true;
      continue;
    }
    if (used + tok.w > budget) break;
    out += tok.t;
    used += tok.w;
  }
  // An opener that survived the cut has lost its reset along with the tail, so
  // close it here or the colour bleeds down the rest of the screen.
  return coloured ? `${out}\x1b[0m` : out;
}

/** Clip to width, then pad with spaces to exactly that width. */
export function pad(s, width) {
  if (width <= 0) return '';
  const cut = clip(s, width);
  return cut + ' '.repeat(Math.max(0, width - stringWidth(cut)));
}

/** Left content, right content, one row, right edge flush. Right wins ties. */
function joinLR(left, right, cols) {
  if (cols <= 0) return '';
  const rightCut = clip(right, cols);
  const rightWidth = stringWidth(rightCut);
  const leftBudget = Math.max(0, cols - rightWidth - 1);
  const leftCut = clip(left, leftBudget);
  const gap = cols - stringWidth(leftCut) - rightWidth;
  return leftCut + ' '.repeat(Math.max(0, gap)) + rightCut;
}

/**
 * Greedy wrap at a cell budget. Splits on spaces, and hard breaks any single
 * run that is wider than the budget, because a pasted 300 character URL has no
 * space in it and must not be allowed to run off the edge.
 *
 * Input is plain text, not styled text. Everything wrapped here is either
 * something a human typed or a sentence this file wrote, and styling is
 * applied to whole rows afterwards.
 */
export function wrapText(text, width) {
  if (width <= 0) return [''];
  const out = [];
  for (const para of String(text).split('\n')) {
    let line = '';
    let used = 0;
    const flush = () => {
      out.push(line);
      line = '';
      used = 0;
    };
    for (const word of para.split(' ')) {
      const w = stringWidth(word);
      if (w > width) {
        // Longer than a whole row on its own. Fill the current row, then take
        // full rows off the front until what is left fits.
        if (used > 0) flush();
        let chunk = '';
        let chunkWidth = 0;
        for (const ch of word) {
          const cw = charWidth(ch.codePointAt(0));
          if (chunkWidth + cw > width) {
            out.push(chunk);
            chunk = '';
            chunkWidth = 0;
          }
          chunk += ch;
          chunkWidth += cw;
        }
        line = chunk;
        used = chunkWidth;
        continue;
      }
      if (used === 0) {
        line = word;
        used = w;
        continue;
      }
      if (used + 1 + w > width) {
        flush();
        line = word;
        used = w;
        continue;
      }
      line += ` ${word}`;
      used += 1 + w;
    }
    out.push(line);
  }
  return out;
}

// ---------------------------------------------------------------------------
// STYLE
// ---------------------------------------------------------------------------

/**
 * The same six 16-colour codes cli/format.mjs uses, and no seventh.
 *
 * This does not import format.color, and the reason is the whole point of the
 * file. That one decides once at module load from process.stdout.isTTY, which
 * is correct for a command that prints and exits and useless for a renderer
 * that has to be able to produce both the coloured and the uncoloured frame
 * inside one test process. Colour here is an argument, never an environment.
 */
function styler(useColor) {
  const on = Boolean(useColor);
  const sgr = (codes) => (s) => (on ? `\x1b[${codes}m${s}\x1b[0m` : String(s));
  return {
    on,
    plain: (s) => String(s),
    green: sgr('32'),
    red: sgr('31'),
    yellow: sgr('33'),
    cyan: sgr('36'),
    dim: sgr('2'),
    bold: sgr('1'),
    // One combined SGR rather than a nested pair. Nesting closes both
    // attributes at the inner reset, which happens to look right and stops
    // looking right the moment anything is appended inside the outer wrap.
    boldRed: sgr('1;31'),
    boldCyan: sgr('1;36'),
  };
}

/**
 * The six safety words, styled the way cli/format.words styles them, because
 * they have to look identical to the pair printed above the alt screen a
 * second earlier. Reimplemented rather than imported for the colour-gate
 * reason above. They are the only thing on screen that gets both bold and a
 * colour, and that is deliberate: they are the only thing on screen the user
 * has a job to do about.
 */
export function safetyWords(str, st) {
  return String(str)
    .trim()
    .split(/\s+/)
    .filter((w) => w.length > 0)
    .map((w) => st.boldCyan(w))
    .join('  ');
}

// ---------------------------------------------------------------------------
// GLYPHS
// ---------------------------------------------------------------------------

/**
 * Two tables, one lookup. RATCHET_ASCII=1 or a console that cannot render box
 * drawing gets the second, and nothing else about the layout changes: every
 * glyph below is one column wide in both tables except the verified badge,
 * and every row is measured rather than counted, so the wider badge simply
 * takes more of the title bar.
 */
const UNICODE_GLYPHS = {
  h: '─',
  v: '│',
  tl: '┌',
  tr: '┐',
  bl: '└',
  br: '┘',
  sep: '·',
  ok: '✓',
  prompt: '>',
  down: 'v',
};

const ASCII_GLYPHS = {
  h: '-',
  v: '|',
  tl: '+',
  tr: '+',
  bl: '+',
  br: '+',
  sep: '.',
  ok: '[ok]',
  prompt: '>',
  down: 'v',
};

export function glyphs(ascii) {
  return ascii ? ASCII_GLYPHS : UNICODE_GLYPHS;
}

// ---------------------------------------------------------------------------
// COMMANDS
// ---------------------------------------------------------------------------

/**
 * One list, read by the completer, the footer and /help alike. A second copy
 * would be a second copy that drifts, and the visible symptom of that drift is
 * a command in the footer that the parser has never heard of.
 */
export const COMMANDS = [
  { name: '/verify', desc: 'compare the six words aloud and record this peer' },
  { name: '/peer', desc: 'who is on the other end, and since when' },
  { name: '/words', desc: 'reprint both fingerprint lines into the transcript' },
  { name: '/stats', desc: 'counts and timings for this session' },
  { name: '/help', desc: 'keys and commands' },
  { name: '/quit', desc: 'say goodbye and leave' },
];

/** Only offered while a changed key is on screen. It is never a normal move. */
export const TRUST_COMMAND = { name: '/trust new', desc: 'accept the new key as unverified and carry on' };

/**
 * The only commands an alarm accepts. `/trust new` belongs to the key change
 * and to nothing else: offering it on a version skew would suggest there is a
 * key there to trust, and there is not.
 */
function alarmCommands(alarm) {
  const quit = COMMANDS[COMMANDS.length - 1];
  const kind = typeof alarm === 'string' ? alarm : (alarm && alarm.kind) || '';
  return kind === 'changed' ? [TRUST_COMMAND, quit] : [quit];
}

export function completionsFor(line, { alarm } = {}) {
  const text = String(line ?? '');
  if (!text.startsWith('/')) return [];
  const pool = alarm ? alarmCommands(alarm) : COMMANDS;
  const q = text.toLowerCase();
  return pool.filter((c) => c.name.startsWith(q));
}

// ---------------------------------------------------------------------------
// STATE
// ---------------------------------------------------------------------------

/**
 * The complete argument to renderFrame. Everything the screen shows is in
 * here, and nothing in here is derived from a clock, a socket or a terminal:
 * the caller resolves all three before it renders. `quietSeconds` is a plain
 * number rather than a timestamp for exactly that reason: a renderer that read
 * Date.now() could not be snapshotted.
 */
export function blankState() {
  return {
    peerAddress: '',
    trust: { state: 'new', label: null, shortHex: '', words: '', conflict: null },
    sessionWords: '',
    peerWords: '',
    link: { state: 'live', pq: false, quietSeconds: 0 },
    transcript: [],
    scroll: 0,
    unseen: 0,
    input: { line: '', cursor: 0, enabled: true, placeholder: 'message, / for commands' },
    completion: null,
    modal: null,
    alarm: null,
    color: true,
    ascii: false,
  };
}

function normalise(state) {
  const base = blankState();
  const s = state ?? {};
  return {
    ...base,
    ...s,
    trust: { ...base.trust, ...(s.trust ?? {}) },
    link: { ...base.link, ...(s.link ?? {}) },
    input: { ...base.input, ...(s.input ?? {}) },
    transcript: Array.isArray(s.transcript) ? s.transcript : [],
  };
}

// ---------------------------------------------------------------------------
// LAYOUT
// ---------------------------------------------------------------------------

const WHO_FIELD = {
  // `you ` carries a trailing space so its four columns line up against `them`.
  // The field is what carries severity when colour is off, so it is fixed
  // width and never abbreviated.
  you: { text: 'you ', tone: 'cyan', body: 'plain' },
  them: { text: 'them', tone: 'yellow', body: 'plain' },
  note: { text: ' .. ', tone: 'dim', body: 'dim' },
  warn: { text: ' !  ', tone: 'yellow', body: 'plain' },
  alarm: { text: ' !! ', tone: 'boldRed', body: 'plain' },
};

// ' HH:MM  who   ' : one space, five for the stamp, two, four for the field,
// two more. Continuation rows hang indent to the same column.
const GUTTER = 14;

const INPUT_ROWS = 3;
const STRIP_ROWS = 2;
export const MAX_COMPLETION_ROWS = 5;

function wantsStrip(s) {
  if (s.modal || s.alarm) return false;
  return s.trust.state !== 'verified';
}

function completionRowsFor(s) {
  if (s.modal || !s.completion || !Array.isArray(s.completion.items)) return 0;
  return Math.min(s.completion.items.length, MAX_COMPLETION_ROWS);
}

/**
 * Rows for every region, resolved against a real terminal height.
 *
 * The arithmetic in the design note is `rows - 1 - 1 - 1 - strip - 3 -
 * completion - 1`, which is right until somebody drags a window down to eight
 * rows and it goes negative. So regions are shed in a fixed order instead,
 * cheapest information first: the footer is a reminder, the completion popup
 * is a convenience, the strip is a duplicate of the badge that is still in the
 * title bar. The input box loses its border before it loses its row, and the
 * title bar is last out because the verification badge lives in it.
 *
 * Exported because the caller needs the same numbers to place the hardware
 * cursor, and two implementations of this would put the cursor in the wrong
 * row on exactly the terminal sizes nobody tests.
 */
export function layout(state, { cols, rows }) {
  const s = normalise(state);
  const height = Math.max(1, Math.floor(rows) || 1);
  const width = Math.max(1, Math.floor(cols) || 1);

  const plan = {
    title: 1,
    ruleTop: 1,
    content: 0,
    ruleBottom: 1,
    strip: wantsStrip(s) ? STRIP_ROWS : 0,
    completion: completionRowsFor(s),
    input: INPUT_ROWS,
    footer: 1,
    cols: width,
    rows: height,
  };

  const fixed = () =>
    plan.title + plan.ruleTop + plan.ruleBottom + plan.strip + plan.completion + plan.input + plan.footer;

  // Content wants at least one row. Shed until it can have one.
  const shed = [
    () => {
      if (plan.footer === 0) return false;
      plan.footer = 0;
      return true;
    },
    () => {
      if (plan.completion === 0) return false;
      plan.completion = 0;
      return true;
    },
    () => {
      if (plan.strip === 0) return false;
      plan.strip = 0;
      return true;
    },
    () => {
      if (plan.ruleBottom === 0) return false;
      plan.ruleBottom = 0;
      return true;
    },
    () => {
      if (plan.ruleTop === 0) return false;
      plan.ruleTop = 0;
      return true;
    },
    () => {
      if (plan.input <= 1) return false;
      plan.input = 1;
      return true;
    },
    () => {
      if (plan.title === 0) return false;
      plan.title = 0;
      return true;
    },
    () => {
      if (plan.input === 0) return false;
      plan.input = 0;
      return true;
    },
  ];

  let i = 0;
  while (height - fixed() < 1 && i < shed.length) {
    if (!shed[i]()) i += 1;
  }
  plan.content = Math.max(0, height - fixed());
  return plan;
}

// ---------------------------------------------------------------------------
// REGIONS
// ---------------------------------------------------------------------------

function badge(s, st, g) {
  if (s.trust.state === 'changed') return st.boldRed('!! key changed');
  if (s.trust.state === 'verified') {
    const name = s.trust.label ? ` "${s.trust.label}"` : '';
    return st.green(`${g.ok} verified${name}`);
  }
  return st.yellow('! unverified');
}

/**
 * One token, bottom right of the title bar. Post quantum is decided in the
 * handshake and cannot change afterwards, so it is two words in a corner
 * rather than anything that asks for attention. The three link states are
 * three different words, which is what keeps them apart with colour off.
 */
/**
 * The one connection token, bottom right of the title bar.
 *
 * There are only three honest states here. `pq live` and `closed` are facts the
 * process knows. The middle one is NOT a health check and must not pretend to
 * be: this wire has no keepalive, so a socket with nothing on it looks exactly
 * like a person who has not typed for a while, and there is no way to tell them
 * apart without adding a frame. So it says `quiet 4m`, which is true either
 * way, and it says it in dim rather than yellow, because a quiet chat is the
 * normal case and a yellow corner that lights up every time both people stop
 * typing is a warning nobody will read twice.
 */
function linkToken(s, st) {
  if (s.link.state === 'closed') return st.red('closed');
  if (s.link.state === 'quiet') return st.dim(`quiet ${quietFor(s.link.quietSeconds)}`);
  return st.green(s.link.pq ? 'pq live' : 'live');
}

function quietFor(seconds) {
  const n = Math.max(0, Math.round(Number(seconds) || 0));
  if (n < 60) return `${n}s`;
  if (n < 3600) return `${Math.floor(n / 60)}m`;
  return `${Math.floor(n / 3600)}h`;
}

function titleBar(s, st, g, cols) {
  const sep = st.dim(`  ${g.sep}  `);
  const name = ' ratchet chat';
  const withAddress = s.peerAddress ? `${name}${sep}${s.peerAddress}` : name;
  const right = `${badge(s, st, g)}${sep}${linkToken(s, st)} `;

  // The badge is the one thing in this row that must never be dropped, so on a
  // terminal too narrow for both it survives alone.
  if (stringWidth(right) + 4 > cols) return pad(clip(right, cols), cols);

  // The address goes whole or not at all. Half of 192.168.1.24:4477 is an
  // address nobody can act on, and this CLI already has a house rule against
  // printing one of those. See DESIGN-CLI.md.
  const room = cols - stringWidth(right) - 1;
  const left = stringWidth(withAddress) <= room ? withAddress : name;
  return joinLR(left, right, cols);
}

function rule(st, g, cols) {
  return st.dim(g.h.repeat(Math.max(0, cols)));
}

/**
 * Every transcript entry, wrapped, oldest first. The whole list is rebuilt
 * each frame rather than cached against the last width, because the only
 * thing that invalidates a cache here is a resize and a resize is exactly when
 * a stale cache paints a wrong screen.
 */
export function transcriptRows(s, st, cols) {
  const textWidth = Math.max(1, cols - GUTTER);
  const rows = [];
  for (const entry of s.transcript) {
    const field = WHO_FIELD[entry.who] ?? WHO_FIELD.note;
    const tone = st[field.tone] ?? st.plain;
    const bodyTone = field.body === 'dim' ? st.dim : st.plain;
    const stamp = entry.at ? String(entry.at) : '     ';
    const wrapped = wrapText(entry.text ?? '', textWidth);
    // `cont` is how a block that was one call at the top (a stats table, the
    // help) keeps one stamp and one speaker field for the whole block instead
    // of repeating both down the left edge, which reads as ten separate events.
    const head = entry.cont
      ? ' '.repeat(GUTTER)
      : ` ${st.dim(pad(stamp, 5))}  ${tone(field.text)}  `;
    wrapped.forEach((part, idx) => {
      rows.push(`${idx === 0 ? head : ' '.repeat(GUTTER)}${bodyTone(part)}`);
    });
  }
  return rows;
}

/**
 * Rows the whole transcript occupies at this width. Style independent, because
 * wrapping is decided by cells and colour costs none, which is what lets the
 * caller ask this question without building a styler for it.
 */
export function transcriptHeight(state, cols) {
  const s = normalise(state);
  const textWidth = Math.max(1, Math.floor(cols) - GUTTER);
  let n = 0;
  for (const entry of s.transcript) n += wrapText(entry.text ?? '', Math.max(1, textWidth)).length;
  return n;
}

/** How far up the transcript can be scrolled at this size. Clamped by callers. */
export function maxScroll(state, { cols, rows }) {
  const plan = layout(state, { cols, rows });
  return Math.max(0, transcriptHeight(state, plan.cols) - plan.content);
}

function windowOf(rows, height, scroll) {
  if (height <= 0) return [];
  const top = Math.max(0, rows.length - height - Math.max(0, scroll));
  const slice = rows.slice(top, top + height);
  // Newest at the bottom, so a short transcript is padded above rather than
  // below. A log that starts at the top and grows down would move every line
  // on every message, which is unreadable in a live conversation.
  while (slice.length < height) slice.unshift('');
  return slice;
}

/**
 * Two rows above the input box while the peer is unverified, and zero rows the
 * moment it is. It is the only part of the chrome that grows, and it grows
 * exactly where a user who has not done their one job will be looking.
 *
 * The six words are never clipped. Everything else in this file gets cut to
 * fit; a safety word cut in half is worse than useless because it still looks
 * like a word and it will still get read aloud. When the row is too narrow to
 * carry the label and the words together, the label shrinks and the words move
 * to the second row on their own.
 */
function verificationStrip(s, st, cols) {
  const words = safetyWords(s.sessionWords || 'no words', st);
  const wide = ` ${st.yellow('!')} ${st.dim('compare aloud')}   ${words}`;
  const hint = st.dim('read these six words to the other person out loud. /verify when they match.');
  if (stringWidth(wide) <= cols && stringWidth(`   ${hint}`) <= cols) {
    return [pad(wide, cols), pad(`   ${hint}`, cols)];
  }
  return [pad(` ${st.yellow('!')} ${st.dim('compare aloud, then /verify')}`, cols), pad(`   ${words}`, cols)];
}

function inputRows(s, st, g, cols, height) {
  const inner = Math.max(1, cols - 4);
  const prompt = `${g.prompt} `;
  const promptWidth = stringWidth(prompt);
  const room = Math.max(1, inner - promptWidth);

  let body;
  if (!s.input.enabled) {
    body = st.dim(clip(s.input.placeholder || 'input is disabled', room));
  } else if (s.input.line.length === 0) {
    body = st.dim(clip(s.input.placeholder || '', room));
  } else {
    body = clip(visibleWindow(s.input.line, s.input.cursor, room).text, room);
  }

  const line = `${st.dim(prompt)}${body}`;

  if (height <= 0) return [];
  if (height === 1) return [pad(` ${line}`, cols)];
  const top = st.dim(`${g.tl}${g.h.repeat(Math.max(0, cols - 2))}${g.tr}`);
  const bottom = st.dim(`${g.bl}${g.h.repeat(Math.max(0, cols - 2))}${g.br}`);
  const middle = `${st.dim(g.v)} ${pad(line, inner)} ${st.dim(g.v)}`;
  return [top, middle, bottom].slice(0, height);
}

/**
 * The slice of a long input line that is on screen, chosen so the cursor is
 * always inside it. Scrolls in whole characters and never splits a wide one,
 * because half a CJK glyph is a cell of garbage the terminal will not clean up
 * on its own.
 *
 * Returns the offset it started at as well as the text, because the caller
 * that places the hardware cursor needs to know how much was scrolled off the
 * left edge and recomputing it there is how the two answers drift apart.
 */
function visibleWindow(line, cursor, room) {
  const chars = Array.from(String(line));
  const cur = Math.max(0, Math.min(Number(cursor) || 0, chars.length));
  const widthOf = (from, to) => {
    let w = 0;
    for (let i = from; i < to; i += 1) w += charWidth(chars[i].codePointAt(0));
    return w;
  };
  // One cell is held back so the cursor at the very end of the line has a
  // column of its own to sit in rather than overlapping the last character.
  let start = 0;
  while (start < cur && widthOf(start, cur) > room - 1) start += 1;
  let end = start;
  let used = 0;
  while (end < chars.length) {
    const w = charWidth(chars[end].codePointAt(0));
    if (used + w > room) break;
    used += w;
    end += 1;
  }
  return { text: chars.slice(start, end).join(''), start, cursor: cur, offset: widthOf(start, cur) };
}

/**
 * Where the hardware cursor belongs, one based, so the caller can park it in
 * the input row after painting. Rendering is pure; positioning a real cursor
 * is not, so the two are split here rather than in the middle of a frame.
 */
export function cursorPosition(state, { cols, rows }) {
  const s = normalise(state);
  const g = glyphs(s.ascii);
  const plan = layout(s, { cols, rows });
  // A modal keeps the cursor: the answer to it is typed into the same input
  // box, which is the only caret on screen and has to stay where the eye is.
  if (plan.input === 0 || !s.input.enabled) return null;

  const bordered = plan.input >= INPUT_ROWS;
  const row = plan.rows - plan.footer - plan.input + (bordered ? 2 : 1);
  const inner = Math.max(1, plan.cols - 4);
  const promptWidth = stringWidth(`${g.prompt} `);
  const room = Math.max(1, inner - promptWidth);
  const win = visibleWindow(s.input.line, s.input.cursor, room);

  const base = bordered ? 3 : 2; // border plus a space, or one leading space
  const col = base + promptWidth + Math.min(win.offset, room);
  return { row: Math.max(1, Math.min(row, plan.rows)), col: Math.max(1, Math.min(col, plan.cols)) };
}

function footerRow(s, st, g, cols) {
  const all = (s.alarm ? alarmCommands(s.alarm) : COMMANDS).map((c) => c.name);
  const keys = st.dim('PgUp scroll   Ctrl+C leave ');
  // The unread counter sits with the keys rather than the commands, because it
  // is the only thing in this row that changes, and a changing token in a list
  // of static ones is what the eye finds.
  const right = s.unseen > 0 ? `${st.yellow(`${g.down} ${s.unseen} new`)}   ${keys}` : keys;
  // Commands are dropped whole from the end rather than clipped, because half
  // a command name in a list of commands reads as a command.
  const budget = Math.max(0, cols - stringWidth(stripAnsi(right)) - 1);
  const names = [];
  for (const name of all) {
    const next = [...names, name].join('  ');
    if (stringWidth(next) + 1 > budget) break;
    names.push(name);
  }
  return joinLR(` ${st.dim(names.join('  '))}`, right, cols);
}

function completionRows(s, st, cols, height) {
  if (height <= 0) return [];
  const items = s.completion.items.slice(0, height);
  const index = Math.max(0, Math.min(s.completion.index ?? 0, items.length - 1));
  const nameWidth = Math.max(...items.map((c) => stringWidth(c.name)), 0);
  return items.map((c, i) => {
    const marker = i === index ? st.cyan(g0(s).prompt) : ' ';
    const name = i === index ? st.cyan(pad(c.name, nameWidth)) : pad(c.name, nameWidth);
    return pad(` ${marker} ${name}  ${st.dim(c.desc)}`, cols);
  });
}

function g0(s) {
  return glyphs(s.ascii);
}

// ---------------------------------------------------------------------------
// MODALS AND ALARMS
// ---------------------------------------------------------------------------

/**
 * The verification screen. It takes the whole content region because
 * verification is the one moment in this program where the user has a job, and
 * a job competing with a scrolling transcript is a job that gets skipped.
 *
 * There is no single keystroke in here that confirms anything. cli/chat.mjs
 * has carried that rule since /verify existed and the reasoning is in a
 * comment there: a verification is a human saying they compared six words out
 * loud with another human, and `y` is what a hand does while reading something
 * else. The whole word, typed, or nothing.
 */
function verifyModal(s, st, cols, height) {
  const body = [];
  let group = 0;
  const keep = (line) => body.push({ text: line, optional: false });
  // A paragraph is tagged as one group so that a short window drops all of it
  // rather than its last two rows, which is how a panel ends up displaying a
  // sentence that stops after a comma.
  const prose = (text) => {
    group += 1;
    for (const l of wrapText(text, Math.max(1, cols - 4))) body.push({ text: `  ${l}`, optional: true, group });
  };
  const gap = () => {
    group += 1;
    body.push({ text: '', optional: true, group });
  };

  if (s.modal.step === 'label') {
    gap();
    keep(`  ${st.green('verified.')} ${st.dim('one more thing, and it is optional.')}`);
    gap();
    prose('Give this peer a one word name so the badge in the corner says something you recognise. Press enter on an empty line to skip it.');
    return frameRegion(body, height, cols);
  }

  gap();
  keep(`  ${st.bold('verify this peer')}`);
  gap();
  keep(`  ${st.dim('compare aloud')}   ${safetyWords(s.sessionWords || 'no words', st)}`);
  keep(`  ${st.dim('peer identity')}   ${safetyWords(s.peerWords || 'no words', st)}`);
  gap();
  prose('Read the top line out loud with the other person, on a call or in the same room. Not through this chat: an attacker who can rewrite the keys can rewrite the words too.');
  gap();
  prose('If they read back the SAME six words, nobody is in the middle.');
  gap();
  // The answer is typed into the input box at the bottom, which is where the
  // hardware cursor already is. Echoing it a second time in the panel would put
  // two carets on one screen and leave the reader guessing which one is live.
  keep(`  ${st.dim('type')}  ${st.bold('yes')}  ${st.dim('and press enter to record it. Esc, or anything else, cancels.')}`);
  return frameRegion(body, height, cols);
}

/**
 * The changed key screen, and the crypto alarms that end a session.
 *
 * Two things here are not negotiable. The first is that it says out loud that
 * anything already sent in this session went to the new key: a client that
 * hides that is lying by omission, and the user's next decision depends on it.
 * The second is that nothing dismisses it by accident. The two ways out are
 * both whole commands, typed, and neither of them is a keystroke that a hand
 * resting on a keyboard can produce.
 */
function alarmPanel(s, st, cols, height) {
  const a = s.alarm;
  const inner = Math.max(1, cols - 4);
  const body = [];
  let group = 0;
  const keep = (line) => body.push({ text: line, optional: false });
  const gap = () => {
    group += 1;
    body.push({ text: '', optional: true, group });
  };
  // Same rule as the modal: a paragraph goes whole or not at all.
  const prose = (text) => {
    group += 1;
    for (const l of wrapText(text, inner)) body.push({ text: `  ${l}`, optional: true, group });
  };

  keep(`  ${st.boldRed(`!! ${a.title}`)}`);
  gap();
  for (const block of a.body ?? []) {
    if (block.kind === 'words') {
      keep(`  ${st.dim(block.label)}`);
      keep(`    ${safetyWords(block.words || 'no words recorded', st)}  ${st.dim(block.hex ?? '')}`);
      continue;
    }
    if (block.kind === 'red') {
      // Never optional. This is the sentence that says what already leaked.
      for (const l of wrapText(block.text, inner)) keep(`  ${st.red(l)}`);
      continue;
    }
    if (block.kind === 'blank') {
      gap();
      continue;
    }
    prose(block.text);
  }
  if (a.reason) {
    gap();
    // The machine reason stays on screen because somebody is going to paste it
    // into an issue, and an error you cannot search for is a failure of its own.
    keep(`  ${st.dim(`reason code: ${a.reason}`)}`);
  }
  if (a.actions && a.actions.length > 0) {
    gap();
    keep(`  ${st.dim('type one of these in full:')}`);
    const nameWidth = Math.max(...a.actions.map((act) => stringWidth(act.name)));
    for (const act of a.actions) {
      const oneLine = `    ${st.bold(pad(act.name, nameWidth))}   ${st.dim(act.desc)}`;
      if (stringWidth(oneLine) <= cols) {
        keep(oneLine);
      } else {
        keep(`    ${st.bold(act.name)}`);
        keep(`      ${st.dim(clip(act.desc, Math.max(1, cols - 6)))}`);
      }
    }
  }
  return frameRegion(body, height, cols);
}

/**
 * Fit a panel into a fixed region.
 *
 * Rows arrive tagged optional or not, and when the panel is taller than the
 * region the optional ones go first, from the bottom up. That tagging is the
 * whole point. Every other way of trimming a panel gets the changed-key screen
 * wrong: cutting the tail loses the two commands that are the only way out of
 * it, and cutting the head loses which key was verified and what was already
 * sent to the wrong one. So the explanatory prose and the blank rows are the
 * only things that may go, and the title, the words, the red sentence, the
 * reason code and the commands all stay at any height that can hold them.
 */
function frameRegion(body, height, cols) {
  if (height <= 0) return [];
  const rows = body.slice();
  // Bottom up, and a whole paragraph at a time. Half a paragraph is worse than
  // none of it: it reads as a sentence that was cut off, which is exactly the
  // impression a panel about a key change must not give.
  while (rows.length > height) {
    let last = -1;
    for (let i = rows.length - 1; i >= 0; i -= 1) {
      if (rows[i].optional) { last = i; break; }
    }
    if (last < 0) break;
    const g = rows[last].group;
    let start = last;
    while (start > 0 && rows[start - 1].optional && rows[start - 1].group === g) start -= 1;
    rows.splice(start, last - start + 1);
  }
  // Still too tall even with nothing optional left. Keep the top, where the
  // title and the identity are, and say plainly that the rest is off screen.
  const out = rows.map((r) => pad(r.text, cols));
  if (out.length > height) {
    const cut = out.slice(0, Math.max(0, height - 1));
    cut.push(pad('  ... and more. make this window taller.', cols));
    return cut;
  }
  while (out.length < height) out.push(' '.repeat(cols));
  return out;
}

// ---------------------------------------------------------------------------
// THE FRAME
// ---------------------------------------------------------------------------

/**
 * One screen, as an array of exactly `rows` strings, each at most `cols`
 * terminal cells wide.
 *
 * Pure. No I/O, no clock, no environment. Everything variable is in `state`.
 */
export function renderFrame(state, { cols, rows }) {
  const s = normalise(state);
  const st = styler(s.color);
  const g = glyphs(s.ascii);
  const plan = layout(s, { cols, rows });
  const width = plan.cols;

  const out = [];
  if (plan.title) out.push(titleBar(s, st, g, width));
  if (plan.ruleTop) out.push(rule(st, g, width));

  if (s.modal && s.modal.kind === 'verify') {
    out.push(...verifyModal(s, st, width, plan.content));
  } else if (s.alarm) {
    out.push(...alarmPanel(s, st, width, plan.content));
  } else {
    const all = transcriptRows(s, st, width);
    out.push(...windowOf(all, plan.content, s.scroll).map((l) => pad(l, width)));
  }

  if (plan.ruleBottom) out.push(rule(st, g, width));
  if (plan.strip) out.push(...verificationStrip(s, st, width));
  if (plan.completion) out.push(...completionRows(s, st, width, plan.completion));
  if (plan.input) out.push(...inputRows(s, st, g, width, plan.input));
  if (plan.footer) out.push(footerRow(s, st, g, width));

  // Belt and braces. Every region above already measures itself, and if one of
  // them ever stops doing so the failure has to be a short frame rather than a
  // terminal full of wrapped garbage that survives the process exiting.
  const fixed = out.slice(0, plan.rows).map((l) => clip(l, width));
  while (fixed.length < plan.rows) fixed.push('');
  return fixed;
}
