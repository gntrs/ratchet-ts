// The chat screen, tested with no terminal anywhere in sight.
//
// This is the whole reason cli/ui.mjs is a pure function of its state: every
// screen the chat can be in, including the two that only appear when something
// has gone wrong, is a value here rather than something you have to reproduce
// by getting two processes into a bad mood at the same time. If a frame in this
// file changes, the change was deliberate or it is a bug, and either way it is
// visible in the diff.
//
// The frames below are written out in full on purpose. A test that asserts
// "contains the word verified" passes on a screen that is otherwise garbage.
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  blankState,
  charWidth,
  completionsFor,
  cursorPosition,
  layout,
  maxScroll,
  renderFrame,
  stringWidth,
  stripAnsi,
  transcriptHeight,
} from '../cli/ui.mjs';

const SIZE = { cols: 80, rows: 24 };

/** Colour off unless a test is about colour, so the frames stay readable. */
function base() {
  const s = blankState();
  s.color = false;
  s.peerAddress = '192.168.1.24:4477';
  s.sessionWords = 'scan fiber black abstract cradle struggle';
  s.peerWords = 'goat window faint climb gossip process';
  s.link = { state: 'live', pq: true, quietSeconds: 0 };
  s.transcript = [
    { who: 'you', at: '09:41', text: 'hey, are you at the machine' },
    { who: 'them', at: '09:41', text: 'yeah go' },
    {
      who: 'them',
      at: '09:43',
      text: 'ok. one more thing, the deploy box rebooted so the tailscale address changed',
    },
    { who: 'note', at: '09:44', text: 'sent deploy.age  4.1 kB in 0.31 s' },
  ];
  return s;
}

function verified() {
  const s = base();
  s.trust = {
    state: 'verified', label: 'laptop', shortHex: 'a1b2c3d4e5f60718', words: s.peerWords, conflict: null,
  };
  return s;
}

/** A frame as one string, so an assertion failure prints the whole screen. */
function frame(state, size = SIZE) {
  return renderFrame(state, size).join('\n');
}

// ---------------------------------------------------------------------------
// The two steady states
// ---------------------------------------------------------------------------

test('steady state, verified peer: four rows of chrome and the rest is transcript', () => {
  assert.equal(
    frame(verified()),
    [
      ' ratchet chat  ·  192.168.1.24:4477             ✓ verified "laptop"  ·  pq live ',
      '─'.repeat(80),
      ' '.repeat(80),
      ' '.repeat(80),
      ' '.repeat(80),
      ' '.repeat(80),
      ' '.repeat(80),
      ' '.repeat(80),
      ' '.repeat(80),
      ' '.repeat(80),
      ' '.repeat(80),
      ' '.repeat(80),
      ' '.repeat(80),
      ' '.repeat(80),
      ' 09:41  you   hey, are you at the machine                                       ',
      ' 09:41  them  yeah go                                                           ',
      ' 09:43  them  ok. one more thing, the deploy box rebooted so the tailscale      ',
      '              address changed                                                   ',
      ' 09:44   ..   sent deploy.age  4.1 kB in 0.31 s                                 ',
      '─'.repeat(80),
      '┌──────────────────────────────────────────────────────────────────────────────┐',
      '│ > message, / for commands                                                    │',
      '└──────────────────────────────────────────────────────────────────────────────┘',
      ' /verify  /peer  /words  /stats  /help  /quit        PgUp scroll   Ctrl+C leave ',
    ].join('\n'),
  );
});

test('unverified: the strip takes two rows and the transcript loses exactly two', () => {
  const rows = renderFrame(base(), SIZE);
  const verifiedRows = renderFrame(verified(), SIZE);
  assert.equal(rows.length, verifiedRows.length);

  const strip = rows.slice(-6, -4);
  assert.deepEqual(strip.map((r) => r.trimEnd()), [
    ' ! compare aloud   scan  fiber  black  abstract  cradle  struggle',
    '   read these six words to the other person out loud. /verify when they match.',
  ]);
  // The chrome grew by two, so the content region shrank by two and nothing
  // else moved.
  assert.equal(layout(base(), SIZE).content, layout(verified(), SIZE).content - 2);
});

test('the badge names the state in a word, so colour is never the only carrier', () => {
  assert.match(stripAnsi(renderFrame(verified(), SIZE)[0]), /verified "laptop"/);
  assert.match(stripAnsi(renderFrame(base(), SIZE)[0]), /! unverified/);

  const closed = verified();
  closed.link = { state: 'closed', pq: true, quietSeconds: 0 };
  assert.match(stripAnsi(renderFrame(closed, SIZE)[0]).trimEnd(), /closed$/);

  const quiet = verified();
  quiet.link = { state: 'quiet', pq: true, quietSeconds: 132 };
  assert.match(stripAnsi(renderFrame(quiet, SIZE)[0]).trimEnd(), /quiet 2m$/);
});

// ---------------------------------------------------------------------------
// The screens that only appear when something is being decided
// ---------------------------------------------------------------------------

test('the verify modal asks a real question and names the only answer', () => {
  const s = base();
  s.modal = { kind: 'verify', step: 'ask' };
  s.input = { ...s.input, line: 'ye', cursor: 2, placeholder: 'type yes to record it' };
  const text = frame(s);

  assert.match(text, /verify this peer/);
  assert.match(text, /scan {2}fiber {2}black {2}abstract {2}cradle {2}struggle/);
  assert.match(text, /goat {2}window {2}faint {2}climb {2}gossip {2}process/);
  assert.match(text, /type {2}yes {2}and press enter/);
  assert.match(text, /Esc, or anything else, cancels/);
  // The strip is redundant while the modal is up: the modal is already showing
  // the same six words, and two copies on one screen is two things to compare.
  assert.equal(layout(s, SIZE).strip, 0);
  // The caret stays in the input box: the modal is a question, not a prompt.
  assert.ok(cursorPosition(s, SIZE));
});

test('the changed key alarm says what leaked, keeps the code, and keeps both ways out', () => {
  const s = base();
  s.trust = {
    state: 'changed',
    label: null,
    shortHex: 'ffff0000ffff0000',
    words: s.peerWords,
    conflict: { label: 'laptop', words: 'scan fiber black abstract cradle struggle', hex: 'aaaa1111bbbb2222' },
  };
  s.alarm = {
    kind: 'changed',
    title: 'the key at 192.168.1.24:4477 is not the one you verified',
    body: [
      { kind: 'words', label: 'you verified as "laptop"', words: s.trust.conflict.words, hex: 'aaaa1111bbbb2222' },
      { kind: 'words', label: 'answering now', words: s.peerWords, hex: 'ffff0000ffff0000' },
      { kind: 'blank' },
      {
        kind: 'red',
        text: 'Anything already sent in this session went to the NEW key. Assume whoever holds that key has read it.',
      },
      { kind: 'blank' },
      { kind: 'text', text: 'A peer who reinstalled and a stranger in the middle produce exactly this screen.' },
    ],
    reason: 'peer_key_changed',
    actions: [
      { name: '/trust new', desc: 'accept this key going forward. it stays UNVERIFIED until you /verify it.' },
      { name: '/quit', desc: 'leave now and send nothing more.' },
    ],
  };
  const text = frame(s);

  assert.match(text, /the key at 192\.168\.1\.24:4477 is not the one you verified/);
  assert.match(text, /went to the NEW key/);
  assert.match(text, /reason code: peer_key_changed/);
  assert.match(text, /\/trust new/);
  assert.match(text, /\/quit/);
  // Both keys stay on screen. Which one you verified and which one is talking
  // is the entire question being asked.
  assert.match(text, /aaaa1111bbbb2222/);
  assert.match(text, /ffff0000ffff0000/);
  // An alarm owns the region, so the strip does not also try to use it.
  assert.equal(layout(s, SIZE).strip, 0);
});

test('a fatal crypto alarm leads with the cause and still leaves the reason code', () => {
  const s = base();
  s.alarm = {
    kind: 'fatal',
    title: 'the two ends are running different versions',
    body: [
      { kind: 'text', text: 'This build cannot read that envelope version.' },
      { kind: 'blank' },
      { kind: 'text', text: 'This reads as two ends that do not match rather than someone in the middle.' },
    ],
    reason: 'unknown_version',
    actions: [{ name: '/quit', desc: 'leave and close the socket.' }],
  };
  const text = frame(s);
  assert.match(text, /different versions/);
  assert.match(text, /reason code: unknown_version/);
  // A version skew must not borrow the words an attack gets.
  assert.doesNotMatch(text, /read it\./);
});

test('a short window keeps the reason code and the way out, and drops the prose', () => {
  const s = base();
  s.alarm = {
    kind: 'fatal',
    title: 'a frame arrived that had already been used',
    body: [
      { kind: 'text', text: 'A repeat like this is either a network replaying you or somebody doing it deliberately. '.repeat(3) },
      { kind: 'blank' },
      { kind: 'red', text: 'Everything you sent in this session was encrypted to whatever key answered it.' },
    ],
    reason: 'replay_detected',
    actions: [{ name: '/quit', desc: 'leave and close the socket.' }],
  };
  const text = frame(s, { cols: 80, rows: 14 });
  assert.match(text, /a frame arrived that had already been used/);
  assert.match(text, /reason code: replay_detected/);
  assert.match(text, /\/quit/);
  // Wrapped across two rows at this width, so the assertion stops at the wrap.
  assert.match(text, /encrypted to whatever key answered/);
  // The prose at the top is the only thing that gave way.
  assert.doesNotMatch(text, /doing it deliberately/);
});

// ---------------------------------------------------------------------------
// Degradation
// ---------------------------------------------------------------------------

test('NO_COLOR keeps every word and drops every escape', () => {
  const coloured = renderFrame({ ...verified(), color: true }, SIZE);
  const plain = renderFrame(verified(), SIZE);
  assert.ok(coloured.join('').includes('\x1b['));
  assert.ok(!plain.join('').includes('\x1b'));
  // Same screen, same information. Colour was never carrying any of it.
  assert.deepEqual(coloured.map(stripAnsi), plain);
});

test('ascii mode swaps the box for characters every codepage has', () => {
  const s = verified();
  s.ascii = true;
  const rows = renderFrame(s, SIZE);
  const text = rows.join('\n');
  assert.doesNotMatch(text, /[─│┌┐└┘·✓]/);
  assert.match(text, /\[ok\] verified/);
  assert.match(rows[1], /^-{80}$/);
  assert.match(rows[rows.length - 2], /^\+-+\+$/);
});

test('the completion list pushes up from the input box and never covers it', () => {
  const s = verified();
  s.input = { ...s.input, line: '/w', cursor: 2 };
  s.completion = { items: completionsFor('/w', {}), index: 0 };
  const rows = renderFrame(s, SIZE);
  assert.equal(s.completion.items.length, 1);
  assert.match(rows[rows.length - 5], /\/words {2}reprint/);
  assert.match(rows[rows.length - 3], /^│ > \/w/);
});

test('only the key change alarm offers a way to trust anything', () => {
  const changed = completionsFor('/', { alarm: { kind: 'changed' } }).map((c) => c.name);
  assert.deepEqual(changed, ['/trust new', '/quit']);
  // There is no key to trust on a version skew, and offering one would imply
  // the failure was about identity when it was not.
  const fatal = completionsFor('/', { alarm: { kind: 'fatal' } }).map((c) => c.name);
  assert.deepEqual(fatal, ['/quit']);
});

// ---------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------

test('60 columns: the badge survives, the address is dropped whole', () => {
  const rows = renderFrame(verified(), { cols: 60, rows: 24 });
  for (const row of rows) assert.equal(stringWidth(row), 60);
  assert.match(rows[0], /verified "laptop"/);
  // Half an address is worse than none: nobody can tell 192.168.1.2 from
  // 192.168.1.24 once the tail is gone.
  assert.doesNotMatch(rows[0], /192\.168\.1\.2\b/);
});

test('12 rows: still a screen, still an input box, nothing negative', () => {
  const plan = layout(base(), { cols: 80, rows: 12 });
  assert.equal(renderFrame(base(), { cols: 80, rows: 12 }).length, 12);
  assert.ok(plan.content >= 1);
  assert.ok(plan.input >= 1);
});

test('the row budget never goes negative and never overflows, at any size', () => {
  const states = [base(), verified()];
  const withModal = base();
  withModal.modal = { kind: 'verify', step: 'ask' };
  states.push(withModal);
  const withCompletion = verified();
  withCompletion.input = { ...withCompletion.input, line: '/', cursor: 1 };
  withCompletion.completion = { items: completionsFor('/', {}), index: 2 };
  states.push(withCompletion);

  for (const s of states) {
    for (let cols = 20; cols <= 120; cols += 7) {
      for (let rows = 1; rows <= 30; rows += 1) {
        const size = { cols, rows };
        const plan = layout(s, size);
        for (const [name, n] of Object.entries(plan)) {
          if (name === 'cols' || name === 'rows') continue;
          assert.ok(n >= 0, `${name} went negative at ${cols}x${rows}`);
        }
        const sum = plan.title + plan.ruleTop + plan.content + plan.ruleBottom
          + plan.strip + plan.completion + plan.input + plan.footer;
        assert.equal(sum, rows, `regions do not add up at ${cols}x${rows}`);

        const out = renderFrame(s, size);
        assert.equal(out.length, rows);
        for (const row of out) {
          assert.equal(stringWidth(row), cols, `a row overflowed at ${cols}x${rows}`);
        }
      }
    }
  }
});

// ---------------------------------------------------------------------------
// Scrolling
// ---------------------------------------------------------------------------

test('scrolled up: older lines stay put and the footer counts what arrived', () => {
  const s = verified();
  s.transcript = [];
  for (let i = 0; i < 60; i += 1) {
    s.transcript.push({ who: i % 2 ? 'them' : 'you', at: '10:00', text: `line ${i}` });
  }
  assert.equal(transcriptHeight(s, 80), 60);
  const top = maxScroll(s, SIZE);
  assert.ok(top > 0);

  const bottom = renderFrame(s, SIZE).join('\n');
  assert.match(bottom, /line 59/);

  s.scroll = top;
  s.unseen = 3;
  const rows = renderFrame(s, SIZE);
  const text = rows.join('\n');
  assert.match(text, /line 0/);
  assert.doesNotMatch(text, /line 59/);
  assert.match(rows[rows.length - 1], /v 3 new/);
  // The counter takes its room from the end of the command list, and it takes
  // whole commands. Half a command name in a row of command names would read
  // as a command.
  const footer = stripAnsi(rows[rows.length - 1]);
  assert.match(footer, / \/verify {2}\/peer {2}\/words {2}\/stats {2}\/help {5}v 3 new {3}PgUp scroll {3}Ctrl\+C leave $/);
  assert.doesNotMatch(footer, /\/q\b/);
});

test('scroll is clamped to the content, not to the transcript', () => {
  const s = verified();
  s.scroll = 9999;
  const rows = renderFrame(s, SIZE);
  assert.equal(rows.length, 24);
  // Four entries in a twelve row viewport cannot scroll at all.
  assert.equal(maxScroll(s, SIZE), 0);
});

// ---------------------------------------------------------------------------
// Width
// ---------------------------------------------------------------------------

test('the width table knows the two-cell characters', () => {
  assert.equal(charWidth('a'), 1);
  assert.equal(charWidth('日'), 2);
  assert.equal(charWidth('한'), 2);
  assert.equal(charWidth('！'), 2);
  assert.equal(charWidth('🙂'), 2);
  assert.equal(charWidth('́'), 0);
  assert.equal(charWidth('\r'), 0);
  assert.equal(stringWidth('日本語'), 6);
  assert.equal(stringWidth('\x1b[36mhi\x1b[0m'), 2);
});

test('a CJK and emoji line still lands on the column count', () => {
  const s = verified();
  s.transcript = [
    { who: 'them', at: '09:45', text: '日本語のテキストはセル幅が二倍になります。ここで折り返しが必要です。' },
    { who: 'you', at: '09:45', text: 'ok 🙂 🙂 🙂 tail' },
  ];
  const rows = renderFrame(s, SIZE);
  for (const row of rows) assert.equal(stringWidth(row), 80);
  const text = rows.join('\n');
  assert.match(text, /日本語のテキスト/);
  assert.match(text, /ok 🙂 🙂 🙂 tail/);
});

test('the cursor lands after the visible part of a wide input line', () => {
  const s = verified();
  s.input = { ...s.input, line: '日本語', cursor: 3 };
  const at = cursorPosition(s, SIZE);
  // One space after the border, two for the prompt, six cells of text.
  assert.deepEqual(at, { row: 22, col: 3 + 2 + 6 });
});

test('input disabled hides the caret and says so in the box', () => {
  const s = verified();
  s.input = {
    line: '', cursor: 0, enabled: false, placeholder: 'the session is over',
  };
  assert.equal(cursorPosition(s, SIZE), null);
  assert.match(renderFrame(s, SIZE).join('\n'), /the session is over/);
});
