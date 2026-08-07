// The banner is the first thing anyone sees, and before 0.3.0 it sized itself
// to its content, so a long --out path drew a box 139 columns wide that wrapped
// into garbage on a normal terminal. These tests hold the box inside the
// terminal and hold the truncation honest about which half of a path it keeps.
import test from 'node:test';
import assert from 'node:assert/strict';

import { box, ellipsize } from '../cli/format.mjs';

const ANSI = /\x1b\[[0-9;]*m/g;
const visible = (s) => s.replace(ANSI, '').length;
const widestLine = (s) => Math.max(...s.split('\n').map(visible));

test('a line that already fits is returned untouched', () => {
  assert.equal(ellipsize('short', 40), 'short');
  // Exactly at the budget is still a fit, not an overflow.
  assert.equal(ellipsize('12345', 5), '12345');
});

test('an overlong line comes back exactly at the budget', () => {
  for (const budget of [20, 40, 76, 96]) {
    const out = ellipsize('x'.repeat(500), budget);
    assert.equal(visible(out), budget, `budget ${budget}`);
  }
});

test('truncation drops the middle, so a path keeps its label and its filename', () => {
  const line = 'identity  C:\\Users\\someone\\AppData\\Local\\Temp\\deeply\\nested\\identity';
  const out = ellipsize(line, 40);
  assert.ok(out.startsWith('identity  C:'), `lost the label: ${out}`);
  assert.ok(out.endsWith('identity'), `lost the filename: ${out}`);
  assert.ok(out.includes('...'), 'no ellipsis marker');
  assert.equal(visible(out), 40);
});

test('escape sequences are never cut in half, and colour is closed', () => {
  const dim = (s) => `\x1b[2m${s}\x1b[0m`;
  const line = `label  ${dim('/very/long/path/that/will/not/fit/at/all/file.txt')}`;
  const out = ellipsize(line, 30);

  assert.equal(visible(out), 30);
  // Every escape present must be a whole, well formed SGR sequence.
  for (const seq of out.match(ANSI) ?? []) {
    assert.match(seq, /^\x1b\[[0-9;]*m$/, `mangled escape: ${JSON.stringify(seq)}`);
  }
  // A dim opener survived into the head, so something has to close it or the
  // rest of the terminal output goes dim.
  assert.ok(out.includes('\x1b[0m'), 'colour left open');
  // The raw string ends with a reset, so ask what the reader actually sees.
  assert.ok(out.replace(ANSI, '').endsWith('file.txt'), `lost the filename: ${out}`);
});

test('a budget too small to hold the ellipsis gives up rather than mangling', () => {
  const line = 'aaaaaaaaaaaaaaaaaaaa';
  assert.equal(ellipsize(line, 3), line);
  assert.equal(ellipsize(line, 0), line);
});

test('the box fits the terminal even when its content does not', () => {
  const longPath = 'C:\\Users\\someone\\AppData\\Local\\Temp\\' + 'nested\\'.repeat(20) + 'identity';
  const drawn = box('ratchet recv', [
    'you        one two three four five six',
    `identity   ${longPath}`,
    `saving to  ${longPath}`,
  ]);

  // stdout is not a tty under the test runner, so the fallback applies.
  assert.equal(widestLine(drawn), 80, drawn);

  // Every line is the same width, or the right hand border is ragged.
  const widths = new Set(drawn.split('\n').map(visible));
  assert.equal(widths.size, 1, `ragged border, widths: ${[...widths].join(', ')}`);
});

test('the box still shrinks to fit content that is narrower than the terminal', () => {
  const drawn = box('id', ['a', 'b']);
  assert.ok(widestLine(drawn) < 40, `box did not shrink: ${widestLine(drawn)}`);
  const widths = new Set(drawn.split('\n').map(visible));
  assert.equal(widths.size, 1);
});

test('a title longer than the terminal cannot push the box wide', () => {
  const drawn = box('t'.repeat(300), ['body']);
  assert.equal(widestLine(drawn), 80);
});
