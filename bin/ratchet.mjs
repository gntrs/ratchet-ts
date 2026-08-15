#!/usr/bin/env node
// The ratchet CLI: move a file between two machines, end to end encrypted,
// with no server in the middle.
//
// This file owns exactly two jobs: turning argv into intent, and turning
// results into text. Every byte of crypto lives in cli/protocol.mjs and every
// byte of socket lives in cli/frame.mjs. Keeping that line sharp is what makes
// the security-relevant part reviewable without reading any of this.
//
// The other job this file has, which is not obvious from the imports, is that
// it is the only place a stranger meets this tool. Every message here assumes
// the reader has no idea what a ratchet is and is one bad line away from
// giving up, so an error that does not end with the next command to type is
// treated as a bug.

import { existsSync, readFileSync, unlinkSync } from 'node:fs';
import { mkdir, open, readFile, unlink } from 'node:fs/promises';
import { networkInterfaces } from 'node:os';
import { basename, delimiter, dirname, extname, join, resolve } from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

import { fingerprint, formatFingerprint, isCryptoFailure } from '../dist/index.js';
import { connect, listen } from '../cli/frame.mjs';
import {
  identityFile,
  loadIdentity,
  readIdentityToken,
  resetIdentity,
  rewrapIdentity,
  takeMigrationNotice,
} from '../cli/store.mjs';
import {
  clearRollback,
  commitDescriptor,
  describeProtection,
  passphraseDescriptor,
  plainOrKeychainDescriptor,
  readPassphrase,
  readRollback,
  rollbackFile,
  vaultFile,
  vaultState,
  writeRollback,
} from '../cli/vault.mjs';
import {
  addressOf,
  classifyPeer,
  findPeers,
  forgetPeer,
  listPeers,
  loadPeers,
  markVerified,
  peersFile,
  recordSighting,
  resetPeers,
  savePeers,
} from '../cli/peers.mjs';
import { DEFAULT_CHUNK_BYTES, MAX_CHUNK_BYTES, receivePayload, sendPayload } from '../cli/protocol.mjs';
import { box, color, humanBytes, humanMs, statsTable, words } from '../cli/format.mjs';
// One grouping of the safety words for the whole tool. The chat TUI draws the
// same two rows from the same helper, so the plain banner and the full screen
// cannot disagree about where the fingerprints break.
import { splitPairWords } from '../cli/ui.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_PORT = 4477;

// Anything a text send produces gets this name, and the receiver uses it as
// the hint to echo the content instead of leaving the user to cat a file.
const TEXT_NAME = 'message.txt';
const TEXT_ECHO_LIMIT = 4096;

// ---------------------------------------------------------------------------
// Output routing
// ---------------------------------------------------------------------------

// In --json mode stdout is reserved for the JSON object and nothing else, or
// the whole point of the flag (piping it into something) is lost.
let jsonMode = false;

function say(line = '') {
  (jsonMode ? process.stderr : process.stdout).write(`${line}\n`);
}

function emit(object) {
  process.stdout.write(`${JSON.stringify(object)}\n`);
}

// ---------------------------------------------------------------------------
// How this binary is spelled on this machine
// ---------------------------------------------------------------------------

// The single most common first failure with this tool is `npm i ratchet-ts`
// followed by `ratchet recv` and `command not found`, because a local install
// puts nothing on PATH. It has bitten the author on two machines. So rather
// than printing a command that may not exist, look for one and print what
// actually works here.
let commandCache = null;

function onPath(name) {
  const raw = process.env.PATH || process.env.Path || '';
  if (!raw) return false;
  // On Windows the thing npm actually creates is ratchet.cmd, so a bare
  // existence check for "ratchet" would answer no on a correct global install.
  const exts =
    process.platform === 'win32'
      ? (process.env.PATHEXT || '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean)
      : [''];
  for (const dir of raw.split(delimiter)) {
    if (!dir) continue;
    for (const ext of exts) {
      try {
        if (existsSync(join(dir, name + ext))) return true;
      } catch {
        /* an unreadable PATH entry is not an answer, keep looking */
      }
    }
  }
  return false;
}

/** The prefix every printed command uses, so copy and paste always works. */
function cmd() {
  if (commandCache === null) commandCache = onPath('ratchet') ? 'ratchet' : 'npx ratchet';
  return commandCache;
}

const INSTALL_LINE = 'npm i -g ratchet-ts';

/** Non null only when this machine has the package but not the command. */
function pathNote() {
  if (cmd() === 'ratchet') return null;
  return `There is no ${color.bold('ratchet')} command on this PATH, so the lines above use npx. ${color.bold(INSTALL_LINE)} fixes that.`;
}

// ---------------------------------------------------------------------------
// Progress
// ---------------------------------------------------------------------------

// Below this a progress bar is pure noise: the transfer is over before the
// first repaint, and a bar that flashes once looks like a glitch.
const PROGRESS_MIN_BYTES = 256 * 1024;
const PROGRESS_WIDTH = 78;
const BAR_WIDTH = 22;
// Repaint ceiling. A 60 fps bar costs more in terminal writes than the crypto
// costs in CPU on a fast link, which is a genuinely measurable slowdown.
const REPAINT_MS = 80;

const PROGRESS_TTY = Boolean(process.stderr.isTTY);
let progressDrawn = false;

function humanRate(bytesPerSecond) {
  if (!Number.isFinite(bytesPerSecond) || bytesPerSecond <= 0) return '';
  if (bytesPerSecond < 1e6) return `${Math.round(bytesPerSecond / 1e3)} kB/s`;
  return `${(bytesPerSecond / 1e6).toFixed(1)} MB/s`;
}

function bar(fraction) {
  const filled = Math.max(0, Math.min(BAR_WIDTH, Math.round(fraction * BAR_WIDTH)));
  return `[${'='.repeat(filled)}${' '.repeat(BAR_WIDTH - filled)}]`;
}

/**
 * Progress always goes to stderr, never stdout, so `--json` and any pipe stay
 * clean. Off a TTY it collapses to one line stating the size and then says
 * nothing more: thousands of near identical lines in a log file is not
 * feedback, it is a denial of service on whoever reads the log.
 *
 * The size is not known until the first callback on the receiving side (the
 * header carries it), so the decision to draw at all is deferred to then
 * rather than taken up front.
 */
function makeProgress(label) {
  let mode = null; // null undecided, 'draw', 'quiet'
  let startedAt = 0;
  let lastAt = 0;

  return ({ done, total }) => {
    const size = Number(total) || 0;
    const sent = Number(done) || 0;

    if (mode === null) {
      startedAt = performance.now();
      if (size <= PROGRESS_MIN_BYTES) {
        mode = 'quiet';
      } else if (!PROGRESS_TTY) {
        mode = 'quiet';
        process.stderr.write(`${label} ${humanBytes(size)}\n`);
      } else {
        mode = 'draw';
      }
    }
    if (mode !== 'draw') return;

    const now = performance.now();
    const finished = size > 0 && sent >= size;
    if (!finished && now - lastAt < REPAINT_MS) return;
    lastAt = now;

    const elapsed = Math.max(1, now - startedAt) / 1000;
    const fraction = size > 0 ? Math.min(1, sent / size) : 0;
    const line =
      `${label.padEnd(9)} ${bar(fraction)} ${`${Math.round(fraction * 100)}%`.padStart(4)} ` +
      `${`${humanBytes(sent)}/${humanBytes(size)}`.padEnd(18)} ${humanRate(sent / elapsed)}`;
    progressDrawn = true;
    process.stderr.write(`\r${line.slice(0, PROGRESS_WIDTH).padEnd(PROGRESS_WIDTH)}`);
  };
}

function clearProgress() {
  if (!progressDrawn) return;
  progressDrawn = false;
  process.stderr.write(`\r${' '.repeat(PROGRESS_WIDTH)}\r`);
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** A mistake in the command line, as opposed to a failure during a transfer. */
class UsageError extends Error {}

function usageError(message, ...hint) {
  const err = new UsageError(message);
  err.hint = hint;
  throw err;
}

/**
 * Every failure this file raises carries the next command to type. `hint` is
 * an array of already coloured lines printed under the error, and the rule is
 * that at least one of them is something you can paste into a shell.
 */
function failWith(message, ...hint) {
  const err = new Error(message);
  err.hint = hint;
  throw err;
}

/**
 * A crypto failure earns its own exit code because it means something quite
 * different from a broken pipe: the bytes were tampered with, replayed, or the
 * peer is not who it claims to be. protocol.mjs wraps these, so walk the cause
 * chain rather than testing only the outermost error.
 */
function isCrypto(err) {
  let current = err;
  for (let depth = 0; current && depth < 8; depth += 1) {
    if (isCryptoFailure(current)) return true;
    current = current.cause;
  }
  return false;
}

/**
 * cli/frame.mjs rewraps socket errors into a plain Error, which drops `code`.
 * The original code is still legible in the message text, so read it back out
 * rather than losing the one field that decides what advice to give.
 */
function codeOf(err) {
  let current = err;
  for (let depth = 0; current && depth < 8; depth += 1) {
    if (typeof current.code === 'string') return current.code;
    current = current.cause;
  }
  const text = err && err.message ? String(err.message) : '';
  const match = /\b(E[A-Z]{2,})\b/.exec(text);
  return match ? match[1] : null;
}

/** Fallback advice for errors that reached here without one attached. */
function derivedHint(err) {
  switch (codeOf(err)) {
    case 'ECONNRESET':
    case 'EPIPE':
      return [
        'The other side went away mid transfer. Nothing partial was kept.',
        `Start it again there:  ${color.bold(`${cmd()} recv`)}`,
      ];
    case 'ENOSPC':
      return ['The disk is full, so nothing was written. Free some space and run it again.'];
    case 'EACCES':
    case 'EPERM':
      return ['Permission denied on that path. Pick a directory you own with --out DIR.'];
    default:
      return [];
  }
}

function reportError(err) {
  clearProgress();
  process.stderr.write(`${color.red('error')} ${err && err.message ? err.message : String(err)}\n`);
  const hint = Array.isArray(err && err.hint) && err.hint.length ? err.hint : derivedHint(err);
  for (const line of hint) process.stderr.write(`      ${line}\n`);
  // A stack trace is noise for an expected failure and the only useful thing
  // there is for an unexpected one, so it is opt in rather than a default.
  if (process.env.RATCHET_DEBUG && err && err.stack) {
    process.stderr.write(`${err.stack}\n`);
  }
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

const VALUE_FLAGS = new Set(['--port', '--out', '--to', '--text', '--chunk', '--label']);
const BOOL_FLAGS = new Set(['--once', '--stats', '--json', '--help', '--version', '--reset', '--yes', '-h', '-v']);
const ALIASES = { '-h': '--help', '-v': '--version' };

function flagKey(name) {
  return (ALIASES[name] ?? name).replace(/^--/, '');
}

/**
 * Hand rolled, and unknown flags are a hard error naming the flag. Silently
 * ignoring a typo like --stat is how someone concludes the feature is broken.
 */
function parseArgs(argv) {
  const opts = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--') {
      opts._.push(...argv.slice(i + 1));
      break;
    }
    // A bare dash is the stdin path, not a flag.
    if (arg === '-' || !arg.startsWith('-') || arg.length === 1) {
      opts._.push(arg);
      continue;
    }

    let name = arg;
    let value = null;
    const eq = arg.indexOf('=');
    if (arg.startsWith('--') && eq !== -1) {
      name = arg.slice(0, eq);
      value = arg.slice(eq + 1);
    }

    if (VALUE_FLAGS.has(name)) {
      if (value === null) {
        value = argv[i + 1];
        if (value === undefined) usageError(`${name} needs a value`);
        i += 1;
      }
      opts[flagKey(name)] = value;
      continue;
    }
    if (BOOL_FLAGS.has(name)) {
      if (value !== null) usageError(`${name} does not take a value`);
      opts[flagKey(name)] = true;
      continue;
    }
    usageError(`unknown flag ${name}`, `Run ${color.bold(`${cmd()} --help`)} for the list.`);
  }
  return opts;
}

function parsePort(raw, what) {
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > 65535) {
    usageError(`${what} must be a port between 1 and 65535, got ${raw}`);
  }
  return n;
}

/** Accepts HOST, HOST:PORT, a bare IPv6 literal, and [IPv6]:PORT. */
function parseTo(raw) {
  const text = String(raw).trim();
  if (!text) usageError('--to needs a host', `Example:  ${color.bold(`${cmd()} send file.txt --to 192.168.1.42`)}`);

  if (text.startsWith('[')) {
    const end = text.indexOf(']');
    if (end === -1) usageError(`--to ${raw} is missing a closing bracket`);
    const host = text.slice(1, end);
    const rest = text.slice(end + 1);
    if (!rest) return { host, port: DEFAULT_PORT };
    if (!rest.startsWith(':')) usageError(`--to ${raw} is not HOST or HOST:PORT`);
    return { host, port: parsePort(rest.slice(1), '--to port') };
  }

  const parts = text.split(':');
  if (parts.length === 1) return { host: text, port: DEFAULT_PORT };
  if (parts.length === 2) return { host: parts[0], port: parsePort(parts[1], '--to port') };
  // Several colons and no brackets is an unbracketed IPv6 literal. There is no
  // port in it, because ::1:4477 is ambiguous and guessing would be worse.
  return { host: text, port: DEFAULT_PORT };
}

function parseChunk(raw) {
  if (raw === undefined) return undefined;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1) usageError(`--chunk must be a positive whole number of bytes, got ${raw}`);
  return n;
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

const PKG = JSON.parse(readFileSync(join(HERE, '..', 'package.json'), 'utf8'));

/**
 * Shown when someone types `ratchet` and nothing else. This must never be an
 * error: a bare invocation is what a curious person types first, and greeting
 * them with a non zero exit and a wall of flags is how they close the tab.
 */
function splash() {
  const c = cmd();
  const note = pathNote();
  return [
    `${color.bold('ratchet')} ${PKG.version}   send a file to another machine, encrypted end to end, no server`,
    '',
    `  1.  On BOTH machines:            ${color.bold(INSTALL_LINE)}`,
    `  2.  On the machine RECEIVING:    ${color.bold(`${c} recv`)}`,
    '  3.  It prints a command. Run that one on the machine SENDING.',
    '  4.  Both screens show six words. Read them aloud. Same words means',
    '      you are talking to each other. Different words means stop.',
    '',
    `  ${color.dim(`${c} send .env --to 192.168.1.42`.padEnd(38))}send a secret file`,
    `  ${color.dim(`${c} --help`.padEnd(38))}everything else`,
    ...(note ? ['', color.yellow(note)] : []),
  ].join('\n');
}

const HELP = `ratchet ${PKG.version}   send a file to another machine, encrypted end to end, no server

INSTALL
  ${INSTALL_LINE}   on BOTH machines.

  Without -g there is no ratchet command, only a library, and the shell
  answers "command not found". That is the first thing everyone hits.

THE WHOLE THING
  1. On the machine that RECEIVES:  ratchet recv
  2. It prints a command. Run that one on the machine that SENDS.
  3. Both screens print six words. Read them aloud. Same words means the two
     machines are talking to each other and nobody else. Different words
     means someone is in the middle: stop, and delete whatever arrived.

EXAMPLES
  ratchet recv                              wait here, save what arrives
  ratchet recv --out ~/Downloads --once     one file into Downloads, then quit
  ratchet send .env --to 192.168.1.42       send a secret file, no ceremony
  ratchet send photo.jpg --to 192.168.1.42:5000
  ratchet send --text "wifi is hunter2" --to 192.168.1.42
  pg_dump mydb | ratchet send - --to 192.168.1.42
  ratchet chat --to 192.168.1.42            type back and forth, nothing saved
  ratchet id                                your six words and your key file
  ratchet peers                             who this machine has talked to

COMMANDS
  recv [--port N] [--out DIR] [--once]   listen, then write what arrives
  send PATH --to HOST[:PORT]             send one file, or - to read stdin
  send --text "..." --to HOST[:PORT]     send a message instead of a file
  chat [--port N] | chat --to HOST[:PORT]   live session, no messages on disk
  id [--reset --yes]                     this machine safety words and key file
  peers                                  everyone seen before, and who is verified
  peers verify WHO [--label NAME]        record that you compared the words aloud
  peers forget WHO                       drop one peer, WHO is a label or hex prefix
  lock                                   ask for a passphrase on every command
  unlock                                 stop asking, back to the keychain

FLAGS
  --port N       listen on N instead of ${DEFAULT_PORT}
  --out DIR      where recv writes, default here. It never overwrites.
  --once         recv handles one transfer and exits
  --to HOST      HOST, HOST:PORT, or [IPv6]:PORT
  --text "..."   send a message instead of a file
  --label NAME   the name to file a verified peer under
  --stats        add the full measurement table under the summary line
  --chunk N      plaintext bytes per sealed frame (default ${DEFAULT_CHUNK_BYTES}, max ${MAX_CHUNK_BYTES})
  --json         result as JSON on stdout, all human output on stderr
  --help, --version

WORTH KNOWING
  The two machines talk straight over TCP, so they need a route to each other,
  usually the same wifi. There is no relay and no account.
  Filename, size and hash are encrypted with the payload, so an observer sees
  a byte count and nothing else.
  What lands on the receiving disk is plain, unencrypted content. The wire was
  protected, the file is not.
  Every completed handshake writes one row to ~/.ratchet/peers.json: the peer
  key, its six words, the addresses it came from, and dates. That is how a
  changed key gets noticed. No filename and no message is ever recorded there.
  Delete a row with  ratchet peers forget WHO.

YOUR KEY, AT REST
  ~/.ratchet/identity is your long term secret key and ~/.ratchet/peers.json is
  the list of who you have talked to. Both are sealed with one key that this
  tool keeps in your operating system's own store: DPAPI on Windows, the
  keychain on macOS, the login keyring on Linux. Nothing asks you for anything,
  and a copy of those files taken to another machine is useless.
  ratchet id  says which of the three states you are in.
  If no such store exists here, the files are written in the clear and say so
  in their own first line.  ratchet lock  replaces that with a passphrase, and
  then every command asks for it once.  ratchet unlock  puts it back.
  There is no recovery for a forgotten passphrase. The key is derived from it
  and is stored nowhere.
  RATCHET_HOME moves the key file. RATCHET_DEBUG=1 adds stack traces.
  RATCHET_PASSPHRASE unlocks without a prompt on an unattended machine, and
  RATCHET_NEW_PASSPHRASE is the one  ratchet lock  reads instead of asking.
  Exit codes: 0 ok, 1 failure, 2 crypto failure.`;

// ---------------------------------------------------------------------------
// Incoming filename hygiene
// ---------------------------------------------------------------------------

// The peer chooses this name, so it is hostile input until proven otherwise.
// Windows device names are in here because opening CON or NUL succeeds and
// does something quite unlike writing a file.
const WINDOWS_DEVICES = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)/i;

// Built with the RegExp constructor so this source file carries no raw control
// bytes of its own. A literal NUL in a shipped .mjs upsets more tools than it
// is worth. NUL truncates the name inside any C library that sees it, and the
// rest of this range can repaint the terminal line that reports the name.
const CONTROL_CHARS = new RegExp('[\\u0000-\\u001f\\u007f]', 'g');

// Bidirectional overrides and zero width characters. A name of the form
// "photo" + U+202E + "gnp.exe" renders as "photo.exe.png" in every terminal
// and file manager on earth, which is the oldest filename spoof there is.
// The override is described rather than written, so this source file cannot
// itself be read backwards in an editor.
const SPOOF_CHARS = new RegExp('[\\u200b-\\u200f\\u202a-\\u202e\\u2066-\\u2069\\ufeff]', 'g');

const FALLBACK_NAME = 'payload.bin';
const MAX_NAME_CHARS = 120;
// NAME_MAX on Linux is 255 bytes, not characters. Leave room for the " (2)"
// a collision adds so a de-duplicated name cannot become the thing that fails.
const MAX_NAME_BYTES = 200;

function capName(name) {
  const ext = extname(name);
  // Anything this long is not a file extension, it is the whole name, and
  // preserving it would defeat the cap it is being excluded from.
  const useExt = ext.length > 0 && ext.length <= 16 ? ext : '';
  let chars = Array.from(name.slice(0, name.length - useExt.length));
  if (chars.length > MAX_NAME_CHARS) chars = chars.slice(0, MAX_NAME_CHARS);
  // Popping whole characters rather than slicing the string keeps a surrogate
  // pair intact; half a pair is a name no filesystem will take.
  while (chars.length > 1 && Buffer.byteLength(chars.join('') + useExt, 'utf8') > MAX_NAME_BYTES) {
    chars.pop();
  }
  return chars.join('') + useExt;
}

/**
 * Turn a name chosen by the network into a name that can only ever land
 * directly inside the output directory.
 *
 * Order matters here. Control characters come out first so they cannot hide a
 * separator from the separator check, then the directory components go, then
 * the Windows specific traps. Doing any of these the other way round leaves a
 * gap: strip separators before control characters and "aNUL/../b" still
 * carries a slash past the check.
 */
function safeName(raw) {
  let name = String(raw ?? '')
    .replace(CONTROL_CHARS, '')
    .replace(SPOOF_CHARS, '');

  // Only the last path segment could ever have been a filename. Everything in
  // front of it is a traversal attempt, an absolute path, or a drive letter,
  // and none of those are ours to honour.
  const segments = name.split(/[\\/]/);
  name = segments[segments.length - 1] ?? '';

  // A colon opens an NTFS alternate data stream, so "notes.txt:evil" writes a
  // hidden stream onto notes.txt instead of creating a file with that name.
  const colon = name.indexOf(':');
  if (colon !== -1) name = name.slice(0, colon);

  // Windows silently drops trailing dots and spaces when it opens a path, so
  // "CON " and "x.txt." are not the names they appear to be. Leading dots stay,
  // because .env and .gitignore are exactly the files this tool is for.
  name = name.replace(/^\s+/, '').replace(/[\s.]+$/, '');

  if (!name || WINDOWS_DEVICES.test(name)) return FALLBACK_NAME;
  const capped = capName(name);
  return capped || FALLBACK_NAME;
}

/**
 * Render a name that came off the network so it can be shown to a human.
 *
 * The raw name is the one piece of attacker chosen text this tool ever prints
 * back, and a terminal will happily execute the escape sequences inside it:
 * a name containing a carriage return can erase the warning that is trying to
 * describe it. Everything outside plain printable ASCII becomes an escape, and
 * the result is capped, so the worst a hostile name can do is look ugly.
 */
function escapeRaw(raw) {
  const text = String(raw ?? '');
  let out = '';
  for (const ch of text) {
    const code = ch.codePointAt(0);
    if (code >= 0x20 && code <= 0x7e && ch !== '"' && ch !== '\\') out += ch;
    else if (code <= 0xffff) out += `\\u${code.toString(16).padStart(4, '0')}`;
    else out += `\\u{${code.toString(16)}}`;
    if (out.length > 120) return `${out.slice(0, 120)}...`;
  }
  return out;
}

function quoteRaw(raw) {
  return `"${escapeRaw(raw)}"`;
}

/**
 * The backstop. safeName is careful, but the guarantee the user was given is
 * "a malicious sender cannot write outside --out", and that guarantee should
 * not rest on a regex being exhaustive. Resolve the real path and refuse
 * anything whose parent is not exactly the output directory.
 */
function containedPath(dir, name) {
  const base = resolve(dir);
  const full = resolve(base, name);
  return dirname(full) === base ? full : null;
}

// ---------------------------------------------------------------------------
// Secret material
// ---------------------------------------------------------------------------

// Not a security control. This is a note to a human who just pulled a
// production .env onto a laptop and may not have thought about where it now
// lives. It never refuses and never prompts.
const SECRET_EXACT = new Set([
  '.env',
  '.npmrc',
  '.netrc',
  '.pgpass',
  '.htpasswd',
  'id_rsa',
  'id_dsa',
  'id_ecdsa',
  'id_ed25519',
  'credentials',
]);
const SECRET_EXT = new Set(['.pem', '.key', '.p12', '.pfx', '.jks', '.keystore', '.ppk', '.asc', '.kdbx']);
const SECRET_WORDS = /secret|credential|passwd|password|api[-_. ]?key|private[-_. ]?key/i;

function looksSecret(name) {
  const lower = String(name).toLowerCase();
  if (SECRET_EXACT.has(lower)) return true;
  if (lower.startsWith('.env.') || lower.endsWith('.env')) return true;
  if (SECRET_EXT.has(extname(lower))) return true;
  return SECRET_WORDS.test(lower);
}

function warnSecret(name, path) {
  say('');
  say(`${color.yellow('heads up')} ${color.bold(name)} looks like secret material.`);
  say(`         The transfer was encrypted. The file on this disk is not:`);
  say(`         ${color.bold(path)}`);
}

// ---------------------------------------------------------------------------
// Filesystem
// ---------------------------------------------------------------------------

// Set while a file is partially written, so SIGINT can remove it. A half
// written photo that looks like a real file is worse than no file at all.
let partialPath = null;

/**
 * Claims a filename with the 'wx' flag rather than checking existence first.
 * The check-then-write version has a race, and here the race loses somebody's
 * data, so let the kernel do the claiming.
 *
 * Returns the name it actually used, which is not always the one asked for.
 * The caller has to say so out loud: a file that quietly landed as "(2)" is
 * one the user will look for under the wrong name.
 */
async function writeNoClobber(dir, rawName, bytes) {
  const asked = String(rawName ?? '');
  const name = safeName(rawName);
  // A rewritten name is not a detail to swallow. If the sender asked for
  // "../../x" and this wrote "x", the user is entitled to know the name on the
  // wire was not the name on the disk, because that is what an attack looks
  // like from here.
  const sanitisedFrom = name === asked ? null : asked;
  const ext = extname(name);
  const stem = name.slice(0, name.length - ext.length);

  for (let n = 1; n <= 10000; n += 1) {
    const candidateName = n === 1 ? name : `${stem} (${n})${ext}`;
    const candidate = containedPath(dir, candidateName);
    if (candidate === null) {
      // Unreachable by construction, so if it ever fires the sanitiser has a
      // hole and the right move is to stop, not to invent a name.
      failWith(
        `refusing to write ${candidateName}: it does not resolve inside ${resolve(dir)}`,
        'This is a bug. Please report it with the sender filename.',
      );
    }

    let handle;
    try {
      handle = await open(candidate, 'wx');
    } catch (err) {
      if (err.code === 'EEXIST') continue;
      if (err.code === 'ENOENT' || err.code === 'ENOTDIR') {
        failWith(
          `cannot write into ${resolve(dir)}: the directory is gone`,
          `Point somewhere real:  ${color.bold(`${cmd()} recv --out .`)}`,
        );
      }
      if (err.code === 'EACCES' || err.code === 'EPERM' || err.code === 'EROFS') {
        failWith(
          `cannot write into ${resolve(dir)}: permission denied`,
          `Pick a directory you own:  ${color.bold(`${cmd()} recv --out ~/Downloads`)}`,
        );
      }
      throw err;
    }

    partialPath = candidate;
    try {
      await handle.writeFile(bytes);
      await handle.close();
      partialPath = null;
      return { path: candidate, name: candidateName, renamedFrom: n === 1 ? null : name, sanitisedFrom };
    } catch (err) {
      await handle.close().catch(() => {});
      await unlink(candidate).catch(() => {});
      partialPath = null;
      if (err.code === 'ENOSPC') {
        failWith(
          `the disk holding ${resolve(dir)} filled up, so nothing was kept`,
          `Free some space, then:  ${color.bold(`${cmd()} recv`)}`,
        );
      }
      throw err;
    }
  }

  return failWith(
    `gave up finding a free name for ${name} in ${resolve(dir)} after 10000 tries`,
    `Empty that directory or use  ${color.bold(`${cmd()} recv --out DIR`)}`,
  );
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks);
}

// ---------------------------------------------------------------------------
// Which address can the other machine actually reach
// ---------------------------------------------------------------------------

// An adapter with an address the other machine cannot possibly route to. These
// are the ones that waste the most time, because they look exactly like a LAN
// address and fail with a timeout rather than an error.
const VIRTUAL_IFACE = /docker|^br-|^veth|virbr|vmnet|vboxnet|^bridge\d|vethernet|hyper-v|default switch|\bwsl\b/i;
const VPN_IFACE = /tailscale|^utun|^tun\d|^tap\d|^wg\d|wireguard|zerotier|^ppp|nordlynx|proton|openvpn/i;

/**
 * Rank, low first. The ordering is the whole point: a stranger tries the top
 * line, and if the top line is a docker bridge they conclude the tool is
 * broken rather than that they picked the wrong one of five addresses.
 */
function classify(address, ifaceName) {
  const octets = address.split('.').map(Number);
  const [a, b] = octets;
  const iface = String(ifaceName || '');

  if (VPN_IFACE.test(iface)) return { rank: 4, label: 'VPN, works only if both machines are on it' };
  if (VIRTUAL_IFACE.test(iface)) return { rank: 7, label: 'virtual adapter, another machine cannot reach this' };

  if (a === 192 && b === 168) return { rank: 0, label: 'home or office network' };
  if (a === 10) return { rank: 1, label: 'private network' };
  if (a === 172 && b >= 16 && b <= 31) return { rank: 2, label: 'private network, often a container bridge' };
  if (a === 100 && b >= 64 && b <= 127) return { rank: 5, label: 'Tailscale or carrier NAT' };
  if (a === 169 && b === 254) return { rank: 8, label: 'link local, no DHCP here, usually a dead end' };
  return { rank: 6, label: 'public address, needs the port open on your router' };
}

/**
 * Every non loopback IPv4, ordered most likely to work first and labelled.
 * Loopback is excluded outright: printing 127.0.0.1 as something to type on
 * the other machine is a guaranteed timeout and a lie.
 */
function reachableAddresses() {
  const found = [];
  for (const [ifaceName, entries] of Object.entries(networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.family !== 'IPv4' || entry.internal) continue;
      found.push({ address: entry.address, ...classify(entry.address, ifaceName) });
    }
  }
  found.sort((x, y) => x.rank - y.rank || x.address.localeCompare(y.address));
  return found;
}

/**
 * @param {number} port
 * @param {(address: string) => string} makeCommand full command for one address
 */
function printReach(port, makeCommand) {
  const suffix = port === DEFAULT_PORT ? '' : `:${port}`;
  const addresses = reachableAddresses();

  if (addresses.length === 0) {
    say('This machine has no network address, so no other machine can reach it.');
    say('Join a wifi network and run this again. To try it against itself, here only:');
    say(`  ${color.bold(makeCommand(`127.0.0.1${suffix}`))}   ${color.dim('same machine only')}`);
    return;
  }

  say('Run one of these on the other machine. Try the top one first:');
  const width = Math.max(...addresses.map((a) => makeCommand(a.address + suffix).length));
  for (const entry of addresses) {
    const line = makeCommand(entry.address + suffix);
    say(`  ${color.bold(line.padEnd(width))}   ${color.dim(entry.label)}`);
  }
  say('');
  say(color.dim(`If that says command not found over there, run  ${INSTALL_LINE}  on that machine first.`));
  const note = pathNote();
  if (note) say(color.yellow(note));
}

// ---------------------------------------------------------------------------
// Shared rendering
// ---------------------------------------------------------------------------

/** Dates in this tool are for a human placing an event, not for parsing. */
function whenText(iso) {
  if (!iso) return 'unknown';
  const text = String(iso);
  return text.length >= 10 ? text.slice(0, 10) : text;
}

/**
 * Enough hex to name one peer in a command, not enough to mistake for the whole
 * identity. 12 characters is 48 bits, which no accident collides with, and the
 * full 32 are always one `ratchet peers --json` away.
 */
function shortHex(hex) {
  return String(hex ?? '').slice(0, 12);
}

function verifyHint(hex) {
  return `${cmd()} peers verify ${shortHex(hex)} --label NAME`;
}

/**
 * The four states, on screen. Everything here is drawn from the 16 colour
 * palette in cli/format.mjs and nothing here is wider than the banner it sits
 * under, because this is the same block of output, not a new one.
 */
function renderTrust(verdict, peerWords) {
  if (verdict.state === 'verified') {
    const name = verdict.entry.label ?? shortHex(verdict.entry.hex);
    say(
      `  ${color.dim('trust        ')}  ${color.green('verified')} ${color.bold(name)}` +
        `  ${color.dim(`confirmed ${whenText(verdict.entry.verifiedAt)}`)}`,
    );
    // Quiet on purpose. A verified key arriving from an address it has never
    // used before is a laptop on a different network, which is a Tuesday. The
    // key is what was verified and the key has not changed, so this is a note
    // and never a warning. See classifyPeer in cli/peers.mjs.
    if (verdict.newAddress) {
      say(`  ${color.dim('             ')}  ${color.dim(`first time from ${verdict.address}, same key as always`)}`);
    }
    return;
  }

  if (verdict.state === 'changed') {
    const was = verdict.conflict;
    const wasName = was.label ?? shortHex(was.hex);
    say('');
    say(color.red(color.bold(`  !!  THE KEY AT ${verdict.address} IS NOT THE ONE YOU VERIFIED  !!`)));
    say('');
    say(`  ${color.dim(`verified ${whenText(was.verifiedAt)} as`)} ${color.bold(wasName)}`);
    say(`    ${words(was.words || 'no words recorded')}  ${color.dim(shortHex(was.hex))}`);
    say(`  ${color.dim('answering right now')}`);
    say(`    ${words(peerWords)}  ${color.dim(shortHex(verdict.hex))}`);
    say('');
    say(color.red('  Anything already sent in this session went to the NEW key.'));
    say(color.red('  Assume whoever holds that key has read it.'));
    say('');
    say(`  ${color.dim('From this side a reinstalled laptop and a machine in the middle look exactly')}`);
    say(`  ${color.dim('the same. Only the other person can tell you which it is. Reach them some')}`);
    say(`  ${color.dim(`other way, not through this connection, and ask them to run  ${cmd()} id`)}`);
    say(`  ${color.dim('and read their six words to you.')}`);
    say('');
    say(`  ${color.dim('Then type one of these in full:')}`);
    say(`    ${color.bold(verifyHint(verdict.hex))}`);
    say(`      ${color.dim('the words matched, trust this new key from now on')}`);
    say(`    ${color.bold(`${cmd()} peers forget ${shortHex(was.hex)}`)}`);
    say(`      ${color.dim('drop the old record and decide later')}`);
    say('');
    return;
  }

  const lead = verdict.state === 'new' ? 'first time' : 'seen before, not verified';
  say(`  ${color.dim('trust        ')}  ${lead}`);
  say(`  ${color.dim('             ')}  ${color.dim('read the words above aloud with them. same words on both screens')}`);
  say(`  ${color.dim('             ')}  ${color.dim('means nobody is in the middle. then, to remember it:')}`);
  say(`  ${color.dim('             ')}  ${color.bold(verifyHint(verdict.hex))}`);
}

/**
 * The trust store as the commands use it: load before the handshake, classify
 * and print inside it, write after.
 *
 * That order is not incidental.
 *
 * Classification must run against the store as it was BEFORE this sighting, or
 * the address gets filed under today's key and is then asked whether it
 * conflicts with itself, which it never does. Recording first would disable the
 * alarm completely, and it would look like it worked.
 *
 * The print must be synchronous, because onHandshake is fired and forgotten by
 * the protocol layer. An async render would land its output somewhere in the
 * middle of a progress bar, or after the transfer had already finished, which
 * is far too late for a warning whose entire job is to give somebody the chance
 * to press Ctrl+C.
 *
 * A store that will not load costs the trust check and says so out loud. It does
 * not cost the transfer: the six words still print, which is exactly what this
 * tool offered before the store existed. Degrading silently would be the
 * unacceptable version, because a peers file that anyone can corrupt would then
 * be a peers file that anyone can switch off.
 */
async function openTrust(address) {
  let store = null;
  let broken = null;
  try {
    store = await loadPeers();
  } catch (err) {
    broken = err;
  }
  let seen = null;

  function stage() {
    recordSighting(store, { hex: seen.hex, words: seen.words, address });
  }

  return {
    /** Sync by contract. Called from inside onHandshake, where nothing awaits. */
    observe({ peerHex, peerWords }) {
      if (!peerHex) return;
      if (broken) {
        say(`  ${color.dim('trust        ')}  ${color.yellow('unavailable')} ${color.dim(broken.message)}`);
        return;
      }
      const verdict = classifyPeer(store, { hex: peerHex, address });
      seen = { hex: peerHex, words: peerWords };
      renderTrust(verdict, peerWords);
    },
    /** Deferred until the work is done, so a write cannot delay the warning. */
    async commit() {
      if (!store || !seen) return;
      try {
        stage();
        await savePeers(store);
      } catch (err) {
        say(color.yellow(`could not update ${peersFile()}: ${err.message}`));
      }
    },
    /**
     * The seam cli/chat.mjs calls for /verify. It records the sighting first,
     * because during a live chat the commit has not happened yet and there may
     * be no row to mark.
     */
    async verify(label) {
      if (broken) throw broken;
      if (!seen) throw new Error('no handshake has completed yet');
      stage();
      const entry = markVerified(store, { hex: seen.hex, label });
      await savePeers(store);
      const name = entry.label ?? shortHex(entry.hex);
      return `${name} is now verified. ${peersFile()} remembers this key, not the conversation.`;
    },
  };
}

function handshakeBanner(trust) {
  return ({ peerWords, sessionWords, peerHex }) => {
    // Two rows of six, one per fingerprint. The label sits on the first and the
    // second is indented to line up under it, so the twelve words read as one
    // block rather than as two unrelated things.
    const lines = splitPairWords(sessionWords);
    say(`  ${color.dim('compare aloud')}  ${words(lines[0])}`);
    for (const line of lines.slice(1)) say(`  ${' '.repeat(13)}  ${words(line)}`);
    say(`  ${color.dim('peer identity')}  ${words(peerWords)}`);
    if (trust) trust.observe({ peerHex, peerWords });
  };
}

function renderResult({ verb, name, stats, extra, showStats }) {
  const tail = extra ? ` ${color.dim(`-> ${extra}`)}` : '';
  // A rate is meaningless on a payload this small: it is all handshake, and
  // "0.00 MB/s" next to a one line message just looks like a bug.
  const rate = stats.plainBytes >= 1e6 ? `  ${color.dim(`${stats.throughputMBs.toFixed(2)} MB/s`)}` : '';
  say('');
  say(
    `${color.green(verb)} ${color.bold(name)}  ${humanBytes(stats.plainBytes)} in ${humanMs(stats.wallMs)}` +
      `${rate}${tail}`,
  );
  // The table is an addition, not a replacement. Where the file landed is the
  // one fact a receiver always needs, and it only appears on the short line.
  if (showStats) {
    say('');
    say(statsTable(stats, { direction: verb === 'sent' ? 'sent' : 'received' }));
  }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/**
 * Binding is where the two failures a user cannot diagnose alone live, so
 * both get named and answered rather than surfacing as a raw errno.
 */
async function bind(port) {
  try {
    return await listen({ port });
  } catch (err) {
    if (err.code === 'EADDRINUSE') {
      failWith(
        `port ${port} on this machine is already in use, probably by another ratchet`,
        `Pick another one:  ${color.bold(`${cmd()} recv --port ${port + 1}`)}`,
        `Then the sender uses  ${color.bold(`--to HOST:${port + 1}`)}`,
      );
    }
    if (err.code === 'EACCES') {
      failWith(
        `not allowed to listen on port ${port}, ports below 1024 need administrator rights`,
        `Use a high port instead:  ${color.bold(`${cmd()} recv --port ${DEFAULT_PORT}`)}`,
      );
    }
    throw err;
  }
}

async function outDirectory(opts) {
  const outDir = resolve(opts.out ?? process.cwd());
  try {
    await mkdir(outDir, { recursive: true });
  } catch (err) {
    failWith(
      `cannot use ${outDir} as the output directory: ${err.code ?? err.message}`,
      `Pick one you can write to:  ${color.bold(`${cmd()} recv --out ~/Downloads`)}`,
    );
  }
  return outDir;
}

async function cmdRecv(opts) {
  const port = opts.port === undefined ? DEFAULT_PORT : parsePort(opts.port, '--port');
  const outDir = await outDirectory(opts);

  const identity = await openIdentity();
  const myWords = formatFingerprint(fingerprint(identity));

  // No host, so Node binds every interface. Which address the sender can
  // actually reach is exactly what the user does not know, hence the list.
  const server = await bind(port);

  say(
    box('ratchet recv', [
      `you        ${words(myWords)}`,
      `identity   ${color.dim(identityFile())}`,
      `port       ${color.dim(String(server.port))}`,
      `saving to  ${color.dim(outDir)}`,
    ]),
  );
  say('');
  printReach(server.port, (address) => `${cmd()} send FILE --to ${address}`);
  say('');
  say(color.dim('Waiting for a sender. Ctrl-C to stop.'));

  let failures = 0;
  for await (const channel of server) {
    let failed = null;
    try {
      await receiveOne({ channel, identity, outDir, opts });
    } catch (err) {
      failed = err;
      reportError(err);
    } finally {
      await closeQuietly(channel);
    }

    if (opts.once) {
      // --once means one transfer, not one connection. Anything that opens a
      // socket and then goes away without transferring is not the sender we
      // are waiting for: a port scan, a monitoring probe, a peer whose link
      // dropped before the handshake. Exiting on those turns a listener into
      // something a single stray TCP connect can switch off, and the person
      // waiting for the file has no idea it happened. So keep listening.
      //
      // A crypto failure is the one exception, and it exits. That is not a
      // stranger knocking, it is somebody who reached the handshake and
      // produced bytes that did not verify. Looping there would hand an
      // attacker unlimited attempts against a listener the user believes is
      // waiting for one file, so it stops and says so.
      if (!failed) {
        await closeQuietly(server);
        return 0;
      }
      if (isCrypto(failed)) {
        await closeQuietly(server);
        return 2;
      }
      failures += 1;
      say('');
      say(color.dim('Waiting for a sender. Ctrl-C to stop.'));
      continue;
    }
    if (failed) failures += 1;
    say('');
    say(color.dim('Waiting for the next sender. Ctrl-C to stop.'));
  }
  return failures > 0 ? 1 : 0;
}

/**
 * Close a socket or a server, but never wait forever for it.
 *
 * A graceful close waits for the peer to acknowledge, and a peer that has
 * already walked away never does. Observed in practice: about one `recv --once`
 * in three finished the transfer, wrote the file, printed the result, and then
 * sat on the close for as long as it was left running. The transfer is done at
 * that point, so a socket that will not shut down politely is not a reason to
 * hold a human hostage. Two seconds, then move on.
 */
async function closeQuietly(handle) {
  if (!handle) return;
  let timer;
  try {
    await Promise.race([
      Promise.resolve(handle.close()).catch(() => {}),
      new Promise((resolve) => {
        timer = setTimeout(resolve, 2000);
      }),
    ]);
  } catch {
    /* a close that throws has still stopped being our problem */
  } finally {
    clearTimeout(timer);
  }
}

async function receiveOne({ channel, identity, outDir, opts }) {
  say('');
  say(`Connection from ${color.bold(channel.remote)}`);

  // Loaded per connection, not per process. `recv` without `--once` can sit
  // there for days, and a peers file edited in another terminal in the meantime
  // should be the one that gets consulted.
  const trust = await openTrust(addressOf(channel.remote));

  const received = await receivePayload({
    channel,
    identity,
    onProgress: makeProgress('receiving'),
    // Fires the moment the handshake lands, which is the whole reason it
    // exists: the words have to be on screen while the bytes are still moving,
    // not after, or there is nothing left to abort.
    onHandshake: handshakeBanner(trust),
  });
  clearProgress();
  await trust.commit();

  const written = await writeNoClobber(outDir, received.name, received.bytes);
  // Deliberately the sanitised name and never the raw one. The raw name came
  // off the network and could carry escape sequences that repaint this line.
  renderResult({
    verb: 'received',
    name: written.name,
    stats: received.stats,
    extra: written.path,
    showStats: Boolean(opts.stats),
  });

  if (written.sanitisedFrom) {
    say(
      `${color.yellow('renamed')} the sender asked for ${color.bold(quoteRaw(written.sanitisedFrom))}, ` +
        `which is not a name this will write. Saved as ${color.bold(written.name)} instead.`,
    );
  }

  if (written.renamedFrom) {
    say(
      `${color.yellow('renamed')} ${written.renamedFrom} already existed here, so this one is ` +
        `${color.bold(written.name)}. Nothing was overwritten.`,
    );
  }

  echoTextMessage(written.name, received.bytes);
  if (looksSecret(written.name)) warnSecret(written.name, written.path);
  if (jsonMode) {
    emit({
      direction: 'received',
      name: written.name,
      path: written.path,
      // Escaped, not raw. A --json consumer that prints this field back to a
      // terminal would otherwise inherit the escape sequence problem.
      requestedName: written.sanitisedFrom ? escapeRaw(written.sanitisedFrom) : null,
      renamedFrom: written.renamedFrom,
      secret: looksSecret(written.name),
      ...received.stats,
    });
  }
}

// Same range as CONTROL_CHARS but tab survives, because a pasted config file
// is full of them and stripping them mangles what the sender meant to show.
const ECHO_STRIP = new RegExp('[\\u0000-\\u0008\\u000b-\\u001f\\u007f]', 'g');

/** A text send is useless if the reader has to go and open a file for it. */
function echoTextMessage(name, bytes) {
  if (name !== TEXT_NAME || bytes.length === 0 || bytes.length > TEXT_ECHO_LIMIT) return;
  const text = Buffer.from(bytes).toString('utf8');
  // A replacement character means the bytes were not UTF-8, so this is a
  // binary payload that happens to carry the text name. Do not paint it.
  if (text.includes('\ufffd')) return;
  say('');
  // Escape sequences are stripped for the same reason the filename is
  // sanitised: this content is chosen by whoever is on the other end.
  say(box('message', text.split('\n').map((line) => line.replace(ECHO_STRIP, ''))));
}

/** Wraps connect() so every reason a connection fails ends with a fix. */
async function dial(host, port) {
  try {
    return await connect({ host, port, timeoutMs: 10000 });
  } catch (err) {
    const recv = port === DEFAULT_PORT ? `${cmd()} recv` : `${cmd()} recv --port ${port}`;
    switch (codeOf(err)) {
      case 'ECONNREFUSED':
        return failWith(
          `nothing is listening on ${host}:${port}`,
          'The receiving machine has probably not started yet. Over there, run:',
          `  ${color.bold(recv)}`,
          'Then run this send command again.',
        );
      case 'ENOTFOUND':
      case 'EAI_AGAIN':
        return failWith(
          `cannot look up the name ${host}`,
          `Use the IP address that  ${color.bold(recv)}  printed on the other machine instead.`,
        );
      case 'EHOSTUNREACH':
      case 'ENETUNREACH':
        return failWith(
          `no route from here to ${host}`,
          'The two machines are not on the same network. Put them on the same wifi, or',
          `use the address that  ${color.bold(recv)}  printed over there.`,
        );
      case 'ETIMEDOUT':
        return failWith(
          `${host}:${port} never answered`,
          'Usually a firewall dropping it, or the wrong one of several addresses.',
          `Run  ${color.bold(recv)}  on the other machine and try the next address it lists.`,
        );
      default:
        if (/timed out/.test(String(err.message))) {
          return failWith(
            `${host}:${port} never answered within 10 seconds`,
            'Usually a firewall dropping it, or the wrong one of several addresses.',
            `Run  ${color.bold(recv)}  on the other machine and try the next address it lists.`,
          );
        }
        err.hint = [`Check the receiver is up:  ${color.bold(recv)}`];
        throw err;
    }
  }
}

async function cmdSend(opts, rest) {
  if (!opts.to) {
    usageError(
      'send needs --to HOST or --to HOST:PORT',
      `On the other machine run  ${color.bold(`${cmd()} recv`)}  and it prints the exact line to use.`,
    );
  }
  const { host, port } = parseTo(opts.to);
  const chunkSize = parseChunk(opts.chunk);

  const hasText = typeof opts.text === 'string';
  const pathArg = rest[0];
  if (rest.length > 1) usageError(`send takes one path, got ${rest.length}`);
  if (hasText && pathArg) usageError('give a PATH or --text, not both');
  if (!hasText && !pathArg) {
    usageError(
      'send needs a PATH, or --text "message", or - to read stdin',
      `For example:  ${color.bold(`${cmd()} send .env --to ${host}`)}`,
    );
  }

  let name;
  let bytes;
  if (hasText) {
    name = TEXT_NAME;
    bytes = Buffer.from(opts.text, 'utf8');
  } else if (pathArg === '-') {
    name = TEXT_NAME;
    bytes = await readStdin();
  } else {
    const full = resolve(pathArg);
    try {
      bytes = await readFile(full);
    } catch (err) {
      if (err.code === 'ENOENT') {
        failWith(
          `no such file: ${full}`,
          'That is the exact path this looked for. Check the spelling, or cd to where the file is.',
          `Then:  ${color.bold(`${cmd()} send ${basename(pathArg)} --to ${opts.to}`)}`,
        );
      }
      if (err.code === 'EISDIR') {
        failWith(
          `${full} is a directory, and this sends one file at a time`,
          `Tar it first:  ${color.bold(`tar czf out.tgz ${pathArg} && ${cmd()} send out.tgz --to ${opts.to}`)}`,
        );
      }
      if (err.code === 'EACCES' || err.code === 'EPERM') {
        failWith(`not allowed to read ${full}`, 'Check the file permissions, or run this as the user that owns it.');
      }
      throw err;
    }
    name = basename(pathArg);
  }

  const identity = await openIdentity();
  // The host as typed, without the port. The dialling side has no better handle
  // on where it is calling, and the port here is the listener's, not the peer's.
  const trust = await openTrust(host);
  say(`Connecting to ${color.bold(`${host}:${port}`)}`);
  const channel = await dial(host, port);

  try {
    const stats = await sendPayload({
      channel,
      identity,
      name,
      bytes,
      chunkSize,
      onProgress: makeProgress('sending'),
      onHandshake: handshakeBanner(trust),
    });
    clearProgress();
    await trust.commit();
    renderResult({ verb: 'sent', name, stats, extra: `${host}:${port}`, showStats: Boolean(opts.stats) });
    if (jsonMode) emit({ direction: 'sent', name, to: `${host}:${port}`, ...stats });
    return 0;
  } finally {
    await closeQuietly(channel);
  }
}

/**
 * cli/chat.mjs is loaded on demand rather than imported at the top of this
 * file. A static import of a module that is absent from a given build takes
 * every other command down with it, and `ratchet send` should not stop working
 * because chat is missing.
 */
async function loadChat() {
  try {
    const mod = await import('../cli/chat.mjs');
    if (typeof mod.runChat !== 'function') throw new Error('cli/chat.mjs does not export runChat');
    return mod.runChat;
  } catch (cause) {
    const err = new Error('chat is not available in this build');
    err.cause = cause;
    err.hint = [
      'cli/chat.mjs failed to load. File transfer still works:',
      `  ${color.bold(`${cmd()} recv`)}`,
      `  ${color.bold(`${cmd()} send FILE --to HOST`)}`,
    ];
    throw err;
  }
}

async function cmdChat(opts, rest) {
  if (rest.length > 0) usageError(`chat takes no arguments, got ${rest[0]}`);
  const runChat = await loadChat();
  const identity = await openIdentity();
  // In --json mode stdout belongs to the JSON line, so the conversation goes
  // to stderr instead of corrupting it.
  const out = jsonMode ? process.stderr : process.stdout;

  let channel;
  let server = null;
  let address = null;
  if (opts.to) {
    const { host, port } = parseTo(opts.to);
    address = host;
    say(`Connecting to ${color.bold(`${host}:${port}`)}`);
    channel = await dial(host, port);
  } else {
    const port = opts.port === undefined ? DEFAULT_PORT : parsePort(opts.port, '--port');
    const myWords = formatFingerprint(fingerprint(identity));
    server = await bind(port);
    say(box('ratchet chat', [`you     ${words(myWords)}`, `port    ${color.dim(String(server.port))}`]));
    say('');
    printReach(server.port, (address) => `${cmd()} chat --to ${address}`);
    say('');
    say(color.dim('Waiting for the other person. Ctrl-C to stop.'));

    channel = null;
    for await (const incoming of server) {
      channel = incoming;
      break;
    }
    // Chat is one conversation, so stop accepting the moment one arrives.
    await closeQuietly(server);
    if (!channel) return 1;
    address = addressOf(channel.remote);
    say('');
    say(`Connected to ${color.bold(channel.remote)}`);
  }

  const trust = await openTrust(address);
  const banner = handshakeBanner(trust);

  // The chat screen needs the trust verdict as data, not as printed lines, and
  // openTrust keeps its store private. There must be exactly one classifier and
  // it lives in cli/peers.mjs, so this asks that same function rather than
  // growing a second opinion. This copy is never written to, which also makes
  // it the pre-sighting view classification has to be made against.
  let peerStore = null;
  try {
    peerStore = await loadPeers();
  } catch {
    peerStore = null;
  }

  try {
    const result = await runChat({
      channel,
      identity,
      stdin: process.stdin,
      stdout: out,
      onHandshake: (info) => {
        banner(info);
        if (!peerStore || !info.peerHex) return null;
        try {
          return classifyPeer(peerStore, { hex: info.peerHex, address });
        } catch {
          return null;
        }
      },
      // The seam for /verify. runChat owns the question and the answer, this
      // owns the disk, and neither has to know how the other works.
      onVerify: ({ label }) => trust.verify(label),
    });
    await trust.commit();
    const sent = result && Number.isFinite(result.sent) ? result.sent : 0;
    const received = result && Number.isFinite(result.received) ? result.received : 0;
    say('');
    say(
      `${color.green('chat over')}  sent ${sent}, received ${received}. ` +
        'No message was written to disk.',
    );
    if (jsonMode) emit({ direction: 'chat', sent, received });
    return 0;
  } finally {
    await closeQuietly(channel);
    await closeQuietly(server);
  }
}

async function cmdId(opts) {
  if (opts.reset) {
    if (!opts.yes) {
      usageError(
        'ratchet id --reset throws away your identity for good, and your peer list with it. ' +
          'Every peer that has ever verified your safety words will see different ones and ' +
          'cannot tell that from an attacker. You also lose every verification you have done, ' +
          'so every peer goes back to being a first time stranger.',
        `If that is really what you want:  ${color.bold(`${cmd()} id --reset --yes`)}`,
      );
    }
    const path = identityFile();
    // The peer list goes with it, and this is the point rather than a courtesy.
    // Those rows were collected under the identity being destroyed, and they are
    // the only thing in RATCHET_HOME that names anybody. Leaving them behind
    // meant "start over" quietly kept a dated list of who this machine has
    // talked to, sealed under a vault key that reset does not touch, so it stayed
    // readable to exactly the person doing the reset to get rid of it. Reset now
    // means the home holds no record of any conversation, which is what the word
    // promises.
    const peers = peersFile();
    await resetIdentity();
    await resetPeers();
    say(`${color.yellow('discarded')} ${path}`);
    say(`${color.yellow('discarded')} ${peers}`);
    say(color.dim('A new identity, with new safety words, is minted on the next command.'));
    if (jsonMode) emit({ reset: true, identityFile: path, peersFile: peers });
    return 0;
  }

  await noteInterrupted();
  const identity = await openIdentity();
  // fingerprint() returns { words, hex }, not raw bytes. Scripts get the hex
  // because it carries more bits than the six words do.
  const print = fingerprint(identity);
  const myWords = formatFingerprint(print);
  const state = await vaultState();
  say(
    box('ratchet id', [
      `words     ${words(myWords)}`,
      `identity  ${color.dim(identityFile())}`,
      `at rest   ${atRestLine(state.protection)}`,
    ]),
  );
  if (state.protection === 'none') {
    say('');
    say(
      color.dim(
        `Anyone who copies that file can be you. To need a passphrase instead:  ${color.bold(`${cmd()} lock`)}`,
      ),
    );
  }
  if (jsonMode) emit({ words: myWords, hex: print.hex, identityFile: identityFile(), protection: state.protection });
  return 0;
}

/**
 * Say so, once, if a previous `lock` or `unlock` did not finish.
 *
 * The sidecar is only ever left behind by a crash between the first file write
 * and the descriptor write, so its presence is the single fact worth surfacing:
 * the files on disk may be wrapped under a key the descriptor does not name,
 * and the copies that predate the attempt are sitting in one place.
 */
async function noteInterrupted() {
  const left = await readRollback();
  if (!left) return;
  say(`${color.yellow('interrupted')} ${color.dim('a previous lock or unlock did not finish')}`);
  say(color.dim(`The files as they were before it started:  ${rollbackFile()}`));
  say(color.dim('If everything below reads correctly, that file is safe to delete.'));
  say('');
}

/** The one line `ratchet id` gains, and the only place protection is named. */
function atRestLine(protection) {
  if (protection === 'none') return `${color.yellow('unprotected')} ${color.dim('plain file, no key needed to read it')}`;
  if (protection === 'pass') return `${color.green('passphrase')}  ${color.dim('asked for on every command')}`;
  return `${color.green('sealed')}      ${color.dim(`key held by ${describeProtection(protection)}`)}`;
}

/**
 * loadIdentity, plus the one sentence it may have to say about a file it
 * rewrote without being asked. A migration that happens silently is a
 * migration nobody can audit.
 */
async function openIdentity() {
  const identity = await loadIdentity();
  const notice = takeMigrationNotice();
  if (notice) say(color.dim(notice));
  return identity;
}

// ---------------------------------------------------------------------------
// lock and unlock
// ---------------------------------------------------------------------------

/**
 * The two files this tool leaves on disk, read out under the CURRENT key and
 * written back under a NEW one, with a rollback copy in between.
 *
 * The order is the whole of the safety. Everything is read first, so a failure
 * to open anything aborts before a single byte moves. The rollback sidecar is
 * written second, so a crash from here on is recoverable by hand. The
 * descriptor goes LAST, because it is the only thing that decides which key a
 * later run will reach for: while it still names the old protection, the old
 * files are still openable, and once it names the new one the new files are.
 */
async function reprotect({ descriptor, key }) {
  const before = await vaultState();
  const token = await readIdentityToken();

  let store = null;
  try {
    store = await loadPeers();
  } catch (err) {
    failWith(
      `the peer store will not open, so nothing was changed: ${err.message}`,
      `Move it aside and run this again:  ${color.bold(`mv ${peersFile()} ${peersFile()}.broken`)}`,
    );
  }

  const identityBefore = token === null ? null : await readFile(identityFile(), 'utf8').catch(() => null);
  const peersBefore = await readFile(peersFile(), 'utf8').catch(() => null);
  await writeRollback({
    why: 'ratchet lock or unlock was interrupted. These are the files as they were before it started.',
    descriptor: before.descriptor,
    identity: identityBefore,
    peers: peersBefore,
  });

  if (token !== null) await rewrapIdentity(token, descriptor.protection, key);
  if (peersBefore !== null || Object.keys(store.peers).length > 0) {
    await savePeers(store, { key, protection: descriptor.protection });
  }
  await commitDescriptor(descriptor, key, before.descriptor);
  await clearRollback();
  return before;
}

async function cmdLock(opts) {
  if (opts.reset) usageError('lock takes no --reset');
  const state = await vaultState();
  // Resolve the CURRENT key before asking for a new one, so that re-locking
  // does not print "new passphrase" and then "passphrase" and leave a person
  // guessing which of the two the second prompt means.
  if (state.protection !== 'none') await readIdentityToken();

  // The environment variable is the deliberate channel for a machine with no
  // human at it. A prompt that quietly reads a pipe is the failure this avoids:
  // it would set somebody's passphrase to the next line of their own script.
  const fromEnv = process.env.RATCHET_NEW_PASSPHRASE;
  let passphrase;
  if (typeof fromEnv === 'string' && fromEnv.length > 0) {
    passphrase = fromEnv;
  } else {
    say(color.dim('Nothing on this machine can recover a forgotten passphrase. Write it down somewhere real.'));
    passphrase = await readPassphrase('new passphrase: ');
    if (passphrase.length === 0) failWith('an empty passphrase is not one, so nothing was changed');
    const again = await readPassphrase('again: ');
    if (again !== passphrase) failWith('those two do not match, so nothing was changed');
  }
  if (passphrase.length === 0) failWith('an empty passphrase is not one, so nothing was changed');

  const { descriptor, key } = passphraseDescriptor(passphrase);
  const before = await reprotect({ descriptor, key });

  const what = state.protection === 'pass' ? 'changed' : 'locked';
  say(`${color.green(what)} ${color.dim(identityFile())}`);
  say(
    color.dim(
      before.protection === 'none'
        ? 'Both files were readable by anyone who could read the directory. They are not now.'
        : `The key was held by ${describeProtection(before.protection)}. It is a passphrase now.`,
    ),
  );
  say(color.dim('Every command from here asks for it once.'));
  if (jsonMode) emit({ protection: 'pass', vaultFile: vaultFile() });
  return 0;
}

async function cmdUnlock() {
  const state = await vaultState();
  if (state.protection !== 'pass') {
    say(`${color.dim('nothing to unlock.')} At rest, this identity is ${describeProtection(state.protection)}.`);
    say(color.dim(`Only a passphrase can be removed, and there is none. ${color.bold(`${cmd()} id`)} shows the state.`));
    if (jsonMode) emit({ protection: state.protection, changed: false });
    return 0;
  }

  // Resolving the identity token is what asks for the current passphrase, and
  // getting it wrong stops here, before anything is written.
  const { descriptor, key } = await plainOrKeychainDescriptor();
  await reprotect({ descriptor, key });

  say(`${color.green('unlocked')} ${color.dim(identityFile())}`);
  say(
    color.dim(
      descriptor.protection === 'none'
        ? 'There is no keychain on this machine, so both files are now plain. Anyone who copies them can be you.'
        : `The key is held by ${describeProtection(descriptor.protection)} now, and nothing will ask you for it.`,
    ),
  );
  if (jsonMode) emit({ protection: descriptor.protection, changed: true });
  return 0;
}

/**
 * One line typed in full, read from the terminal.
 *
 * The prompt goes to stderr so that `--json` keeps a clean stdout, and the
 * answer is compared against the whole word. Nothing here accepts a bare `y`,
 * and nothing here treats an empty line as agreement, because the question is
 * "did you compare six words with a human" and only the human knows.
 */
async function askLine(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
  try {
    return await new Promise((resolve) => rl.question(question, resolve));
  } finally {
    rl.close();
  }
}

/**
 * Resolve a label or hex prefix to exactly one peer, or explain why it did not.
 *
 * Ambiguity is an error rather than a guess. These commands change who this
 * machine trusts, and picking the first of two matches is how the wrong row
 * gets marked verified.
 */
function onePeer(store, query) {
  const matches = findPeers(store, query);
  if (matches.length === 0) {
    failWith(
      `no peer matches ${query}`,
      `See what is known:  ${color.bold(`${cmd()} peers`)}`,
    );
  }
  if (matches.length > 1) {
    failWith(
      `${query} matches ${matches.length} peers`,
      'Use more of the hex, which is unique:',
      ...matches.map((p) => `  ${color.bold(shortHex(p.hex))}  ${p.label ?? color.dim('no label')}`),
    );
  }
  return matches[0];
}

function peersList(store) {
  const all = listPeers(store);
  if (jsonMode) {
    emit({ peersFile: peersFile(), peers: all });
    if (all.length === 0) return 0;
  }
  say(box('ratchet peers', [`known   ${color.bold(String(all.length))}`, `file    ${color.dim(peersFile())}`]));
  if (all.length === 0) {
    say('');
    say(color.dim('Nobody yet. This fills in the first time a send, recv or chat completes.'));
    return 0;
  }
  say('');
  for (const peer of all) {
    const mark = peer.verified ? color.green('verified  ') : color.dim('unverified');
    const name = peer.label ? color.bold(peer.label) : color.dim('no label');
    say(`  ${mark}  ${color.bold(shortHex(peer.hex))}  ${name}`);
    say(`              ${words(peer.words || color.dim('no words recorded'))}`);
    const seenAt = peer.addresses.length > 0 ? peer.addresses.join(', ') : 'nowhere recorded';
    say(`              ${color.dim(`last seen ${whenText(peer.lastSeen)} from ${seenAt}`)}`);
    say('');
  }
  say(color.dim(`Verify one:  ${color.bold(`${cmd()} peers verify HEX --label NAME`)}`));
  say(color.dim(`Drop one:    ${color.bold(`${cmd()} peers forget HEX`)}`));
  return 0;
}

async function cmdPeers(opts, rest) {
  const [sub, ...args] = rest;
  let store;
  try {
    store = await loadPeers();
  } catch (err) {
    failWith(
      err.message,
      'Nothing else is affected: this file only remembers who you have talked to.',
      `Move it aside and this rebuilds itself:  ${color.bold(`mv ${peersFile()} ${peersFile()}.broken`)}`,
    );
  }

  if (sub === undefined || sub === 'list') {
    if (args.length > 0) usageError(`peers list takes no arguments, got ${args[0]}`);
    return peersList(store);
  }

  if (sub === 'forget') {
    const query = args.join(' ').trim();
    if (!query) {
      usageError(
        'peers forget needs a label or a hex prefix',
        `See what is known:  ${color.bold(`${cmd()} peers`)}`,
      );
    }
    // The query is joined rather than taken as args[0], so a label with a space
    // in it needs no quoting.
    const peer = onePeer(store, query);
    forgetPeer(store, peer.hex);
    await savePeers(store);
    const name = peer.label ?? shortHex(peer.hex);
    say(`${color.yellow('forgotten')} ${color.bold(name)} ${color.dim(shortHex(peer.hex))}`);
    say(color.dim('The next connection from that key is a first meeting again, with no warning.'));
    if (jsonMode) emit({ forgot: peer.hex, label: peer.label ?? null });
    return 0;
  }

  if (sub === 'verify') {
    const query = args.join(' ').trim();
    if (!query) {
      usageError(
        'peers verify needs a label or a hex prefix',
        `The banner after a handshake prints the exact line to paste.`,
        `Or list them:  ${color.bold(`${cmd()} peers`)}`,
      );
    }
    const peer = onePeer(store, query);
    const label = typeof opts.label === 'string' ? opts.label.trim() : '';

    // The whole point of the six words is that a person said them out loud to
    // another person. Nothing on this machine can check that, so the only
    // honest implementation is to ask, and to take one answer.
    say('');
    say(`  ${color.bold(shortHex(peer.hex))}  ${words(peer.words || 'no words recorded')}`);
    say('');
    say(color.dim('  Have you read those six words aloud with that person, on a call or in the'));
    say(color.dim('  same room, and did they read back the same ones?'));
    say('');
    const answer = (await askLine('  Type yes to record that, anything else cancels: ')).trim();
    if (answer !== 'yes') {
      say(`${color.dim('not verified.')} Nothing was changed.`);
      if (jsonMode) emit({ verified: false, hex: peer.hex });
      return 1;
    }

    const entry = markVerified(store, { hex: peer.hex, label: label || peer.label });
    await savePeers(store);
    const name = entry.label ?? shortHex(entry.hex);
    say(`${color.green('verified')} ${color.bold(name)} ${color.dim(shortHex(entry.hex))}`);
    say(color.dim('A different key at that address will now be called out, loudly.'));
    if (jsonMode) emit({ verified: true, hex: entry.hex, label: entry.label });
    return 0;
  }

  usageError(
    `unknown peers command ${sub}`,
    `There are three:  ${color.bold('list')}, ${color.bold('verify')}, ${color.bold('forget')}.`,
  );
  return 1;
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

process.on('SIGINT', () => {
  clearProgress();
  if (partialPath) {
    try {
      unlinkSync(partialPath);
      process.stderr.write(`removed the partial file ${partialPath}\n`);
    } catch {
      /* nothing useful to say if the cleanup itself fails during a shutdown */
    }
  }
  process.stderr.write('interrupted\n');
  process.exit(130);
});

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  jsonMode = Boolean(opts.json);

  if (opts.version) {
    process.stdout.write(`${PKG.version}\n`);
    return 0;
  }

  const [command, ...rest] = opts._;

  if (opts.help) {
    process.stdout.write(`${HELP}\n`);
    return 0;
  }
  if (!command) {
    // Typing the bare name is the first thing a curious person does. Answering
    // that with an error and a page of flags is how a tool loses someone in
    // the first ten seconds, so this succeeds and stays short.
    process.stdout.write(`${splash()}\n`);
    return 0;
  }

  switch (command) {
    case 'recv':
    case 'receive':
      if (rest.length > 0) {
        usageError(
          `recv takes no arguments, got ${rest[0]}`,
          `Did you mean  ${color.bold(`${cmd()} send ${rest[0]} --to HOST`)} ?`,
        );
      }
      return cmdRecv(opts);
    case 'send':
      return cmdSend(opts, rest);
    case 'chat':
      return cmdChat(opts, rest);
    case 'id':
      if (rest.length > 0) usageError(`id takes no arguments, got ${rest[0]}`);
      return cmdId(opts);
    case 'peers':
      return cmdPeers(opts, rest);
    case 'lock':
      if (rest.length > 0) usageError(`lock takes no arguments, got ${rest[0]}`);
      return cmdLock(opts);
    case 'unlock':
      if (rest.length > 0) usageError(`unlock takes no arguments, got ${rest[0]}`);
      return cmdUnlock();
    default:
      usageError(
        `unknown command ${command}`,
        `There are seven:  ${color.bold('recv')}, ${color.bold('send')}, ${color.bold('chat')}, ` +
          `${color.bold('id')}, ${color.bold('peers')}, ${color.bold('lock')}, ${color.bold('unlock')}.`,
        `Run  ${color.bold(`${cmd()} --help`)}`,
      );
      return 1;
  }
}

/**
 * Wait until stdout and stderr have actually left the process, then leave.
 *
 * Returning from the top level is not enough. Roughly one run in six of
 * `recv --once` sat there forever with the transfer complete and the file on
 * disk, because a socket handle somewhere below survived server.close() and
 * kept the event loop alive. A tool that finishes its job and then hangs looks
 * broken and gets Ctrl-C'd, so the exit is explicit rather than hopeful.
 *
 * The flush matters: on a pipe both streams are asynchronous, and calling
 * process.exit() with bytes still queued drops them. That would silently eat
 * the last line of --json output when someone pipes into jq.
 */
async function finish(code) {
  for (const stream of [process.stdout, process.stderr]) {
    if (stream.writableLength > 0) {
      await new Promise((resolve) => {
        // A write error means the reader is gone, which is not worth stalling
        // for. Either way the wait ends.
        stream.once('drain', resolve);
        stream.once('error', resolve);
        setTimeout(resolve, 2000).unref();
      });
    }
  }
  process.exit(code);
}

let exitCode;
try {
  exitCode = await main();
} catch (err) {
  if (err instanceof UsageError) {
    process.stderr.write(`${color.red('usage')} ${err.message}\n`);
    const hint = Array.isArray(err.hint) && err.hint.length ? err.hint : [`Run ${color.bold(`${cmd()} --help`)}`];
    for (const line of hint) process.stderr.write(`      ${line}\n`);
    exitCode = 1;
  } else {
    reportError(err);
    exitCode = isCrypto(err) ? 2 : 1;
  }
}
await finish(exitCode);
