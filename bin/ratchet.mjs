#!/usr/bin/env node
// The ratchet CLI: move a file between two machines, end to end encrypted,
// with no server in the middle.
//
// This file owns exactly two jobs: turning argv into intent, and turning
// results into text. Every byte of crypto lives in cli/protocol.mjs and every
// byte of socket lives in cli/frame.mjs. Keeping that line sharp is what makes
// the security-relevant part reviewable without reading any of this.

import { readFileSync, unlinkSync } from 'node:fs';
import { mkdir, open, readFile, unlink } from 'node:fs/promises';
import { networkInterfaces } from 'node:os';
import { basename, dirname, extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { fingerprint, formatFingerprint, isCryptoFailure } from '../dist/index.js';
import { connect, listen } from '../cli/frame.mjs';
import { identityFile, loadIdentity, resetIdentity } from '../cli/store.mjs';
import { DEFAULT_CHUNK_BYTES, MAX_CHUNK_BYTES, receivePayload, sendPayload } from '../cli/protocol.mjs';
import { box, color, humanBytes, humanMs, progressLine, statsTable, words } from '../cli/format.mjs';

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

const PROGRESS_TTY = Boolean(process.stderr.isTTY);
const PROGRESS_WIDTH = 78;

/**
 * Progress goes to stderr on a TTY only. Written to a pipe or a log it would
 * be thousands of near identical lines, which is noise rather than feedback.
 */
function makeProgress(label) {
  if (!PROGRESS_TTY) return undefined;
  let lastAt = 0;
  return ({ done, total }) => {
    const now = performance.now();
    const finished = total > 0 && done >= total;
    if (!finished && now - lastAt < 80) return;
    lastAt = now;
    process.stderr.write(`\r${progressLine({ done, total, label }).padEnd(PROGRESS_WIDTH)}`);
  };
}

function clearProgress() {
  if (PROGRESS_TTY) process.stderr.write(`\r${' '.repeat(PROGRESS_WIDTH)}\r`);
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** A mistake in the command line, as opposed to a failure during a transfer. */
class UsageError extends Error {}

function usageError(message) {
  throw new UsageError(message);
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

function reportError(err) {
  clearProgress();
  process.stderr.write(`${color.red('error')} ${err && err.message ? err.message : String(err)}\n`);
  // A stack trace is noise for an expected failure and the only useful thing
  // there is for an unexpected one, so it is opt in rather than a default.
  if (process.env.RATCHET_DEBUG && err && err.stack) {
    process.stderr.write(`${err.stack}\n`);
  }
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

const VALUE_FLAGS = new Set(['--port', '--out', '--to', '--text', '--chunk']);
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
    usageError(`unknown flag ${name}`);
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
  if (!text) usageError('--to needs a host');

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

const HELP = `ratchet ${PKG.version}   encrypted file transfer between two machines, no server

TWO MACHINE FLOW
  1. On the machine that RECEIVES:  ratchet recv
     It prints the exact command to run on the other machine.
  2. Run that command on the machine that SENDS.
  3. Compare the six safety words shown on both screens. If they differ,
     someone is in the middle. Stop and delete whatever arrived.

EXAMPLES
  ratchet recv --out ~/Downloads --once
  ratchet send photo.jpg --to 192.168.1.42
  echo "the wifi password is hunter2" | ratchet send - --to 192.168.1.42

COMMANDS
  recv [--port N] [--out DIR] [--once]   listen, then write what arrives
  send PATH --to HOST[:PORT]             send a file, or - to read stdin
  send --text "..." --to HOST[:PORT]     send a message instead of a file
  id [--reset --yes]                     this machine safety words and key file

FLAGS
  --stats        add the full measurement table under the summary line
  --chunk N      plaintext bytes per sealed frame (default ${DEFAULT_CHUNK_BYTES}, max ${MAX_CHUNK_BYTES})
  --json         stats as JSON on stdout, all human output on stderr
  --help, --version

Port defaults to ${DEFAULT_PORT}. The payload and the metadata (filename, size,
hash) are both encrypted, so an observer sees a byte count and nothing else.
There is no relay and no account: the two machines talk straight over TCP,
which means they need a route to each other, usually the same LAN.
Set RATCHET_DEBUG=1 for stack traces. Exit codes: 0 ok, 1 failure, 2 crypto.`;

// ---------------------------------------------------------------------------
// Filesystem
// ---------------------------------------------------------------------------

// The peer chooses this name, so it is hostile input until proven otherwise.
// Windows device names are in here because opening CON or NUL succeeds and
// does something quite unlike writing a file.
const WINDOWS_DEVICES = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)/i;

// Built with the RegExp constructor so this source file carries no raw control
// bytes of its own. A literal NUL in a shipped .mjs upsets more tools than it
// is worth.
const CONTROL_CHARS = new RegExp('[\\u0000-\\u001f\\u007f]', 'g');

function safeName(raw) {
  const stripped = String(raw ?? '')
    // Control characters can rewrite a terminal line or hide the real
    // extension, and a path separator is how a peer would try to write
    // outside --out. Both go before anything else looks at the name.
    .replace(CONTROL_CHARS, '')
    .replace(/[\\/]/g, '_')
    .trim();
  if (!stripped || stripped === '.' || stripped === '..' || WINDOWS_DEVICES.test(stripped)) {
    return 'payload.bin';
  }
  return stripped.slice(0, 200);
}

// Set while a file is partially written, so SIGINT can remove it. A half
// written photo that looks like a real file is worse than no file at all.
let partialPath = null;

/**
 * Claims a filename with the 'wx' flag rather than checking existence first.
 * The check-then-write version has a race, and here the race loses somebody's
 * data, so let the kernel do the claiming.
 */
async function writeNoClobber(dir, rawName, bytes) {
  const name = safeName(rawName);
  const ext = extname(name);
  const stem = name.slice(0, name.length - ext.length);

  for (let n = 0; n < 10000; n += 1) {
    const candidate = join(dir, n === 0 ? name : `${stem}-${n}${ext}`);
    let handle;
    try {
      handle = await open(candidate, 'wx');
    } catch (err) {
      if (err.code === 'EEXIST') continue;
      throw err;
    }
    partialPath = candidate;
    try {
      await handle.writeFile(bytes);
      await handle.close();
      partialPath = null;
      return candidate;
    } catch (err) {
      await handle.close().catch(() => {});
      await unlink(candidate).catch(() => {});
      partialPath = null;
      throw err;
    }
  }
  throw new Error(`gave up finding a free name for ${name} in ${dir} after 10000 tries`);
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks);
}

/** Every non loopback IPv4, because the user does not know which one routes. */
function lanAddresses() {
  const found = [];
  for (const entries of Object.values(networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.family === 'IPv4' && !entry.internal) found.push(entry.address);
    }
  }
  return found;
}

// ---------------------------------------------------------------------------
// Shared rendering
// ---------------------------------------------------------------------------

function handshakeBanner() {
  return ({ peerWords, sessionWords }) => {
    say(`  ${color.dim('compare aloud')}  ${words(sessionWords)}`);
    say(`  ${color.dim('peer identity')}  ${words(peerWords)}`);
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

async function cmdRecv(opts) {
  const port = opts.port === undefined ? DEFAULT_PORT : parsePort(opts.port, '--port');
  const outDir = resolve(opts.out ?? process.cwd());
  await mkdir(outDir, { recursive: true });

  const identity = await loadIdentity();
  const myWords = formatFingerprint(fingerprint(identity));

  // No host, so Node binds every interface. Which address the sender can
  // actually reach is exactly what the user does not know, hence the list.
  const server = await listen({ port });

  say(
    box('ratchet recv', [
      `you        ${words(myWords)}`,
      `identity   ${color.dim(identityFile())}`,
      `port       ${color.dim(String(server.port))}`,
      `saving to  ${color.dim(outDir)}`,
    ]),
  );
  say('');

  const suffix = server.port === DEFAULT_PORT ? '' : `:${server.port}`;
  const addresses = lanAddresses();
  if (addresses.length === 0) {
    say('No non loopback IPv4 address on this machine. From this machine only:');
    say(`  ${color.bold(`ratchet send FILE --to 127.0.0.1${suffix}`)}`);
  } else {
    say('Run one of these on the other machine, whichever address it can reach:');
    for (const address of addresses) {
      say(`  ${color.bold(`ratchet send FILE --to ${address}${suffix}`)}`);
    }
  }
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
      await channel.close().catch(() => {});
    }

    if (opts.once) {
      await server.close();
      if (!failed) return 0;
      return isCrypto(failed) ? 2 : 1;
    }
    if (failed) failures += 1;
    say('');
    say(color.dim('Waiting for the next sender. Ctrl-C to stop.'));
  }
  return failures > 0 ? 1 : 0;
}

async function receiveOne({ channel, identity, outDir, opts }) {
  say('');
  say(`Connection from ${color.bold(channel.remote)}`);

  const received = await receivePayload({
    channel,
    identity,
    onProgress: makeProgress('receiving'),
    // Fires the moment the handshake lands, which is the whole reason it
    // exists: the words have to be on screen while the bytes are still moving,
    // not after, or there is nothing left to abort.
    onHandshake: handshakeBanner(),
  });
  clearProgress();

  const path = await writeNoClobber(outDir, received.name, received.bytes);
  renderResult({
    verb: 'received',
    name: received.name,
    stats: received.stats,
    extra: path,
    showStats: Boolean(opts.stats),
  });

  echoTextMessage(received.name, received.bytes);
  if (jsonMode) emit({ direction: 'received', name: received.name, path, ...received.stats });
}

/** A text send is useless if the reader has to go and open a file for it. */
function echoTextMessage(name, bytes) {
  if (name !== TEXT_NAME || bytes.length === 0 || bytes.length > TEXT_ECHO_LIMIT) return;
  const text = Buffer.from(bytes).toString('utf8');
  // A replacement character means the bytes were not UTF-8, so this is a
  // binary payload that happens to carry the text name. Do not paint it.
  if (text.includes('�')) return;
  say('');
  say(box('message', text.split('\n')));
}

async function cmdSend(opts, rest) {
  if (!opts.to) usageError('send needs --to HOST or --to HOST:PORT');
  const { host, port } = parseTo(opts.to);
  const chunkSize = parseChunk(opts.chunk);

  const hasText = typeof opts.text === 'string';
  const pathArg = rest[0];
  if (rest.length > 1) usageError(`send takes one path, got ${rest.length}`);
  if (hasText && pathArg) usageError('give a PATH or --text, not both');
  if (!hasText && !pathArg) usageError('send needs a PATH, or --text "message", or - to read stdin');

  let name;
  let bytes;
  if (hasText) {
    name = TEXT_NAME;
    bytes = Buffer.from(opts.text, 'utf8');
  } else if (pathArg === '-') {
    name = TEXT_NAME;
    bytes = await readStdin();
  } else {
    try {
      bytes = await readFile(pathArg);
    } catch (err) {
      if (err.code === 'ENOENT') throw new Error(`no such file: ${pathArg}`);
      if (err.code === 'EISDIR') throw new Error(`${pathArg} is a directory, and this sends one file at a time`);
      throw err;
    }
    name = basename(pathArg);
  }

  const identity = await loadIdentity();
  say(`Connecting to ${color.bold(`${host}:${port}`)}`);
  const channel = await connect({ host, port, timeoutMs: 10000 });

  try {
    const stats = await sendPayload({
      channel,
      identity,
      name,
      bytes,
      chunkSize,
      onProgress: makeProgress('sending'),
      onHandshake: handshakeBanner(),
    });
    clearProgress();
    renderResult({ verb: 'sent', name, stats, extra: `${host}:${port}`, showStats: Boolean(opts.stats) });
    if (jsonMode) emit({ direction: 'sent', name, to: `${host}:${port}`, ...stats });
    return 0;
  } finally {
    await channel.close().catch(() => {});
  }
}

async function cmdId(opts) {
  if (opts.reset) {
    if (!opts.yes) {
      usageError(
        'ratchet id --reset throws away your identity for good. Every peer that has ever ' +
          'verified your safety words will see different ones and cannot tell that from an ' +
          'attacker. Add --yes if that is really what you want.',
      );
    }
    const path = identityFile();
    await resetIdentity();
    say(`${color.yellow('discarded')} ${path}`);
    say(color.dim('A new identity, with new safety words, is minted on the next command.'));
    if (jsonMode) emit({ reset: true, identityFile: path });
    return 0;
  }

  const identity = await loadIdentity();
  // fingerprint() returns { words, hex }, not raw bytes. Scripts get the hex
  // because it carries more bits than the six words do.
  const print = fingerprint(identity);
  const myWords = formatFingerprint(print);
  say(box('ratchet id', [`words     ${words(myWords)}`, `identity  ${color.dim(identityFile())}`]));
  if (jsonMode) emit({ words: myWords, hex: print.hex, identityFile: identityFile() });
  return 0;
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

  if (opts.help || !command) {
    // Help asked for goes to stdout and succeeds; help because you typed
    // nothing goes to stderr and fails, so a script cannot mistake it for work.
    (opts.help ? process.stdout : process.stderr).write(`${HELP}\n`);
    return opts.help ? 0 : 1;
  }

  switch (command) {
    case 'recv':
    case 'receive':
      if (rest.length > 0) usageError(`recv takes no arguments, got ${rest[0]}`);
      return cmdRecv(opts);
    case 'send':
      return cmdSend(opts, rest);
    case 'id':
      if (rest.length > 0) usageError(`id takes no arguments, got ${rest[0]}`);
      return cmdId(opts);
    default:
      usageError(`unknown command ${command}. Run ratchet --help.`);
      return 1;
  }
}

try {
  process.exitCode = await main();
} catch (err) {
  if (err instanceof UsageError) {
    process.stderr.write(`${color.red('usage')} ${err.message}\n`);
    process.stderr.write(color.dim('Run ratchet --help.\n'));
    process.exitCode = 1;
  } else {
    reportError(err);
    process.exitCode = isCrypto(err) ? 2 : 1;
  }
}
