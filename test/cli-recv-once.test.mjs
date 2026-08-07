// What --once actually promises.
//
// The help text says "recv handles one transfer and exits". Until 0.3.2 the
// code exited on one *connection*, which is a different thing: a port scan, a
// monitoring probe, or a peer whose link dropped before the handshake would
// switch the listener off, and the person waiting for the file would be told
// nothing. This was found by opening a bare TCP socket to a live receiver on
// another machine and closing it again, which killed it.
//
// These are the only tests in the suite that run the real binary as a child
// process. That is deliberate: the bug lived in the accept loop in
// bin/ratchet.mjs, which no unit test reaches, and a fake socket would have
// proven nothing about it.
import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(here, '..', 'bin', 'ratchet.mjs');

/** Ports well above the 4477 default so a real receiver on this box is safe. */
let nextPort = 47610;
const takePort = () => (nextPort += 1);

function tempDir(tag) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `ratchet-${tag}-`));
}

/**
 * Starts `recv --once` and resolves when it says it is listening. Waiting for
 * the banner rather than sleeping keeps this off a fixed timeout, which is
 * what makes a spawn test flaky on a loaded machine.
 */
function startReceiver({ port, outDir, home }) {
  const child = spawn(process.execPath, [BIN, 'recv', '--out', outDir, '--once', '--port', String(port)], {
    env: { ...process.env, RATCHET_HOME: home, NO_COLOR: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let output = '';
  const exited = new Promise((resolve) => child.on('exit', (code) => resolve(code)));
  const ready = new Promise((resolve, reject) => {
    const onData = (buf) => {
      output += String(buf);
      if (output.includes('Waiting for a sender')) resolve();
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.on('exit', () => reject(new Error(`receiver exited before listening:\n${output}`)));
  });

  return { child, exited, ready, out: () => output };
}

/** Opens a socket, optionally writes, then closes. The hostile-probe shape. */
function poke(port, payload) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host: '127.0.0.1', port });
    s.setTimeout(5000);
    s.on('connect', () => {
      if (payload) s.write(payload);
      setTimeout(() => { s.destroy(); resolve(true); }, payload ? 250 : 0);
    });
    s.on('timeout', () => { s.destroy(); reject(new Error('poke timed out')); });
    s.on('error', (err) => reject(err));
  });
}

/** True if something accepts a connection on this port right now. */
function isListening(port) {
  return new Promise((resolve) => {
    const s = net.connect({ host: '127.0.0.1', port });
    s.setTimeout(2500);
    s.on('connect', () => { s.destroy(); resolve(true); });
    s.on('timeout', () => { s.destroy(); resolve(false); });
    s.on('error', () => resolve(false));
  });
}

test('a bare TCP connect does not switch off a --once receiver', async () => {
  const port = takePort();
  const outDir = tempDir('out');
  const recv = startReceiver({ port, outDir, home: tempDir('home') });
  await recv.ready;

  // Three of them, because one surviving could be a race rather than a rule.
  for (let i = 0; i < 3; i += 1) await poke(port);

  assert.equal(await isListening(port), true, `probes killed the receiver:\n${recv.out()}`);
  recv.child.kill();
  await recv.exited;
});

test('a completed transfer still ends a --once receiver, with the file intact', async () => {
  const port = takePort();
  const outDir = tempDir('out');
  const recv = startReceiver({ port, outDir, home: tempDir('home') });
  await recv.ready;

  // Probe first, so this also proves a receiver that survived a probe can
  // still take the transfer it was waiting for.
  await poke(port);

  const payload = Buffer.alloc(200 * 1024);
  for (let i = 0; i < payload.length; i += 1) payload[i] = (i * 31 + 7) & 0xff;
  const srcDir = tempDir('src');
  const src = path.join(srcDir, 'payload.bin');
  fs.writeFileSync(src, payload);

  const sender = spawn(process.execPath, [BIN, 'send', src, '--to', `127.0.0.1:${port}`], {
    env: { ...process.env, RATCHET_HOME: tempDir('home2'), NO_COLOR: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const sendCode = await new Promise((resolve) => sender.on('exit', resolve));
  assert.equal(sendCode, 0, 'the sender did not exit cleanly');

  assert.equal(await recv.exited, 0, `receiver exit code was wrong:\n${recv.out()}`);
  const landed = fs.readFileSync(path.join(outDir, 'payload.bin'));
  assert.deepEqual(landed, payload, 'the file that landed is not the file that was sent');
});

test('a crypto failure does end a --once receiver, rather than looping', async () => {
  const port = takePort();
  const outDir = tempDir('out');
  const recv = startReceiver({ port, outDir, home: tempDir('home') });
  await recv.ready;

  // A well formed frame carrying an envelope version this build will never
  // accept. This reaches the decoder, unlike a bare connect, so it is somebody
  // producing bytes that do not verify. Looping there would hand an attacker
  // unlimited attempts against a listener the user thinks is waiting for one
  // file, so it has to stop.
  const body = Buffer.from([0xff, 0x01, 1, 2, 3, 4, 5, 6, 7, 8]);
  const len = Buffer.alloc(4);
  len.writeUInt32BE(body.length, 0);
  await poke(port, Buffer.concat([len, body]));

  assert.equal(await recv.exited, 2, `expected exit 2 for a crypto failure:\n${recv.out()}`);
});
