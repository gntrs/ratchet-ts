// What the vault has to be true for, on disk, in every state it can be in.
//
// The claim these tests exist to defend is one sentence: with the vault key the
// two files behave exactly as they did before, and without it a copy of them is
// a count of peers and nothing else. Everything below is one half of that
// sentence.
//
// Three protection states are reachable, and the suite runs the same round trip
// through each: `none` (no keychain, no passphrase), a keychain if this machine
// has one ratchet can reach, and `pass`. The keychain leg is skipped rather than
// faked where no backend answers, because a mocked keychain proves nothing about
// the only interesting question, which is whether the real one is there.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { fingerprint } from '../dist/index.js';
import { identityFile, loadIdentity, takeMigrationNotice } from '../cli/store.mjs';
import { loadPeers, peersFile, recordSighting, savePeers } from '../cli/peers.mjs';
import {
  commitDescriptor,
  forgetCachedKey,
  passphraseDescriptor,
  vaultFile,
  vaultKey,
  vaultState,
} from '../cli/vault.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(here, '..', 'bin', 'ratchet.mjs');

const HEX_A = '64dae47ce4cad8f9a3136c8473cb0719';
const WORDS_A = 'gospel strong busy sister pulse lamp';

const VAULT_ENV = ['RATCHET_HOME', 'RATCHET_VAULT', 'RATCHET_PASSPHRASE', 'RATCHET_NEW_PASSPHRASE'];

/**
 * Runs `fn` against a throwaway RATCHET_HOME with a chosen environment.
 *
 * The module level key cache is cleared on the way in and on the way out. It is
 * keyed by home directory, so a stale entry would let one test read a file that
 * the next test's key should not open, which is exactly the property most of
 * these tests are checking.
 */
async function withHome(env, fn) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'ratchet-vault-'));
  const saved = Object.fromEntries(VAULT_ENV.map((name) => [name, process.env[name]]));
  process.env.RATCHET_HOME = dir;
  for (const [name, value] of Object.entries(env)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  forgetCachedKey();
  try {
    return await fn(dir);
  } finally {
    forgetCachedKey();
    takeMigrationNotice();
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    await rm(dir, { recursive: true, force: true });
  }
}

/** The plain environment: no forced state, no passphrase, whatever this box has. */
const DEFAULT_ENV = { RATCHET_VAULT: undefined, RATCHET_PASSPHRASE: undefined, RATCHET_NEW_PASSPHRASE: undefined };

/** Forces the no-keychain path, which is the only state every machine can reach. */
const PLAIN_ENV = { ...DEFAULT_ENV, RATCHET_VAULT: 'none' };

let keychainAnswer = null;

/**
 * True if this machine has a keychain backend that actually enrolled. Measured
 * once, by asking for a key and reading back what the descriptor says, because
 * "is secret-tool on PATH" and "does secret-tool work" are different questions.
 */
async function keychainWorks() {
  if (keychainAnswer !== null) return keychainAnswer;
  keychainAnswer = await withHome(DEFAULT_ENV, async () => {
    await vaultKey({ create: true });
    const state = await vaultState();
    return state.protection !== 'none' && state.protection !== 'pass';
  });
  return keychainAnswer;
}

/** Puts this home into the `pass` state before anything has been written into it. */
async function lockWith(passphrase) {
  const before = await vaultState();
  const { descriptor, key } = passphraseDescriptor(passphrase);
  await commitDescriptor(descriptor, key, before.descriptor);
  return key;
}

/** The one payload line of the identity file, and the rest of it, split apart. */
async function identityParts() {
  const raw = await readFile(identityFile(), 'utf8');
  const lines = raw.split('\n');
  const at = lines.findIndex((line) => line.startsWith('OCX'));
  assert.notEqual(at, -1, 'the identity file has no payload line');
  return { raw, lines, at, payload: lines[at] };
}

async function rewritePayload(mutate) {
  const { lines, at, payload } = await identityParts();
  lines[at] = mutate(payload);
  await writeFile(identityFile(), lines.join('\n'), 'utf8');
  return lines[at];
}

function runCli(args, env) {
  const child = spawn(process.execPath, [BIN, ...args], {
    env: { ...process.env, ...env, NO_COLOR: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  child.stdout.on('data', (buf) => { out += String(buf); });
  child.stderr.on('data', (buf) => { out += String(buf); });
  return new Promise((resolve) => child.on('exit', (code) => resolve({ code, out })));
}

// ---------------------------------------------------------------------------
// Round trip through every protection state
// ---------------------------------------------------------------------------

test('an unprotected home says so in the file, and round trips', async () => {
  await withHome(PLAIN_ENV, async () => {
    const first = await loadIdentity();
    const notice = takeMigrationNotice();
    assert.ok(notice && notice.includes('plain file'), 'a plain identity was minted without saying so');

    const { raw, payload } = await identityParts();
    assert.ok(payload.startsWith('OCXV1.none.'), `payload was ${payload.slice(0, 24)}`);
    assert.ok(raw.startsWith('#'), 'the file does not describe itself');
    assert.ok(raw.includes('NOT ENCRYPTED'), 'an unprotected file does not say it is unprotected');
    assert.ok(raw.includes('ratchet lock'), 'an unprotected file does not carry the fix');
    // The whole point of the `none` state is that it is honest, not that it is
    // safe: the secret really is readable, and the header really does say so.
    assert.ok(payload.includes('OCX3.identity.'), 'a `none` file should hold the bare token');

    forgetCachedKey();
    const second = await loadIdentity();
    assert.equal(fingerprint(second).hex, fingerprint(first).hex);
    assert.equal((await vaultState()).protection, 'none');
  });
});

test('a passphrase home seals the identity, and only that passphrase opens it', async () => {
  await withHome({ ...PLAIN_ENV, RATCHET_PASSPHRASE: 'correct horse battery staple' }, async () => {
    await lockWith('correct horse battery staple');
    const first = await loadIdentity();
    assert.equal(takeMigrationNotice(), null, 'a sealed mint should not announce a migration');

    const { raw, payload } = await identityParts();
    assert.ok(payload.startsWith('OCXV1.pass.'), `payload was ${payload.slice(0, 24)}`);
    assert.ok(!raw.includes('OCX3.identity.'), 'the secret token is still in the clear');

    forgetCachedKey();
    const second = await loadIdentity();
    assert.equal(fingerprint(second).hex, fingerprint(first).hex);

    forgetCachedKey();
    process.env.RATCHET_PASSPHRASE = 'correct horse battery stapler';
    await assert.rejects(loadIdentity(), /passphrase is wrong/i);
    // A wrong passphrase must not have touched the file on its way out.
    const after = await identityParts();
    assert.equal(after.payload, payload, 'a failed unlock rewrote the identity');
  });
});

test('a passphrase file refuses to open with no passphrase at all', async () => {
  await withHome({ ...PLAIN_ENV, RATCHET_PASSPHRASE: 'a passphrase for the file' }, async () => {
    await lockWith('a passphrase for the file');
    await loadIdentity();
    forgetCachedKey();
    delete process.env.RATCHET_PASSPHRASE;
    // stdin under the test runner is not a TTY, so this is also the check that
    // the prompt refuses rather than eating whatever the next line happens to be.
    await assert.rejects(loadIdentity(), /passphrase is needed/i);
  });
});

test('a keychain home seals the identity and never asks for anything', async (t) => {
  if (!(await keychainWorks())) {
    t.skip('no keychain backend on this machine');
    return;
  }
  await withHome(DEFAULT_ENV, async () => {
    const first = await loadIdentity();
    assert.equal(takeMigrationNotice(), null);
    const state = await vaultState();
    assert.ok(state.protection !== 'none' && state.protection !== 'pass', `protection was ${state.protection}`);

    const { raw, payload } = await identityParts();
    assert.ok(payload.startsWith(`OCXV1.${state.protection}.`), `payload was ${payload.slice(0, 24)}`);
    assert.ok(!raw.includes('OCX3.identity.'), 'the secret token is still in the clear');

    forgetCachedKey();
    const second = await loadIdentity();
    assert.equal(fingerprint(second).hex, fingerprint(first).hex, 'the keychain did not give the key back');
  });
});

test('unlocking with a passphrase costs enough to be worth doing', async (t) => {
  await withHome({ ...PLAIN_ENV, RATCHET_PASSPHRASE: 'a passphrase worth timing' }, async () => {
    await lockWith('a passphrase worth timing');
    await loadIdentity();
    forgetCachedKey();
    const started = process.hrtime.bigint();
    const key = await vaultKey({ create: false });
    const ms = Number(process.hrtime.bigint() - started) / 1e6;
    assert.equal(key.length, 32);
    t.diagnostic(`passphrase unlock took ${ms.toFixed(0)} ms`);
    // Both ends matter. Too cheap and an offline guesser gets a free run at it;
    // too slow and people turn it off. The floor is the real assertion, the
    // ceiling is loose because CI machines are not this laptop.
    assert.ok(ms > 60, `unlock was suspiciously cheap at ${ms.toFixed(0)} ms`);
    assert.ok(ms < 10000, `unlock took ${ms.toFixed(0)} ms, which nobody will tolerate`);
  });
});

// ---------------------------------------------------------------------------
// Migration off the plaintext file
// ---------------------------------------------------------------------------

test('an old plaintext identity is re-wrapped, keeps its fingerprint, and says so once', async (t) => {
  if (!(await keychainWorks())) {
    t.skip('no keychain backend on this machine');
    return;
  }
  await withHome(DEFAULT_ENV, async () => {
    // Mint under `none`, which is byte for byte what 0.3.x wrote, then take the
    // header off so the file is the bare token an old build left behind.
    process.env.RATCHET_VAULT = 'none';
    const before = await loadIdentity();
    takeMigrationNotice();
    const { payload } = await identityParts();
    const bare = payload.slice('OCXV1.none.'.length);
    await writeFile(identityFile(), `${bare}\n`, 'utf8');
    await rm(vaultFile(), { force: true });

    delete process.env.RATCHET_VAULT;
    forgetCachedKey();
    const after = await loadIdentity();
    assert.equal(fingerprint(after).hex, fingerprint(before).hex, 'migration changed the identity');
    const notice = takeMigrationNotice();
    assert.ok(notice && /sealed/i.test(notice), `migration was silent, notice was ${notice}`);

    const moved = await identityParts();
    assert.ok(moved.payload.startsWith('OCXV1.'), 'the file was not re-wrapped');
    assert.ok(!moved.raw.includes(bare), 'the plaintext token is still on disk');

    // Said once, not on every command afterwards.
    forgetCachedKey();
    await loadIdentity();
    assert.equal(takeMigrationNotice(), null, 'the migration notice repeats');
  });
});

test('a migrated identity still completes a real handshake', async () => {
  // Two homes, one of them carrying a pre-0.4 plaintext identity that has just
  // been migrated. The point is not that the CLI runs, it is that the key that
  // came out of the envelope is the same key the peer will accept.
  await withHome(DEFAULT_ENV, async (home) => {
    process.env.RATCHET_VAULT = 'none';
    const before = await loadIdentity();
    takeMigrationNotice();
    const { payload } = await identityParts();
    await writeFile(identityFile(), `${payload.slice('OCXV1.none.'.length)}\n`, 'utf8');
    await rm(vaultFile(), { force: true });
    delete process.env.RATCHET_VAULT;
    forgetCachedKey();

    const migrated = await loadIdentity();
    assert.equal(fingerprint(migrated).hex, fingerprint(before).hex);

    const outDir = await mkdtemp(path.join(os.tmpdir(), 'ratchet-vault-out-'));
    const srcDir = await mkdtemp(path.join(os.tmpdir(), 'ratchet-vault-src-'));
    const peerHome = await mkdtemp(path.join(os.tmpdir(), 'ratchet-vault-peer-'));
    const src = path.join(srcDir, 'payload.bin');
    const payloadBytes = Buffer.alloc(64 * 1024);
    for (let i = 0; i < payloadBytes.length; i += 1) payloadBytes[i] = (i * 37 + 11) & 0xff;
    await writeFile(src, payloadBytes);

    const port = 47701;
    const recv = spawn(
      process.execPath,
      [BIN, 'recv', '--out', outDir, '--once', '--port', String(port)],
      { env: { ...process.env, RATCHET_HOME: home, NO_COLOR: '1' }, stdio: ['ignore', 'pipe', 'pipe'] },
    );
    let recvOut = '';
    const exited = new Promise((resolve) => recv.on('exit', resolve));
    await new Promise((resolve, reject) => {
      const onData = (buf) => {
        recvOut += String(buf);
        if (recvOut.includes('Waiting for a sender')) resolve();
      };
      recv.stdout.on('data', onData);
      recv.stderr.on('data', onData);
      recv.on('exit', () => reject(new Error(`receiver exited early:\n${recvOut}`)));
    });

    const sent = await runCli(['send', src, '--to', `127.0.0.1:${port}`], { RATCHET_HOME: peerHome });
    assert.equal(sent.code, 0, `send failed:\n${sent.out}`);
    assert.equal(await exited, 0, `receiver failed:\n${recvOut}`);
    const landed = await readFile(path.join(outDir, 'payload.bin'));
    assert.deepEqual(landed, payloadBytes, 'the migrated identity moved the wrong bytes');

    await rm(outDir, { recursive: true, force: true });
    await rm(srcDir, { recursive: true, force: true });
    await rm(peerHome, { recursive: true, force: true });
  });
});

// ---------------------------------------------------------------------------
// The peers file under a key, and under the wrong one
// ---------------------------------------------------------------------------

test('a peers file written under one key does not open under another', async () => {
  await withHome({ ...PLAIN_ENV, RATCHET_PASSPHRASE: 'the first passphrase' }, async () => {
    await lockWith('the first passphrase');
    const store = await loadPeers();
    recordSighting(store, { hex: HEX_A, words: WORDS_A, address: '192.168.1.42', label: 'Ana' });
    await savePeers(store);

    const text = await readFile(peersFile(), 'utf8');
    for (const secret of [HEX_A, WORDS_A, '192.168.1.42', 'Ana']) {
      assert.ok(!text.includes(secret), `${secret} is on disk in the clear`);
    }

    // A different passphrase is a different key. The rows must not open, and the
    // failure must be a refusal rather than a store that quietly comes back empty.
    forgetCachedKey();
    process.env.RATCHET_PASSPHRASE = 'the second passphrase';
    const { descriptor, key } = passphraseDescriptor('the second passphrase');
    await commitDescriptor(descriptor, key, null);
    forgetCachedKey();
    await assert.rejects(loadPeers(), /vault|corrupt/i);

    // And the file is still there, untouched, for whoever still has the key.
    assert.equal(await readFile(peersFile(), 'utf8'), text, 'a failed open rewrote the store');
  });
});

test('a sealed peers file yields a count of peers and nothing else', async () => {
  await withHome({ ...PLAIN_ENV, RATCHET_PASSPHRASE: 'a passphrase for counting' }, async () => {
    await lockWith('a passphrase for counting');
    const store = await loadPeers();
    recordSighting(store, { hex: HEX_A, words: WORDS_A, address: '10.0.0.9', label: 'Ana' });
    recordSighting(store, { hex: 'ff'.repeat(16), words: 'one two three four five six', address: '10.0.0.10' });
    await savePeers(store);

    const raw = JSON.parse(await readFile(peersFile(), 'utf8'));
    assert.equal(Object.keys(raw.peers).length, 2, 'the count is the one thing a copy does learn');
    for (const row of Object.values(raw.peers)) {
      assert.equal(typeof row, 'string', 'a row is not a single opaque blob');
    }
    // Every row the same length, so a copy cannot tell a labelled peer from an
    // unlabelled one by measuring. One of these two has a label and the other
    // does not.
    const sizes = new Set(Object.values(raw.peers).map((row) => row.length));
    assert.equal(sizes.size, 1, `rows leak their contents by length: ${[...sizes].join(', ')}`);
  });
});

test('the same store re-saved twice looks different on disk', async () => {
  await withHome({ ...PLAIN_ENV, RATCHET_PASSPHRASE: 'a passphrase for salting' }, async () => {
    await lockWith('a passphrase for salting');
    const store = await loadPeers();
    recordSighting(store, { hex: HEX_A, words: WORDS_A, address: '10.0.0.9' });
    await savePeers(store);
    const first = await readFile(peersFile(), 'utf8');
    await savePeers(store);
    const second = await readFile(peersFile(), 'utf8');
    // Fresh salt, fresh nonces. Two copies taken a week apart must not line up
    // row for row, or the row name becomes a stable handle for one person.
    assert.notEqual(first, second, 'two writes of the same store are byte identical');
    assert.notDeepEqual(
      Object.keys(JSON.parse(first).peers),
      Object.keys(JSON.parse(second).peers),
      'the row name is stable across writes',
    );

    forgetCachedKey();
    const back = await loadPeers();
    assert.equal(back.peers[HEX_A].words, WORDS_A, 'the store did not survive the re-save');
  });
});

test('timestamps in a sealed store are days, not minutes', async () => {
  await withHome({ ...PLAIN_ENV, RATCHET_PASSPHRASE: 'a passphrase for clocks' }, async () => {
    await lockWith('a passphrase for clocks');
    const store = await loadPeers();
    recordSighting(store, { hex: HEX_A, words: WORDS_A, address: '10.0.0.9' });
    assert.ok(store.peers[HEX_A].lastSeen.includes('T'), 'in memory it is still a full stamp');
    await savePeers(store);
    forgetCachedKey();
    const back = await loadPeers();
    // Day resolution answers "have I talked to them recently" and refuses to
    // answer "when exactly is this person at their desk".
    assert.match(back.peers[HEX_A].firstSeen, /^\d{4}-\d{2}-\d{2}$/);
    assert.match(back.peers[HEX_A].lastSeen, /^\d{4}-\d{2}-\d{2}$/);
  });
});

// ---------------------------------------------------------------------------
// Damage
// ---------------------------------------------------------------------------

test('a truncated sealed identity is refused, not silently replaced', async () => {
  await withHome({ ...PLAIN_ENV, RATCHET_PASSPHRASE: 'a passphrase for truncation' }, async () => {
    await lockWith('a passphrase for truncation');
    const before = await loadIdentity();
    forgetCachedKey();
    const cut = await rewritePayload((line) => line.slice(0, Math.floor(line.length / 2)));

    await assert.rejects(loadIdentity(), /corrupt/i);
    const after = await identityParts();
    assert.equal(after.payload, cut, 'the corrupt file was overwritten');
    assert.ok(fingerprint(before).hex.length > 0);
  });
});

test('a single flipped byte in the envelope is refused', async () => {
  await withHome({ ...PLAIN_ENV, RATCHET_PASSPHRASE: 'a passphrase for flipping' }, async () => {
    await lockWith('a passphrase for flipping');
    await loadIdentity();
    forgetCachedKey();
    await rewritePayload((line) => {
      const at = line.length - 5;
      const ch = line[at] === 'A' ? 'B' : 'A';
      return line.slice(0, at) + ch + line.slice(at + 1);
    });
    await assert.rejects(loadIdentity(), /corrupt/i);
  });
});

test('rewriting the protection tag is refused rather than confusing the reader', async () => {
  await withHome({ ...PLAIN_ENV, RATCHET_PASSPHRASE: 'a passphrase for tags' }, async () => {
    await lockWith('a passphrase for tags');
    await loadIdentity();
    forgetCachedKey();
    // Same key, same ciphertext, a lying header. The tag is fed to the AEAD as
    // associated data precisely so this is an authentication failure.
    await rewritePayload((line) => line.replace('OCXV1.pass.', 'OCXV1.dpapi.'));
    await assert.rejects(loadIdentity(), /corrupt/i);
  });
});

test('a corrupt peers file is refused rather than reset to empty', async () => {
  await withHome({ ...PLAIN_ENV, RATCHET_PASSPHRASE: 'a passphrase for damage' }, async () => {
    await lockWith('a passphrase for damage');
    const store = await loadPeers();
    recordSighting(store, { hex: HEX_A, words: WORDS_A, address: '10.0.0.9' });
    await savePeers(store);

    const raw = JSON.parse(await readFile(peersFile(), 'utf8'));
    const id = Object.keys(raw.peers)[0];
    raw.peers[id] = `${raw.peers[id].slice(0, -6)}AAAAAA`;
    await writeFile(peersFile(), JSON.stringify(raw), 'utf8');
    forgetCachedKey();
    await assert.rejects(loadPeers(), /corrupt|vault/i);
  });
});

test('a sealed peers file with the vault gone is refused, not read as plain', async () => {
  await withHome({ ...PLAIN_ENV, RATCHET_PASSPHRASE: 'a passphrase to lose' }, async () => {
    await lockWith('a passphrase to lose');
    const store = await loadPeers();
    recordSighting(store, { hex: HEX_A, words: WORDS_A, address: '10.0.0.9' });
    await savePeers(store);

    await rm(vaultFile(), { force: true });
    forgetCachedKey();
    // Losing the descriptor must not degrade into "well, treat it as plain".
    await assert.rejects(loadPeers(), /vault|sealed/i);
  });
});

// ---------------------------------------------------------------------------
// What the user is told
// ---------------------------------------------------------------------------

test('ratchet id reports the protection state, and offers the fix when there is none', async () => {
  await withHome(PLAIN_ENV, async (home) => {
    const plain = await runCli(['id', '--json'], { RATCHET_HOME: home, RATCHET_VAULT: 'none' });
    assert.equal(plain.code, 0, plain.out);
    assert.ok(plain.out.includes('unprotected'), `no state line:\n${plain.out}`);
    assert.ok(plain.out.includes('ratchet lock'), `no way out offered:\n${plain.out}`);
    const emitted = JSON.parse(plain.out.slice(plain.out.indexOf('{')));
    assert.equal(emitted.protection, 'none');
  });
});

test('lock then unlock moves both files and keeps the identity', async () => {
  await withHome(PLAIN_ENV, async (home) => {
    const env = { RATCHET_HOME: home, RATCHET_VAULT: 'none' };
    const before = await runCli(['id', '--json'], env);
    assert.equal(before.code, 0, before.out);
    const beforeHex = JSON.parse(before.out.slice(before.out.indexOf('{'))).hex;

    const locked = await runCli(['lock'], { ...env, RATCHET_NEW_PASSPHRASE: 'a passphrase from the CLI' });
    assert.equal(locked.code, 0, locked.out);

    const asked = await runCli(['id', '--json'], { ...env, RATCHET_PASSPHRASE: 'a passphrase from the CLI' });
    assert.equal(asked.code, 0, asked.out);
    const afterLock = JSON.parse(asked.out.slice(asked.out.indexOf('{')));
    assert.equal(afterLock.protection, 'pass');
    assert.equal(afterLock.hex, beforeHex, 'lock changed the identity');

    const undone = await runCli(['unlock'], { ...env, RATCHET_PASSPHRASE: 'a passphrase from the CLI' });
    assert.equal(undone.code, 0, undone.out);
    const after = await runCli(['id', '--json'], env);
    assert.equal(after.code, 0, after.out);
    const afterUnlock = JSON.parse(after.out.slice(after.out.indexOf('{')));
    assert.equal(afterUnlock.hex, beforeHex, 'unlock changed the identity');
    // RATCHET_VAULT=none was forced above, so unlock has nowhere to put the key
    // and must land on the honest state rather than inventing a third one.
    assert.equal(afterUnlock.protection, 'none');

    // No sidecar left behind by a run that finished.
    const leftovers = await readFile(path.join(home, 'vault.rollback'), 'utf8').catch((err) => err.code);
    assert.equal(leftovers, 'ENOENT', 'the rollback sidecar outlived the operation');
  });
});
