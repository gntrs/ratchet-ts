// The trust store, the classification that decides whether a user gets warned,
// and the two derivations that used to exist twice each.
//
// The classification tests are the ones that matter. Two of them assert that
// nothing happens, and those are the ones a future change is most likely to
// break: an alarm that fires on a roaming laptop trains people to ignore it,
// which costs more than having no alarm at all.
import test from 'node:test';
import assert from 'node:assert/strict';

import { mkdtemp, readFile, stat, writeFile, rm } from 'node:fs/promises';
import { platform, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  PEERS_VERSION,
  addressOf,
  classifyPeer,
  findPeers,
  forgetPeer,
  listPeers,
  loadPeers,
  lookupPeer,
  markVerified,
  peersFile,
  recordSighting,
  resetPeers,
  savePeers,
} from '../cli/peers.mjs';
import { FAILURE_CONTEXTS, explainError, explainFailure, pairWords, wrapCrypto } from '../cli/protocol.mjs';
import { CryptoFailureError, fingerprint, formatFingerprint } from '../dist/index.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');

/**
 * Every test that touches disk gets its own RATCHET_HOME. peersFile() reads the
 * environment on every call rather than at import, so this is enough to keep a
 * test out of the user's real ~/.ratchet, and there is no ordering hazard
 * between tests as long as each one restores what it found.
 */
async function withHome(fn) {
  const before = process.env.RATCHET_HOME;
  const dir = await mkdtemp(join(tmpdir(), 'ratchet-peers-'));
  process.env.RATCHET_HOME = dir;
  try {
    return await fn(dir);
  } finally {
    if (before === undefined) delete process.env.RATCHET_HOME;
    else process.env.RATCHET_HOME = before;
    await rm(dir, { recursive: true, force: true });
  }
}

const fill = (n, b) => Buffer.alloc(n, b);
/** X25519 is 32 bytes, ML-KEM-768 public is 1184. Fixed content, so fixed words. */
const IDENTITY_A = { classicalPublic: fill(32, 0x11), pqPublic: fill(1184, 0x22), sigPublic: fill(1952, 0x33) };
const IDENTITY_B = { classicalPublic: fill(32, 0xaa), pqPublic: fill(1184, 0xbb), sigPublic: fill(1952, 0xcc) };

const HEX_A = 'a'.repeat(32);
const HEX_B = 'b'.repeat(32);
const WORDS_A = 'alpha bravo charlie delta echo foxtrot';
const WORDS_B = 'golf hotel india juliet kilo lima';

function storeWith(entries) {
  const store = { v: PEERS_VERSION, peers: {} };
  for (const entry of entries) {
    recordSighting(store, {
      hex: entry.hex,
      words: entry.words,
      address: entry.address,
      now: entry.now ?? '2026-01-01T00:00:00.000Z',
    });
    if (entry.verified) {
      markVerified(store, { hex: entry.hex, label: entry.label, now: entry.now ?? '2026-01-01T00:00:00.000Z' });
    }
  }
  return store;
}

// ---------------------------------------------------------------------------
// The safety words, pinned
// ---------------------------------------------------------------------------

// If this test ever fails, the derivation moved, and every peer anybody has
// verified now shows different words with no way to tell that from an attack.
// Fix the code, not the literal.
//
// The literal has changed twice, both times on purpose, both times in 0.5.1 or
// later:
//
//   2026-08-15, 0.5.1. The derivation stopped hashing the two identities
//   together and started concatenating their fingerprints. The old six word
//   value was 'dumb engine cake curious area collect'. A combined hash gives a
//   man in the middle, who picks the key shown to each side, a birthday search
//   at about 2^33 instead of a preimage at 2^66.
//
//   2026-08-15, 0.6.0. The identity grew an ML-DSA-65 verifying key and the
//   fingerprint domain went to v2 so the digest covers it. A fingerprint that
//   ignored the signing key would let an attacker keep both old keys, swap in a
//   signing key of their own, and print the same words.
//
// Anyone who verified a peer before 0.6.0 has to compare again. That is the
// honest consequence of putting a third key in the identity, and the digest
// silently ignoring it would have been the dishonest alternative.
test('pairWords is pinned to a fixed pair of identities', () => {
  assert.equal(
    pairWords(IDENTITY_A, IDENTITY_B),
    'fatal perfect piano steel absent extend forward powder unveil airport lake result',
  );
});

test('pairWords does not depend on which side computes it', () => {
  assert.equal(pairWords(IDENTITY_B, IDENTITY_A), pairWords(IDENTITY_A, IDENTITY_B));
});

// The security property itself, not just a pinned string. The words have to BE
// the two fingerprints, because that is what forces an attacker into two
// independent second preimages rather than one collision search.
test('pairWords is the two identity fingerprints, not a hash of the pair', () => {
  const a = formatFingerprint(fingerprint(IDENTITY_A)).split(' ');
  const b = formatFingerprint(fingerprint(IDENTITY_B)).split(' ');
  const got = pairWords(IDENTITY_A, IDENTITY_B).split(' ');
  assert.equal(got.length, a.length + b.length);
  // Order is by fingerprint hex, so one of the two arrangements must match
  // exactly. Both fingerprints appear whole and neither is mixed into the other.
  const forward = [...a, ...b].join(' ');
  const backward = [...b, ...a].join(' ');
  assert.ok(got.join(' ') === forward || got.join(' ') === backward);
});

// A peer whose fingerprint is unchanged must not move the other peer's words.
// If it did, the two sides could not compare position by position and the whole
// construction would be back to a single blended value.
test('changing one identity leaves the other identity words intact', () => {
  const other = { classicalPublic: fill(32, 0x5c), pqPublic: fill(1184, 0x5d), sigPublic: fill(1952, 0x5e) };
  const aWords = formatFingerprint(fingerprint(IDENTITY_A)).split(' ');
  const got = pairWords(IDENTITY_A, other).split(' ');
  const at = got.indexOf(aWords[0]);
  assert.notEqual(at, -1);
  assert.deepEqual(got.slice(at, at + aWords.length), aWords);
});

test('pairWords is defined exactly once in the CLI', async () => {
  // The drift guard. Two copies of a security derivation is a bug waiting for
  // whoever edits one of them, and that is exactly the state this replaced.
  const sources = await Promise.all(
    ['cli/protocol.mjs', 'cli/chat.mjs'].map((p) => readFile(join(ROOT, p), 'utf8')),
  );
  const definitions = sources.join('\n').match(/function pairWords\s*\(/g) ?? [];
  assert.equal(definitions.length, 1);
});

// ---------------------------------------------------------------------------
// Failure wording
// ---------------------------------------------------------------------------

/** The authoritative union, read from the source so a new value cannot slip by. */
async function cryptoFailureReasons() {
  const types = await readFile(join(ROOT, 'src/types.ts'), 'utf8');
  const block = types.match(/export type CryptoFailureReason =([\s\S]*?);/);
  assert.ok(block, 'CryptoFailureReason is no longer declared the way this test reads it');
  const reasons = block[1].match(/'([a-z_]+)'/g).map((s) => s.slice(1, -1));
  assert.ok(reasons.length > 0);
  return reasons;
}

test('every CryptoFailureReason has wording in every context', async () => {
  const reasons = await cryptoFailureReasons();
  for (const reason of reasons) {
    for (const context of FAILURE_CONTEXTS) {
      const text = explainFailure(reason, context);
      assert.ok(text, `${reason} has no ${context} wording`);
      // A sentence, not a restatement of the code.
      assert.ok(text.length > 20, `${reason} in ${context} is too short to be an explanation`);
      assert.ok(!text.includes(reason), `${reason} in ${context} just repeats the code`);
    }
  }
});

test('the reason code survives into the message a user sees', async () => {
  const reasons = await cryptoFailureReasons();
  for (const reason of reasons) {
    const failure = new CryptoFailureError(reason, 'terse library text');
    const wrapped = wrapCrypto(failure, 'opening a frame', 'chat');
    assert.ok(wrapped.message.includes(`(${reason})`), `${reason} is not searchable in the output`);
    assert.ok(wrapped.message.startsWith('opening a frame: '));
    assert.equal(wrapped.reason, reason);
    assert.equal(wrapped.cause, failure);
    // And chat sees the sentence, not the library's own terse text.
    assert.ok(!wrapped.message.includes('terse library text'));
    assert.equal(explainError(failure, 'opening a frame', 'chat'), wrapped.message);
  }
});

test('chat wording never tells a chat user the transfer is over', async () => {
  const reasons = await cryptoFailureReasons();
  for (const reason of reasons) {
    const text = explainFailure(reason, 'chat');
    assert.ok(!/\btransfer\b/.test(text), `${reason} still talks about a transfer in chat`);
  }
});

test('an unknown context falls back to the transfer wording rather than nothing', () => {
  assert.equal(explainFailure('replay_detected', 'nonsense'), explainFailure('replay_detected', 'transfer'));
});

test('explainError passes a plain error through untouched', () => {
  assert.equal(explainError(new Error('socket closed'), 'reading', 'chat'), 'reading: socket closed');
});

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

test('a hex never seen here is new', () => {
  const store = storeWith([]);
  const verdict = classifyPeer(store, { hex: HEX_A, address: '192.168.1.42' });
  assert.equal(verdict.state, 'new');
  assert.equal(verdict.entry, null);
});

test('a hex seen before with nobody vouching for it is known', () => {
  const store = storeWith([{ hex: HEX_A, words: WORDS_A, address: '192.168.1.42' }]);
  const verdict = classifyPeer(store, { hex: HEX_A, address: '192.168.1.42' });
  assert.equal(verdict.state, 'known');
  assert.equal(verdict.entry.verified, false);
});

test('a hex a human confirmed is verified', () => {
  const store = storeWith([
    { hex: HEX_A, words: WORDS_A, address: '192.168.1.42', verified: true, label: 'Ana' },
  ]);
  const verdict = classifyPeer(store, { hex: HEX_A, address: '192.168.1.42' });
  assert.equal(verdict.state, 'verified');
  assert.equal(verdict.entry.label, 'Ana');
  assert.equal(verdict.newAddress, false);
});

test('a different key at an address that carried a verified one is changed', () => {
  const store = storeWith([
    { hex: HEX_A, words: WORDS_A, address: '192.168.1.42', verified: true, label: 'Ana' },
  ]);
  const verdict = classifyPeer(store, { hex: HEX_B, address: '192.168.1.42' });
  assert.equal(verdict.state, 'changed');
  assert.equal(verdict.conflict.hex, HEX_A);
  assert.equal(verdict.conflict.label, 'Ana');
  assert.equal(verdict.conflict.words, WORDS_A);
});

// The two that must stay quiet.

test('a different key at an address that was never verified does NOT alarm', () => {
  // Nobody ever read anything aloud about the old key, so there is no claim to
  // have been broken. Alarming here would fire on every DHCP lease rotation.
  const store = storeWith([{ hex: HEX_A, words: WORDS_A, address: '192.168.1.42' }]);
  const verdict = classifyPeer(store, { hex: HEX_B, address: '192.168.1.42' });
  assert.equal(verdict.state, 'new');
  assert.equal(verdict.conflict, null);
});

test('a verified key arriving from a new address does NOT alarm', () => {
  // What was verified is the key, and the key did not change. Someone opened
  // their laptop on another network.
  const store = storeWith([
    { hex: HEX_A, words: WORDS_A, address: '192.168.1.42', verified: true, label: 'Ana' },
  ]);
  const verdict = classifyPeer(store, { hex: HEX_A, address: '10.0.0.7' });
  assert.equal(verdict.state, 'verified');
  assert.equal(verdict.conflict, null);
  assert.equal(verdict.newAddress, true);
});

test('an unverified key returning from a new address is still only known', () => {
  const store = storeWith([{ hex: HEX_A, words: WORDS_A, address: '192.168.1.42' }]);
  const verdict = classifyPeer(store, { hex: HEX_A, address: '10.0.0.7' });
  assert.equal(verdict.state, 'known');
  assert.equal(verdict.newAddress, true);
});

test('with no address there is nothing to conflict with', () => {
  const store = storeWith([
    { hex: HEX_A, words: WORDS_A, address: '192.168.1.42', verified: true, label: 'Ana' },
  ]);
  const verdict = classifyPeer(store, { hex: HEX_B, address: null });
  assert.equal(verdict.state, 'new');
  assert.equal(verdict.conflict, null);
});

test('classifying does not mutate the store', () => {
  const store = storeWith([
    { hex: HEX_A, words: WORDS_A, address: '192.168.1.42', verified: true, label: 'Ana' },
  ]);
  const before = JSON.stringify(store);
  classifyPeer(store, { hex: HEX_B, address: '192.168.1.42' });
  assert.equal(JSON.stringify(store), before);
});

test('recording a sighting before classifying would disarm the alarm', () => {
  // Written down as a test because it is the ordering mistake that looks
  // harmless and turns the whole feature off.
  const store = storeWith([
    { hex: HEX_A, words: WORDS_A, address: '192.168.1.42', verified: true, label: 'Ana' },
  ]);
  assert.equal(classifyPeer(store, { hex: HEX_B, address: '192.168.1.42' }).state, 'changed');
  recordSighting(store, { hex: HEX_B, words: WORDS_B, address: '192.168.1.42' });
  // Still changed, because the conflict is with the OTHER row, which is why the
  // order only matters for the address list and not for the verdict itself.
  assert.equal(classifyPeer(store, { hex: HEX_B, address: '192.168.1.42' }).state, 'changed');
});

// ---------------------------------------------------------------------------
// Mutation
// ---------------------------------------------------------------------------

test('a sighting creates a row, then updates it', () => {
  const store = storeWith([]);
  const first = recordSighting(store, {
    hex: HEX_A,
    words: WORDS_A,
    address: '192.168.1.42',
    now: '2026-01-01T00:00:00.000Z',
  });
  assert.equal(first.firstSeen, '2026-01-01T00:00:00.000Z');
  assert.equal(first.verified, false);
  assert.deepEqual(first.addresses, ['192.168.1.42']);

  const second = recordSighting(store, {
    hex: HEX_A,
    words: WORDS_A,
    address: '10.0.0.7',
    now: '2026-02-02T00:00:00.000Z',
  });
  assert.equal(second.firstSeen, '2026-01-01T00:00:00.000Z');
  assert.equal(second.lastSeen, '2026-02-02T00:00:00.000Z');
  assert.deepEqual(second.addresses, ['192.168.1.42', '10.0.0.7']);
  assert.equal(Object.keys(store.peers).length, 1);
});

test('the same address is not appended twice', () => {
  const store = storeWith([]);
  recordSighting(store, { hex: HEX_A, words: WORDS_A, address: '192.168.1.42' });
  recordSighting(store, { hex: HEX_A, words: WORDS_A, address: '192.168.1.42' });
  assert.deepEqual(store.peers[HEX_A].addresses, ['192.168.1.42']);
});

test('marking verified needs an existing row and records when', () => {
  const store = storeWith([]);
  assert.throws(() => markVerified(store, { hex: HEX_A, label: 'Ana' }), /no peer with identity/);
  recordSighting(store, { hex: HEX_A, words: WORDS_A, address: '192.168.1.42' });
  const entry = markVerified(store, { hex: HEX_A, label: 'Ana', now: '2026-03-03T00:00:00.000Z' });
  assert.equal(entry.verified, true);
  assert.equal(entry.label, 'Ana');
  assert.equal(entry.verifiedAt, '2026-03-03T00:00:00.000Z');
});

test('forgetting a peer removes it and returns what went', () => {
  const store = storeWith([{ hex: HEX_A, words: WORDS_A, address: '192.168.1.42', verified: true, label: 'Ana' }]);
  const gone = forgetPeer(store, HEX_A);
  assert.equal(gone.label, 'Ana');
  assert.equal(lookupPeer(store, HEX_A), null);
  assert.equal(forgetPeer(store, HEX_A), null);
});

test('a peer is found by label or by hex prefix, and a miss is empty', () => {
  const store = storeWith([
    { hex: HEX_A, words: WORDS_A, address: '192.168.1.42', verified: true, label: 'Ana' },
    { hex: HEX_B, words: WORDS_B, address: '10.0.0.7' },
  ]);
  assert.deepEqual(findPeers(store, 'ana').map((p) => p.hex), [HEX_A]);
  assert.deepEqual(findPeers(store, 'ANA').map((p) => p.hex), [HEX_A]);
  assert.deepEqual(findPeers(store, HEX_B.slice(0, 8)).map((p) => p.hex), [HEX_B]);
  assert.deepEqual(findPeers(store, 'nobody'), []);
  assert.deepEqual(findPeers(store, ''), []);
});

test('listing puts the most recently seen first', () => {
  const store = storeWith([
    { hex: HEX_A, words: WORDS_A, address: '192.168.1.42', now: '2026-01-01T00:00:00.000Z' },
    { hex: HEX_B, words: WORDS_B, address: '10.0.0.7', now: '2026-05-05T00:00:00.000Z' },
  ]);
  assert.deepEqual(listPeers(store).map((p) => p.hex), [HEX_B, HEX_A]);
});

// ---------------------------------------------------------------------------
// Disk
// ---------------------------------------------------------------------------

test('a store that has never been written loads as empty', async () => {
  await withHome(async () => {
    const store = await loadPeers();
    assert.equal(store.v, PEERS_VERSION);
    assert.deepEqual(store.peers, {});
  });
});

test('a saved store comes back with its verifications intact', async () => {
  await withHome(async () => {
    const store = storeWith([
      { hex: HEX_A, words: WORDS_A, address: '192.168.1.42', verified: true, label: 'Ana' },
      { hex: HEX_B, words: WORDS_B, address: '10.0.0.7' },
    ]);
    await savePeers(store);

    const back = await loadPeers();
    assert.equal(Object.keys(back.peers).length, 2);
    assert.equal(back.peers[HEX_A].verified, true);
    assert.equal(back.peers[HEX_A].label, 'Ana');
    assert.equal(back.peers[HEX_A].words, WORDS_A);
    assert.deepEqual(back.peers[HEX_A].addresses, ['192.168.1.42']);
    assert.equal(back.peers[HEX_B].verified, false);
    assert.equal(back.peers[HEX_B].verifiedAt, null);
    assert.equal(classifyPeer(back, { hex: HEX_A, address: '192.168.1.42' }).state, 'verified');
  });
});

test('the write leaves no temp file behind', async () => {
  await withHome(async (dir) => {
    await savePeers(storeWith([{ hex: HEX_A, words: WORDS_A, address: '192.168.1.42' }]));
    const { readdir } = await import('node:fs/promises');
    const left = await readdir(dir);
    // A save now also mints the vault descriptor, because a write is the moment
    // a home directory acquires protection. What must never be left behind is a
    // staging file: those hold the same secrets under a name nobody cleans up.
    assert.ok(left.includes('peers.json'), `expected peers.json, got ${left.join(', ')}`);
    assert.deepEqual(left.filter((name) => name.endsWith('.tmp')), []);
  });
});

test('the file records no message content, and no plaintext about who', async () => {
  await withHome(async () => {
    await savePeers(storeWith([{ hex: HEX_A, words: WORDS_A, address: '192.168.1.42', verified: true, label: 'Ana' }]));
    const text = await readFile(peersFile(), 'utf8');
    const raw = JSON.parse(text);
    assert.deepEqual(Object.keys(raw).sort(), ['note', 'peers', 'protection', 'salt', 'v']);

    // The whole target property, asserted the blunt way: none of the four things
    // that identify a human survive as readable text in this file.
    for (const secret of [HEX_A, WORDS_A, '192.168.1.42', 'Ana']) {
      assert.equal(text.includes(secret), false, `${secret} is readable in peers.json`);
    }
    // One row per peer and nothing else: a copy without the key is a count.
    // Each row is a single opaque string, so there are no per field lengths to
    // read either.
    assert.equal(Object.keys(raw.peers).length, 1);
    assert.equal(typeof Object.values(raw.peers)[0], 'string');
  });
});

test('a corrupt store is refused rather than silently replaced', async () => {
  await withHome(async () => {
    // Starting over would throw away every verification a human made, and would
    // let anyone who can write this file downgrade a verified peer to unknown
    // without a word on screen.
    await savePeers(storeWith([{ hex: HEX_A, words: WORDS_A, address: '1.2.3.4', verified: true, label: 'Ana' }]));
    await writeFile(peersFile(), '{ this is not json');
    await assert.rejects(loadPeers(), /corrupt/);
  });
});

test('a truncated store is refused too', async () => {
  await withHome(async () => {
    await savePeers(storeWith([{ hex: HEX_A, words: WORDS_A, address: '1.2.3.4', verified: true, label: 'Ana' }]));
    const whole = await readFile(peersFile(), 'utf8');
    await writeFile(peersFile(), whole.slice(0, Math.floor(whole.length / 2)));
    await assert.rejects(loadPeers(), /corrupt/);
  });
});

test('a store from a future version is refused, not guessed at', async () => {
  await withHome(async () => {
    await writeFile(peersFile(), JSON.stringify({ v: PEERS_VERSION + 1, peers: {} }));
    await assert.rejects(loadPeers(), /version/);
  });
});

test('a store whose shape is wrong is refused', async () => {
  await withHome(async () => {
    await writeFile(peersFile(), JSON.stringify([1, 2, 3]));
    await assert.rejects(loadPeers(), /corrupt/);
    await writeFile(peersFile(), JSON.stringify({ v: PEERS_VERSION, peers: 'nope' }));
    await assert.rejects(loadPeers(), /corrupt/);
  });
});

test('a hand edited verified field only counts when it is literally true', async () => {
  await withHome(async () => {
    await writeFile(
      peersFile(),
      JSON.stringify({
        v: PEERS_VERSION,
        peers: { [HEX_A]: { label: 'Ana', words: WORDS_A, verified: 'yes', addresses: ['1.2.3.4'] } },
      }),
    );
    const store = await loadPeers();
    assert.equal(store.peers[HEX_A].verified, false);
    // And therefore it cannot arm the alarm for anybody else either.
    assert.equal(classifyPeer(store, { hex: HEX_B, address: '1.2.3.4' }).state, 'new');
  });
});

test('the peers file is 0600 where the platform has file modes', async (t) => {
  if (platform() === 'win32') {
    t.skip('NTFS ACLs, not POSIX mode bits');
    return;
  }
  await withHome(async () => {
    await savePeers(storeWith([{ hex: HEX_A, words: WORDS_A, address: '1.2.3.4' }]));
    const info = await stat(peersFile());
    assert.equal(info.mode & 0o777, 0o600);
  });
});

test('resetting removes the file and tolerates it already being gone', async () => {
  await withHome(async () => {
    await savePeers(storeWith([{ hex: HEX_A, words: WORDS_A, address: '1.2.3.4' }]));
    await resetPeers();
    await resetPeers();
    assert.deepEqual((await loadPeers()).peers, {});
  });
});

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

test('addressOf drops the ephemeral port from an endpoint', () => {
  assert.equal(addressOf('192.168.1.42:51234'), '192.168.1.42');
  assert.equal(addressOf('[2001:db8::1]:4477'), '2001:db8::1');
  assert.equal(addressOf('2001:db8::1:4477'), '2001:db8::1');
  assert.equal(addressOf(''), null);
  assert.equal(addressOf(null), null);
});
