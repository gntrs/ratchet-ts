/**
 * The peer trust store: who this machine has talked to, and what a human said
 * out loud about them.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS FILE EXISTS
 * ---------------------------------------------------------------------------
 *
 * The six safety words exist so two people can catch a machine in the middle by
 * reading them aloud. That check only works the first time unless something
 * remembers the answer. Without a store, a user can verify six words with
 * someone on Monday, get an entirely different peer on Tuesday, and see no
 * difference at all on screen: the words are printed, they are different, and
 * nobody remembers Monday's. That is precisely the attack the fingerprint was
 * built to catch, walking straight past it.
 *
 * So this file remembers. It is the only place in the CLI that keeps state
 * about anyone other than the user.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS PUTS ON YOUR DISK, AND WHAT IT NEVER WILL
 * ---------------------------------------------------------------------------
 *
 * ~/.ratchet/peers.json records IDENTITIES and ADDRESSES. For each peer: the
 * identity digest hex, its six words, the first and last time this machine saw
 * it, whether a human verified it and when, the label that human gave it, and
 * the network addresses it has arrived from.
 *
 * It records NOTHING about what was said or sent. No message text, no filename,
 * no size, no count, no hash of any payload. `ratchet chat` still writes nothing
 * to disk about the content of a conversation and this file does not change
 * that promise.
 *
 * It is still a real privacy change and it is worth being blunt about it: before
 * this file, running `ratchet` left behind one identity key and no history. Now
 * it leaves a durable, timestamped list of who this machine has talked to and
 * from which addresses. Anyone who can read the file learns the shape of a
 * social graph that was previously nowhere on disk. That is the price of being
 * able to detect a changed key at all, and `ratchet peers forget` is how a user
 * takes any single row of it back.
 *
 * ---------------------------------------------------------------------------
 * KEYED BY HEX, NEVER BY WORDS
 * ---------------------------------------------------------------------------
 *
 * The hex is the identity. The words are a 66 bit projection of it, meant for
 * a human mouth, and 66 bits is a number somebody with a GPU can work towards.
 * Keying on the words would make the store no stronger than the weakest part of
 * the display. The words are stored anyway, next to the hex, so a peer can still
 * be described to a human when something has gone wrong and the description is
 * the only thing that will help.
 */

import { randomBytes } from 'node:crypto';
import { chmod, mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { platform } from 'node:os';
import { join } from 'node:path';

import { homeDir } from './store.mjs';

/**
 * Bumped only when the shape below changes in a way an older reader cannot
 * cope with. A reader that meets a version it does not know refuses rather
 * than guessing, because guessing at a trust record is how a verification
 * quietly turns into a non-verification.
 */
export const PEERS_VERSION = 1;

/**
 * A roaming laptop can collect a new address every time it moves, and this file
 * has no upper bound of its own. The cap is on addresses per peer, oldest
 * dropped first, and it fails OPEN rather than closed: losing the oldest
 * address means a later key swap at that address is no longer a conflict this
 * can see. That is the honest direction for the bound to fail. A store that
 * grew forever would be its own bug.
 */
const MAX_ADDRESSES = 32;

export function peersFile() {
  return join(homeDir(), 'peers.json');
}

function emptyStore() {
  return { v: PEERS_VERSION, peers: {} };
}

/**
 * Coerce one entry into the shape the rest of this file assumes.
 *
 * Defensive rather than trusting, because this file is plain JSON in a
 * directory the user can edit, and a hand-typed `"verified": "yes"` must not
 * become a verification. Only a literal `true` counts, and everything else
 * falls back to the safest reading rather than to whatever was on disk.
 */
function normaliseEntry(hex, raw) {
  if (!raw || typeof raw !== 'object') return null;
  const addresses = Array.isArray(raw.addresses)
    ? raw.addresses.filter((a) => typeof a === 'string' && a.length > 0).slice(-MAX_ADDRESSES)
    : [];
  return {
    hex,
    label: typeof raw.label === 'string' && raw.label.length > 0 ? raw.label : null,
    words: typeof raw.words === 'string' ? raw.words : '',
    firstSeen: typeof raw.firstSeen === 'string' ? raw.firstSeen : null,
    lastSeen: typeof raw.lastSeen === 'string' ? raw.lastSeen : null,
    verified: raw.verified === true,
    verifiedAt: typeof raw.verifiedAt === 'string' ? raw.verifiedAt : null,
    addresses,
  };
}

/** The on-disk projection. `hex` is the key, so it is not repeated in the value. */
function serialiseEntry(entry) {
  return {
    label: entry.label,
    words: entry.words,
    firstSeen: entry.firstSeen,
    lastSeen: entry.lastSeen,
    verified: entry.verified,
    verifiedAt: entry.verifiedAt,
    addresses: entry.addresses,
  };
}

/**
 * Reads the store, returning an empty one when the file has never been written.
 *
 * A file that exists but does not parse is NEVER silently replaced, for the
 * same reason cli/store.mjs refuses to replace a corrupt identity: starting
 * over would discard every verification a human made, and the difference
 * between "this peer was never verified" and "the record of it was destroyed"
 * is the whole value of the record. Someone who can corrupt this file would
 * otherwise be able to downgrade every verified peer back to unknown without
 * anything appearing on screen. So it throws, names the path, and says what to
 * do about it. Callers on the transfer path catch that and print it rather than
 * failing the transfer, so a broken file costs the user the trust check and
 * tells them so, in place of costing them the tool.
 */
export async function loadPeers() {
  const path = peersFile();
  let raw;
  try {
    raw = await readFile(path, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return emptyStore();
    throw err;
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (cause) {
    throw new Error(
      `${path} is corrupt: it is not valid JSON. Move it aside to start a fresh trust store. ` +
        `Refusing to do that automatically because it would throw away every peer you have verified, ` +
        `and a peer that was verified is not the same thing as a peer that never was.`,
      { cause },
    );
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`${path} is corrupt: the top level is not a JSON object. Move it aside to start again.`);
  }
  if (parsed.v !== PEERS_VERSION) {
    throw new Error(
      `${path} is version ${String(parsed.v)} and this ratchet reads version ${PEERS_VERSION}. ` +
        `A newer ratchet wrote it. Upgrade, or move the file aside to start a fresh trust store.`,
    );
  }
  if (!parsed.peers || typeof parsed.peers !== 'object' || Array.isArray(parsed.peers)) {
    throw new Error(`${path} is corrupt: the peers field is not a JSON object. Move it aside to start again.`);
  }

  const peers = {};
  for (const [hex, value] of Object.entries(parsed.peers)) {
    const entry = normaliseEntry(hex, value);
    if (entry) peers[hex] = entry;
  }
  return { v: PEERS_VERSION, peers };
}

/**
 * Same stage-and-rename discipline as the identity file. A crash or a power cut
 * mid write leaves the temp file orphaned and the real store exactly as it was,
 * never half written, because rename is atomic on POSIX and on NTFS within one
 * volume. That matters more here than for the identity: a half written trust
 * store is a store that has silently forgotten a verification.
 */
export async function savePeers(store) {
  const path = peersFile();
  const out = { v: PEERS_VERSION, peers: {} };
  for (const [hex, entry] of Object.entries(store.peers)) out.peers[hex] = serialiseEntry(entry);

  await mkdir(homeDir(), { recursive: true, mode: 0o700 });
  // The mode passed to mkdir and writeFile is masked by umask, so what lands on
  // disk can be looser than asked for. chmod after the fact is the only way to
  // get the real bits, and on Windows it is a genuine no-op rather than a
  // silent lie: this file carries no file-mode confidentiality there at all,
  // only whatever the default ACL on the user's profile directory grants.
  if (platform() !== 'win32') {
    await chmod(homeDir(), 0o700);
  }

  const tmp = `${path}.${randomBytes(6).toString('hex')}.tmp`;
  await writeFile(tmp, `${JSON.stringify(out, null, 2)}\n`, { mode: 0o600 });
  if (platform() !== 'win32') {
    await chmod(tmp, 0o600);
  }
  await rename(tmp, path);
}

/** Deletes the whole store. Tolerates the file already being gone. */
export async function resetPeers() {
  try {
    await unlink(peersFile());
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
}

export function lookupPeer(store, hex) {
  if (typeof hex !== 'string' || hex.length === 0) return null;
  return store.peers[hex.toLowerCase()] ?? null;
}

/** Every peer, most recently seen first, so a list command needs no sort of its own. */
export function listPeers(store) {
  return Object.values(store.peers).sort((a, b) => String(b.lastSeen ?? '').localeCompare(String(a.lastSeen ?? '')));
}

/**
 * Peers whose hex starts with `query`, or whose label matches it exactly,
 * case insensitively. Two ways to name the same row because a human who gave a
 * peer a label will use the label, and a human staring at an alarm has a hex
 * prefix on screen and no label at all.
 */
export function findPeers(store, query) {
  const q = String(query ?? '').trim().toLowerCase();
  if (q.length === 0) return [];
  const byLabel = Object.values(store.peers).filter((p) => p.label && p.label.toLowerCase() === q);
  if (byLabel.length > 0) return byLabel;
  return Object.values(store.peers).filter((p) => p.hex.startsWith(q));
}

// ---------------------------------------------------------------------------
// CLASSIFICATION
// ---------------------------------------------------------------------------

/**
 * What this machine can honestly say about the peer on the other end.
 *
 *   new        this hex has never been seen here
 *   known      seen before, nobody has verified it out loud
 *   verified   seen before, a human confirmed the words and said so
 *   changed    this ADDRESS previously carried a different, VERIFIED hex
 *
 * READ THIS BEFORE MAKING IT SMARTER. It is deliberately narrow, and the
 * temptation to widen it is the whole hazard.
 *
 * There is no username in this protocol and no account. Trust on first use has
 * nothing stable to bind a key to except an address, and an address is a bad
 * anchor: DHCP hands out a different one next week, laptops roam between
 * networks, a VPN changes it on every reconnect, and an office puts forty
 * people behind one. So an address is evidence, not identity, and the only
 * shape it can carry that is worth waking a user for is a genuine conflict:
 * somewhere a human once said "yes, that is Ana" about a key at an address, and
 * today a DIFFERENT key answers there.
 *
 * The two cases that look alarming and are not:
 *
 *   A previously UNVERIFIED association changes. Nothing was ever claimed about
 *   it. Nobody read anything aloud, so there is no claim to have been broken,
 *   and firing on this would mean crying wolf every time a DHCP lease rotates.
 *
 *   A VERIFIED peer arrives from a NEW address. What was verified is the KEY,
 *   and the key did not change. Someone opened their laptop on a different
 *   network. This gets one quiet informational line, not an alarm, because
 *   turning "your friend is on another wifi" into a red screen is how a user
 *   learns to ignore the red screen.
 *
 * One known false positive is accepted rather than papered over: two different
 * verified peers behind one NAT address will trip `changed` when the second
 * arrives. The alternative is a carve-out saying "the new key is verified too,
 * so it is fine", and that carve-out silently narrows the one alarm this tool
 * has. A rare false positive that a human can resolve in ten seconds is the
 * better failure than an alarm that has learned to stay quiet.
 *
 * Pure, and deliberately so: no clock, no disk, no I/O. It is the part that can
 * lie to a user, so it is the part that has to be trivially testable.
 */
export function classifyPeer(store, { hex, address }) {
  const key = String(hex ?? '').toLowerCase();
  const at = typeof address === 'string' && address.length > 0 ? address : null;
  const entry = store.peers[key] ?? null;

  let conflict = null;
  if (at) {
    for (const other of Object.values(store.peers)) {
      if (other.hex === key) continue;
      if (!other.verified) continue;
      if (!other.addresses.includes(at)) continue;
      // Most recently verified wins the report if there are somehow several.
      // There is only ever one line of space to show a conflict in.
      if (!conflict || String(other.verifiedAt ?? '') > String(conflict.verifiedAt ?? '')) conflict = other;
    }
  }

  const newAddress = Boolean(at) && !(entry && entry.addresses.includes(at));

  if (conflict) return { state: 'changed', hex: key, address: at, entry, conflict, newAddress };
  if (!entry) return { state: 'new', hex: key, address: at, entry: null, conflict: null, newAddress };
  if (entry.verified) return { state: 'verified', hex: key, address: at, entry, conflict: null, newAddress };
  return { state: 'known', hex: key, address: at, entry, conflict: null, newAddress };
}

// ---------------------------------------------------------------------------
// MUTATION
// ---------------------------------------------------------------------------

function nowIso(now) {
  return now ?? new Date().toISOString();
}

/**
 * Creates or updates the row for one peer. Pure in the sense that matters: it
 * takes a store and hands one back, and writing it is a separate decision.
 *
 * Call this AFTER classifyPeer, never before. Recording the sighting first
 * would add today's address to today's key and then ask whether today's key
 * conflicts with itself, which is a question with only one answer.
 */
export function recordSighting(store, { hex, words, address, now }) {
  const key = String(hex ?? '').toLowerCase();
  if (key.length === 0) throw new Error('recordSighting needs a peer identity hex');
  const stamp = nowIso(now);
  const at = typeof address === 'string' && address.length > 0 ? address : null;

  const existing = store.peers[key];
  const entry = existing ?? {
    hex: key,
    label: null,
    words: typeof words === 'string' ? words : '',
    firstSeen: stamp,
    lastSeen: stamp,
    verified: false,
    verifiedAt: null,
    addresses: [],
  };

  entry.lastSeen = stamp;
  if (!entry.firstSeen) entry.firstSeen = stamp;
  // Both are derived from the same identity digest, so this cannot rewrite the
  // words of one key into another's. It only fills in a row written by a build
  // that did not have them.
  if (typeof words === 'string' && words.length > 0) entry.words = words;
  if (at && !entry.addresses.includes(at)) {
    entry.addresses.push(at);
    if (entry.addresses.length > MAX_ADDRESSES) entry.addresses = entry.addresses.slice(-MAX_ADDRESSES);
  }

  store.peers[key] = entry;
  return entry;
}

/**
 * Marks a peer verified. The caller is responsible for having asked a human a
 * real question first, and for having got a real answer: nothing in here can
 * tell an affirmative from a default, so nothing in here pretends to.
 */
export function markVerified(store, { hex, label, now }) {
  const key = String(hex ?? '').toLowerCase();
  const entry = store.peers[key];
  if (!entry) throw new Error(`no peer with identity ${key} in ${peersFile()}`);
  entry.verified = true;
  entry.verifiedAt = nowIso(now);
  if (typeof label === 'string' && label.trim().length > 0) entry.label = label.trim();
  return entry;
}

/** Removes one peer. Returns the row that went, or null if there was none. */
export function forgetPeer(store, hex) {
  const key = String(hex ?? '').toLowerCase();
  const entry = store.peers[key] ?? null;
  if (entry) delete store.peers[key];
  return entry;
}

// ---------------------------------------------------------------------------
// Address handling
// ---------------------------------------------------------------------------

/**
 * The host part of an endpoint string that is KNOWN to carry a port.
 *
 * Feed this `channel.remote` from cli/frame.mjs, which is always built as
 * `${remoteAddress}:${remotePort}`, and nothing else. A bare host is already an
 * address and must be passed through untouched, because `2001:db8::1` and
 * `2001:db8::1:4477` are not distinguishable without knowing which one you
 * hold, and guessing wrong on a dialled host would file every sighting under a
 * mangled key.
 *
 * The port is dropped on purpose. On an inbound connection it is ephemeral, a
 * different number every time, so keeping it would make every sighting a brand
 * new address and the conflict check would never have two of anything to
 * compare. The host is the only part with any continuity, and even that is weak:
 * see classifyPeer.
 *
 * The two ends of one link therefore file different strings: the dialling side
 * records the host a human typed, which may be a name, and the listening side
 * records the IP the kernel saw. That asymmetry is inherent and harmless, since
 * each store only ever compares its own records against each other.
 */
export function addressOf(remote) {
  const text = String(remote ?? '').trim();
  if (text.length === 0) return null;
  // [2001:db8::1]:4477, the bracketed form.
  if (text.startsWith('[')) {
    const end = text.indexOf(']');
    return end === -1 ? text : text.slice(1, end);
  }
  const colon = text.lastIndexOf(':');
  if (colon <= 0) return text;
  return text.slice(0, colon);
}
