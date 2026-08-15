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
 * remembers the answer. Without a store, a user can verify the safety words with
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
 * Through 0.3.x it recorded all of that in plain JSON, and that was a real
 * privacy regression dressed up as a security feature: a timestamped, labelled
 * list of who this machine had talked to and from where, in a file that had not
 * existed at all one version earlier. The trust store is worth having, so the
 * answer is to harden it rather than to delete it.
 *
 * ---------------------------------------------------------------------------
 * THE PROPERTY THIS FILE NOW HAS
 * ---------------------------------------------------------------------------
 *
 * WITH the vault key, this store works exactly as it did before: same in memory
 * shape, same classification, same alarm.
 *
 * WITHOUT it, a copy of this file yields a COUNT OF PEERS AND NOTHING ELSE. No
 * names, no words, no addresses, no dates, no verification flags. Every row is
 * one padded XChaCha20-Poly1305 envelope, so the rows do not even differ in
 * length, and the map key each one is filed under is a MAC of the peer identity
 * under a subkey of the vault key, which reveals the identity to nobody and can
 * be recomputed in one step by anybody holding the key. See cli/vault.mjs for
 * where that key lives and what it does not protect against.
 *
 * When no vault is available the file falls back to plain JSON, exactly as it
 * was, and says "UNPROTECTED" in its own note field rather than looking the
 * same as a protected one.
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

import { createHmac, randomBytes } from 'node:crypto';
import { readFile, unlink } from 'node:fs/promises';
import { join } from 'node:path';

import {
  VAULT_INFO,
  b64u,
  ensureHome,
  homeDir,
  pad,
  seal,
  subkey,
  unb64u,
  unpad,
  unseal,
  vaultKey,
  vaultState,
  writeAtomic,
} from './vault.mjs';

/**
 * Bumped only when the shape below changes in a way an older reader cannot
 * cope with. A reader that meets a version it does not know refuses rather
 * than guessing, because guessing at a trust record is how a verification
 * quietly turns into a non-verification.
 *
 * 1 was the plain JSON store of 0.3.x, which this still reads so that nobody
 * loses a verification by upgrading. 2 is the sealed store.
 */
export const PEERS_VERSION = 2;
const LEGACY_PEERS_VERSION = 1;

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

/**
 * Timestamps are coarsened to the day on the way to disk, and only there.
 *
 * Minute resolution is the part that turns a contact list into a pattern of
 * life record. "Have I talked to this person recently" and "how long have I
 * known this key", which are the two questions this file exists to answer, are
 * both answered at day resolution. "This person is at their desk at 08:47 on
 * weekdays" is not a question anybody asked it, and it is the one a stolen copy
 * answers best.
 *
 * Coarsening on write rather than in recordSighting keeps the in memory value
 * at full resolution for the life of the process, which costs nothing and
 * keeps every caller's contract unchanged. Slicing an already coarsened value
 * is a no-op, so a load and save cycle is stable.
 */
function day(stamp) {
  const text = typeof stamp === 'string' ? stamp : '';
  return text.length >= 10 ? text.slice(0, 10) : null;
}

/** The on-disk projection. `hex` is the key, so it is not repeated in the value. */
function serialiseEntry(entry) {
  return {
    label: entry.label,
    words: entry.words,
    firstSeen: day(entry.firstSeen),
    lastSeen: day(entry.lastSeen),
    verified: entry.verified,
    verifiedAt: day(entry.verifiedAt),
    addresses: entry.addresses,
  };
}

// ---------------------------------------------------------------------------
// The sealed shape
// ---------------------------------------------------------------------------

/**
 * The name a row is filed under.
 *
 * The brief asked for a salted hash of the identity hex, so that a copied file
 * cannot be run against a rainbow table of known public keys. This does that
 * and one thing more: the hash is KEYED, with a subkey of the vault key, and
 * the per file salt is mixed in as well.
 *
 * The upgrade is free and it closes a real gap. A salt that is stored in the
 * same file only stops a PRECOMPUTED table. It does nothing against an attacker
 * who has a specific key in mind and wants to know whether this machine has
 * talked to it, because they can hash that one candidate with the salt they can
 * read. Keying it means an attacker without the vault key cannot even ask that
 * question. The salt still earns its place: it makes two files written under
 * one vault key file the same peer under different names, so two stolen
 * directories cannot be correlated row by row.
 *
 * Lookup stays one MAC per handshake, which is what the brief cared about.
 */
function indexOf(salt, indexKey, hex) {
  return b64u(createHmac('sha256', indexKey).update(salt).update(Buffer.from(hex, 'utf8')).digest().subarray(0, 16));
}

function entryAad(id) {
  return `${VAULT_INFO.peersEntry}|${id}`;
}

/**
 * Everything except the row name goes inside the envelope, INCLUDING the
 * addresses, and that is a deliberate departure from the brief.
 *
 * The brief asked for addresses to be salted hashes on the same argument as the
 * identity hex. The argument does not carry over. An identity digest is 128
 * bits of unguessable value, so hashing it hides it. An IPv4 address is one of
 * 2^32 values and the salt is in the file, so a copied store can be exhausted
 * against the whole address space in seconds on any GPU, and the answer comes
 * back as the plain address. Hashing them would look like protection and
 * provide close to none. Sealing them provides all of it, and it costs nothing
 * here because loadPeers already decrypts every row into memory: the alarm then
 * compares plain strings exactly as it always did, so classifyPeer is untouched
 * and its tests are untouched with it.
 *
 * The known IPv4 versus IPv6 gap is therefore unchanged: 127.0.0.1 and
 * ::ffff:127.0.0.1 remain two different rows in the address list, because they
 * are two different strings. Hashing would have preserved that gap exactly,
 * since it preserves inequality; sealing preserves it too. Neither makes it
 * better or worse. It is a normalisation bug in addressOf's callers, and the
 * honest place to fix it is there, not by pretending an encoding choice is a
 * privacy control.
 *
 * `verified` goes inside as well, which is stronger than the brief asked for. A
 * plaintext boolean can be flipped by anyone who can write the file; one inside
 * an AEAD cannot be flipped by anyone who cannot forge a tag. Since the store is
 * unreadable without the key anyway, there was never a reason to leave the one
 * field the whole file exists for exposed on its own.
 */
function sealEntry(entryKey, id, entry) {
  const body = JSON.stringify({ hex: entry.hex, ...serialiseEntry(entry) });
  return b64u(seal(entryKey, entryAad(id), pad(Buffer.from(body, 'utf8'))));
}

function openEntry(entryKey, id, blob) {
  const plain = unpad(unseal(entryKey, entryAad(id), unb64u(blob)));
  const parsed = JSON.parse(plain.toString('utf8'));
  if (!parsed || typeof parsed !== 'object' || typeof parsed.hex !== 'string') return null;
  return parsed;
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
const PROTECTED_NOTE =
  'Every row below is one sealed envelope. With the vault key this is a normal trust store. ' +
  'Without it, it is a count of peers and nothing else: no names, no words, no addresses, no dates.';

const UNPROTECTED_NOTE =
  'UNPROTECTED. Every row below is readable by anyone who can read this file: who this machine has ' +
  'talked to, from where, and when. No keychain was reachable here. Run: ratchet lock';

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
  if (parsed.v !== PEERS_VERSION && parsed.v !== LEGACY_PEERS_VERSION) {
    throw new Error(
      `${path} is version ${String(parsed.v)} and this ratchet reads version ${PEERS_VERSION}. ` +
        `A newer ratchet wrote it. Upgrade, or move the file aside to start a fresh trust store.`,
    );
  }
  if (!parsed.peers || typeof parsed.peers !== 'object' || Array.isArray(parsed.peers)) {
    throw new Error(`${path} is corrupt: the peers field is not a JSON object. Move it aside to start again.`);
  }

  // Version 1, and version 2 written on a machine with no vault, are both plain
  // rows keyed by hex. Version 1 files get upgraded the next time anything is
  // saved, which is the first completed handshake.
  const sealed = parsed.v === PEERS_VERSION && parsed.protection && parsed.protection !== 'none';
  if (!sealed) {
    const peers = {};
    for (const [hex, value] of Object.entries(parsed.peers)) {
      const entry = normaliseEntry(hex, value);
      if (entry) peers[hex] = entry;
    }
    return { v: PEERS_VERSION, peers };
  }

  if (typeof parsed.salt !== 'string') {
    throw new Error(`${path} is corrupt: it says it is sealed but carries no salt, so no row in it can be named.`);
  }
  const key = await vaultKey();
  if (!key) {
    throw new Error(
      `${path} is sealed with ${String(parsed.protection)} and there is no vault key here to open it. ` +
        `Nothing is lost while the "vault" file beside it survives. A store sealed to a keychain does not ` +
        `travel to another machine or another user account.`,
    );
  }
  const salt = unb64u(parsed.salt);
  const entryKey = subkey(key, VAULT_INFO.peersEntry);
  const indexKey = subkey(key, VAULT_INFO.peersIndex);

  const peers = {};
  for (const [id, blob] of Object.entries(parsed.peers)) {
    let raw2;
    try {
      raw2 = typeof blob === 'string' ? openEntry(entryKey, id, blob) : null;
    } catch (cause) {
      throw new Error(
        `${path} is corrupt: row ${id} did not open with this machine's vault key. Either the file was ` +
          `changed since it was written, or it belongs to another vault. It is not being discarded, because ` +
          `discarding it would throw away every verification in it.`,
        { cause },
      );
    }
    if (!raw2) throw new Error(`${path} is corrupt: row ${id} opened into something that is not a peer record.`);
    // The row name is recomputed rather than trusted. A row moved from one name
    // to another cannot survive the AEAD's associated data anyway, so this is
    // belt and braces, and it costs one MAC.
    if (indexOf(salt, indexKey, String(raw2.hex).toLowerCase()) !== id) {
      throw new Error(`${path} is corrupt: row ${id} holds a peer that does not belong under that name.`);
    }
    const entry = normaliseEntry(String(raw2.hex).toLowerCase(), raw2);
    if (entry) peers[entry.hex] = entry;
  }
  return { v: PEERS_VERSION, peers };
}

/**
 * Same stage-and-rename discipline as the identity file. A crash or a power cut
 * mid write leaves the temp file orphaned and the real store exactly as it was,
 * never half written, because rename is atomic on POSIX and on NTFS within one
 * volume. That matters more here than for the identity: a half written trust
 * store is a store that has silently forgotten a verification.
 *
 * A write is also the moment this directory acquires a vault if it has none,
 * which is why the key is asked for with `create`. A read never creates one.
 */
export async function savePeers(store, override = null) {
  const path = peersFile();
  await ensureHome();

  // `override` exists for exactly one caller: `ratchet lock` and `ratchet
  // unlock`, which are mid transaction and hold a key that the descriptor on
  // disk does not name yet. Nothing else may pass it, because writing this file
  // under a key the descriptor does not point at is how a store becomes
  // unreadable.
  const key = override ? override.key : await vaultKey({ create: true });
  if (!key) {
    const out = { v: PEERS_VERSION, protection: 'none', note: UNPROTECTED_NOTE, peers: {} };
    for (const [hex, entry] of Object.entries(store.peers)) out.peers[hex] = serialiseEntry(entry);
    await writeAtomic(path, `${JSON.stringify(out, null, 2)}\n`);
    return;
  }

  const protection = override ? override.protection : (await vaultState()).protection;
  // A fresh salt on every write, not a stable one. Rewriting the file renames
  // every row, so two snapshots of the same store taken a week apart cannot be
  // diffed row by row by somebody who has both and neither key.
  const salt = randomBytes(16);
  const entryKey = subkey(key, VAULT_INFO.peersEntry);
  const indexKey = subkey(key, VAULT_INFO.peersIndex);

  const out = { v: PEERS_VERSION, protection, note: PROTECTED_NOTE, salt: b64u(salt), peers: {} };
  for (const entry of Object.values(store.peers)) {
    const id = indexOf(salt, indexKey, entry.hex);
    out.peers[id] = sealEntry(entryKey, id, entry);
  }
  await writeAtomic(path, `${JSON.stringify(out, null, 2)}\n`);
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
