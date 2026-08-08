/**
 * The identity store: one file, one identity, one writer.
 *
 * loadIdentity() is deliberately the only function in this module that can
 * write cli/identity. Every other path (handshake, transfer, whatever calls
 * this next) only ever reads. That asymmetry is what makes a stray bug
 * elsewhere unable to clobber a user's fingerprint out from under them.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS ON DISK, AND IN WHICH OF THREE SHAPES
 * ---------------------------------------------------------------------------
 *
 * Until 0.4.0 this file held exportIdentity() output verbatim: both secret
 * halves, X25519 and ML-KEM-768, in base64url, with nothing in front of them.
 * Anyone who read it could impersonate the user forever and complete a
 * handshake as them with anyone who had not verified the six words out loud.
 * Forward secrecy does not help with that: it protects messages already sent,
 * not the identity that signs for the next ones.
 *
 * Now the file is self describing, and a reader can tell which of three things
 * is true without guessing:
 *
 *   # a comment block explaining what the file is
 *   OCXV1.dpapi.<base64url of 24 byte nonce || XChaCha20-Poly1305 ciphertext>
 *
 *   OCXV1.pass.<base64url of the same shape, key derived from a passphrase>
 *
 *   OCXV1.none.OCX2.identity.<base64url>      the old content, tagged as bare
 *
 * plus the fourth shape it must still read, which is every file written before
 * this existed:
 *
 *   OCX2.identity.<base64url>                 no header at all
 *
 * The inner token keeps its own version marker and this module does not care
 * which one it is. A 0.3.x file holds `OCX1.identity.`, a 0.4.x file holds
 * `OCX2.identity.`, and both are handed to importIdentity() unchanged so that
 * the library, not the CLI, decides what it can still read.
 *
 * A file in that last shape loads, is re-wrapped immediately in whatever
 * protection this machine can offer, and says so once. "Re-wrapped on the next
 * write" would in practice mean never, because nothing else in the CLI ever
 * writes this file again after it is minted.
 *
 * The protection tag is authenticated, not decorative: it is fed to the AEAD as
 * associated data, so an attacker who rewrites `OCXV1.pass.` to `OCXV1.dpapi.`
 * gets an authentication failure rather than a confusing decrypt.
 */

import { chmod, mkdir, readFile, unlink } from 'node:fs/promises';
import { platform } from 'node:os';
import { join } from 'node:path';

import { engine, exportIdentity, importIdentity } from '../dist/index.js';
import {
  VAULT_INFO,
  b64u,
  describeProtection,
  ensureHome,
  homeDir,
  seal,
  subkey,
  unb64u,
  unseal,
  vaultKey,
  vaultState,
  writeAtomic,
} from './vault.mjs';

export { homeDir };

const WRAPPER = 'OCXV1';
// Any identity token, of any body version. The CLI's job is to recognise one,
// not to date it: importIdentity() owns the question of which versions still
// load, and duplicating that answer here would mean a second place to forget.
const TOKEN_SHAPE = /^OCX\d+\.identity\./;

function isToken(text) {
  return TOKEN_SHAPE.test(text);
}

export function identityFile() {
  return join(homeDir(), 'identity');
}

function aadFor(protection) {
  return `ratchet-ts.identity.v1|${protection}`;
}

/**
 * The comment block. It exists so that a person who opens this file in an
 * editor, which is exactly what a worried person does, is told what they are
 * looking at and what to do about it, in their own language, without running
 * anything.
 */
function header(protection) {
  if (protection === 'none') {
    return [
      '# ratchet identity. THIS FILE IS NOT ENCRYPTED.',
      '# It holds both halves of your long term secret key. Anyone who copies it',
      '# can be you: they can complete a handshake in your name with anyone who',
      '# has not compared your six words out loud.',
      '# No keychain was reachable on this machine. To protect it with a',
      '# passphrase instead, run:  ratchet lock',
    ];
  }
  return [
    `# ratchet identity, sealed with the vault key held by ${describeProtection(protection)}.`,
    '# Without that key this file is noise. See the "vault" file beside it.',
    '# It still holds both halves of your long term secret key, so treat a copy',
    '# of it as sensitive even in this form.',
  ];
}

function compose(protection, payload) {
  return `${header(protection).join('\n')}\n${WRAPPER}.${protection}.${payload}\n`;
}

/**
 * The first line that is not a comment and not blank. Comments are stripped by
 * the reader rather than being merely conventional, so the explanation above
 * can grow without ever becoming something the parser trips over.
 */
function payloadLine(raw) {
  for (const line of String(raw).split(/\r?\n/)) {
    const text = line.trim();
    if (text.length === 0 || text.startsWith('#')) continue;
    return text;
  }
  return '';
}

function corrupt(path, detail, cause) {
  return new Error(
    `${path} is corrupt: ${detail}. ` +
      `Run ratchet id --reset --yes (or delete the file) to discard it and mint a new one. ` +
      `Refusing to do that automatically because it would silently change your fingerprint.`,
    { cause },
  );
}

/**
 * Turns the file's one payload line into an identity token, unsealing it if it is
 * sealed. Returns the token and how the file was protected, because the caller
 * has to know whether what it just read needs re-wrapping.
 */
async function tokenFrom(path, line) {
  if (line.startsWith(`${WRAPPER}.`)) {
    const rest = line.slice(WRAPPER.length + 1);
    const dot = rest.indexOf('.');
    if (dot <= 0) throw corrupt(path, 'the header names no protection');
    const protection = rest.slice(0, dot);
    const body = rest.slice(dot + 1);
    if (protection === 'none') {
      if (!isToken(body)) throw corrupt(path, 'it says it is unprotected but holds no identity token');
      return { token: body, protection: 'none', legacy: false };
    }
    const key = await vaultKey();
    if (!key) {
      throw new Error(
        `${path} says it is sealed with ${describeProtection(protection)}, but there is no vault to open it. ` +
          `Nothing is lost while both this file and that key store survive. If you moved this file from another ` +
          `machine, move the "vault" file next to it as well, and note that a keychain sealed vault does not travel.`,
      );
    }
    let plain;
    try {
      plain = unseal(subkey(key, VAULT_INFO.identity), aadFor(protection), unb64u(body));
    } catch (cause) {
      throw corrupt(path, 'it did not open with this machine\'s vault key, so it was written by another one or changed since', cause);
    }
    const token = plain.toString('utf8');
    if (!isToken(token)) throw corrupt(path, 'what came out of the envelope is not an identity token');
    return { token, protection, legacy: false };
  }

  if (isToken(line)) return { token: line, protection: 'none', legacy: true };
  throw corrupt(path, 'it does not parse as an identity token');
}

/**
 * Write the token, sealed if there is anything to seal it with.
 *
 * `create: true` on the vault lookup is what makes protection turn itself on:
 * a write is the moment a directory acquires a vault, and a read never is.
 */
async function writeIdentityFile(path, token) {
  const key = await vaultKey({ create: true });
  const state = await vaultState();
  const protection = key ? state.protection : 'none';
  await ensureHome();
  if (!key) {
    await writeAtomic(path, compose('none', token));
    return 'none';
  }
  const sealed = seal(subkey(key, VAULT_INFO.identity), aadFor(protection), Buffer.from(token, 'utf8'));
  await writeAtomic(path, compose(protection, b64u(sealed)));
  return protection;
}

/**
 * One sentence about something that changed on disk without being asked for,
 * drained by bin/ratchet.mjs after it loads the identity. A migration that
 * happens silently is a migration a user cannot audit, and this is the only
 * place in the CLI that rewrites a file the user did not ask it to rewrite.
 */
let migrationNotice = null;

export function takeMigrationNotice() {
  const notice = migrationNotice;
  migrationNotice = null;
  return notice;
}

/**
 * Reads the persisted identity, minting one on first run. This is the only
 * function in this module allowed to write cli/identity, see the module
 * comment for why that matters.
 *
 * A file that exists but fails to parse is never silently replaced. Doing so
 * would mint a new identity and change the user's fingerprint without any
 * signal, which defeats the entire point of a fingerprint: it exists so a
 * changed identity is visible, not so it can change quietly on disk error.
 */
export async function loadIdentity() {
  const path = identityFile();
  let raw;
  try {
    raw = await readFile(path, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') {
      await mkdir(homeDir(), { recursive: true, mode: 0o700 });
      if (platform() !== 'win32') await chmod(homeDir(), 0o700);
      const identity = await engine.createIdentity();
      const protection = await writeIdentityFile(path, exportIdentity(identity));
      if (protection === 'none') {
        migrationNotice =
          'This machine has no keychain ratchet can reach, so the identity it just minted is in a plain file.';
      }
      return identity;
    }
    throw err;
  }

  const line = payloadLine(raw);
  if (line.length === 0) throw corrupt(path, 'it holds no identity line at all, only comments or nothing');

  const { token, protection, legacy } = await tokenFrom(path, line);

  let identity;
  try {
    identity = importIdentity(token);
  } catch (cause) {
    throw corrupt(path, 'it does not parse as an identity token', cause);
  }

  // A pre-0.4.0 file, or a file written before a keychain became available.
  // Upgrade it in place, and never at the cost of the identity itself: if the
  // rewrite fails, the user still has a working identity and one line saying
  // the upgrade did not happen.
  if (legacy) {
    try {
      const now = await writeIdentityFile(path, token);
      migrationNotice =
        now === 'none'
          ? `${path} was a plain file and still is: no keychain on this machine would take the key. Run ratchet lock to use a passphrase.`
          : `${path} was a plain file. It has been sealed with the vault key held by ${describeProtection(now)}.`;
    } catch (err) {
      migrationNotice = `${path} is still unprotected: sealing it failed with ${err.message}`;
    }
  }

  return identity;
}

/** Deletes the persisted identity. Tolerates the file already being gone. */
export async function resetIdentity() {
  try {
    await unlink(identityFile());
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
}

/**
 * Re-writes the identity file under a new vault key. Used only by lock and
 * unlock, which have already resolved the OLD key and read the token out.
 */
export async function rewrapIdentity(token, protection, key) {
  const path = identityFile();
  await ensureHome();
  if (!key) {
    await writeAtomic(path, compose('none', token));
    return;
  }
  const sealed = seal(subkey(key, VAULT_INFO.identity), aadFor(protection), Buffer.from(token, 'utf8'));
  await writeAtomic(path, compose(protection, b64u(sealed)));
}

/**
 * The identity as the token it is stored as, without importing it. lock and
 * unlock need the bytes, not a parsed key pair, and asking importIdentity to
 * parse them just so exportIdentity can put them back is a round trip that can
 * only introduce a difference.
 */
export async function readIdentityToken() {
  const path = identityFile();
  let raw;
  try {
    raw = await readFile(path, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
  const line = payloadLine(raw);
  if (line.length === 0) throw corrupt(path, 'it holds no identity line at all');
  const { token } = await tokenFrom(path, line);
  return token;
}
