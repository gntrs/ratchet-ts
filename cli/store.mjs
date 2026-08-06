/**
 * The identity store: one file, one identity, one writer.
 *
 * loadIdentity() is deliberately the only function in this module that can
 * write cli/identity. Every other path (handshake, transfer, whatever calls
 * this next) only ever reads. That asymmetry is what makes a stray bug
 * elsewhere unable to clobber a user's fingerprint out from under them.
 */

import { randomBytes } from 'node:crypto';
import { chmod, mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { homedir, platform } from 'node:os';
import { join } from 'node:path';

import { engine, exportIdentity, importIdentity } from '../dist/index.js';

export function homeDir() {
  return process.env.RATCHET_HOME || join(homedir(), '.ratchet');
}

export function identityFile() {
  return join(homeDir(), 'identity');
}

/**
 * Write the token atomically: stage it in a sibling temp file, then rename
 * over the real path. A crash or power loss mid write leaves the temp file
 * orphaned and the real identity file exactly as it was, never half written,
 * because rename is atomic on both POSIX and NTFS within the same volume.
 */
async function writeIdentityFile(path, token) {
  const tmp = `${path}.${randomBytes(6).toString('hex')}.tmp`;
  await writeFile(tmp, `${token}\n`, { mode: 0o600 });
  // The mode passed to writeFile is masked by umask, so the file that lands
  // on disk can be looser than 0o600 even though we asked for it. chmod after
  // the fact is the only way to get the real bits, and it is a genuine no-op
  // on Windows (NTFS ACLs, not POSIX mode bits) rather than a silent lie, so
  // this identity file carries no file-mode confidentiality on Windows at
  // all: whatever the OS default ACL for the user's profile directory grants
  // is what protects it there.
  if (platform() !== 'win32') {
    await chmod(tmp, 0o600);
  }
  await rename(tmp, path);
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
      if (platform() !== 'win32') {
        await chmod(homeDir(), 0o700);
      }
      const identity = await engine.createIdentity();
      await writeIdentityFile(path, exportIdentity(identity));
      return identity;
    }
    throw err;
  }

  const token = raw.trim();
  try {
    return importIdentity(token);
  } catch (cause) {
    throw new Error(
      `${path} is corrupt: it does not parse as an OCX1 identity token. ` +
        `Run resetIdentity() (or delete the file) to discard it and mint a new one. ` +
        `Refusing to do that automatically because it would silently change your fingerprint.`,
      { cause },
    );
  }
}

/** Deletes the persisted identity. Tolerates the file already being gone. */
export async function resetIdentity() {
  try {
    await unlink(identityFile());
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
}
