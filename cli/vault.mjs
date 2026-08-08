/**
 * The vault: one CLI level secret, protecting both files this tool leaves on a
 * user's disk.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS EXISTS
 * ---------------------------------------------------------------------------
 *
 * src/serialize.ts is right that at rest protection is a platform question the
 * library cannot answer, because a library does not know whether it is running
 * on a laptop, in a browser, or inside a hardware token. That is a defensible
 * position for a library. It is not a defensible position for a command that
 * people install and run, because the answer to "where does the key live" then
 * defaults to "in a plain text file next to the thing it protects".
 *
 * Before this module, ~/.ratchet/identity held both secret halves of the long
 * term identity in base64url with nothing in front of them, and
 * ~/.ratchet/peers.json held a timestamped list of who this machine had talked
 * to and from which addresses. Forward secrecy protects past messages. It does
 * not protect future impersonation, and it does nothing at all for a contact
 * list. Backup software, a synced folder, a stolen laptop, a shared machine and
 * a hostile postinstall script in an unrelated project all reach both files.
 *
 * So there is one key here, with two consumers, and the order in which it is
 * resolved is the whole design.
 *
 * ---------------------------------------------------------------------------
 * THE THREE STATES, AND WHY THERE ARE ONLY THREE
 * ---------------------------------------------------------------------------
 *
 *   1. OS keychain. Windows DPAPI, the macOS keychain, or libsecret on Linux.
 *      This is the default wherever it works, and it is invisible: the user
 *      types `ratchet chat` and is asked nothing, ever. A security feature
 *      nobody can operate is not a security feature.
 *
 *   2. Passphrase. Only if the user asked for one with `ratchet lock`. Costs a
 *      prompt on every command, which is exactly why it is not the default.
 *
 *   3. Unprotected, which is what every version before this one did, except
 *      that now the file says so in its own first line and `ratchet id` says
 *      so out loud with the command that fixes it.
 *
 * There is deliberately no fourth state. Every extra state is another branch
 * where a file can be readable for a reason nobody predicted, and the whole
 * value of this module is that a reader can tell which of three things is true
 * by looking at one line.
 *
 * The key is never stored next to the thing it protects, with one honest
 * exception that is called out where it happens: see the DPAPI backend below.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS IS NOT
 * ---------------------------------------------------------------------------
 *
 * None of the keychain backends defend against code running as the same user
 * at the same time. DPAPI unprotects for any process of that Windows account,
 * the macOS keychain will hand the item to anything the user has allowed, and
 * secret-tool answers an unlocked session. What all three defend against is a
 * copy of the files: a backup, a sync folder, a disk pulled out of a laptop, a
 * repository somebody committed their home directory into. That is the threat
 * the plaintext file lost to, and it is the threat this wins.
 *
 * A passphrase is the only state here that survives an attacker who has both
 * the files and the running machine's user account, and only while it is not
 * typed.
 */

import { spawnSync } from 'node:child_process';
import { createHash, createHmac, hkdfSync, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { chmod, mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { homedir, platform } from 'node:os';
import { join } from 'node:path';
import readline from 'node:readline';

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';

/**
 * Bumped only when the descriptor shape changes in a way an older reader
 * cannot cope with. A reader that meets a version it does not know refuses
 * rather than guessing, because guessing here means guessing at how a secret
 * is protected.
 */
export const VAULT_VERSION = 1;

/**
 * The five values the `protection` field can hold. `none` is a real state and
 * is written down as one: a file that does not say what protects it is a file
 * whose reader has to assume, and assuming is how "I thought that was
 * encrypted" happens.
 */
export const PROTECTIONS = ['none', 'dpapi', 'macos', 'libsecret', 'pass'];

const KEYCHAIN_SERVICE = 'ratchet-ts';

/**
 * Domain separation. The vault key is never used directly for anything: every
 * consumer gets its own subkey through HKDF, so a flaw in one use cannot be
 * pushed sideways into another, and a ciphertext from one file can never be
 * opened as if it came from the other.
 */
const INFO_IDENTITY = 'ratchet-ts.cli.identity.v1';
const INFO_PEERS_ENTRY = 'ratchet-ts.cli.peers.entry.v1';
const INFO_PEERS_INDEX = 'ratchet-ts.cli.peers.index.v1';
const INFO_CHECK = 'ratchet-ts.cli.vault.check.v1';

/**
 * scrypt, with the parameters argued rather than copied.
 *
 * Argon2id would be the better primitive and it is not reachable: Node has no
 * Argon2 in node:crypto, @noble/hashes ships argon2 only from v2 under a path
 * this package does not depend on today, and pulling a new npm dependency into
 * a security tool to save a factor of two in GPU cost is the wrong trade. So
 * scrypt, which is in node:crypto, is memory hard, and is what is actually
 * available without adding an install time supply chain risk to the exact tool
 * whose selling point is that nobody reads your messages.
 *
 * N = 2^18, r = 8, p = 1 costs 128 * N * r = 256 MiB of memory per guess and
 * measured 1164, 1181 and 1335 ms across three runs on the development laptop
 * (Windows 11, Node 25). That is over the one second an unlock wants to stay
 * under, and it is kept anyway: the derivation happens once per process, not
 * once per command, and only for somebody who chose `ratchet lock`. Halving it
 * to N = 2^17 measured 599 to 644 ms and halves the memory to 128 MiB, which
 * doubles how many guesses a card runs at once. A second of the user's time,
 * once, buys that back. The
 * attacker these are chosen against is somebody who copied ~/.ratchet and runs
 * a GPU rig against it offline. Memory, not iteration count, is what makes
 * that expensive: a 24 GB card holds roughly ninety concurrent 256 MiB scrypt
 * instances, against the tens of thousands of concurrent hashes the same card
 * manages for PBKDF2 or a bare SHA. Raising p would double the work without
 * touching that ratio, so the budget goes into N.
 *
 * The parameters live in the file rather than in this constant, so a future
 * build can raise them without orphaning anybody's identity, and a machine too
 * small to allocate 256 MiB fails loudly with its own error rather than
 * silently deriving a different, weaker key.
 */
const SCRYPT = { name: 'scrypt', N: 262144, r: 8, p: 1 };

const NONCE_LEN = 24;
const TAG_LEN = 16;

// ---------------------------------------------------------------------------
// Paths and small encodings
// ---------------------------------------------------------------------------

export function homeDir() {
  return process.env.RATCHET_HOME || join(homedir(), '.ratchet');
}

export function vaultFile() {
  return join(homeDir(), 'vault');
}

export function b64u(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

export function unb64u(text) {
  return Buffer.from(String(text), 'base64url');
}

/** mkdir plus the real mode bits, which writeFile alone cannot promise. */
export async function ensureHome() {
  const dir = homeDir();
  await mkdir(dir, { recursive: true, mode: 0o700 });
  // On Windows this is a genuine no-op rather than a silent lie: NTFS uses
  // ACLs, not POSIX mode bits, so the only thing guarding this directory there
  // is whatever the default ACL on the user profile grants.
  if (platform() !== 'win32') await chmod(dir, 0o700);
  return dir;
}

/**
 * Stage in a sibling temp file, then rename over the target. A crash mid write
 * leaves the temp file orphaned and the real file exactly as it was, never
 * half written, because rename is atomic on POSIX and on NTFS within one
 * volume.
 */
export async function writeAtomic(path, text) {
  const tmp = `${path}.${randomBytes(6).toString('hex')}.tmp`;
  await writeFile(tmp, text, { mode: 0o600 });
  if (platform() !== 'win32') await chmod(tmp, 0o600);
  await rename(tmp, path);
}

// ---------------------------------------------------------------------------
// The sealed blob format, shared by both files
// ---------------------------------------------------------------------------

/**
 * XChaCha20-Poly1305, and the reason is the nonce and nothing else.
 *
 * ChaCha20-Poly1305 has a 96 bit nonce, which is small enough that generating
 * them at random needs a counter or a birthday argument to stay safe. This
 * module has neither a counter it can trust nor a place to keep one: the same
 * key seals the identity file and every row of the peer store, files get
 * rewritten on every sighting, and two ratchet processes can be running at
 * once. XChaCha20 takes a 192 bit nonce, where a fresh random value per seal
 * has a collision probability that stays negligible for any number of writes a
 * human will ever perform. That removes the one piece of state this code would
 * otherwise have to get right forever.
 */
export function seal(key, info, plaintext) {
  const nonce = randomBytes(NONCE_LEN);
  const aead = xchacha20poly1305(key, nonce, Buffer.from(info, 'utf8'));
  const ct = aead.encrypt(Buffer.from(plaintext));
  return Buffer.concat([nonce, Buffer.from(ct)]);
}

/**
 * Returns the plaintext, or throws. It never returns null for a failure: a
 * caller that has to remember to check a return value is a caller that will
 * one day forget, and forgetting here means treating unopenable data as empty.
 */
export function unseal(key, info, blob) {
  const bytes = Buffer.from(blob);
  if (bytes.length < NONCE_LEN + TAG_LEN) throw new Error('sealed blob is too short to be one');
  const nonce = bytes.subarray(0, NONCE_LEN);
  const ct = bytes.subarray(NONCE_LEN);
  const aead = xchacha20poly1305(key, nonce, Buffer.from(info, 'utf8'));
  return Buffer.from(aead.decrypt(ct));
}

/** A 32 byte subkey per use. The vault key itself never encrypts anything. */
export function subkey(vaultKey, info) {
  return Buffer.from(hkdfSync('sha256', vaultKey, Buffer.alloc(0), Buffer.from(info, 'utf8'), 32));
}

/**
 * Pad to a multiple of BLOCK bytes so a ciphertext length says nothing about
 * what is inside it. Without this, a peer row sealing the label "Mum" and one
 * sealing "the guy from the conference" are told apart by anyone holding the
 * file, which gives away roughly how long every name in the contact list is.
 */
const BLOCK = 256;

export function pad(plaintext) {
  const body = Buffer.from(plaintext);
  const header = Buffer.alloc(4);
  header.writeUInt32BE(body.length, 0);
  const total = 4 + body.length;
  const padded = Math.ceil(total / BLOCK) * BLOCK;
  return Buffer.concat([header, body, Buffer.alloc(padded - total)]);
}

export function unpad(padded) {
  const bytes = Buffer.from(padded);
  if (bytes.length < 4) throw new Error('padded block is too short');
  const len = bytes.readUInt32BE(0);
  if (len > bytes.length - 4) throw new Error('padded block claims a length it does not have');
  return bytes.subarray(4, 4 + len);
}

// ---------------------------------------------------------------------------
// Backend: Windows DPAPI, reached through PowerShell
// ---------------------------------------------------------------------------

/**
 * Windows has no keychain a child process can both write and read back.
 * cmdkey writes to Credential Manager and cannot read a secret out again, and
 * reading one needs CredRead through P/Invoke, which in Windows PowerShell 5.1
 * means Add-Type compiling C# on the fly, which is both slow and one missing
 * compiler away from failing on somebody's machine.
 *
 * What is reachable, on every Windows install, with no dependency, is DPAPI:
 * System.Security.Cryptography.ProtectedData, sealing to the current user
 * account. Measured on the development laptop: 250 to 290 ms per PowerShell
 * round trip, which is the process spawn, not the crypto (the Protect call
 * itself is about 10 ms and Unprotect about 4 ms). That cost lands once per
 * ratchet invocation because the resolved key is cached for the life of the
 * process.
 *
 * THE HONEST PART. DPAPI produces a sealed blob rather than storing anything
 * for us, so that blob lives in ~/.ratchet/vault, which is next to the files it
 * protects. The blob is not the key: unsealing it requires the Windows user's
 * DPAPI master key, which lives in the user profile and is itself wrapped by
 * the account credential. So copying ~/.ratchet gets an attacker nothing.
 * Copying the entire Windows profile AND recovering the account password does
 * get them the key, which is exactly the property every browser on Windows has
 * for its saved passwords. If that is not good enough for a particular user,
 * `ratchet lock` is the answer and it is one command.
 *
 * The secret crosses on stdin, never on the command line, because a command
 * line is readable by every other process on the machine while it runs.
 */
const DPAPI_ENTROPY = 'ratchet-ts.vault.v1';

function powershellPath() {
  if (platform() !== 'win32') return null;
  return process.env.RATCHET_POWERSHELL || 'powershell.exe';
}

function runPowerShell(script, input) {
  const exe = powershellPath();
  if (!exe) return null;
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  const result = spawnSync(exe, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded], {
    input,
    encoding: 'utf8',
    windowsHide: true,
    timeout: 20000,
    maxBuffer: 1 << 20,
  });
  if (result.error || result.status !== 0) return null;
  const out = String(result.stdout || '').trim();
  return out.length > 0 ? out : null;
}

const DPAPI_PROLOGUE = `
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Security | Out-Null
$entropy = [Text.Encoding]::UTF8.GetBytes('${DPAPI_ENTROPY}')
$incoming = [Console]::In.ReadToEnd().Trim()
$bytes = [Convert]::FromBase64String($incoming)
`;
// NOTE, and this one cost an hour: $input is a PowerShell automatic variable,
// the enumerator over pipeline input. Assigning to it is a parse error, not a
// runtime error, so the whole script dies before line one and the only symptom
// is a CLIXML blob on stderr saying "An expression was expected". Any variable
// name here is fine except that one.

function dpapiProtect(secret) {
  const out = runPowerShell(
    `${DPAPI_PROLOGUE}
$sealed = [Security.Cryptography.ProtectedData]::Protect($bytes, $entropy, 'CurrentUser')
[Console]::Out.Write([Convert]::ToBase64String($sealed))
`,
    Buffer.from(secret).toString('base64'),
  );
  return out ? Buffer.from(out, 'base64') : null;
}

function dpapiUnprotect(sealed) {
  const out = runPowerShell(
    `${DPAPI_PROLOGUE}
$open = [Security.Cryptography.ProtectedData]::Unprotect($bytes, $entropy, 'CurrentUser')
[Console]::Out.Write([Convert]::ToBase64String($open))
`,
    Buffer.from(sealed).toString('base64'),
  );
  return out ? Buffer.from(out, 'base64') : null;
}

// ---------------------------------------------------------------------------
// Backend: macOS keychain, and Linux libsecret
// ---------------------------------------------------------------------------

function run(exe, args, input) {
  const result = spawnSync(exe, args, { input, encoding: 'utf8', timeout: 20000, maxBuffer: 1 << 20 });
  if (result.error || result.status !== 0) return null;
  return String(result.stdout || '');
}

/**
 * macOS. `security add-generic-password -w VALUE` puts the value on the
 * command line, which is visible to other processes of this user for the
 * moment it runs. There is no stdin form of that flag: giving -w no value
 * makes the tool prompt on the terminal, which cannot work in a command that
 * must never prompt. The exposure is transient and same user, which is a class
 * of attacker DPAPI and libsecret already lose to, so it does not change what
 * this module claims. It is written down here rather than hidden.
 *
 * Unmeasured on this machine: the development laptop is Windows and has no
 * /usr/bin/security. That is exactly why enrollment probes before it commits,
 * see enroll().
 */
function macosStore(account, secret) {
  return (
    run('/usr/bin/security', [
      'add-generic-password',
      '-U',
      '-s', KEYCHAIN_SERVICE,
      '-a', account,
      '-D', 'ratchet vault key',
      '-w', Buffer.from(secret).toString('base64'),
    ]) !== null
  );
}

function macosFetch(account) {
  const out = run('/usr/bin/security', ['find-generic-password', '-s', KEYCHAIN_SERVICE, '-a', account, '-w']);
  if (out === null) return null;
  const text = out.trim();
  return text.length > 0 ? Buffer.from(text, 'base64') : null;
}

function macosDelete(account) {
  run('/usr/bin/security', ['delete-generic-password', '-s', KEYCHAIN_SERVICE, '-a', account]);
}

/** Linux, libsecret. This one takes the secret on stdin, so nothing lands in argv. */
function libsecretStore(account, secret) {
  return (
    run(
      'secret-tool',
      ['store', '--label=ratchet vault key', 'service', KEYCHAIN_SERVICE, 'account', account],
      Buffer.from(secret).toString('base64'),
    ) !== null
  );
}

function libsecretFetch(account) {
  const out = run('secret-tool', ['lookup', 'service', KEYCHAIN_SERVICE, 'account', account]);
  if (out === null) return null;
  const text = out.trim();
  return text.length > 0 ? Buffer.from(text, 'base64') : null;
}

function libsecretDelete(account) {
  run('secret-tool', ['clear', 'service', KEYCHAIN_SERVICE, 'account', account]);
}

// ---------------------------------------------------------------------------
// Backend dispatch
// ---------------------------------------------------------------------------

/**
 * The account name a keychain item is filed under. It is derived from the home
 * directory so that two RATCHET_HOME directories on one machine get two
 * different vault keys, which is what makes a copied file from one of them
 * useless to the other. The path is hashed rather than stored, because a
 * keychain entry listing somebody's directory layout is itself a small leak,
 * and the descriptor remembers the result so moving the directory does not
 * strand the key.
 */
function accountFor(dir) {
  return `vault-${createHash('sha256').update(dir, 'utf8').digest('hex').slice(0, 16)}`;
}

function keychainCandidates() {
  if (platform() === 'win32') return ['dpapi'];
  if (platform() === 'darwin') return ['macos'];
  if (platform() === 'linux') return ['libsecret'];
  return [];
}

function keychainStore(protection, descriptor, key) {
  if (protection === 'dpapi') {
    const sealed = dpapiProtect(key);
    if (!sealed) return null;
    return { ...descriptor, sealed: b64u(sealed) };
  }
  if (protection === 'macos') return macosStore(descriptor.account, key) ? descriptor : null;
  if (protection === 'libsecret') return libsecretStore(descriptor.account, key) ? descriptor : null;
  return null;
}

function keychainFetch(protection, descriptor) {
  if (protection === 'dpapi') {
    if (typeof descriptor.sealed !== 'string') return null;
    return dpapiUnprotect(unb64u(descriptor.sealed));
  }
  if (protection === 'macos') return macosFetch(descriptor.account);
  if (protection === 'libsecret') return libsecretFetch(descriptor.account);
  return null;
}

function keychainDelete(protection, descriptor) {
  if (protection === 'macos') macosDelete(descriptor.account);
  if (protection === 'libsecret') libsecretDelete(descriptor.account);
  // dpapi keeps nothing outside the descriptor, so removing the descriptor is
  // the whole of the deletion.
}

// ---------------------------------------------------------------------------
// The descriptor file
// ---------------------------------------------------------------------------

const NOTE = {
  none: 'UNPROTECTED. The identity and peer files next to this one are readable by anyone who can read this directory. Run: ratchet lock',
  dpapi: 'The vault key is sealed to this Windows user account with DPAPI. The sealed blob below is not the key and is useless on another account.',
  macos: 'The vault key lives in the macOS keychain under service ratchet-ts. It is not in this file.',
  libsecret: 'The vault key lives in the login keyring under service ratchet-ts. It is not in this file.',
  pass: 'The vault key is derived from a passphrase that is not stored anywhere. Lose it and the identity below is gone for good.',
};

function descriptorText(descriptor) {
  return `${JSON.stringify(descriptor, null, 2)}\n`;
}

function parseDescriptor(path, raw) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (cause) {
    throw new Error(
      `${path} is corrupt: it is not valid JSON. It records how your identity file is protected, ` +
        `so it is not guessed at. If you have no identity worth keeping, delete the whole directory and start over.`,
      { cause },
    );
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`${path} is corrupt: the top level is not a JSON object.`);
  }
  if (parsed.v !== VAULT_VERSION) {
    throw new Error(
      `${path} is version ${String(parsed.v)} and this ratchet reads version ${VAULT_VERSION}. ` +
        `A newer ratchet wrote it. Upgrade rather than deleting it, or the identity it protects is gone.`,
    );
  }
  if (!PROTECTIONS.includes(parsed.protection)) {
    throw new Error(`${path} is corrupt: ${JSON.stringify(parsed.protection)} is not a protection this build knows.`);
  }
  return parsed;
}

/**
 * The descriptor as it is on disk, or null when there is none.
 *
 * A missing descriptor is not an error. It is what every install before this
 * one looks like, and what a fresh directory looks like before the first
 * write.
 */
export async function readDescriptor() {
  const path = vaultFile();
  let raw;
  try {
    raw = await readFile(path, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
  return parseDescriptor(path, raw);
}

/**
 * Writes a descriptor, refusing to overwrite one that appeared underneath us.
 *
 * `exclusive` is used during enrollment. Two ratchet processes starting at the
 * same second would otherwise both mint a vault key, both write, and the loser
 * would then seal a file under a key whose descriptor no longer exists, which
 * is a permanently unreadable identity produced by nothing worse than double
 * clicking. Losing that race means reading the winner's descriptor and using
 * it instead.
 */
async function writeDescriptor(descriptor, { exclusive = false } = {}) {
  await ensureHome();
  const path = vaultFile();
  const text = descriptorText(descriptor);
  if (!exclusive) {
    await writeAtomic(path, text);
    return descriptor;
  }
  try {
    await writeFile(path, text, { mode: 0o600, flag: 'wx' });
    if (platform() !== 'win32') await chmod(path, 0o600);
    return descriptor;
  } catch (err) {
    if (err.code !== 'EEXIST') throw err;
    return readDescriptor();
  }
}

// ---------------------------------------------------------------------------
// Passphrase
// ---------------------------------------------------------------------------

function scryptKey(passphrase, salt, params) {
  const N = Number(params.N);
  const r = Number(params.r);
  const p = Number(params.p);
  if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p) || N < 2 || r < 1 || p < 1) {
    throw new Error('the vault file asks for scrypt parameters that are not numbers');
  }
  // Node's default maxmem is 32 MiB, which every parameter set worth using is
  // over. The ceiling is raised explicitly rather than by lowering N.
  const maxmem = 128 * N * r + (32 << 20);
  return scryptSync(Buffer.from(passphrase, 'utf8'), Buffer.from(salt), 32, { N, r, p, maxmem });
}

/**
 * A tag that says "this passphrase was the right one" without saying anything
 * about the passphrase. It is a MAC under a subkey, so it leaks nothing that
 * the sealed files do not already leak, and it exists only so a wrong
 * passphrase produces "wrong passphrase" instead of "your identity file is
 * corrupt", which is the difference between a user retyping and a user
 * deleting their identity.
 */
function checkTag(vaultKey) {
  return createHmac('sha256', subkey(vaultKey, INFO_CHECK)).update('ratchet-ts.vault.check').digest().subarray(0, 16);
}

function checkMatches(descriptor, vaultKey) {
  if (typeof descriptor.check !== 'string') return true;
  const want = unb64u(descriptor.check);
  const got = checkTag(vaultKey);
  return want.length === got.length && timingSafeEqual(want, got);
}

/**
 * One line read from the terminal with echo off.
 *
 * When stdin is not a terminal this REFUSES rather than reading a line. A
 * script piping into ratchet would otherwise hand over whatever its next line
 * happened to be, silently, as a passphrase: on a wrong guess that is a
 * confusing failure, and on `ratchet lock` it would set the user's passphrase
 * to a line of their own shell script. RATCHET_PASSPHRASE is the deliberate
 * channel for automation, and it is deliberate precisely because a user has to
 * type it on purpose.
 */
export async function readPassphrase(prompt) {
  if (!process.stdin.isTTY) {
    throw new Error(
      'a passphrase is needed and there is no terminal to type it into. ' +
        'Run this command directly in a terminal, or set RATCHET_PASSPHRASE for an unattended machine.',
    );
  }
  process.stderr.write(prompt);
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr, terminal: true });
  // Nothing is echoed, not even asterisks: a length on screen is a length over
  // anybody's shoulder.
  rl._writeToOutput = () => {};
  try {
    const answer = await new Promise((resolve) => rl.question('', resolve));
    return answer;
  } finally {
    rl.close();
    process.stderr.write('\n');
  }
}

async function passphraseFor(prompt) {
  const fromEnv = process.env.RATCHET_PASSPHRASE;
  if (typeof fromEnv === 'string' && fromEnv.length > 0) return fromEnv;
  return readPassphrase(prompt);
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/**
 * Resolved vault keys, keyed by home directory.
 *
 * Per directory rather than one global, because tests and the two machine
 * workflow both move RATCHET_HOME inside a single process, and a key cached
 * from the previous directory would decrypt nothing and look like corruption.
 * The cache is what keeps the keychain round trip to once per invocation.
 */
const cache = new Map();

export function forgetCachedKey() {
  cache.clear();
}

/**
 * What is protecting this directory right now, without unlocking anything.
 * Cheap, does no I/O beyond one small read, and never prompts. This is what
 * `ratchet id` prints and what `lock` and `unlock` branch on.
 */
export async function vaultState() {
  const descriptor = await readDescriptor();
  if (!descriptor) return { protection: 'none', enrolled: false, descriptor: null };
  return { protection: descriptor.protection, enrolled: true, descriptor };
}

/**
 * Try each keychain backend for this platform, and PROVE it works before
 * committing to it.
 *
 * The proof is the whole point. Storing a key in a keychain that silently did
 * not store it, and then sealing an identity under that key, destroys the
 * identity. So enrollment writes the key, reads it back through the same path
 * a later run will use, and compares. Anything less is trusting an exit code
 * from a program that might not be the program we think it is.
 */
async function enrollKeychain(dir) {
  const forced = process.env.RATCHET_VAULT;
  if (forced === 'none') return null;
  const key = randomBytes(32);
  for (const protection of keychainCandidates()) {
    const base = { v: VAULT_VERSION, protection, note: NOTE[protection], account: accountFor(dir) };
    let descriptor;
    try {
      descriptor = keychainStore(protection, base, key);
    } catch {
      descriptor = null;
    }
    if (!descriptor) continue;
    let back = null;
    try {
      back = keychainFetch(protection, descriptor);
    } catch {
      back = null;
    }
    if (back && back.length === key.length && timingSafeEqual(back, key)) {
      return { descriptor, key };
    }
    // It answered, and it answered wrong. Do not leave a half made item behind.
    try {
      keychainDelete(protection, descriptor);
    } catch {
      /* the cleanup failing tells us nothing we can act on */
    }
  }
  return null;
}

/**
 * Make sure this directory has a vault, creating one on first write.
 *
 * This is the invisible path. It runs the first time anything is written, it
 * asks the user nothing, and it ends in the strongest state that actually
 * works on this machine. When no keychain works it ends in `none`, writes that
 * down, and lets the caller tell the user, because the alternative is either
 * refusing to run at all or pretending.
 */
export async function ensureVault() {
  const dir = homeDir();
  const existing = await readDescriptor();
  if (existing) return existing;

  const enrolled = await enrollKeychain(dir);
  if (enrolled) {
    const written = await writeDescriptor(enrolled.descriptor, { exclusive: true });
    // If another process won the race, its descriptor is the truth and this
    // process's key is thrown away unused.
    if (written && written.protection === enrolled.descriptor.protection && written.sealed === enrolled.descriptor.sealed) {
      cache.set(dir, enrolled.key);
    }
    return written;
  }

  return writeDescriptor({ v: VAULT_VERSION, protection: 'none', note: NOTE.none }, { exclusive: true });
}

/**
 * The 32 byte vault key, or null when this directory is unprotected.
 *
 * `create` is what separates a read from a write. Reading a directory that has
 * no vault must not invent one, or a `ratchet peers` on somebody's old install
 * would quietly enroll a key and change what their files mean. Writing one
 * must, or the protection would never turn on by itself.
 */
export async function vaultKey({ create = false } = {}) {
  const dir = homeDir();
  const descriptor = create ? await ensureVault() : await readDescriptor();
  if (!descriptor) return null;
  if (descriptor.protection === 'none') return null;

  const cached = cache.get(dir);
  if (cached) return cached;

  if (descriptor.protection === 'pass') {
    if (!descriptor.kdf || typeof descriptor.kdf.salt !== 'string') {
      throw new Error(`${vaultFile()} says passphrase but carries no salt, so no passphrase can open it.`);
    }
    const passphrase = await passphraseFor('passphrase: ');
    if (!passphrase) throw new Error('an empty passphrase is not one');
    const key = scryptKey(passphrase, unb64u(descriptor.kdf.salt), descriptor.kdf);
    if (!checkMatches(descriptor, key)) {
      throw new Error(
        'that passphrase is wrong. Nothing was changed and nothing was lost, so try again. ' +
          'There is no recovery for a forgotten one: the key is derived from it and stored nowhere.',
      );
    }
    cache.set(dir, key);
    return key;
  }

  let key = null;
  try {
    key = keychainFetch(descriptor.protection, descriptor);
  } catch {
    key = null;
  }
  if (!key || key.length !== 32) {
    throw new Error(
      `${vaultFile()} says your identity is protected by ${describeProtection(descriptor.protection)}, ` +
        `and that store did not hand the key back. Nothing is lost while that file and the keychain entry ` +
        `both survive: this is usually a locked keyring or a different user account. Unlock the keyring and try again.`,
    );
  }
  cache.set(dir, key);
  return key;
}

// ---------------------------------------------------------------------------
// lock and unlock
// ---------------------------------------------------------------------------

/**
 * Build the descriptor for a passphrase vault. The caller re-wraps both files
 * under the returned key BEFORE the descriptor is written, so a crash halfway
 * cannot leave a directory whose descriptor and whose files disagree.
 */
export function passphraseDescriptor(passphrase) {
  const salt = randomBytes(16);
  const key = scryptKey(passphrase, salt, SCRYPT);
  const descriptor = {
    v: VAULT_VERSION,
    protection: 'pass',
    note: NOTE.pass,
    kdf: { ...SCRYPT, salt: b64u(salt) },
    check: b64u(checkTag(key)),
  };
  return { descriptor, key };
}

/** The keychain or plaintext descriptor `ratchet unlock` returns to. */
export async function plainOrKeychainDescriptor() {
  const enrolled = await enrollKeychain(homeDir());
  if (enrolled) return enrolled;
  return { descriptor: { v: VAULT_VERSION, protection: 'none', note: NOTE.none }, key: null };
}

/**
 * Commit a new protection state. Called only after both files have been
 * re-wrapped under `key` in memory and written, so the descriptor is the last
 * thing to move.
 */
export async function commitDescriptor(descriptor, key, previous) {
  await writeDescriptor(descriptor);
  if (key) cache.set(homeDir(), key);
  else cache.delete(homeDir());
  // Only now is the old keychain item unreachable by anything, so only now is
  // it safe to remove.
  if (previous && previous.protection !== descriptor.protection) {
    try {
      keychainDelete(previous.protection, previous);
    } catch {
      /* an orphaned keychain item is untidy, not dangerous */
    }
  }
}

// ---------------------------------------------------------------------------
// The rollback sidecar
// ---------------------------------------------------------------------------

/**
 * Changing protection means rewriting three files, and there is no way to make
 * three writes atomic.
 *
 * Whatever order they go in, a crash in the middle can leave a directory whose
 * descriptor and whose sealed files disagree, and for a keychain state that is
 * not a recoverable inconvenience, it is an identity destroyed by a power cut.
 * So before anything moves, the previous contents of all three land in one
 * sidecar file, and the sidecar is deleted only once the new descriptor is in
 * place.
 *
 * The sidecar is a copy, so it is exactly as sensitive as what it copies and no
 * more: from a passphrase or keychain state it holds ciphertext, and from the
 * unprotected state it holds the same plaintext that was already sitting there.
 * A leftover one means a crash happened, and both `ratchet id` and the identity
 * loader point at it rather than leaving somebody staring at a file that will
 * not open.
 */
export function rollbackFile() {
  return join(homeDir(), 'vault.rollback');
}

export async function writeRollback(payload) {
  await ensureHome();
  await writeAtomic(rollbackFile(), `${JSON.stringify({ v: VAULT_VERSION, ...payload }, null, 2)}\n`);
}

export async function readRollback() {
  try {
    return JSON.parse(await readFile(rollbackFile(), 'utf8'));
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    return null;
  }
}

export async function clearRollback() {
  try {
    await unlink(rollbackFile());
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
}

export async function removeVault() {
  try {
    await unlink(vaultFile());
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
  cache.delete(homeDir());
}

// ---------------------------------------------------------------------------
// Words for humans
// ---------------------------------------------------------------------------

export function describeProtection(protection) {
  switch (protection) {
    case 'dpapi':
      return 'this Windows account (DPAPI)';
    case 'macos':
      return 'the macOS keychain';
    case 'libsecret':
      return 'the login keyring';
    case 'pass':
      return 'a passphrase';
    default:
      return 'nothing';
  }
}

/** The subkey names the two consumers ask for, exported so nobody retypes them. */
export const VAULT_INFO = {
  identity: INFO_IDENTITY,
  peersEntry: INFO_PEERS_ENTRY,
  peersIndex: INFO_PEERS_INDEX,
};
