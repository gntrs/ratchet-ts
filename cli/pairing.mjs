// Pairing codes: one string that replaces "what is your IP address".
//
// ---------------------------------------------------------------------------
// WHAT IS IN A CODE AND WHY EACH PART IS THERE
// ---------------------------------------------------------------------------
//
// Two fields, 24 bytes, rendered as 39 characters of Crockford base32 in groups
// of six.
//
//   16 bytes  rendezvous secret. Random per session. The relay never sees it:
//             both clients meet on SHA-256 of it, so the operator matches two
//             sockets without being able to join or replay the rendezvous. 128
//             bits because this is the only thing standing between a stranger
//             and the socket, and it is typed once by a human rather than
//             brute-forced interactively.
//
//    8 bytes  the first 64 bits of the receiver's identity fingerprint. The
//             sender checks the peer it actually reached against this before it
//             sends anything.
//
// ---------------------------------------------------------------------------
// WHY THE FINGERPRINT PREFIX IS IN THERE AT ALL
// ---------------------------------------------------------------------------
//
// The rendezvous secret already keeps strangers out of the socket, so on its
// own the code looks sufficient. It is not, and the case it misses is the one
// that actually happens: the code travels over WhatsApp, or a work Slack, or it
// is read out on a call somebody else is on. A code that leaks is a code an
// attacker can race the real receiver to.
//
// With the fingerprint pinned, winning that race is not enough. The attacker
// arrives at the rendezvous holding their own identity, the sender compares the
// fingerprint of whoever answered against the 64 bits in the code, and it does
// not match. This is the same check the safety words perform, moved into the
// setup step so that the MACHINE does it every time instead of a human doing it
// sometimes.
//
// That is the real win here and it is worth stating plainly: the weakest link
// in this whole design has always been that verification is a ritual people
// skip. A pairing code makes the first check automatic. It does not replace
// comparing words for a peer you intend to keep, and `ratchet peers verify`
// still exists, because 64 bits pinned by a code you may have pasted somewhere
// is a different claim from 132 bits two people read aloud.
//
// ---------------------------------------------------------------------------
// WHY 64 BITS AND NOT MORE
// ---------------------------------------------------------------------------
//
// The attack it has to stop is a second-preimage: an attacker with the code
// wants an identity whose fingerprint starts with the same 64 bits. That is
// 2^64 keypairs at 1.9 ms each on the machine these benchmarks run on, which is
// about a billion core-years. There is no birthday shortcut, because the target
// is fixed by the receiver before the attacker sees the code.
//
// More bits would cost more typing for no reachable gain. Fewer would start to
// matter: 32 bits is 2^32 keypairs, roughly 95 core-days, which is a weekend on
// rented hardware.
import { createHash, randomBytes } from 'node:crypto';

import { fingerprint } from '../dist/index.js';
import { RENDEZVOUS_ID_BYTES, rendezvousId } from '../relay/server.mjs';

/**
 * Crockford base32: no I, L, O or U.
 *
 * I and L look like 1, O looks like 0, and U is out because Crockford drops it
 * to avoid accidental obscenities. Decoding folds the lookalikes back, so
 * somebody who types a one where the code shows an I still gets in. That is not
 * politeness, it is the difference between a code that works read aloud over a
 * bad phone line and one that does not.
 */
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const DECODE = new Map();
for (let i = 0; i < ALPHABET.length; i += 1) DECODE.set(ALPHABET[i], i);
DECODE.set('I', 1);
DECODE.set('L', 1);
DECODE.set('O', 0);
DECODE.set('U', DECODE.get('V'));

export const SECRET_BYTES = 16;
export const FINGERPRINT_PIN_BYTES = 8;
export const CODE_BYTES = SECRET_BYTES + FINGERPRINT_PIN_BYTES;
/** ceil(24 * 8 / 5). The last character carries four payload bits, not five. */
export const CODE_CHARS = 39;
const GROUP = 6;

function toBase32(bytes) {
  let out = '';
  let acc = 0;
  let bits = 0;
  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(acc >>> bits) & 0x1f];
    }
  }
  if (bits > 0) out += ALPHABET[(acc << (5 - bits)) & 0x1f];
  return out;
}

function fromBase32(text) {
  let acc = 0;
  let bits = 0;
  const out = [];
  for (const char of text) {
    const value = DECODE.get(char);
    if (value === undefined) return null;
    acc = (acc << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >>> bits) & 0xff);
    }
  }
  // Whatever is left is the padding the encoder added to fill the last
  // character, and it has to be zero. Accepting a non-zero remainder would give
  // two spellings of one code, and a code with two spellings is a code where
  // "they read it back and it matched" stops meaning what people think.
  if (bits >= 5 || (acc & ((1 << bits) - 1)) !== 0) return null;
  return Uint8Array.from(out);
}

/** Groups of six, hyphenated. Nothing depends on the hyphens when reading. */
export function formatCode(raw) {
  const groups = [];
  for (let at = 0; at < raw.length; at += GROUP) groups.push(raw.slice(at, at + GROUP));
  return groups.join('-');
}

/**
 * Mint a code for a receiver identity.
 *
 * Returns the code to show a human and the rendezvous id to present to the
 * relay. The secret itself is not returned: nothing outside this module needs
 * it, and the fewer places it exists the fewer places it leaks from.
 */
export function newPairingCode(identity) {
  const secret = randomBytes(SECRET_BYTES);
  const pin = fingerprintPin(identity);
  const raw = Buffer.concat([secret, Buffer.from(pin)]);
  return {
    code: formatCode(toBase32(raw)),
    rendezvous: rendezvousId(secret),
  };
}

/** The 64 bits of a fingerprint that a code carries. */
export function fingerprintPin(identity) {
  const hex = fingerprint(identity).hex;
  return Uint8Array.from(Buffer.from(hex.slice(0, FINGERPRINT_PIN_BYTES * 2), 'hex'));
}

/**
 * Read a code a human typed. Case, hyphens, spaces and lookalike characters are
 * all forgiven; anything else is refused with a reason rather than a null.
 */
export function parsePairingCode(input) {
  if (typeof input !== 'string') return { ok: false, reason: 'that is not a code' };
  const cleaned = input.trim().toUpperCase().replace(/[\s-]/g, '');
  if (cleaned.length === 0) return { ok: false, reason: 'no code given' };
  if (cleaned.length !== CODE_CHARS) {
    return { ok: false, reason: `a code is ${CODE_CHARS} characters, this one is ${cleaned.length}` };
  }
  const raw = fromBase32(cleaned);
  if (raw === null || raw.length !== CODE_BYTES) {
    return { ok: false, reason: 'that is not a valid code, check for a mistyped character' };
  }
  return {
    ok: true,
    rendezvous: rendezvousId(raw.subarray(0, SECRET_BYTES)),
    pin: raw.subarray(SECRET_BYTES),
    code: formatCode(cleaned),
  };
}

/**
 * Does the peer we reached match the code we were given?
 *
 * Takes the peer's fingerprint HEX, which is what the transfer layer actually
 * has at the moment the decision must be made. An earlier version took a
 * PublicIdentity and computed the fingerprint itself, which was wrong twice
 * over: the handshake callback carries no identity object, so every real call
 * passed `{ hex }` and threw inside fingerprint(), and the throw was then eaten
 * by a catch one layer up. The file went to the wrong machine and the check
 * reported nothing. Taking the hex removes the conversion that was failing.
 *
 * Compared byte by byte with no early exit. Not because a timing side channel
 * on a public fingerprint prefix is a real attack, but because a comparison
 * that returns early on the first differing byte invites somebody to copy this
 * function somewhere it does matter.
 */
export function pinMatches(pin, peerHex) {
  if (typeof peerHex !== 'string') return false;
  const actual = Buffer.from(peerHex.slice(0, FINGERPRINT_PIN_BYTES * 2), 'hex');
  if (actual.length !== FINGERPRINT_PIN_BYTES || pin.length !== FINGERPRINT_PIN_BYTES) return false;
  let same = 0;
  for (let i = 0; i < pin.length; i += 1) same |= pin[i] ^ actual[i];
  return same === 0;
}

export { RENDEZVOUS_ID_BYTES, rendezvousId };

/** Only for tests, which need to build a code from a known secret. */
export function codeFromParts(secret, pin) {
  const raw = Buffer.concat([Buffer.from(secret), Buffer.from(pin)]);
  if (raw.length !== CODE_BYTES) throw new Error(`a code is ${CODE_BYTES} bytes, got ${raw.length}`);
  return formatCode(toBase32(raw));
}

/** Exposed so the relay client and the tests agree on the hello bytes. */
export function relayHello(magic, rendezvous) {
  return Buffer.concat([Buffer.from(magic), Buffer.from(rendezvous)]);
}

/** Not used here, but a caller wiring its own transport wants the digest. */
export function digestOf(bytes) {
  return createHash('sha256').update(Buffer.from(bytes)).digest();
}
