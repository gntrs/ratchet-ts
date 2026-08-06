/**
 * Known-answer vector generator. Run with: npx tsx scripts/gen-vectors.mjs
 *
 * Writes test/vectors.json. The vectors pin the OCX1 handshake and the first
 * ratchet turns to exact bytes, so another implementation can reproduce the
 * protocol from the seeds alone and byte-compare every intermediate value.
 *
 * Why a generator script instead of hand-written constants: the derivation
 * below mirrors src/handshake.ts and src/ratchet.ts step by step, using the
 * same kdf, envelope, and primitive modules the engine uses. When the protocol
 * changes on purpose, rerun this script and the diff of vectors.json IS the
 * wire-format change, reviewable in one place. When it changes by accident,
 * test/vectors.test.ts fails and nothing here needs to run at all.
 *
 * Every random choice the live engine makes is replaced by a fixed seed:
 *
 *   - X25519 keypairs come from x25519.keygen(seed). The noble implementation
 *     uses the 32 byte seed verbatim as the secret key, clamping happens
 *     inside the scalar multiplication, so the seed IS the secret key.
 *   - ML-KEM-768 keypairs come from ml_kem768.keygen(seed) with the 64 byte
 *     FIPS 203 seed (d || z).
 *   - ML-KEM encapsulation takes its 32 byte message m explicitly, which the
 *     noble API allows, so even the KEM ciphertext is reproducible.
 *   - The conversation id and the AEAD nonces are fixed constants.
 *
 * The seeds are counter patterns (byte i of a seed with offset k is (k + i)
 * mod 256) so a reader can spot at a glance that nothing is hidden in them.
 */

import { writeFileSync } from 'node:fs';

import { x25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';

import { concat, toHex, utf8ToBytes } from '../src/bytes.js';
import { decodeEnvelope, encodeEnvelope, messageAad } from '../src/envelope.js';
import { kdfChain, kdfHandshake, kdfRoot } from '../src/kdf.js';
import { ratchetDecrypt } from '../src/ratchet.js';

/** Counter pattern: recognisably arbitrary, impossible to mistake for entropy. */
function pattern(offset, length) {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) out[i] = (offset + i) & 0xff;
  return out;
}

// ---------------------------------------------------------------------------
// Fixed inputs. These, plus the two plaintexts, are the entire input surface.
// ---------------------------------------------------------------------------

const seeds = {
  aliceIdentityX25519: pattern(0x00, 32),
  aliceIdentityMlKem768: pattern(0x10, 64),
  bobIdentityX25519: pattern(0x20, 32),
  bobIdentityMlKem768: pattern(0x30, 64),
  bobRatchet1X25519: pattern(0x40, 32),
  kemEncapsulationMsg: pattern(0x50, 32),
  aliceRatchet1X25519: pattern(0x60, 32),
  bobRatchet2X25519: pattern(0x70, 32),
};

const nonces = {
  message0: pattern(0x80, 24),
  reply0: pattern(0x90, 24),
};

// Same shape newConversationId() produces: 32 lowercase hex chars.
const conversationId = 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf';

const plaintexts = {
  message0: 'OCX1 known answer: first message, initiator to responder',
  reply0: 'OCX1 known answer: first reply, responder to initiator',
};

// ---------------------------------------------------------------------------
// Identities. Mirrors createIdentity() in src/identity.ts with seeds injected.
// ---------------------------------------------------------------------------

const aliceClassical = x25519.keygen(seeds.aliceIdentityX25519);
const alicePq = ml_kem768.keygen(seeds.aliceIdentityMlKem768);
const bobClassical = x25519.keygen(seeds.bobIdentityX25519);
const bobPq = ml_kem768.keygen(seeds.bobIdentityMlKem768);

// ---------------------------------------------------------------------------
// Invite. Mirrors beginInvite() with the conversation id injected.
// ---------------------------------------------------------------------------

const inviteToken = encodeEnvelope({
  kind: 'invite',
  sender: { classicalPublic: aliceClassical.publicKey, pqPublic: alicePq.publicKey },
  conversationId,
});

// ---------------------------------------------------------------------------
// Accept. Mirrors acceptInvite() with the ratchet seed and KEM message
// injected. dh1 binds Bob's identity, dh2 binds his fresh ratchet key, and
// the KEM shared secret is the post-quantum contribution.
// ---------------------------------------------------------------------------

const bobRatchet1 = x25519.keygen(seeds.bobRatchet1X25519);
const kem = ml_kem768.encapsulate(alicePq.publicKey, seeds.kemEncapsulationMsg);

const dh1 = x25519.getSharedSecret(bobClassical.secretKey, aliceClassical.publicKey);
const dh2 = x25519.getSharedSecret(bobRatchet1.secretKey, aliceClassical.publicKey);
const handshakeRootKey = kdfHandshake(concat(dh1, dh2, kem.sharedSecret), conversationId);

const acceptToken = encodeEnvelope({
  kind: 'accept',
  sender: { classicalPublic: bobClassical.publicKey, pqPublic: bobPq.publicKey },
  conversationId,
  kemCiphertext: kem.cipherText,
  ratchetPublic: bobRatchet1.publicKey,
});

// ---------------------------------------------------------------------------
// Complete. Mirrors completeInvite(): Alice re-derives the same root from her
// side (checked below), then takes one DH ratchet step with a fresh key.
// ---------------------------------------------------------------------------

const dh1Alice = x25519.getSharedSecret(aliceClassical.secretKey, bobClassical.publicKey);
const dh2Alice = x25519.getSharedSecret(aliceClassical.secretKey, bobRatchet1.publicKey);
const pqAlice = ml_kem768.decapsulate(kem.cipherText, alicePq.secretKey);
const handshakeRootAlice = kdfHandshake(concat(dh1Alice, dh2Alice, pqAlice), conversationId);
if (toHex(handshakeRootAlice) !== toHex(handshakeRootKey)) {
  throw new Error('initiator and responder disagree on the handshake root, refusing to write vectors');
}

const aliceRatchet1 = x25519.keygen(seeds.aliceRatchet1X25519);
const stepDh = x25519.getSharedSecret(aliceRatchet1.secretKey, bobRatchet1.publicKey);
const stepped = kdfRoot(handshakeRootKey, stepDh);
const rootAfterAliceStep = stepped.rootKey;
const chainAliceToBob = stepped.chainKey;

// ---------------------------------------------------------------------------
// Bob's DH ratchet on receiving message 0. Mirrors dhRatchet(): the receive
// step lands on the same root and chain Alice computed, then Bob's fresh
// ratchet key opens his sending chain.
// ---------------------------------------------------------------------------

const bobRatchet2 = x25519.keygen(seeds.bobRatchet2X25519);
const bobSendDh = x25519.getSharedSecret(bobRatchet2.secretKey, aliceRatchet1.publicKey);
const bobStepped = kdfRoot(rootAfterAliceStep, bobSendDh);
const rootAfterBobStep = bobStepped.rootKey;
const chainBobToAlice = bobStepped.chainKey;

// ---------------------------------------------------------------------------
// Message keys: three per direction, walking each chain with kdfChain exactly
// as ratchetEncrypt/ratchetDecrypt would.
// ---------------------------------------------------------------------------

function walkChain(chainKey, count) {
  const keys = [];
  let ck = chainKey;
  for (let i = 0; i < count; i += 1) {
    const step = kdfChain(ck);
    keys.push(step.messageKey);
    ck = step.nextChainKey;
  }
  return keys;
}

const messageKeysAliceToBob = walkChain(chainAliceToBob, 3);
const messageKeysBobToAlice = walkChain(chainBobToAlice, 3);

// ---------------------------------------------------------------------------
// Wire messages. Mirrors ratchetEncrypt() with the nonce injected: the header
// is bound as AAD, the body is XChaCha20-Poly1305 under message key 0.
// ---------------------------------------------------------------------------

function sealMessage(messageKey, nonce, ratchetPublic, plaintext) {
  const header = {
    conversationId,
    ratchetPublic,
    messageNumber: 0,
    previousChainLength: 0,
    nonce,
  };
  const ciphertext = xchacha20poly1305(messageKey, nonce, messageAad(header)).encrypt(utf8ToBytes(plaintext));
  return encodeEnvelope({ kind: 'message', ...header, ciphertext });
}

const message0Token = sealMessage(messageKeysAliceToBob[0], nonces.message0, aliceRatchet1.publicKey, plaintexts.message0);
const reply0Token = sealMessage(messageKeysBobToAlice[0], nonces.reply0, bobRatchet2.publicKey, plaintexts.reply0);

// ---------------------------------------------------------------------------
// Sanity gate: before writing anything, prove the real engine opens these
// tokens. A vectors file the engine itself rejects would be worse than none.
// ---------------------------------------------------------------------------

const bobSession = {
  conversationId,
  role: 'responder',
  peer: { classicalPublic: aliceClassical.publicKey, pqPublic: alicePq.publicKey },
  rootKey: handshakeRootKey,
  selfRatchetPublic: bobRatchet1.publicKey,
  selfRatchetSecret: bobRatchet1.secretKey,
  sendCount: 0,
  recvCount: 0,
  previousSendCount: 0,
  skippedKeys: {},
};
const opened = ratchetDecrypt(bobSession, decodeEnvelope(message0Token));
if (opened.plaintext !== plaintexts.message0) {
  throw new Error('the real ratchet rejected the generated message 0, refusing to write vectors');
}

const aliceSession = {
  conversationId,
  role: 'initiator',
  peer: { classicalPublic: bobClassical.publicKey, pqPublic: bobPq.publicKey },
  rootKey: rootAfterAliceStep,
  selfRatchetPublic: aliceRatchet1.publicKey,
  selfRatchetSecret: aliceRatchet1.secretKey,
  peerRatchetPublic: bobRatchet1.publicKey,
  sendChainKey: chainAliceToBob,
  sendCount: 0,
  recvCount: 0,
  previousSendCount: 0,
  skippedKeys: {},
};
const openedReply = ratchetDecrypt(aliceSession, decodeEnvelope(reply0Token));
if (openedReply.plaintext !== plaintexts.reply0) {
  throw new Error('the real ratchet rejected the generated reply 0, refusing to write vectors');
}

// ---------------------------------------------------------------------------
// Emit. Hex everywhere, tokens verbatim. The _note fields are documentation
// for implementors reading the JSON without this script next to it.
// ---------------------------------------------------------------------------

const hexAll = (record) => Object.fromEntries(Object.entries(record).map(([k, v]) => [k, toHex(v)]));

const vectors = {
  _note: [
    'OCX1 known-answer vectors. Generated by scripts/gen-vectors.mjs, verified by test/vectors.test.ts.',
    'All randomness is replaced by the fixed seeds below. X25519 seeds are used verbatim as secret keys.',
    'ML-KEM-768 seeds are the 64 byte FIPS 203 keygen seed (d || z); kemEncapsulationMsg is the 32 byte encapsulation message m.',
    'Handshake: dh1 = DH(bobIdentity, aliceIdentity), dh2 = DH(bobRatchet1, aliceIdentity), ikm = dh1 || dh2 || kemSharedSecret,',
    'handshakeRootKey = HKDF-SHA256(ikm, salt "OCX1 hybrid handshake v1", info conversationId, 32 bytes).',
    'Each DH ratchet step: HKDF-SHA256(dh, salt currentRootKey, info "OCX1 root ratchet v1", 64 bytes) -> rootKey || chainKey.',
    'Each chain step: messageKey = HMAC-SHA256(chainKey, 0x01), nextChainKey = HMAC-SHA256(chainKey, 0x02).',
    'Messages are XChaCha20-Poly1305 with the encoded header as AAD, see messageAad in src/envelope.ts.',
  ],
  conversationId,
  seeds: hexAll(seeds),
  nonces: hexAll(nonces),
  plaintexts,
  derived: {
    aliceClassicalPublic: toHex(aliceClassical.publicKey),
    alicePqPublic: toHex(alicePq.publicKey),
    bobClassicalPublic: toHex(bobClassical.publicKey),
    bobPqPublic: toHex(bobPq.publicKey),
    bobRatchet1Public: toHex(bobRatchet1.publicKey),
    aliceRatchet1Public: toHex(aliceRatchet1.publicKey),
    bobRatchet2Public: toHex(bobRatchet2.publicKey),
    kemCiphertext: toHex(kem.cipherText),
    kemSharedSecret: toHex(kem.sharedSecret),
    dh1: toHex(dh1),
    dh2: toHex(dh2),
    handshakeRootKey: toHex(handshakeRootKey),
    rootAfterAliceStep: toHex(rootAfterAliceStep),
    rootAfterBobStep: toHex(rootAfterBobStep),
    chainAliceToBob: toHex(chainAliceToBob),
    chainBobToAlice: toHex(chainBobToAlice),
    messageKeysAliceToBob: messageKeysAliceToBob.map(toHex),
    messageKeysBobToAlice: messageKeysBobToAlice.map(toHex),
  },
  tokens: {
    invite: inviteToken,
    accept: acceptToken,
    message0: message0Token,
    reply0: reply0Token,
  },
};

writeFileSync(new URL('../test/vectors.json', import.meta.url), JSON.stringify(vectors, null, 2) + '\n');
console.log('wrote test/vectors.json');
