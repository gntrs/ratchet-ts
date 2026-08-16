/**
 * Known-answer vector generator. Run with: npx tsx scripts/gen-vectors.mjs
 *
 * Writes test/vectors.json. The vectors pin the OCX2 handshake and the first
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
 *   - The conversation id is a fixed constant.
 *
 * The nonce is a seed again, and the seed list below says so. A draft of 0.4.0
 * derived it from the message number, which removed it from this file entirely;
 * that derivation was rejected, because a session restored from a stale
 * snapshot replays a message key, and a replayed key under a replayed nonce
 * hands an observer the XOR of two plaintexts. 0.4.0 ships 12 random bytes on
 * the wire instead, so the nonce is a random choice once more and a
 * known-answer file has to pin it like any other.
 *
 * THE SEAM, AND WHY IT CANNOT LEAK INTO A REAL SEAL. This script never calls
 * ratchetEncrypt. It builds the two message tokens out of primitives, the same
 * way it builds every key above them, and hands chacha20poly1305 a nonce out of
 * `seeds`. src/ratchet.ts has no parameter, option, or exported hook that would
 * let a caller supply a nonce: freshNonce() reads the CSPRNG and nothing else,
 * and it is not exported. So the fixed nonce lives here, in a file that is not
 * shipped, and there is no code path from a normal seal to it. The check at the
 * bottom of this script still opens both tokens with the real ratchetDecrypt,
 * so the receive path is exercised for real even though the send path is not.
 *
 * The seeds are counter patterns (byte i of a seed with offset k is (k + i)
 * mod 256) so a reader can spot at a glance that nothing is hidden in them.
 */

import { writeFileSync } from 'node:fs';

import { x25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';

import { concat, toHex, utf8ToBytes } from '../src/bytes.js';
import {
  conversationIdToBytes,
  decodeEnvelope,
  encodeEnvelope,
  messageAad,
} from '../src/envelope.js';
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
  aliceIdentityMlDsa65: pattern(0xa0, 32),
  bobIdentityMlDsa65: pattern(0xb0, 32),
  bobRatchet1X25519: pattern(0x40, 32),
  kemEncapsulationMsg: pattern(0x50, 32),
  aliceRatchet1X25519: pattern(0x60, 32),
  bobRatchet2X25519: pattern(0x70, 32),
  // Two nonces rather than one. Both messages are number 0 of their chain and
  // sit under different keys, so a single value would be safe here, but a
  // known-answer file that reuses a nonce reads like a mistake to anyone who
  // does not stop to check the keys, and the next person to copy this shape may
  // not have two different keys.
  message0Nonce: pattern(0x80, 12),
  reply0Nonce: pattern(0x90, 12),
};

// Same shape newConversationId() produces: 32 lowercase hex chars.
const conversationId = 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf';
const conversationIdBytes = conversationIdToBytes(conversationId);

const plaintexts = {
  message0: 'OCX2 known answer: first message, initiator to responder',
  reply0: 'OCX2 known answer: first reply, responder to initiator',
};

// ---------------------------------------------------------------------------
// Identities. Mirrors createIdentity() in src/identity.ts with seeds injected.
// ---------------------------------------------------------------------------

const aliceClassical = x25519.keygen(seeds.aliceIdentityX25519);
const alicePq = ml_kem768.keygen(seeds.aliceIdentityMlKem768);
const aliceSig = ml_dsa65.keygen(seeds.aliceIdentityMlDsa65);
const bobClassical = x25519.keygen(seeds.bobIdentityX25519);
const bobPq = ml_kem768.keygen(seeds.bobIdentityMlKem768);
const bobSig = ml_dsa65.keygen(seeds.bobIdentityMlDsa65);

const alicePublic = {
  classicalPublic: aliceClassical.publicKey,
  pqPublic: alicePq.publicKey,
  sigPublic: aliceSig.publicKey,
};
const bobPublic = {
  classicalPublic: bobClassical.publicKey,
  pqPublic: bobPq.publicKey,
  sigPublic: bobSig.publicKey,
};

/**
 * Deterministic signing, which the library itself does NOT use.
 *
 * FIPS 204 offers both a hedged and a deterministic mode. The hedged one mixes
 * fresh randomness into every signature and is the right default for a real
 * signer, because it costs nothing and it takes away a class of fault and
 * side-channel attacks that a deterministic signer is exposed to. src/handshake
 * therefore signs hedged, which means two invites from one identity over one
 * conversation id are not byte identical, and that is correct.
 *
 * A known-answer file cannot live with that. So this generator, and only this
 * generator, pins extraEntropy to false and produces the deterministic
 * signature for the same key and message. The vectors pin the transcript
 * construction, the key derivation and the encoding, which is what they are for.
 * They deliberately do not pin the randomness of a live signature.
 */
const signFixed = (msg, secretKey) => ml_dsa65.sign(msg, secretKey, { extraEntropy: false });

/**
 * Mirrors transcript() in src/handshake.ts: a domain string, then a big endian
 * u32 length for every part in order, then the parts.
 */
const transcript = (domain, parts) => {
  const lengths = new Uint8Array(4 * parts.length);
  const view = new DataView(lengths.buffer);
  parts.forEach((part, i) => view.setUint32(i * 4, part.length, false));
  return concat(utf8ToBytes(domain), lengths, ...parts);
};

const inviteTranscript = (id, sender) =>
  transcript('OCX2 invite transcript v1', [
    utf8ToBytes(id),
    sender.classicalPublic,
    sender.pqPublic,
    sender.sigPublic,
  ]);

const acceptTranscript = (id, initiator, responder, kemCiphertext, ratchetPublic) =>
  transcript('OCX2 accept transcript v1', [
    utf8ToBytes(id),
    initiator.classicalPublic,
    initiator.pqPublic,
    initiator.sigPublic,
    responder.classicalPublic,
    responder.pqPublic,
    responder.sigPublic,
    kemCiphertext,
    ratchetPublic,
  ]);

// ---------------------------------------------------------------------------
// Invite. Mirrors beginInvite() with the conversation id injected.
// ---------------------------------------------------------------------------

const inviteSignature = signFixed(inviteTranscript(conversationId, alicePublic), aliceSig.secretKey);

const inviteToken = encodeEnvelope({
  kind: 'invite',
  sender: alicePublic,
  conversationId,
  signature: inviteSignature,
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

const acceptSignature = signFixed(
  acceptTranscript(conversationId, alicePublic, bobPublic, kem.cipherText, bobRatchet1.publicKey),
  bobSig.secretKey,
);

const acceptToken = encodeEnvelope({
  kind: 'accept',
  sender: bobPublic,
  conversationId,
  kemCiphertext: kem.cipherText,
  ratchetPublic: bobRatchet1.publicKey,
  signature: acceptSignature,
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
// Wire messages. Mirrors ratchetEncrypt(): the header plus the unsent tail of
// the conversation id is bound as AAD, the body is ChaCha20-Poly1305 under
// message key 0 with the nonce from `seeds`. The real seal draws that nonce
// from the CSPRNG; see the seam paragraph at the top of this file.
//
// Message 0 of a chain always carries the ratchet key, so both of these are
// step envelopes and the AAD extension is the 12 byte id tail alone. The
// keyless case, where the 32 byte ratchet key joins the AAD without joining
// the wire, is pinned in test/envelope-bytes.test.ts instead.
// ---------------------------------------------------------------------------

function sealMessage(messageKey, ratchetPublic, nonce, plaintext) {
  const header = {
    sessionTag: conversationIdBytes.subarray(0, 4),
    messageNumber: 0,
    previousChainLength: 0,
    ratchetPublic,
    nonce,
  };
  const aad = messageAad(header, conversationIdBytes, ratchetPublic);
  const ciphertext = chacha20poly1305(messageKey, nonce, aad).encrypt(utf8ToBytes(plaintext));
  return encodeEnvelope({ kind: 'message', ...header, ciphertext });
}

const message0Token = sealMessage(
  messageKeysAliceToBob[0],
  aliceRatchet1.publicKey,
  seeds.message0Nonce,
  plaintexts.message0,
);
const reply0Token = sealMessage(
  messageKeysBobToAlice[0],
  bobRatchet2.publicKey,
  seeds.reply0Nonce,
  plaintexts.reply0,
);

// ---------------------------------------------------------------------------
// Sanity gate: before writing anything, prove the real engine opens these
// tokens. A vectors file the engine itself rejects would be worse than none.
// ---------------------------------------------------------------------------

const bobSession = {
  conversationId,
  role: 'responder',
  peer: alicePublic,
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
  peer: bobPublic,
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
    'OCX2 known-answer vectors. Generated by scripts/gen-vectors.mjs, verified by test/vectors.test.ts.',
    'All randomness is replaced by the fixed seeds below. X25519 seeds are used verbatim as secret keys.',
    'ML-KEM-768 seeds are the 64 byte FIPS 203 keygen seed (d || z); kemEncapsulationMsg is the 32 byte encapsulation message m.',
    'Handshake: dh1 = DH(bobIdentity, aliceIdentity), dh2 = DH(bobRatchet1, aliceIdentity), ikm = dh1 || dh2 || kemSharedSecret,',
    'handshakeRootKey = HKDF-SHA256(ikm, salt "OCX2 hybrid handshake v1", info conversationId, 32 bytes).',
    'Each DH ratchet step: HKDF-SHA256(dh, salt currentRootKey, info "OCX2 root ratchet v1", 64 bytes) -> rootKey || chainKey.',
    'Each chain step: one HMAC-SHA512(chainKey, 0x01) -> nextChainKey || messageKey. 0.3.x used two HMAC-SHA256 instead.',
    'Messages are ChaCha20-Poly1305 (RFC 8439, 12 byte nonce). The nonce is random per seal and is transmitted, in the header immediately before the ciphertext.',
    'message0Nonce and reply0Nonce in seeds are the fixed stand-ins a known-answer file needs; a real seal draws those 12 bytes from the CSPRNG.',
    'AAD is the wire header followed by conversationId bytes 4..16 and, when the header omits it, the 32 byte sender ratchet public. See messageAad in src/envelope.ts.',
  ],
  conversationId,
  seeds: hexAll(seeds),
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
