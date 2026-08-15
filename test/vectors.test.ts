import { test } from 'node:test';
import assert from 'node:assert/strict';

import { x25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';

import type { SessionState } from '../src/contract.js';
import { concat, toHex, utf8ToBytes } from '../src/bytes.js';
import { conversationIdToBytes, decodeEnvelope, encodeEnvelope, messageAad } from '../src/envelope.js';
import { kdfChain, kdfHandshake, kdfRoot } from '../src/kdf.js';
import { ratchetDecrypt } from '../src/ratchet.js';

/**
 * Known-answer vectors.
 *
 * test/vectors.json, produced by scripts/gen-vectors.mjs, freezes one complete
 * deterministic run of the protocol: seeds in, root keys, message keys, and
 * exact wire tokens out. This suite re-derives every one of those values from
 * the seeds alone and compares byte for byte, so any change to the KDF inputs,
 * the mixing order, the envelope encoding, or the AAD layout shows up as a
 * failing known answer rather than as a silent wire-format break.
 *
 * The last test hands the vector tokens to the real ratchet, which is what
 * separates "the JSON is self-consistent" from "the JSON describes the actual
 * protocol": a re-derivation bug that made both the generator and this file
 * drift together would still fail there.
 *
 * Loading the JSON: @types/node is deliberately absent from this package and
 * test/node-builtins.d.ts declares only the test-runner surface, so fs is
 * reached through a dynamic specifier the compiler does not resolve. At
 * runtime this is a plain import of node:fs.
 */
interface FsLike {
  readonly readFileSync: (path: URL, options: { encoding: 'utf8' }) => string;
}
const fsModule = 'node:' + 'fs';
const fs = (await import(fsModule)) as FsLike;

interface Vectors {
  readonly conversationId: string;
  readonly seeds: {
    readonly aliceIdentityX25519: string;
    readonly aliceIdentityMlKem768: string;
    readonly aliceIdentityMlDsa65: string;
    readonly bobIdentityX25519: string;
    readonly bobIdentityMlKem768: string;
    readonly bobIdentityMlDsa65: string;
    readonly bobRatchet1X25519: string;
    readonly kemEncapsulationMsg: string;
    readonly aliceRatchet1X25519: string;
    readonly bobRatchet2X25519: string;
    readonly message0Nonce: string;
    readonly reply0Nonce: string;
  };
  readonly plaintexts: { readonly message0: string; readonly reply0: string };
  readonly derived: {
    readonly aliceClassicalPublic: string;
    readonly alicePqPublic: string;
    readonly bobClassicalPublic: string;
    readonly bobPqPublic: string;
    readonly bobRatchet1Public: string;
    readonly aliceRatchet1Public: string;
    readonly bobRatchet2Public: string;
    readonly kemCiphertext: string;
    readonly kemSharedSecret: string;
    readonly dh1: string;
    readonly dh2: string;
    readonly handshakeRootKey: string;
    readonly rootAfterAliceStep: string;
    readonly rootAfterBobStep: string;
    readonly chainAliceToBob: string;
    readonly chainBobToAlice: string;
    readonly messageKeysAliceToBob: readonly string[];
    readonly messageKeysBobToAlice: readonly string[];
  };
  readonly tokens: {
    readonly invite: string;
    readonly accept: string;
    readonly message0: string;
    readonly reply0: string;
  };
}

const vectors = JSON.parse(
  fs.readFileSync(new URL('./vectors.json', import.meta.url), { encoding: 'utf8' }),
) as Vectors;

function fromHex(hex: string): Uint8Array {
  assert.equal(hex.length % 2, 0, 'hex strings in vectors.json must have even length');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    assert.ok(Number.isInteger(byte), 'vectors.json contains a non-hex character');
    out[i] = byte;
  }
  return out;
}

/**
 * The full deterministic run, re-derived from the seeds. Kept as one function
 * because the later stages consume the earlier ones; each test then checks
 * one slice of the result against the JSON.
 */
function deriveAll(v: Vectors) {
  const aliceClassical = x25519.keygen(fromHex(v.seeds.aliceIdentityX25519));
  const alicePq = ml_kem768.keygen(fromHex(v.seeds.aliceIdentityMlKem768));
  const aliceSig = ml_dsa65.keygen(fromHex(v.seeds.aliceIdentityMlDsa65));
  const bobClassical = x25519.keygen(fromHex(v.seeds.bobIdentityX25519));
  const bobPq = ml_kem768.keygen(fromHex(v.seeds.bobIdentityMlKem768));
  const bobSig = ml_dsa65.keygen(fromHex(v.seeds.bobIdentityMlDsa65));

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

  const bobRatchet1 = x25519.keygen(fromHex(v.seeds.bobRatchet1X25519));
  const kem = ml_kem768.encapsulate(alicePq.publicKey, fromHex(v.seeds.kemEncapsulationMsg));

  // Rebuilt here rather than imported from src/handshake, which does not export
  // it. That is the point of this file: if the transcript construction in the
  // library drifts from what is written down here, the signature stops matching
  // the recorded token and this fails, instead of both sides drifting together.
  const transcript = (domain: string, parts: Uint8Array[]): Uint8Array => {
    const lengths = new Uint8Array(4 * parts.length);
    const view = new DataView(lengths.buffer);
    parts.forEach((part, i) => view.setUint32(i * 4, part.length, false));
    return concat(utf8ToBytes(domain), lengths, ...parts);
  };
  // Deterministic mode, because the library signs hedged and a hedged signature
  // is different every time. What is pinned is the transcript and the encoding.
  const signFixed = (msg: Uint8Array, secretKey: Uint8Array): Uint8Array =>
    ml_dsa65.sign(msg, secretKey, { extraEntropy: false });

  const inviteSignature = signFixed(
    transcript('OCX2 invite transcript v1', [
      utf8ToBytes(v.conversationId),
      alicePublic.classicalPublic,
      alicePublic.pqPublic,
      alicePublic.sigPublic,
    ]),
    aliceSig.secretKey,
  );
  const acceptSignature = signFixed(
    transcript('OCX2 accept transcript v1', [
      utf8ToBytes(v.conversationId),
      alicePublic.classicalPublic,
      alicePublic.pqPublic,
      alicePublic.sigPublic,
      bobPublic.classicalPublic,
      bobPublic.pqPublic,
      bobPublic.sigPublic,
      kem.cipherText,
      bobRatchet1.publicKey,
    ]),
    bobSig.secretKey,
  );

  // Responder-side mixing, exactly as acceptInvite orders it: identity DH,
  // ratchet DH, KEM secret.
  const dh1 = x25519.getSharedSecret(bobClassical.secretKey, aliceClassical.publicKey);
  const dh2 = x25519.getSharedSecret(bobRatchet1.secretKey, aliceClassical.publicKey);
  const handshakeRootKey = kdfHandshake(concat(dh1, dh2, kem.sharedSecret), v.conversationId);

  // Initiator-side agreement: X25519 symmetry plus decapsulation must land on
  // the identical root, otherwise the vectors describe a broken handshake.
  const pqAlice = ml_kem768.decapsulate(kem.cipherText, alicePq.secretKey);
  const rootAlice = kdfHandshake(
    concat(
      x25519.getSharedSecret(aliceClassical.secretKey, bobClassical.publicKey),
      x25519.getSharedSecret(aliceClassical.secretKey, bobRatchet1.publicKey),
      pqAlice,
    ),
    v.conversationId,
  );
  assert.equal(toHex(rootAlice), toHex(handshakeRootKey));

  // Alice's post-handshake ratchet step from completeInvite, then Bob's
  // answering step from dhRatchet. Each yields a root and a sending chain.
  const aliceRatchet1 = x25519.keygen(fromHex(v.seeds.aliceRatchet1X25519));
  const aliceStep = kdfRoot(handshakeRootKey, x25519.getSharedSecret(aliceRatchet1.secretKey, bobRatchet1.publicKey));

  const bobRatchet2 = x25519.keygen(fromHex(v.seeds.bobRatchet2X25519));
  const bobStep = kdfRoot(aliceStep.rootKey, x25519.getSharedSecret(bobRatchet2.secretKey, aliceRatchet1.publicKey));

  const walk = (chainKey: Uint8Array, count: number): Uint8Array[] => {
    const keys: Uint8Array[] = [];
    let ck = chainKey;
    for (let i = 0; i < count; i += 1) {
      const step = kdfChain(ck);
      keys.push(step.messageKey);
      ck = step.nextChainKey;
    }
    return keys;
  };

  return {
    aliceClassical,
    alicePq,
    aliceSig,
    alicePublic,
    bobClassical,
    bobPq,
    bobSig,
    bobPublic,
    inviteSignature,
    acceptSignature,
    bobRatchet1,
    aliceRatchet1,
    bobRatchet2,
    kem,
    dh1,
    dh2,
    handshakeRootKey,
    rootAfterAliceStep: aliceStep.rootKey,
    chainAliceToBob: aliceStep.chainKey,
    rootAfterBobStep: bobStep.rootKey,
    chainBobToAlice: bobStep.chainKey,
    messageKeysAliceToBob: walk(aliceStep.chainKey, 3),
    messageKeysBobToAlice: walk(bobStep.chainKey, 3),
  };
}

const derived = deriveAll(vectors);

test('vectors: public keys and KEM outputs re-derive from the seeds', () => {
  assert.equal(toHex(derived.aliceClassical.publicKey), vectors.derived.aliceClassicalPublic);
  assert.equal(toHex(derived.alicePq.publicKey), vectors.derived.alicePqPublic);
  assert.equal(toHex(derived.bobClassical.publicKey), vectors.derived.bobClassicalPublic);
  assert.equal(toHex(derived.bobPq.publicKey), vectors.derived.bobPqPublic);
  assert.equal(toHex(derived.bobRatchet1.publicKey), vectors.derived.bobRatchet1Public);
  assert.equal(toHex(derived.aliceRatchet1.publicKey), vectors.derived.aliceRatchet1Public);
  assert.equal(toHex(derived.bobRatchet2.publicKey), vectors.derived.bobRatchet2Public);
  assert.equal(toHex(derived.kem.cipherText), vectors.derived.kemCiphertext);
  assert.equal(toHex(derived.kem.sharedSecret), vectors.derived.kemSharedSecret);
});

test('vectors: the hybrid handshake root re-derives, with both DH values on record', () => {
  assert.equal(toHex(derived.dh1), vectors.derived.dh1);
  assert.equal(toHex(derived.dh2), vectors.derived.dh2);
  assert.equal(toHex(derived.handshakeRootKey), vectors.derived.handshakeRootKey);
});

test('vectors: root evolution and the first three message keys each direction re-derive', () => {
  assert.equal(toHex(derived.rootAfterAliceStep), vectors.derived.rootAfterAliceStep);
  assert.equal(toHex(derived.chainAliceToBob), vectors.derived.chainAliceToBob);
  assert.equal(toHex(derived.rootAfterBobStep), vectors.derived.rootAfterBobStep);
  assert.equal(toHex(derived.chainBobToAlice), vectors.derived.chainBobToAlice);
  assert.deepEqual(derived.messageKeysAliceToBob.map(toHex), vectors.derived.messageKeysAliceToBob);
  assert.deepEqual(derived.messageKeysBobToAlice.map(toHex), vectors.derived.messageKeysBobToAlice);
});

test('vectors: all four wire tokens re-encode byte for byte', () => {
  const invite = encodeEnvelope({
    kind: 'invite',
    sender: derived.alicePublic,
    conversationId: vectors.conversationId,
    signature: derived.inviteSignature,
  });
  assert.equal(invite, vectors.tokens.invite);

  const accept = encodeEnvelope({
    kind: 'accept',
    sender: derived.bobPublic,
    conversationId: vectors.conversationId,
    kemCiphertext: derived.kem.cipherText,
    ratchetPublic: derived.bobRatchet1.publicKey,
    signature: derived.acceptSignature,
  });
  assert.equal(accept, vectors.tokens.accept);

  // Message tokens: the same construction ratchetEncrypt performs, spelled out
  // from primitives so nothing but the KDF outputs is taken on trust.
  //
  // The nonce is an input again. A draft of 0.4.0 derived it from the message
  // number, which let this file supply twelve zero bytes and pin the derivation
  // for free; the shipped build draws twelve random bytes per seal instead, so a
  // known-answer file has to be handed the same fixed value the generator used.
  // That value lives in vectors.json under seeds, and reading it here rather
  // than hard coding it keeps one copy of the number.
  //
  // The header doubles as the front of the AAD, and the nonce is inside the
  // header, so a byte-equal token pins that the nonce is bound as well as sent.
  // messageAad then appends the 12 conversation id bytes that never travel.
  // Change the layout anywhere and the tag moves.
  const conversationIdBytes = conversationIdToBytes(vectors.conversationId);
  const seal = (
    messageKey: Uint8Array,
    ratchetPublic: Uint8Array,
    nonce: Uint8Array,
    plaintext: string,
  ): string => {
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
  };

  const mk0 = derived.messageKeysAliceToBob[0];
  const rk0 = derived.messageKeysBobToAlice[0];
  assert.ok(mk0);
  assert.ok(rk0);
  const message0Nonce = fromHex(vectors.seeds.message0Nonce);
  const reply0Nonce = fromHex(vectors.seeds.reply0Nonce);
  // The length is asserted, not assumed: a vectors file carrying 24 bytes here
  // would be describing XChaCha20, which is not what this build speaks.
  assert.equal(message0Nonce.length, 12);
  assert.equal(reply0Nonce.length, 12);
  assert.notDeepEqual(message0Nonce, reply0Nonce);
  assert.equal(
    seal(mk0, derived.aliceRatchet1.publicKey, message0Nonce, vectors.plaintexts.message0),
    vectors.tokens.message0,
  );
  assert.equal(
    seal(rk0, derived.bobRatchet2.publicKey, reply0Nonce, vectors.plaintexts.reply0),
    vectors.tokens.reply0,
  );
});

test('vectors: the real ratchet opens the vector tokens', () => {
  // Bob's session as acceptInvite would have produced it with the vector
  // randomness. If ratchetDecrypt opens message 0 from this state, the vector
  // tokens are real protocol traffic, not merely self-consistent bytes.
  const bobSession: SessionState = {
    conversationId: vectors.conversationId,
    role: 'responder',
    peer: derived.alicePublic,
    rootKey: derived.handshakeRootKey,
    selfRatchetPublic: derived.bobRatchet1.publicKey,
    selfRatchetSecret: derived.bobRatchet1.secretKey,
    sendCount: 0,
    recvCount: 0,
    previousSendCount: 0,
    skippedKeys: {},
  };
  const message0 = decodeEnvelope(vectors.tokens.message0);
  assert.equal(message0.kind, 'message');
  if (message0.kind !== 'message') throw new Error('unreachable');
  const openedByBob = ratchetDecrypt(bobSession, message0);
  assert.equal(openedByBob.plaintext, vectors.plaintexts.message0);
  // The DH ratchet step inside that decrypt must land on the vector's root.
  // ratchetDecrypt then immediately steps again with a fresh random key for
  // Bob's send chain, so the stored root has moved past rootAfterAliceStep;
  // the receive chain it derived is the part that is still pinned.
  assert.equal(toHex(openedByBob.session.peerRatchetPublic ?? new Uint8Array(0)), vectors.derived.aliceRatchet1Public);

  // Alice's session as completeInvite would have produced it, one ratchet
  // step past the handshake root, opening Bob's reply.
  const aliceSession: SessionState = {
    conversationId: vectors.conversationId,
    role: 'initiator',
    peer: derived.bobPublic,
    rootKey: derived.rootAfterAliceStep,
    selfRatchetPublic: derived.aliceRatchet1.publicKey,
    selfRatchetSecret: derived.aliceRatchet1.secretKey,
    peerRatchetPublic: derived.bobRatchet1.publicKey,
    sendChainKey: derived.chainAliceToBob,
    sendCount: 0,
    recvCount: 0,
    previousSendCount: 0,
    skippedKeys: {},
  };
  const reply0 = decodeEnvelope(vectors.tokens.reply0);
  assert.equal(reply0.kind, 'message');
  if (reply0.kind !== 'message') throw new Error('unreachable');
  const openedByAlice = ratchetDecrypt(aliceSession, reply0);
  assert.equal(openedByAlice.plaintext, vectors.plaintexts.reply0);

  // And the handshake tokens round-trip through the codec unchanged, so the
  // vectors also pin the invite and accept wire encoding.
  assert.equal(encodeEnvelope(decodeEnvelope(vectors.tokens.invite)), vectors.tokens.invite);
  assert.equal(encodeEnvelope(decodeEnvelope(vectors.tokens.accept)), vectors.tokens.accept);
});
