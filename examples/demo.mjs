// Live demo: two people, one encrypted conversation, and a tamper that fails.
// Run:  node examples/demo.mjs
import assert from 'node:assert/strict';
import { engine, formatFingerprint } from '../dist/index.js';

// 1. Two identities, generated locally. No server, no accounts.
const alice = await engine.createIdentity();
const bob = await engine.createIdentity();

// 2. Handshake. Alice invites, Bob accepts. Tokens are plain strings.
const { token: inviteToken, pending } = await engine.invite(alice);
const bobOpen = await engine.open(bob, inviteToken, {});
let bobSession = bobOpen.session;
const aliceOpen = await engine.open(alice, bobOpen.reply, { pending });
let aliceSession = aliceOpen.session;

// 3. Both sides independently compute the same 6 safety words.
//    Say them out loud: if they match, there is no machine in the middle.
console.log('safety words:', formatFingerprint(bobOpen.peerFingerprint));

// 4. A real message, encrypted on Alice's side, decrypted on Bob's.
const a1 = await engine.seal(aliceSession, 'passport scan attached');
aliceSession = a1.session;
const b1 = await engine.open(bob, a1.token, { session: bobSession });
bobSession = b1.session;
console.log('bob reads   :', b1.plaintext);
assert.equal(b1.plaintext, 'passport scan attached');

// 5. Bob replies. Direction change triggers a ratchet step.
const b2 = await engine.seal(bobSession, 'got it, thanks');
const a2 = await engine.open(alice, b2.token, { session: aliceSession });
console.log('alice reads :', a2.plaintext);
assert.equal(a2.plaintext, 'got it, thanks');

// 6. Tamper: flip one character of a fresh ciphertext. It must fail closed.
const a3 = await engine.seal(a1.session, 'this will be corrupted in transit');
const chars = a3.token.split('');
chars[chars.length - 3] = chars[chars.length - 3] === 'A' ? 'B' : 'A';
const corrupted = chars.join('');
let rejected = false;
try {
  const r = await engine.open(bob, corrupted, { session: bobSession });
  if (r && r.outcome === 'failed') rejected = true;
} catch { rejected = true; }
console.log('tamper      :', rejected ? 'rejected (as it must be)' : 'ACCEPTED - BUG');
assert.equal(rejected, true);

console.log('\nOK: real encryption, real decryption, tampering fails closed.');
