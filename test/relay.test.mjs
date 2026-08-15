// The relay and the pairing codes, over real sockets on loopback.
//
// Nothing here is mocked. A relay that works against a fake socket and not
// against a real one is the failure mode this whole file exists to catch, and
// the two bugs it did catch while being written were both about buffering: a
// hello read greedily eats the peer's first frame, and a status byte read with
// `on` instead of `once` does it again one layer up.
import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';

import { engine } from '../dist/index.js';
import { connectViaRelay, RELAY_STATUS_BUSY, RELAY_STATUS_PAIRED } from '../cli/frame.mjs';
import {
  CODE_CHARS,
  FINGERPRINT_PIN_BYTES,
  SECRET_BYTES,
  codeFromParts,
  fingerprintPin,
  formatCode,
  newPairingCode,
  parsePairingCode,
  pinMatches,
} from '../cli/pairing.mjs';
import {
  HELLO_BYTES,
  RELAY_MAGIC,
  STATUS_BUSY,
  STATUS_PAIRED,
  createRelay,
  rendezvousId,
} from '../relay/server.mjs';

async function withRelay(limits, fn) {
  const relay = createRelay(limits ? { limits } : {});
  const address = await relay.listen(0, '127.0.0.1');
  try {
    return await fn({ host: '127.0.0.1', port: address.port, relay });
  } finally {
    await relay.close();
  }
}

const dial = ({ host, port, rendezvous }) =>
  connectViaRelay({ host, port, rendezvous, magic: RELAY_MAGIC, timeoutMs: 5000, waitMs: 5000 });

// ---------------------------------------------------------------------------
// The status constants, which live in two files on purpose
// ---------------------------------------------------------------------------

test('the client and the server agree about the status bytes', () => {
  // cli/frame.mjs deliberately does not import the server: somebody who
  // installed the client from npm has no reason to carry it. That is a
  // duplication, so it gets a test rather than a comment asking people to keep
  // two numbers in step.
  assert.equal(RELAY_STATUS_PAIRED, STATUS_PAIRED);
  assert.equal(RELAY_STATUS_BUSY, STATUS_BUSY);
});

// ---------------------------------------------------------------------------
// Pairing codes
// ---------------------------------------------------------------------------

test('a code round trips, and carries the rendezvous and the fingerprint pin', async () => {
  const bob = await engine.createIdentity();
  const { code, rendezvous } = newPairingCode(engine.publicOf(bob));

  const parsed = parsePairingCode(code);
  assert.ok(parsed.ok, parsed.reason);
  assert.deepEqual(Buffer.from(parsed.rendezvous), Buffer.from(rendezvous));
  assert.ok(pinMatches(parsed.pin, engine.fingerprint(engine.publicOf(bob)).hex));
});

test('the pin does not match a different identity', async () => {
  const bob = await engine.createIdentity();
  const mallory = await engine.createIdentity();
  const parsed = parsePairingCode(newPairingCode(engine.publicOf(bob)).code);
  assert.ok(parsed.ok);
  assert.equal(pinMatches(parsed.pin, engine.fingerprint(engine.publicOf(mallory)).hex), false);
});

test('a code survives being read aloud badly', async () => {
  // The whole reason for Crockford: somebody reading a code over the phone says
  // "one" for I and "zero" for O, and the person typing writes what they heard.
  // A code that refuses that is a code that fails exactly when it is being used
  // the way it is meant to be used.
  const bob = await engine.createIdentity();
  const { code } = newPairingCode(engine.publicOf(bob));
  const mangled = code
    .toLowerCase()
    .replace(/-/g, ' ')
    .replace(/1/g, 'l')
    .replace(/0/g, 'o');

  const straight = parsePairingCode(code);
  const heard = parsePairingCode(mangled);
  assert.ok(heard.ok, heard.reason);
  assert.deepEqual(Buffer.from(heard.rendezvous), Buffer.from(straight.rendezvous));
});

test('a mistyped or truncated code is refused with a reason, never silently', async () => {
  const bob = await engine.createIdentity();
  const { code } = newPairingCode(engine.publicOf(bob));

  for (const bad of ['', 'nonsense', code.slice(0, 10), `${code}Z`, null, 42]) {
    const parsed = parsePairingCode(bad);
    assert.equal(parsed.ok, false);
    assert.ok(typeof parsed.reason === 'string' && parsed.reason.length > 8);
  }
});

test('a code has exactly one spelling', () => {
  // Non-zero padding bits in the last character would give two strings that
  // decode to one code. Then "they read it back and it matched" would stop
  // meaning that both sides hold the same bytes.
  const secret = Buffer.alloc(SECRET_BYTES, 0x11);
  const pin = Buffer.alloc(FINGERPRINT_PIN_BYTES, 0x22);
  const code = codeFromParts(secret, pin);
  const cleaned = code.replace(/-/g, '');
  assert.equal(cleaned.length, CODE_CHARS);

  const last = cleaned[cleaned.length - 1];
  const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  for (const candidate of alphabet) {
    if (candidate === last) continue;
    const variant = formatCode(cleaned.slice(0, -1) + candidate);
    const parsed = parsePairingCode(variant);
    // Either it is refused, or it decodes to genuinely different bytes. What it
    // must never do is decode to the same 24 bytes as the real code.
    if (parsed.ok) {
      assert.notDeepEqual(Buffer.from(parsed.pin), pin, `${variant} is a second spelling`);
    }
  }
});

test('the relay never sees the secret, only a hash of it', () => {
  // The operator matches two sockets on this value. If it were the secret
  // itself, an operator could join a rendezvous it is carrying, or start one
  // against somebody who is waiting.
  const secret = Buffer.alloc(SECRET_BYTES, 0x5a);
  const id = rendezvousId(secret);
  assert.equal(id.length, 16);
  assert.notEqual(Buffer.from(id).toString('hex'), secret.toString('hex'));
  // Deterministic, or the two sides would never meet.
  assert.deepEqual(Buffer.from(rendezvousId(secret)), Buffer.from(id));
});

test('the pin is the front of the identity fingerprint, not something adjacent', async () => {
  const bob = await engine.createIdentity();
  const pin = fingerprintPin(engine.publicOf(bob));
  assert.equal(pin.length, FINGERPRINT_PIN_BYTES);
  assert.equal(
    Buffer.from(pin).toString('hex'),
    engine.fingerprint(engine.publicOf(bob)).hex.slice(0, FINGERPRINT_PIN_BYTES * 2),
  );
});

// ---------------------------------------------------------------------------
// The relay, over real sockets
// ---------------------------------------------------------------------------

test('two clients on one rendezvous are introduced and can talk', async () => {
  await withRelay(null, async ({ host, port }) => {
    const rendezvous = rendezvousId(Buffer.alloc(SECRET_BYTES, 1));

    // The first arrival waits, the second pairs instantly. Starting the first
    // without awaiting it is the real ordering, not a convenience.
    const firstPromise = dial({ host, port, rendezvous });
    const second = await dial({ host, port, rendezvous });
    const first = await firstPromise;

    await first.send(Buffer.from('hello from the waiter'));
    const got = await second.receive();
    assert.equal(Buffer.from(got).toString(), 'hello from the waiter');

    await second.send(Buffer.from('and back'));
    assert.equal(Buffer.from(await first.receive()).toString(), 'and back');

    await first.close();
    await second.close();
  });
});

test('a whole ratchet handshake and a message survive the relay', async () => {
  // The relay is a pipe, so this should work without the protocol knowing. The
  // reason to prove it rather than assume it is that a relay which drops or
  // duplicates a single byte produces a handshake that fails in a way that
  // looks like a crypto bug.
  await withRelay(null, async ({ host, port }) => {
    const rendezvous = rendezvousId(Buffer.alloc(SECRET_BYTES, 2));
    const alice = await engine.createIdentity();
    const bob = await engine.createIdentity();

    const aPromise = dial({ host, port, rendezvous });
    const b = await dial({ host, port, rendezvous });
    const a = await aPromise;

    // Bob invites, Alice accepts, Bob completes, Alice sends. Same sequence
    // cli/protocol.mjs runs, done by hand so the test owns the ordering.
    const invited = await engine.invite(bob);
    await b.send(Buffer.from(invited.token, 'utf8'));

    const inviteBytes = await a.receive();
    const accepted = await engine.open(alice, Buffer.from(inviteBytes).toString('utf8'), {});
    await a.send(Buffer.from(accepted.reply, 'utf8'));

    const replyBytes = await b.receive();
    const done = await engine.open(bob, Buffer.from(replyBytes).toString('utf8'), {
      pending: invited.pending,
    });
    assert.equal(done.outcome, 'accepted');

    // Bob invited, so Bob is the initiator and the only one with a send chain
    // until he speaks. Alice, as responder, cannot send first: same asymmetry
    // as Signal, and the reason cli/protocol.mjs has a ready frame.
    const sealed = await engine.seal(done.session, 'through a relay that cannot read this');
    await b.send(Buffer.from(sealed.token, 'utf8'));
    const opened = await engine.open(alice, Buffer.from(await a.receive()).toString('utf8'), {
      session: accepted.session,
    });
    assert.equal(opened.plaintext, 'through a relay that cannot read this');

    // And the fingerprints agree across the relay, which is what the pairing
    // code pin is checked against in the CLI.
    assert.equal(done.peerFingerprint.hex, engine.fingerprint(engine.publicOf(alice)).hex);
    assert.equal(accepted.peerFingerprint.hex, engine.fingerprint(engine.publicOf(bob)).hex);

    await a.close();
    await b.close();
  });
});

test('a client sending its first frame immediately after the hello does not lose it', async () => {
  // The bug this pins: a server that reads greedily consumes the hello AND
  // whatever came behind it, then pipes only what arrives afterwards. The first
  // frame vanishes, and because it is a handshake frame the failure surfaces
  // much later as a timeout with no explanation.
  await withRelay(null, async ({ host, port }) => {
    const rendezvous = rendezvousId(Buffer.alloc(SECRET_BYTES, 3));

    const waiter = await new Promise((resolve, reject) => {
      const socket = net.createConnection({ host, port }, () => resolve(socket));
      socket.once('error', reject);
    });
    // Hello and payload in ONE write, so they land in one TCP segment.
    waiter.write(Buffer.concat([RELAY_MAGIC, Buffer.from(rendezvous), Buffer.from('EARLY')]));

    const partner = await new Promise((resolve, reject) => {
      const socket = net.createConnection({ host, port }, () => resolve(socket));
      socket.once('error', reject);
    });
    partner.write(Buffer.concat([RELAY_MAGIC, Buffer.from(rendezvous)]));

    const received = await new Promise((resolve, reject) => {
      let buffered = Buffer.alloc(0);
      partner.on('data', (chunk) => {
        buffered = Buffer.concat([buffered, chunk]);
        // status byte plus the five bytes the waiter sent
        if (buffered.length >= 6) resolve(buffered);
      });
      partner.once('error', reject);
      setTimeout(() => reject(new Error('the early bytes never arrived')), 4000);
    });

    assert.equal(received[0], STATUS_PAIRED);
    assert.equal(received.subarray(1, 6).toString(), 'EARLY');

    waiter.destroy();
    partner.destroy();
  });
});

test('a full relay refuses rather than accepting a connection it cannot serve', async () => {
  await withRelay({ ...{ waitMs: 5000, sessionMs: 5000, helloMs: 2000, maxWaitingPerIp: 16 }, maxWaiting: 1 }, async ({ host, port }) => {
    const first = dial({ host, port, rendezvous: rendezvousId(Buffer.alloc(SECRET_BYTES, 4)) });
    // Give the first one time to land in the waiting map.
    await new Promise((r) => setTimeout(r, 100));

    await assert.rejects(
      dial({ host, port, rendezvous: rendezvousId(Buffer.alloc(SECRET_BYTES, 5)) }),
      /full/,
    );
    first.catch(() => {});
  });
});

test('a client that never sends a hello is dropped', async () => {
  await withRelay({ waitMs: 5000, sessionMs: 5000, helloMs: 200, maxWaiting: 8, maxWaitingPerIp: 8 }, async ({ host, port, relay }) => {
    const socket = await new Promise((resolve, reject) => {
      const s = net.createConnection({ host, port }, () => resolve(s));
      s.once('error', reject);
    });
    await new Promise((resolve) => socket.once('close', resolve));
    assert.equal(relay.stats().waiting, 0);
  });
});

test('garbage that is not a hello is dropped without a reply', async () => {
  await withRelay(null, async ({ host, port, relay }) => {
    const socket = await new Promise((resolve, reject) => {
      const s = net.createConnection({ host, port }, () => resolve(s));
      s.once('error', reject);
    });
    let replied = false;
    socket.on('data', () => {
      replied = true;
    });
    socket.write(Buffer.alloc(HELLO_BYTES, 0x41));
    await new Promise((resolve) => socket.once('close', resolve));
    assert.equal(replied, false, 'a wrong magic must not be answered, only dropped');
    assert.equal(relay.stats().waiting, 0);
  });
});

test('a waiting client that hangs up frees its slot', async () => {
  await withRelay(null, async ({ host, port, relay }) => {
    const rendezvous = rendezvousId(Buffer.alloc(SECRET_BYTES, 6));
    const socket = await new Promise((resolve, reject) => {
      const s = net.createConnection({ host, port }, () => resolve(s));
      s.once('error', reject);
    });
    socket.write(Buffer.concat([RELAY_MAGIC, Buffer.from(rendezvous)]));
    await new Promise((r) => setTimeout(r, 150));
    assert.equal(relay.stats().waiting, 1);

    socket.destroy();
    await new Promise((r) => setTimeout(r, 150));
    assert.equal(relay.stats().waiting, 0, 'a dropped waiter must not hold its rendezvous forever');
  });
});

test('two different rendezvous ids never meet', async () => {
  await withRelay({ waitMs: 400, sessionMs: 5000, helloMs: 2000, maxWaiting: 8, maxWaitingPerIp: 8 }, async ({ host, port }) => {
    const a = dial({ host, port, rendezvous: rendezvousId(Buffer.alloc(SECRET_BYTES, 7)) });
    const b = dial({ host, port, rendezvous: rendezvousId(Buffer.alloc(SECRET_BYTES, 8)) });
    // Neither pairs, so both hit the wait timeout and reject.
    await assert.rejects(a);
    await assert.rejects(b);
  });
});

// ---------------------------------------------------------------------------
// The gate that can refuse, and the banner that cannot
// ---------------------------------------------------------------------------

test('a banner that throws does not stop a transfer, and verifyPeer does', async () => {
  // This pins the distinction that a real bug turned on. The pairing code check
  // was written as an onHandshake banner, the banner threw on a mismatched
  // peer, cli/protocol.mjs caught it because a broken banner must never cost
  // somebody their file, and the transfer completed to the wrong machine with
  // no sign anything had been checked.
  //
  // Both halves are asserted, because fixing this by making banners fatal would
  // be the wrong repair: a rendering bug really must not fail a transfer.
  const { listen, connect } = await import('../cli/frame.mjs');
  const { sendPayload, receivePayload } = await import('../cli/protocol.mjs');

  const server = await listen({ port: 0 });
  const alice = await engine.createIdentity();
  const bob = await engine.createIdentity();

  async function transfer({ onHandshake, verifyPeer }) {
    // The receiving side is expected to fail when the sender refuses, so its
    // rejection is captured here rather than left to become an unhandled one.
    const accept = (async () => {
      for await (const channel of server) {
        try {
          return await receivePayload({ channel, identity: bob });
        } finally {
          await channel.close();
        }
      }
      return null;
    })().catch((err) => ({ failed: err }));
    const channel = await connect({ host: '127.0.0.1', port: server.port });
    try {
      const stats = await sendPayload({
        channel,
        identity: alice,
        name: 'f.txt',
        bytes: Buffer.from('payload'),
        onHandshake,
        verifyPeer,
      });
      await accept;
      return stats;
    } finally {
      await channel.close();
    }
  }

  // A banner that throws: the transfer completes anyway.
  const stats = await transfer({
    onHandshake: () => {
      throw new Error('the banner is broken');
    },
  });
  assert.ok(stats.plainBytes === 7);

  // A verifyPeer that throws: the transfer does not.
  await assert.rejects(
    transfer({
      verifyPeer: () => {
        throw new Error('that is not the peer I was promised');
      },
    }),
    /not the peer I was promised/,
  );

  await server.close();
});
