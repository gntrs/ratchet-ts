// Reassembly tests for the length prefixed transport in cli/frame.mjs.
//
// A real socket cannot be told to split a length prefix across two 'data'
// events, and that split is precisely the case that corrupts a large
// transfer, so most of these drive the reader through a fake socket and hand
// it exactly the chunking they want. The last two use real loopback TCP to
// prove the same code path works when Node owns the chunk boundaries.
import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { connect, listen, __internal } from '../cli/frame.mjs';

const { makeChannel, MAX_FRAME } = __internal;

/** Minimum of net.Socket that makeChannel actually touches. */
class FakeSocket extends EventEmitter {
  constructor() {
    super();
    this.writes = [];
    this.destroyed = false;
    this.noDelay = false;
    this.flushed = true;
  }

  setNoDelay(on) {
    this.noDelay = on;
  }

  write(buf) {
    this.writes.push(Buffer.from(buf));
    return this.flushed;
  }

  destroy() {
    this.destroyed = true;
  }

  end() {
    this.destroyed = true;
    this.emit('close');
  }

  /** Deliver bytes exactly as one 'data' event. */
  feed(bytes) {
    this.emit('data', Buffer.from(bytes));
  }
}

function fakeChannel() {
  const socket = new FakeSocket();
  return { socket, channel: makeChannel(socket, 'fake:0') };
}

function frame(payload) {
  const body = Buffer.from(payload);
  const out = Buffer.allocUnsafe(4 + body.length);
  out.writeUInt32BE(body.length, 0);
  body.copy(out, 4);
  return out;
}

function filled(n, seed) {
  const out = Buffer.allocUnsafe(n);
  for (let i = 0; i < n; i += 1) out[i] = (i * 31 + seed) & 0xff;
  return out;
}

test('reassembles frames delivered one byte at a time', async () => {
  const { socket, channel } = fakeChannel();
  const payloads = [filled(1, 3), filled(65519, 7), filled(0, 0), filled(300, 11)];
  const wire = Buffer.concat(payloads.map(frame));

  const got = [];
  const reader = (async () => {
    for (let i = 0; i < payloads.length; i += 1) got.push(await channel.receive());
  })();

  for (let i = 0; i < wire.length; i += 1) socket.feed(wire.subarray(i, i + 1));
  await reader;

  assert.equal(got.length, 4);
  for (let i = 0; i < payloads.length; i += 1) {
    assert.deepEqual(Buffer.from(got[i]), payloads[i], `frame ${i} mismatch`);
  }
});

test('handles a length prefix straddling two data events', async () => {
  const { socket, channel } = fakeChannel();
  const payload = filled(70000, 5);
  const wire = frame(payload);

  const pending = channel.receive();
  // Two bytes of the prefix, then the rest of the prefix glued to the body.
  socket.feed(wire.subarray(0, 2));
  socket.feed(wire.subarray(2, 4096));
  socket.feed(wire.subarray(4096));

  assert.deepEqual(Buffer.from(await pending), payload);
});

test('handles three whole frames plus half a fourth in one buffer', async () => {
  const { socket, channel } = fakeChannel();
  const payloads = [filled(10, 1), filled(65519, 2), filled(4, 3), filled(9000, 4)];
  const wire = Buffer.concat(payloads.map(frame));
  const wholeThree = 3 * 4 + payloads[0].length + payloads[1].length + payloads[2].length;
  const half = wholeThree + Math.floor((4 + payloads[3].length) / 2);

  socket.feed(wire.subarray(0, half));
  for (let i = 0; i < 3; i += 1) {
    assert.deepEqual(Buffer.from(await channel.receive()), payloads[i], `frame ${i} mismatch`);
  }

  const fourth = channel.receive();
  socket.feed(wire.subarray(half));
  assert.deepEqual(Buffer.from(await fourth), payloads[3]);
});

test('a prefix above the cap kills the connection before allocating', async () => {
  const { socket, channel } = fakeChannel();
  const pending = channel.receive();
  const prefix = Buffer.allocUnsafe(4);
  prefix.writeUInt32BE(MAX_FRAME + 1, 0);
  socket.feed(prefix);

  await assert.rejects(pending, /exceeds the 8388608 byte limit/);
  assert.equal(socket.destroyed, true);
});

test('a prefix with the high bit set is still read as unsigned', async () => {
  const { socket, channel } = fakeChannel();
  const pending = channel.receive();
  // 0xffffffff would come back as -1 from a signed shift and slip past the cap.
  socket.feed(Buffer.from([0xff, 0xff, 0xff, 0xff]));
  await assert.rejects(pending, /4294967295 bytes/);
  assert.equal(socket.destroyed, true);
});

test('a truncated frame at EOF rejects instead of looking like a clean close', async () => {
  const { socket, channel } = fakeChannel();
  const wire = frame(filled(100, 1));
  const pending = channel.receive();
  socket.feed(wire.subarray(0, 40));
  socket.emit('end');
  await assert.rejects(pending, /truncated frame/);
});

test('a clean close resolves the pending read with null', async () => {
  const { socket, channel } = fakeChannel();
  const pending = channel.receive();
  socket.emit('end');
  assert.equal(await pending, null);
});

test('send emits one write of prefix plus payload', async () => {
  const { socket, channel } = fakeChannel();
  const payload = filled(1000, 9);
  await channel.send(payload);
  assert.equal(socket.writes.length, 1, 'prefix and payload must not be two writes');
  assert.deepEqual(socket.writes[0], frame(payload));
});

test('send waits for drain when the socket is backed up', async () => {
  const { socket, channel } = fakeChannel();
  socket.flushed = false;
  let done = false;
  const pending = channel.send(filled(64, 1)).then(() => {
    done = true;
  });
  await new Promise((r) => setImmediate(r));
  assert.equal(done, false, 'send resolved without waiting for drain');
  socket.emit('drain');
  await pending;
  assert.equal(done, true);
});

test('send refuses a string and refuses an oversize frame', async () => {
  const { channel } = fakeChannel();
  await assert.rejects(channel.send('OCX1.msg.abcd'), /expects a Uint8Array/);
  await assert.rejects(channel.send(new Uint8Array(MAX_FRAME + 1)), /exceeds the 8388608 byte limit/);
});

test('round trips arbitrary bytes over real TCP', async () => {
  const server = await listen({ host: '127.0.0.1' });
  const accepted = (async () => {
    for await (const ch of server) return ch;
    return null;
  })();
  const client = await connect({ host: '127.0.0.1', port: server.port });
  const peer = await accepted;

  // Byte 10 is the old newline delimiter and byte 0 used to be unrepresentable
  // in a base64 token, so both belong in the very first frame across a socket.
  const payloads = [
    Buffer.from([0, 10, 13, 255, 0]),
    filled(0, 0),
    filled(65519, 17),
    filled(1, 2),
  ];
  for (const p of payloads) await client.send(p);
  for (const p of payloads) assert.deepEqual(Buffer.from(await peer.receive()), p);

  await client.close();
  await peer.close();
  await server.close();
});

test('survives a large transfer split by the kernel however it likes', async () => {
  const server = await listen({ host: '127.0.0.1' });
  const accepted = (async () => {
    for await (const ch of server) return ch;
    return null;
  })();
  const client = await connect({ host: '127.0.0.1', port: server.port });
  const peer = await accepted;

  // 763 kB in 65519 byte frames, the case the CLI actually runs.
  const total = 763 * 1024;
  const chunk = 65519;
  const source = filled(total, 23);
  const frames = [];
  for (let off = 0; off < total; off += chunk) {
    frames.push(source.subarray(off, Math.min(off + chunk, total)));
  }

  const reader = (async () => {
    const seen = [];
    for (let i = 0; i < frames.length; i += 1) seen.push(Buffer.from(await peer.receive()));
    return Buffer.concat(seen);
  })();
  for (const f of frames) await client.send(f);

  assert.deepEqual(await reader, source);

  await client.close();
  await peer.close();
  await server.close();
});
