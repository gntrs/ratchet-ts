// Length prefixed binary frame transport over node:net.
//
// The wire is [u32 big endian payload length][payload bytes], repeated. It
// used to be one base64 token per line, which was easy to read in a hexdump
// and cost 33% of every byte on the wire plus an encode and a decode on each
// side. A length prefix carries arbitrary bytes, so payloads travel raw.
//
// Big endian because that is what every other length prefixed protocol on a
// socket uses, and a hexdump of the first four bytes should read as the size
// left to right without mental byte swapping.
import net from 'node:net';

// A hostile or buggy peer could otherwise name any size it likes and make us
// allocate for it. 8 MiB is generous for a chunked payload frame and small
// enough that a runaway sender fails fast instead of eating memory.
const MAX_FRAME = 8 * 1024 * 1024;

// Bytes of length prefix in front of every payload.
const PREFIX_BYTES = 4;

// A peer that accepts the connection and then says nothing would otherwise
// park a read forever, which is exactly what happens when you aim a sender at
// an echo server or an idle port. Two leashes, because the two situations are
// not equally suspicious: a peer that has never framed anything at us is
// probably not speaking this protocol at all, while a peer that already has
// earns patience, since a slow link can go quiet between the last payload
// chunk and the acknowledgement that follows it.
const FIRST_FRAME_TIMEOUT_MS = 20000;
const IDLE_TIMEOUT_MS = 120000;
// Cap on how long close() waits for the peer to answer our FIN before we stop
// being polite, so shutdown can never be the thing that hangs.
const LINGER_MS = 5000;

const EMPTY = Buffer.alloc(0);

// Shared by both listen() and connect() because a Channel means the same
// thing on either side of the socket: framed reads, backpressured writes,
// one error path, one shutdown path.
function makeChannel(socket, remote) {
  // Chunks are small and latency bound (handshake round trips, chunked
  // payload frames); Nagle batching would add a stall on every one of them.
  socket.setNoDelay(true);

  let frameQueue = [];
  // At most one receive() is ever in flight at a time in practice, but there
  // is no reason to assume the caller won't overlap calls, so treat waiter as
  // a single slot rather than pretending it can't happen.
  let waiter = null; // { resolve, reject } | null
  // Unconsumed bytes, kept as the chunks TCP handed us. Concatenating on
  // every 'data' event instead would recopy the whole partial frame each
  // time, which turns one 8 MiB frame into quadratic memcpy.
  let pendingChunks = [];
  let pendingSize = 0;
  let ended = false;
  let fatalError = null;
  let closePromise = null;
  let sawFrame = false;
  let idleTimer = null;

  function disarmIdle() {
    if (idleTimer) {
      clearTimeout(idleTimer);
      idleTimer = null;
    }
  }

  function armIdle() {
    disarmIdle();
    if (!waiter) return;
    const ms = sawFrame ? IDLE_TIMEOUT_MS : FIRST_FRAME_TIMEOUT_MS;
    idleTimer = setTimeout(() => {
      idleTimer = null;
      fail(new Error(
        sawFrame
          ? `no data from ${remote} for ${Math.round(ms / 1000)}s, giving up`
          : `${remote} accepted the connection but sent nothing for ${Math.round(ms / 1000)}s, so it is probably not a ratchet peer`,
      ));
    }, ms);
    // A pending read must never be the only thing keeping the process alive
    // once we have decided to stop waiting for this peer.
    if (typeof idleTimer.unref === 'function') idleTimer.unref();
  }

  function emitFrame(frame) {
    // Once the peer has framed anything at us it has proved it speaks this
    // protocol, so subsequent waits get the longer leash.
    sawFrame = true;
    if (waiter) {
      const w = waiter;
      waiter = null;
      disarmIdle();
      w.resolve(frame);
    } else {
      frameQueue.push(frame);
    }
  }

  function fail(err) {
    // First failure wins; a destroyed socket can still raise a follow up
    // 'error' and we don't want that to clobber the real cause.
    if (fatalError) return;
    fatalError = err;
    disarmIdle();
    if (waiter) {
      const w = waiter;
      waiter = null;
      w.reject(err);
    }
    socket.destroy();
  }

  // Read the length prefix without consuming it. The prefix is four bytes and
  // TCP is free to split them across two 'data' events, so this walks the
  // chunk list instead of assuming the first chunk holds all four.
  function peekLength() {
    const head = pendingChunks[0];
    if (head.length >= PREFIX_BYTES) return head.readUInt32BE(0);
    let value = 0;
    let need = PREFIX_BYTES;
    let ci = 0;
    let oi = 0;
    while (need > 0) {
      const chunk = pendingChunks[ci];
      if (oi >= chunk.length) {
        ci += 1;
        oi = 0;
        continue;
      }
      // Multiply rather than shift: << is a signed 32 bit operation, so a top
      // byte of 0x80 or higher would come back negative and defeat the cap.
      value = value * 256 + chunk[oi];
      oi += 1;
      need -= 1;
    }
    return value;
  }

  // Consume exactly n bytes off the front of the chunk list. The caller has
  // already checked that n bytes are there.
  function takeFront(n) {
    if (n === 0) return EMPTY;
    const head = pendingChunks[0];
    if (head.length === n) {
      pendingChunks.shift();
      pendingSize -= n;
      return head;
    }
    if (head.length > n) {
      // The common case: one 'data' event held the whole frame and more. A
      // view costs nothing and the frame is consumed immediately.
      const out = head.subarray(0, n);
      pendingChunks[0] = head.subarray(n);
      pendingSize -= n;
      return out;
    }
    const out = Buffer.allocUnsafe(n);
    let off = 0;
    while (off < n) {
      const chunk = pendingChunks[0];
      const take = Math.min(chunk.length, n - off);
      chunk.copy(out, off, 0, take);
      if (take === chunk.length) pendingChunks.shift();
      else pendingChunks[0] = chunk.subarray(take);
      off += take;
    }
    pendingSize -= n;
    return out;
  }

  function onData(chunk) {
    // A chunk can still land after fail() destroyed the socket; parsing it
    // would resolve reads on a channel we have already declared dead.
    if (fatalError) return;
    pendingChunks.push(chunk);
    pendingSize += chunk.length;
    // One event can carry a fragment of a frame, several whole frames, or
    // several whole frames plus a fragment. Loop until what is left is short.
    for (;;) {
      if (pendingSize < PREFIX_BYTES) return;
      const len = peekLength();
      // Never trust the prefix. Refusing before takeFront is what keeps a
      // peer from making us allocate whatever number it felt like sending.
      if (len > MAX_FRAME) {
        fail(new Error(`frame of ${len} bytes from ${remote} exceeds the ${MAX_FRAME} byte limit`));
        return;
      }
      if (pendingSize < PREFIX_BYTES + len) return;
      takeFront(PREFIX_BYTES);
      emitFrame(takeFront(len));
    }
  }

  socket.on('data', onData);
  // A socket that can raise 'error' without a handler crashes the process,
  // so this listener exists purely to route failures into pending promises
  // instead of letting Node's default behavior take the process down.
  socket.on('error', (err) => fail(err));
  socket.on('end', () => {
    ended = true;
    disarmIdle();
    if (waiter) {
      const w = waiter;
      waiter = null;
      if (pendingSize > 0) {
        const err = new Error(`connection from ${remote} closed with a truncated frame`);
        fatalError = err;
        w.reject(err);
      } else {
        w.resolve(null);
      }
    }
  });

  /** Next whole frame as bytes, or null once the peer closed cleanly. */
  async function receive() {
    if (frameQueue.length) return frameQueue.shift();
    if (fatalError) throw fatalError;
    if (ended) {
      if (pendingSize > 0) {
        // The peer went away mid frame. Returning null here would look like
        // a clean close to the caller, which is a lie worth throwing over.
        const err = new Error(`connection from ${remote} closed with a truncated frame`);
        fatalError = err;
        throw err;
      }
      return null;
    }
    return new Promise((resolve, reject) => {
      waiter = { resolve, reject };
      // Armed only while somebody is actually blocked on a read. A channel
      // sitting idle between transfers is not a stalled one, so the clock
      // starts here and not when the socket goes quiet.
      armIdle();
    });
  }

  async function send(bytes) {
    if (fatalError) throw fatalError;
    if (socket.destroyed) throw new Error(`channel to ${remote} is closed`);
    if (!(bytes instanceof Uint8Array)) {
      // Catching this here rather than letting Buffer coerce a string means a
      // caller that missed the switch to bytes fails loudly instead of
      // shipping a UTF-8 reinterpretation of its own ciphertext.
      throw new Error('channel.send expects a Uint8Array of frame bytes');
    }
    if (bytes.length > MAX_FRAME) {
      throw new Error(`frame of ${bytes.length} bytes exceeds the ${MAX_FRAME} byte limit`);
    }
    // Prefix and payload go out as one buffer, not two writes. Two writes
    // from overlapping send() calls could interleave, and a prefix followed
    // by somebody else's payload desynchronises the peer's reader forever.
    const out = Buffer.allocUnsafe(PREFIX_BYTES + bytes.length);
    out.writeUInt32BE(bytes.length, 0);
    out.set(bytes, PREFIX_BYTES);
    return new Promise((resolve, reject) => {
      function onError(err) {
        socket.off('error', onError);
        reject(err);
      }
      socket.once('error', onError);
      // write() returning false means the kernel buffer is full; resolving
      // anyway here is exactly the unbounded-memory growth the pinned
      // interface calls out, so we wait for 'drain' instead.
      const flushed = socket.write(out);
      if (flushed) {
        socket.off('error', onError);
        resolve();
      } else {
        socket.once('drain', () => {
          socket.off('error', onError);
          resolve();
        });
      }
    });
  }

  function close() {
    disarmIdle();
    if (!closePromise) {
      closePromise = new Promise((resolve) => {
        if (socket.destroyed) {
          resolve();
          return;
        }
        // A peer that never answers our FIN must not hold the process open.
        const linger = setTimeout(() => socket.destroy(), LINGER_MS);
        if (typeof linger.unref === 'function') linger.unref();
        socket.once('close', () => clearTimeout(linger));
        // end() sends our FIN and lets the peer's remaining frames still
        // arrive; 'close' only fires once the handle is fully torn down,
        // which is what "resolves after the socket is fully destroyed" means.
        socket.once('close', () => resolve());
        socket.end();
      });
    }
    return closePromise;
  }

  // next is the name the CLI has always called; receive is the name the
  // binary transport is specified under. Same function, so a mixed set of
  // callers during the switch cannot end up reading two different queues.
  return { remote, send, receive, next: receive, close };
}

export async function listen({ port = 0, host } = {}) {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    const pendingChannels = [];
    const pendingPulls = [];
    const CLOSED = Symbol('frame-server-closed');
    let closed = false;
    let closePromise = null;
    let bound = false;

    server.on('connection', (socket) => {
      const remote = `${socket.remoteAddress}:${socket.remotePort}`;
      const channel = makeChannel(socket, remote);
      // A connection that lands before the consumer calls next() on the
      // iterator must not be dropped, so it waits in a queue either way.
      if (pendingPulls.length) {
        pendingPulls.shift()(channel);
      } else {
        pendingChannels.push(channel);
      }
    });

    server.on('error', (err) => {
      if (!bound) reject(err);
    });

    server.listen(port, host, () => {
      bound = true;
      const addr = server.address();

      async function* channels() {
        for (;;) {
          if (pendingChannels.length) {
            yield pendingChannels.shift();
            continue;
          }
          if (closed) return;
          const next = await new Promise((res) => pendingPulls.push(res));
          if (next === CLOSED) return;
          yield next;
        }
      }

      function close() {
        if (!closePromise) {
          closePromise = new Promise((resolve) => {
            closed = true;
            while (pendingPulls.length) pendingPulls.shift()(CLOSED);
            // Nobody is ever going to pull these now; leaking the sockets
            // would just be a slower way of leaking memory.
            while (pendingChannels.length) pendingChannels.shift().close();
            server.close(() => resolve());
          });
        }
        return closePromise;
      }

      resolve({
        port: addr.port,
        close,
        [Symbol.asyncIterator]: channels,
      });
    });
  });
}

export async function connect({ host, port, timeoutMs = 10000 } = {}) {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(new Error(`connect to ${host}:${port} timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    function cleanup() {
      clearTimeout(timer);
      socket.off('error', onError);
      socket.off('connect', onConnect);
    }

    function onError(err) {
      if (settled) return;
      settled = true;
      cleanup();
      socket.destroy();
      reject(new Error(`connect to ${host}:${port} failed: ${err.message}`));
    }

    function onConnect() {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(makeChannel(socket, `${socket.remoteAddress}:${socket.remotePort}`));
    }

    socket.once('error', onError);
    socket.once('connect', onConnect);
    socket.connect(port, host);
  });
}

// Reassembly is the one part of this file that has already been got wrong
// once, and a real socket will not reproduce a prefix split across two 'data'
// events on demand. Exported so the test can drive the reader with exactly
// the chunking it wants. Not part of the CLI's interface.
export const __internal = { makeChannel, MAX_FRAME };
