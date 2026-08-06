// Newline delimited frame transport over node:net.
//
// ratchet-ts tokens are ASCII (base64url plus dots), so a bare newline is a
// safe delimiter, no escaping needed. The wire format is intentionally dumb:
// one frame per line, UTF-8, nothing else.
import net from 'node:net';

// A hostile or buggy peer that never sends a newline would otherwise make us
// buffer without bound. 8 MiB is generous for a chunked payload frame and
// small enough that a runaway sender fails fast instead of eating memory.
const MAX_FRAME = 8 * 1024 * 1024;

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

// Shared by both listen() and connect() because a Channel means the same
// thing on either side of the socket: framed reads, backpressured writes,
// one error path, one shutdown path.
function makeChannel(socket, remote) {
  // Chunks are small and latency bound (handshake round trips, chunked
  // payload frames); Nagle batching would add a stall on every one of them.
  socket.setNoDelay(true);

  let frameQueue = [];
  // At most one next() is ever in flight at a time in practice, but there is
  // no reason to assume the caller won't overlap calls, so treat waiter as a
  // single slot rather than pretending it can't happen.
  let waiter = null; // { resolve, reject } | null
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

  function onData(chunk) {
    let start = 0;
    for (;;) {
      const idx = chunk.indexOf(10, start); // '\n'
      if (idx === -1) {
        const rest = chunk.subarray(start);
        if (rest.length) {
          // This fragment has no terminator yet; it must be kept, not just
          // counted, or the bytes vanish the moment the frame completes in
          // a later chunk.
          pendingChunks.push(rest);
          pendingSize += rest.length;
          if (pendingSize > MAX_FRAME) {
            fail(new Error(`frame exceeds ${MAX_FRAME} byte limit from ${remote}`));
          }
        }
        return;
      }
      const piece = chunk.subarray(start, idx);
      pendingSize += piece.length;
      if (pendingSize > MAX_FRAME) {
        fail(new Error(`frame exceeds ${MAX_FRAME} byte limit from ${remote}`));
        return;
      }
      pendingChunks.push(piece);
      const frameBuf = pendingChunks.length === 1 ? pendingChunks[0] : Buffer.concat(pendingChunks, pendingSize);
      pendingChunks = [];
      pendingSize = 0;
      emitFrame(frameBuf.toString('utf8'));
      start = idx + 1;
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

  async function next() {
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

  async function send(line) {
    if (fatalError) throw fatalError;
    if (socket.destroyed) throw new Error(`channel to ${remote} is closed`);
    return new Promise((resolve, reject) => {
      function onError(err) {
        socket.off('error', onError);
        reject(err);
      }
      socket.once('error', onError);
      // write() returning false means the kernel buffer is full; resolving
      // anyway here is exactly the unbounded-memory growth the pinned
      // interface calls out, so we wait for 'drain' instead.
      const flushed = socket.write(line + '\n', 'utf8');
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

  return { remote, send, next, close };
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
