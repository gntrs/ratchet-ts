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

// How many bytes we let pile up unflushed in the socket before send() makes the
// caller wait. This is the memory bound on a slow peer, and it is the whole
// backpressure policy in one number.
//
// It replaces an accidental bound of 16384, Node's default
// writableHighWaterMark, which was never chosen for this transport. A payload
// chunk is 65519 plaintext bytes plus envelope plus a 4 byte prefix, so every
// single chunk frame was four times the default watermark: write() returned
// false on essentially every write and send() parked on 'drain' until the
// kernel had taken the whole frame. Measured on a 10.5 MB transfer, 160 of 163
// sender writes tripped it, and the sender therefore never sealed a chunk while
// the previous one was still moving. The comment in cli/protocol.mjs promising
// exactly that overlap was false for that reason.
//
// 1 MiB, because the bound has to satisfy three things at once:
//
//   - Bigger than one frame, or we are back where we started. The largest frame
//     this transport accepts is MAX_FRAME, but the largest one this CLI sends is
//     a sealed 64 KiB chunk, so 1 MiB clears the real traffic by 16x.
//   - Big enough to keep a fat long link busy. Bandwidth times round trip is
//     what a sender has to keep unacknowledged to avoid idling, and 1 MiB covers
//     100 Mbit/s at 80 ms, which is a relayed VPN hop between continents.
//   - Small enough that a stalled receiver is not a memory bug. A peer that
//     stops reading costs 1 MiB per channel here, plus at most one frame that
//     was already submitted when the limit was hit. That is the safety the old
//     wait-on-every-write had, kept, and it is why send() still waits rather
//     than resolving and letting the queue grow without limit.
//
// A frame larger than this bound is still allowed and still bounded: write()
// takes it, returns false, and send() waits, which is exactly the old behaviour
// for the one case it was the right behaviour for.
const WRITE_WINDOW = 1024 * 1024;

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
  // Senders parked because the socket is over WRITE_WINDOW. A list rather than
  // a per-write socket.once('drain'), because a caller is now free to keep
  // sealing while an earlier send is still parked, and a listener per in flight
  // write would both leak and trip Node's max listener warning.
  let drainWaiters = [];

  function releaseWrites() {
    if (!drainWaiters.length) return;
    const waiting = drainWaiters;
    drainWaiters = [];
    for (const w of waiting) w.resolve();
  }

  function rejectWrites(err) {
    if (!drainWaiters.length) return;
    const waiting = drainWaiters;
    drainWaiters = [];
    for (const w of waiting) w.reject(err);
  }

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
    // A write parked on 'drain' would otherwise hang forever, since a destroyed
    // socket never drains.
    rejectWrites(err);
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
  // Fires when the unflushed bytes fall back under the watermark, which is the
  // bound in WRITE_WINDOW. One listener for the life of the channel.
  socket.on('drain', releaseWrites);
  // A socket that can raise 'error' without a handler crashes the process,
  // so this listener exists purely to route failures into pending promises
  // instead of letting Node's default behavior take the process down.
  socket.on('error', (err) => fail(err));
  // A socket torn down without an 'error' still has to unpark anyone waiting on
  // a drain that is never coming. close() destroying after LINGER_MS is the
  // ordinary way to get here.
  socket.on('close', () => {
    rejectWrites(fatalError ?? new Error(`connection to ${remote} closed before the frame drained`));
  });
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

  /**
   * Put one frame on the socket.
   *
   * The bytes are handed to write() synchronously, before this function ever
   * returns, so frame order on the wire is the order send() was CALLED in, not
   * the order the returned promises are awaited in. That is what lets a caller
   * seal the next frame while this one is in flight: submit, go do CPU work,
   * await the promise before submitting the next one. Awaiting is what enforces
   * the bound, so a caller that never awaits is back to an unbounded queue.
   *
   * The promise resolves once the socket is back under WRITE_WINDOW, which on
   * anything smaller than the window is immediately.
   *
   * `prefixReserved` says the caller has already left PREFIX_BYTES of room at
   * the front of `bytes` for the length, so the prefix is written in place and
   * the frame goes out with no copy at all. The default builds the frame here,
   * which costs one allocation and one copy of the whole payload. The wire is
   * identical either way: the same four bytes then the same payload. The price
   * of the no-copy path is that the socket holds the caller's memory until the
   * returned promise resolves, so that buffer is off limits until then.
   */
  async function send(bytes, { prefixReserved = false } = {}) {
    if (fatalError) throw fatalError;
    if (socket.destroyed) throw new Error(`channel to ${remote} is closed`);
    if (!(bytes instanceof Uint8Array)) {
      // Catching this here rather than letting Buffer coerce a string means a
      // caller that missed the switch to bytes fails loudly instead of
      // shipping a UTF-8 reinterpretation of its own ciphertext.
      throw new Error('channel.send expects a Uint8Array of frame bytes');
    }
    if (prefixReserved && bytes.length < PREFIX_BYTES) {
      throw new Error(
        `channel.send was told the first ${PREFIX_BYTES} bytes are a reserved length prefix, but the frame is only ${bytes.length} bytes long`,
      );
    }
    const payloadBytes = prefixReserved ? bytes.length - PREFIX_BYTES : bytes.length;
    if (payloadBytes > MAX_FRAME) {
      throw new Error(`frame of ${payloadBytes} bytes exceeds the ${MAX_FRAME} byte limit`);
    }
    // Prefix and payload go out as one buffer, not two writes. Two writes
    // from overlapping send() calls could interleave, and a prefix followed
    // by somebody else's payload desynchronises the peer's reader forever.
    let out;
    if (prefixReserved) {
      // A view over the caller's memory, not a copy of it. Buffer.from on an
      // ArrayBuffer aliases; the writeUInt32BE lands in the caller's buffer,
      // which is the point.
      out = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.length);
    } else {
      out = Buffer.allocUnsafe(PREFIX_BYTES + bytes.length);
      out.set(bytes, PREFIX_BYTES);
    }
    out.writeUInt32BE(payloadBytes, 0);
    // false means the socket now holds at least WRITE_WINDOW unflushed bytes.
    // Resolving anyway would be the unbounded-memory growth the pinned
    // interface calls out, so we park until 'drain' says the backlog cleared.
    // The bytes are already queued in order either way.
    if (socket.write(out)) return;
    return new Promise((resolve, reject) => {
      drainWaiters.push({ resolve, reject });
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
  //
  // prefixBytes is how a caller learns what `prefixReserved` costs without
  // importing this module. cli/protocol.mjs takes its channel by injection and
  // knows nothing about the framing on purpose, so asking the channel is the
  // only way it can leave the right amount of room in front of an envelope. A
  // transport with no prefix reports 0 and the caller reserves nothing.
  return { remote, prefixBytes: PREFIX_BYTES, send, receive, next: receive, close };
}


/**
 * Dial a relay, present a rendezvous id, and hand back an ordinary channel.
 *
 * THE POINT OF THIS FUNCTION IS HOW LITTLE IT DOES. Once the relay answers with
 * its paired byte, the socket is a plain byte pipe to the other person and
 * every layer above here is unchanged: same length prefixed frames, same
 * envelopes, same handshake, same session. cli/protocol.mjs cannot tell a relay
 * channel from a direct one and is never told, which is why adding a relay
 * needed no change to the wire format and cannot weaken it.
 *
 * The relay's reply is one byte and it is read with `once`, because everything
 * after it belongs to the peer. Reading greedily here would swallow the first
 * frame of a partner who was already waiting and is therefore already sending,
 * which is the common case rather than a rare one: the second party to arrive
 * gets paired instantly.
 */
export async function connectViaRelay({ host, port, rendezvous, magic, timeoutMs = 15000, waitMs = 10 * 60 * 1000 }) {
  const socket = new net.Socket({ writableHighWaterMark: WRITE_WINDOW });
  return new Promise((resolve, reject) => {
    let settled = false;
    let timer = setTimeout(() => bail(new Error(`connect to relay ${host}:${port} timed out after ${timeoutMs}ms`)), timeoutMs);

    function bail(err) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      reject(err);
    }

    socket.once('error', (err) => bail(new Error(`relay ${host}:${port}: ${err.message}`)));

    socket.once('connect', () => {
      socket.setNoDelay(true);
      socket.write(Buffer.concat([Buffer.from(magic), Buffer.from(rendezvous)]));
      // From here the wait is for a partner, which is a person doing something,
      // so the deadline is minutes rather than seconds.
      clearTimeout(timer);
      timer = setTimeout(
        () => bail(new Error('nobody joined this pairing code in time')),
        waitMs,
      );

      const onStatus = (chunk) => {
        if (settled) return;
        const status = chunk[0];
        // Anything past the status byte is the peer already talking. Put it
        // back so the framing layer reads it as the first frame.
        if (chunk.length > 1) socket.unshift(chunk.subarray(1));
        if (status === RELAY_STATUS_PAIRED) {
          settled = true;
          clearTimeout(timer);
          resolve(makeChannel(socket, `relay ${host}:${port}`));
          return;
        }
        bail(new Error(
          status === RELAY_STATUS_BUSY
            ? 'the relay is full, try again shortly'
            : 'the relay gave up waiting for the other side',
        ));
      };

      // once, not on: exactly one byte is ours and the rest is the peer's.
      socket.once('data', onStatus);
    });

    socket.once('close', () => bail(new Error('the relay closed the connection')));
    socket.connect(port, host);
  });
}

/** Mirrors relay/server.mjs. Duplicated as two constants rather than imported,
 * because cli/frame.mjs must not depend on the server: a client installed from
 * npm has no reason to carry it. test/relay.test.mjs asserts the two agree. */
export const RELAY_STATUS_PAIRED = 0x01;
export const RELAY_STATUS_BUSY = 0x02;

export async function listen({ port = 0, host } = {}) {
  return new Promise((resolve, reject) => {
    // highWaterMark is the knob that decides when write() starts saying false,
    // and it has to be set at construction: the socket exposes it read only
    // afterwards. net.createServer applies it to every accepted socket. It
    // moves the readable side too, which this transport does not care about
    // either way, because 'data' is consumed synchronously and nothing ever
    // accumulates on that side.
    const server = net.createServer({ highWaterMark: WRITE_WINDOW });
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
    // Only the writable side here, since net.Socket takes the per-direction
    // option and the connecting side has no reason to move the other one.
    const socket = new net.Socket({ writableHighWaterMark: WRITE_WINDOW });
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

/**
 * Bytes of length prefix on every frame.
 *
 * Exported so a caller that wants the no-copy send path knows how much room to
 * leave at the front of its buffer, and so nobody has to hardcode 4 to find out.
 */
export const FRAME_PREFIX_BYTES = PREFIX_BYTES;

// Reassembly is the one part of this file that has already been got wrong
// once, and a real socket will not reproduce a prefix split across two 'data'
// events on demand. Exported so the test can drive the reader with exactly
// the chunking it wants. Not part of the CLI's interface.
export const __internal = { makeChannel, MAX_FRAME, WRITE_WINDOW };
