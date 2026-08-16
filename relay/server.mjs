// A rendezvous relay. It introduces two sockets and then gets out of the way.
//
//   node relay/server.mjs                  port 4488, all interfaces
//   node relay/server.mjs --port 8080
//   RATCHET_RELAY_PORT=8080 node relay/server.mjs
//
// ---------------------------------------------------------------------------
// WHY THIS EXISTS
// ---------------------------------------------------------------------------
//
// Both addresses `ratchet recv` prints are private. That makes the tool work on
// one LAN, over Tailscale, or through a port forward, and nowhere else, which
// is everything social about it blocked on one missing piece. Two people on two
// home connections cannot reach each other because neither can accept an
// inbound connection, and that is not a bug in either of their routers, it is
// what carrier grade NAT is.
//
// Both ends dialling OUT to one small public host fixes it for everybody, and
// it fixes it without anybody having to configure anything, because outbound
// TCP is the one thing every network allows.
//
// ---------------------------------------------------------------------------
// WHAT THIS SERVER LEARNS, STATED PLAINLY
// ---------------------------------------------------------------------------
//
// Ciphertext, byte counts, timing, and two IP addresses. It is trusted for
// AVAILABILITY and for nothing else. It cannot read a message, cannot modify
// one without the AEAD noticing, and cannot impersonate either party, because
// the ratchet handshake is signed and the safety words are compared out of
// band. A hostile relay's whole power is to refuse service, to log who talked
// to whom and when, and to see how much was said.
//
// That last part is real metadata and this file will not pretend otherwise. If
// two IP addresses meeting at a timestamp is the thing you need to hide, a
// relay you do not run is the wrong answer and Tor or a private host is the
// right one.
//
// It never sees the rendezvous secret. The code the two people share out of
// band is hashed before it reaches the wire, so what the relay matches on is
// H(secret) and it cannot derive the secret from it. That matters because it
// means an operator who logs everything still cannot rejoin a past rendezvous
// or start a new one against somebody who is waiting.
//
// ---------------------------------------------------------------------------
// WHAT IT DELIBERATELY DOES NOT DO
// ---------------------------------------------------------------------------
//
// No accounts, no database, no persistence, no logging of payload bytes. State
// is one map of waiting sockets and it dies with the process. There is nothing
// to subpoena that is not also in a netflow log, and that is a design goal
// rather than a shortcut.
//
// No TLS. The bytes crossing it are already an authenticated ratchet envelope,
// so a TLS layer would encrypt ciphertext to a host that is not trusted to read
// it anyway. What TLS would add is hiding the rendezvous id from a network
// observer on the relay's own leg. Put it behind a terminating proxy if that
// matters to you; nothing here depends on the transport.
import net from 'node:net';
import { createHash } from 'node:crypto';

/** RTCHREL and a version. Anything else on the socket is not a client of ours. */
export const RELAY_MAGIC = Buffer.from('RTCHREL1', 'ascii');
export const RENDEZVOUS_ID_BYTES = 16;
export const HELLO_BYTES = RELAY_MAGIC.length + RENDEZVOUS_ID_BYTES;

/** Sent to both sides the moment they are introduced. One byte, then raw pipe. */
export const STATUS_PAIRED = 0x01;
/** Sent instead when the server is refusing, followed by nothing. */
export const STATUS_BUSY = 0x02;
export const STATUS_TIMEOUT = 0x03;

export const DEFAULT_PORT = 4488;

/**
 * Limits, all of them low, because this process is meant to be something you
 * can run on the smallest box a provider sells and forget about.
 *
 * The two that actually keep it alive are WAIT_MS and MAX_WAITING. A rendezvous
 * server with no wait timeout accumulates half-open pairs forever, and one with
 * no cap on how many can wait is a memory exhaustion target that costs an
 * attacker one TCP connection per slot.
 */
export const LIMITS = {
  /** How long a first arrival waits for its partner before being hung up on. */
  waitMs: 10 * 60 * 1000,
  /** How long a paired session may last, so a wedged pair cannot sit forever. */
  sessionMs: 6 * 60 * 60 * 1000,
  /** Distinct rendezvous ids that may be waiting at once. */
  maxWaiting: 1024,
  /** Sockets one IP may have in the waiting state. Slows down slot squatting. */
  maxWaitingPerIp: 16,
  /** How long a connection has to send its hello before it is dropped. */
  helloMs: 10 * 1000,
};

/**
 * The id two clients meet on, derived from the shared secret rather than being
 * the shared secret.
 *
 * This is the whole reason the relay cannot join a rendezvous it is carrying.
 * It sees this value and would need a preimage to recover the code, and the
 * code is what authorises a party to the rendezvous. Domain separated so that
 * this digest can never collide with any other use of SHA-256 in the protocol.
 *
 * Exported and used by the client too, because two implementations of a
 * derivation is how they drift.
 */
export function rendezvousId(secret) {
  const hash = createHash('sha256');
  hash.update(Buffer.from('ratchet relay rendezvous v1', 'ascii'));
  hash.update(Buffer.from(secret));
  return hash.digest().subarray(0, RENDEZVOUS_ID_BYTES);
}

/** Peer address without the ephemeral port, which is what a limit keys on. */
function ipOf(socket) {
  return socket.remoteAddress ?? 'unknown';
}

export function createRelay({ limits = LIMITS, onEvent } = {}) {
  /** rendezvous id hex -> { socket, timer, ip } waiting for a partner. */
  const waiting = new Map();
  /** ip -> count of sockets that ip has in `waiting`. */
  const waitingByIp = new Map();
  /**
   * Every socket this relay currently owns, waiting or paired.
   *
   * net.Server.close() stops accepting and then waits for existing connections
   * to end on their own, which for a relay means forever: both sides of a
   * paired session are idle by design and a waiting client is idle by
   * definition. Without this set, close() never resolves, the process will not
   * shut down on SIGTERM, and a test suite hangs with no output at all rather
   * than failing. That is exactly how this was found.
   */
  const live = new Set();
  const say = (event) => {
    if (onEvent) onEvent(event);
  };

  function releaseWaiting(key, entry) {
    waiting.delete(key);
    const n = (waitingByIp.get(entry.ip) ?? 1) - 1;
    if (n <= 0) waitingByIp.delete(entry.ip);
    else waitingByIp.set(entry.ip, n);
    clearTimeout(entry.timer);
  }

  /**
   * After this the server is a pipe and nothing else. No parsing, no framing,
   * no inspection: whatever one side writes, the other side reads. That is what
   * makes the relay transparent to every version of the wire protocol, past and
   * future, and it is why adding a relay did not require touching the envelope.
   */
  function pair(key, first, firstRest, second, secondRest) {
    const status = Buffer.of(STATUS_PAIRED);
    first.write(status);
    second.write(status);

    // Bytes that arrived in the same TCP segment as a hello. They belong to the
    // peer, so they are forwarded here, after the status byte and before the
    // pipe is attached.
    //
    // Forwarded explicitly rather than pushed back with socket.unshift(). That
    // was the first implementation and it silently dropped them: attaching a
    // 'data' listener puts the socket in flowing mode, and an unshift there
    // re-emits between the listener being removed and pipe() being attached,
    // with nobody listening. The failure surfaced much later as a handshake
    // that never completed, which is the worst possible place to find it.
    if (firstRest && firstRest.length) second.write(firstRest);
    if (secondRest && secondRest.length) first.write(secondRest);

    const started = Date.now();
    let bytes = 0;
    const count = (chunk) => {
      bytes += chunk.length;
    };
    first.on('data', count);
    second.on('data', count);

    first.pipe(second);
    second.pipe(first);

    const cap = setTimeout(() => {
      first.destroy();
      second.destroy();
    }, limits.sessionMs);

    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      clearTimeout(cap);
      first.destroy();
      second.destroy();
      say({ type: 'closed', id: key, bytes, ms: Date.now() - started });
    };
    for (const socket of [first, second]) {
      socket.once('close', finish);
      socket.once('error', finish);
    }

    say({ type: 'paired', id: key });
  }

  const server = net.createServer((socket) => {
    socket.setNoDelay(true);
    live.add(socket);
    socket.once('close', () => live.delete(socket));
    const ip = ipOf(socket);

    // Read exactly the hello and not one byte more. Anything after it belongs
    // to the peer, and consuming it here would silently eat the first frame of
    // a fast sender.
    let buffered = Buffer.alloc(0);
    let settled = false;

    const helloTimer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
    }, limits.helloMs);

    const refuse = (status) => {
      settled = true;
      clearTimeout(helloTimer);
      socket.end(Buffer.of(status));
    };

    function onData(chunk) {
      if (settled) return;
      buffered = buffered.length === 0 ? chunk : Buffer.concat([buffered, chunk]);
      if (buffered.length < HELLO_BYTES) return;

      settled = true;
      clearTimeout(helloTimer);
      socket.off('data', onData);

      if (!buffered.subarray(0, RELAY_MAGIC.length).equals(RELAY_MAGIC)) {
        socket.destroy();
        return;
      }

      const id = buffered.subarray(RELAY_MAGIC.length, HELLO_BYTES);
      const key = id.toString('hex');
      // Anything the client sent after its hello is the peer's first bytes.
      // Copied out, because `buffered` may be a view over a pooled read buffer
      // that the socket reuses before this is forwarded.
      const rest = Buffer.from(buffered.subarray(HELLO_BYTES));

      const held = waiting.get(key);
      if (held) {
        releaseWaiting(key, held);
        pair(key, held.socket, held.rest, socket, rest);
        return;
      }

      if (waiting.size >= limits.maxWaiting) {
        say({ type: 'refused', reason: 'server full' });
        refuse(STATUS_BUSY);
        return;
      }
      const perIp = waitingByIp.get(ip) ?? 0;
      if (perIp >= limits.maxWaitingPerIp) {
        say({ type: 'refused', reason: 'too many waiting from one address' });
        refuse(STATUS_BUSY);
        return;
      }

      const timer = setTimeout(() => {
        const entry = waiting.get(key);
        if (!entry || entry.socket !== socket) return;
        releaseWaiting(key, entry);
        say({ type: 'timeout', id: key });
        socket.end(Buffer.of(STATUS_TIMEOUT));
      }, limits.waitMs);
      // An unref'd timer would let the process exit with somebody waiting.
      // Keeping it referenced is deliberate: this is a server.

      const entry = { socket, timer, ip, rest };
      waiting.set(key, entry);
      waitingByIp.set(ip, perIp + 1);
      say({ type: 'waiting', id: key, waiting: waiting.size });

      const drop = () => {
        const current = waiting.get(key);
        if (current && current.socket === socket) releaseWaiting(key, current);
      };
      socket.once('close', drop);
      socket.once('error', drop);
    }

    socket.on('data', onData);
    socket.on('error', () => socket.destroy());
  });

  return {
    server,
    /** Exposed for tests and for an operator who wants a health endpoint. */
    stats: () => ({ waiting: waiting.size }),
    listen: (port, host) =>
      new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => resolve(server.address()));
      }),
    close: () =>
      new Promise((resolve) => {
        for (const [key, entry] of [...waiting]) releaseWaiting(key, entry);
        // Destroy before close, not after. close() only stops the listener; the
        // sockets are what keep the handle alive.
        for (const socket of [...live]) socket.destroy();
        live.clear();
        server.close(() => resolve());
      }),
  };
}

// Run directly rather than imported. `node relay/server.mjs`.
if (import.meta.url === `file://${process.argv[1]}`) {
  const argPort = (() => {
    const i = process.argv.indexOf('--port');
    if (i !== -1) return Number.parseInt(process.argv[i + 1] ?? '', 10);
    if (process.env.RATCHET_RELAY_PORT) return Number.parseInt(process.env.RATCHET_RELAY_PORT, 10);
    return DEFAULT_PORT;
  })();
  const port = Number.isFinite(argPort) && argPort >= 0 && argPort <= 65535 ? argPort : DEFAULT_PORT;

  const relay = createRelay({
    // Rendezvous ids only, never addresses and never bytes. An operator needs
    // to see that it is working and how much it is carrying; nobody needs a log
    // that says which two IP addresses met.
    onEvent: (event) => {
      const at = new Date().toISOString();
      if (event.type === 'closed') {
        console.log(`${at}  closed   ${event.id.slice(0, 8)}  ${event.bytes} bytes in ${event.ms} ms`);
      } else if (event.type === 'paired') {
        console.log(`${at}  paired   ${event.id.slice(0, 8)}`);
      } else if (event.type === 'waiting') {
        console.log(`${at}  waiting  ${event.id.slice(0, 8)}  (${event.waiting} in flight)`);
      } else if (event.type === 'timeout') {
        console.log(`${at}  timeout  ${event.id.slice(0, 8)}`);
      } else {
        console.log(`${at}  refused  ${event.reason}`);
      }
    },
  });

  const address = await relay.listen(port);
  console.log(`ratchet relay on ${address.address}:${address.port}`);
  console.log('it introduces two sockets and pipes them. it cannot read anything.');

  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.on(signal, async () => {
      await relay.close();
      process.exit(0);
    });
  }
}
