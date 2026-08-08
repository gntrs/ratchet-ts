/**
 * Two person encrypted terminal chat over one ratchet session.
 *
 * ---------------------------------------------------------------------------
 * WIRE PROTOCOL
 * ---------------------------------------------------------------------------
 *
 * Every frame is one ratchet-ts token, delimited by cli/frame.mjs. Nothing but
 * tokens crosses the socket, so a passive observer learns a byte count and a
 * message count and nothing else: not the text, not who spoke first.
 *
 *   1. BOTH -> BOTH        invite token
 *
 *      Both ends invite, unconditionally, before reading anything. runChat is
 *      handed an already connected channel and the pinned signature carries no
 *      role flag, so there is nothing in scope that says "you are the listener".
 *      Guessing wrong deadlocks (both wait) or collides (both accept), so
 *      instead both sides speak and the tie is broken afterwards from data both
 *      of them can see.
 *
 *   2. BOTH                 leader = the lower conversation id, compared as an
 *                           ASCII hex string.
 *
 *      A conversation id is 128 random bits minted by beginInvite, so the two
 *      ids differ with overwhelming probability and both machines compute the
 *      same winner from the same two strings. The LEADER's invite survives; the
 *      follower drops its own pending and answers the leader's invite instead.
 *      Identity keys are deliberately not the tiebreak: two terminals sharing
 *      one RATCHET_HOME have identical identity keys and would deadlock.
 *
 *   3. FOLLOWER -> LEADER   accept token
 *
 *      `engine.open(identity, invite, {})` yields outcome `invite` with a reply
 *      and a session. The reply goes straight back.
 *
 *   4. LEADER               `engine.open(identity, reply, { pending })` yields
 *                            outcome `accepted`. Root key agreed on both sides.
 *
 *   5. LEADER -> FOLLOWER   sealed `{ v, t: 'ready' }`
 *
 *      Required by the ratchet, not by this protocol. acceptInvite builds a
 *      responder session with no send chain, so the follower cannot speak until
 *      the leader's first message reveals an initiator ratchet public key. One
 *      sealed frame is the cheapest way to unlock it. handshakeMs covers steps
 *      1 through 5, because until 5 lands the chat is only half duplex.
 *
 *   6. EITHER -> EITHER     sealed `{ v, t: 'msg', b: <text> }`, any order,
 *                           for as long as both ends stay up.
 *
 *   7. EITHER -> EITHER     sealed `{ v, t: 'bye' }` on /quit or Ctrl+C.
 *
 *      Best effort and never waited on. It is the difference between the peer
 *      seeing "the peer left" and the peer seeing a socket die under it.
 *
 * Sessions are immutable. Every seal and open returns a new one and the old one
 * is dead the instant it is used. Unlike a file transfer, a chat has two things
 * touching the session at once, so reassigning in place is not enough on its
 * own. See withSession below for the lock that makes it safe.
 */

import readline from 'node:readline';

import { decodeEnvelope, engine, fingerprint, formatFingerprint } from '../dist/index.js';
import { color } from './format.mjs';
import { explainError, pairWords } from './protocol.mjs';

/** Bumped only on a breaking frame change, so a mismatch is a clean refusal. */
const PROTOCOL_VERSION = 1;

/**
 * Hard ceiling imposed by the envelope, not chosen here. Every variable length
 * field in an OCX1 envelope carries a u16 length prefix and XChaCha20-Poly1305
 * adds a 16 byte tag, so one byte more than this and encodeEnvelope throws a
 * RangeError before any crypto runs. Someone pasting a novel into the prompt
 * should get a polite refusal, not a stack trace.
 */
const WIRE_MAX_PLAINTEXT = 0xffff - 16;

const PROMPT = '> ';

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

/**
 * Tokens are ASCII (base64url plus dots) and the channel carries bytes, so the
 * conversion is a plain UTF-8 encode. Doing it here rather than reaching for a
 * binary envelope keeps this file working against the channel exactly as the
 * pinned interface describes it, with no second wire format to keep in step.
 */
function toWire(token) {
  return Buffer.from(token, 'utf8');
}

/**
 * Accepts a string as well as bytes on purpose. cli/frame.mjs is mid migration
 * from newline delimited text to length prefixed binary, and a chat that only
 * works against one of the two halves is a chat that is broken for whichever
 * side of the integration lands second.
 */
function fromWire(frame) {
  if (typeof frame === 'string') return frame;
  return Buffer.isBuffer(frame) ? frame.toString('utf8') : Buffer.from(frame).toString('utf8');
}

/**
 * Same reason as fromWire: the pinned interface names receive(), the file on
 * disk today exports next(). Prefer the pinned name, fall back to the old one.
 */
async function recvFrame(channel) {
  if (typeof channel.receive === 'function') return channel.receive();
  if (typeof channel.next === 'function') return channel.next();
  throw new Error('the channel exposes neither receive() nor next()');
}

/** A closed channel mid-handshake is a distinct failure from a crypto one. */
async function expectFrame(channel, what) {
  const frame = await recvFrame(channel);
  if (frame === null || frame === undefined) {
    throw new Error(`connection closed while waiting for ${what}`);
  }
  return frame;
}

/**
 * One translation table for the whole CLI, in cli/protocol.mjs, read here in
 * its chat wording. This used to be a weaker local fallback that printed the
 * library's own terse message, so `ratchet send` explained what a
 * `replay_detected` meant and `ratchet chat` printed the bare code.
 */
function explain(err, during) {
  return explainError(err, during, 'chat');
}

function parseControl(text, what) {
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`${what} was not valid JSON, so the peer is not speaking this protocol`);
  }
  if (!body || typeof body !== 'object') {
    throw new Error(`${what} was not a JSON object, so the peer is not speaking this protocol`);
  }
  return body;
}

/**
 * Fired the instant the handshake settles, carrying the two word strings and
 * the peer identity hex, so bin/ can print the safety words at the top exactly
 * the way send and recv do and classify the peer against the same trust store.
 * A thrown or rejected callback is swallowed: a broken banner must never take
 * down a live conversation.
 *
 * pairWords is imported from cli/protocol.mjs rather than copied. This file used
 * to carry its own copy with a comment asking whoever edited either one to edit
 * both, which is a rule with no enforcement: the day the two drifted, a user
 * comparing a chat against a file transfer would have seen two different word
 * sets for one pair of identities and concluded, wrongly, that something was
 * wrong.
 */
function announce(onHandshake, peerWords, sessionWords, handshakeMs, peerHex) {
  if (typeof onHandshake !== 'function') return;
  try {
    void onHandshake({ peerWords, sessionWords, handshakeMs, peerHex });
  } catch {
    /* a broken banner must never fail a chat */
  }
}

// ---------------------------------------------------------------------------
// Terminal
// ---------------------------------------------------------------------------

function stamp() {
  const d = new Date();
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

/**
 * The input line and the message log share one screen, and the log is written
 * by a socket that does not care what the user is halfway through typing.
 *
 * The rule everything below obeys: before anything is written to the log, the
 * input line is erased from the screen; after, it is drawn again from
 * rl.line and rl.cursor, which readline has kept accurate the whole time. The
 * user's half typed message never moves and never gets eaten.
 *
 * Column arithmetic assumes single width characters. A CJK or emoji heavy line
 * that wraps will redraw one cell off, which is cosmetic and self corrects on
 * the next keystroke. Handling wide characters properly needs a width table,
 * and there are no dependencies to get one from.
 */
function makeTerminal({ input, output }) {
  const interactive = Boolean(input.isTTY && output.isTTY);
  const rl = readline.createInterface({
    input,
    output,
    prompt: interactive ? PROMPT : '',
    terminal: interactive,
  });

  // Uncoloured on purpose. readline does its own cursor arithmetic against the
  // prompt string, and an escape sequence in there is a wrong column waiting to
  // happen on any terminal that measures bytes rather than cells.
  const promptWidth = PROMPT.length;

  // A crash between setRawMode(true) and rl.close() leaves the user's shell
  // with no echo and no line editing, which is the single worst thing a
  // terminal program can do to someone. The finally block below is the real
  // fix; this is the belt to its braces, for the paths that never reach it
  // (an uncaught throw, or a process.exit from someone else's SIGINT handler).
  const restore = () => {
    try {
      if (input.isTTY && typeof input.setRawMode === 'function') input.setRawMode(false);
    } catch {
      /* the process is already going down, there is nothing better to try */
    }
  };
  process.on('exit', restore);

  function cols() {
    return output.columns && output.columns > 0 ? output.columns : 80;
  }

  /** Rows the current input occupies below its first row, and where the cursor sits in it. */
  function geometry(lineLength, cursorOffset) {
    const width = cols();
    return {
      lastRow: Math.floor((promptWidth + lineLength) / width),
      curRow: Math.floor((promptWidth + cursorOffset) / width),
      curCol: (promptWidth + cursorOffset) % width,
    };
  }

  /** Erase the whole input, wrapped rows included, leaving the cursor at its start. */
  function eraseInput(lineLength, cursorOffset) {
    const { lastRow, curRow } = geometry(lineLength, cursorOffset);
    if (lastRow > curRow) readline.moveCursor(output, 0, lastRow - curRow);
    for (let row = lastRow; row > 0; row -= 1) {
      readline.cursorTo(output, 0);
      readline.clearLine(output, 0);
      readline.moveCursor(output, 0, -1);
    }
    readline.cursorTo(output, 0);
    readline.clearLine(output, 0);
  }

  function drawInput() {
    const { lastRow, curRow, curCol } = geometry(rl.line.length, rl.cursor);
    output.write(PROMPT + rl.line);
    // Writing the line leaves the cursor at its end. Put it back where the user
    // actually is, which is only the same place when they have not moved it.
    if (curRow !== lastRow) readline.moveCursor(output, 0, curRow - lastRow);
    readline.cursorTo(output, curCol);
  }

  let closed = false;

  /** Write one log line above the prompt without disturbing the prompt. */
  function print(text) {
    if (closed || !interactive) {
      output.write(`${text}\n`);
      return;
    }
    eraseInput(rl.line.length, rl.cursor);
    output.write(`${text}\n`);
    drawInput();
  }

  /**
   * Called from the 'line' handler, where readline has already echoed the typed
   * text and moved to a fresh row. Erase what it echoed so the message can be
   * reprinted in the same shape as everything else in the log.
   */
  function consumeEcho(raw) {
    if (closed || !interactive) return;
    const { lastRow } = geometry(raw.length, raw.length);
    readline.moveCursor(output, 0, -1);
    for (let row = lastRow; row > 0; row -= 1) {
      readline.cursorTo(output, 0);
      readline.clearLine(output, 0);
      readline.moveCursor(output, 0, -1);
    }
    readline.cursorTo(output, 0);
    readline.clearLine(output, 0);
  }

  function start() {
    if (interactive) rl.prompt(true);
  }

  function close() {
    if (closed) return;
    closed = true;
    if (interactive) eraseInput(rl.line.length, rl.cursor);
    process.off('exit', restore);
    // close() takes the tty back out of raw mode and restores the cursor, which
    // is the whole reason this is not optional.
    rl.close();
    restore();
  }

  return { rl, interactive, print, consumeEcho, drawInput, start, close };
}

// ---------------------------------------------------------------------------
// Chat
// ---------------------------------------------------------------------------

/**
 * Full duplex encrypted chat over an already connected channel.
 *
 * Returns once either side leaves, the peer disconnects, or the user presses
 * Ctrl+C. Resolves rather than throws on all three: a peer hanging up is the
 * normal end of a conversation, not an error.
 */
export async function runChat({ channel, identity, stdin, stdout, onHandshake, onVerify }) {
  const input = stdin ?? process.stdin;
  const output = stdout ?? process.stdout;

  let sent = 0;
  let received = 0;
  let session = null;

  // ------------------------------------------------------------------
  // Handshake. No UI yet, so a failure here is a plain throw to the caller.
  // ------------------------------------------------------------------

  const handshakeStart = performance.now();

  const invited = await engine.invite(identity);
  // Sent before reading anything. Both ends do this, so neither can be the one
  // that waits for a first move that never comes.
  await channel.send(toWire(invited.token));

  const peerToken = fromWire(await expectFrame(channel, 'the peer invite'));
  let peerInvite;
  try {
    peerInvite = decodeEnvelope(peerToken);
  } catch (err) {
    throw new Error(explain(err, 'reading the peer invite'));
  }
  if (peerInvite.kind !== 'invite') {
    throw new Error(`expected an invite from the peer, got a ${peerInvite.kind} token`);
  }
  if (peerInvite.conversationId === invited.pending.conversationId) {
    // 128 random bits colliding means something is echoing our own frames back
    // at us, which is a loopback misconfiguration rather than a peer.
    throw new Error('the peer sent back our own conversation id, so the channel is looping traffic to itself');
  }

  const leading = invited.pending.conversationId < peerInvite.conversationId;

  if (leading) {
    // Our invite wins, so the peer is answering it right now. Its invite is
    // dropped unopened, along with the pending state behind it on that side.
    const reply = fromWire(await expectFrame(channel, 'the peer accept'));
    let accepted;
    try {
      accepted = await engine.open(identity, reply, { pending: invited.pending });
    } catch (err) {
      throw new Error(explain(err, 'opening the peer accept'));
    }
    if (accepted.outcome !== 'accepted') {
      throw new Error(`expected an accept from the peer, got ${accepted.outcome}`);
    }
    session = accepted.session;

    // completeInvite already took a DH step, so this side has a send chain and
    // the peer has none. Speak once to unlock it. See step 5 in the header.
    const ready = await engine.seal(session, JSON.stringify({ v: PROTOCOL_VERSION, t: 'ready' }));
    session = ready.session;
    await channel.send(toWire(ready.token));
  } else {
    let opened;
    try {
      opened = await engine.open(identity, peerToken, {});
    } catch (err) {
      throw new Error(explain(err, 'opening the peer invite'));
    }
    if (opened.outcome !== 'invite') {
      throw new Error(`expected an invite from the peer, got ${opened.outcome}`);
    }
    session = opened.session;
    await channel.send(toWire(opened.reply));

    const readyFrame = fromWire(await expectFrame(channel, 'the peer ready frame'));
    let readyOpen;
    try {
      readyOpen = await engine.open(identity, readyFrame, { session });
    } catch (err) {
      throw new Error(explain(err, 'opening the peer ready frame'));
    }
    if (readyOpen.outcome !== 'message') {
      throw new Error(`expected a ready frame from the peer, got ${readyOpen.outcome}`);
    }
    session = readyOpen.session;
    const body = parseControl(readyOpen.plaintext, 'the peer ready frame');
    if (body.v !== PROTOCOL_VERSION) {
      throw new Error(`the peer speaks protocol v${body.v}, this is v${PROTOCOL_VERSION}`);
    }
    if (body.t !== 'ready') {
      throw new Error(`expected a ready frame from the peer, got a ${String(body.t)} frame`);
    }
  }

  const handshakeMs = performance.now() - handshakeStart;
  const peerPrint = fingerprint(session.peer);
  const peerWords = formatFingerprint(peerPrint);
  const sessionWords = pairWords(identity, session.peer);
  announce(onHandshake, peerWords, sessionWords, handshakeMs, peerPrint.hex);

  // ------------------------------------------------------------------
  // Session lock
  // ------------------------------------------------------------------

  /**
   * Serialises every read-modify-write of `session` behind one promise chain.
   *
   * Sessions are immutable: seal and open both return a NEW session and the old
   * one is dead. Both are async, so an inbound message arriving while an
   * outbound one is being sealed would have both operations read the same
   * `session`, and whichever assignment lands second silently discards the
   * other's ratchet step. The symptom is not a crash, it is a message that
   * decrypts as replay_detected on the far end ten seconds later, which is
   * about the worst possible bug to have to chase. One chain, one owner of
   * `session` at a time, and the race cannot happen.
   *
   * The chain is kept alive across failures deliberately: a single bad frame
   * must not poison every turn that comes after it.
   */
  let lock = Promise.resolve();
  function withSession(fn) {
    const run = lock.then(fn);
    lock = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  // ------------------------------------------------------------------
  // Terminal and loop
  // ------------------------------------------------------------------

  const term = makeTerminal({ input, output });

  let ended = false;
  let settle;
  const finished = new Promise((resolve) => {
    settle = resolve;
  });
  function finish(reason) {
    if (ended) return;
    ended = true;
    settle(reason);
  }

  const you = color.cyan('you ');
  const them = color.yellow('them');

  function logLine(who, text) {
    for (const part of text.split('\n')) {
      term.print(`${color.dim(stamp())}  ${who}  ${part}`);
    }
  }

  function note(text) {
    term.print(color.dim(text));
  }

  async function sealAndSend(body) {
    const json = JSON.stringify(body);
    if (Buffer.byteLength(json, 'utf8') > WIRE_MAX_PLAINTEXT) {
      throw new Error(`message is too long for one frame, limit is about ${WIRE_MAX_PLAINTEXT} bytes`);
    }
    await withSession(async () => {
      const sealed = await engine.seal(session, json);
      session = sealed.session;
      // Inside the lock, not after it. Sealing in order and then writing out of
      // order would hand the peer messages whose numbers arrive backwards, which
      // works (the ratchet parks skipped keys) but burns skip budget for no
      // reason and makes any real ordering bug impossible to spot.
      await channel.send(toWire(sealed.token));
    });
  }

  async function sendText(text) {
    try {
      await sealAndSend({ v: PROTOCOL_VERSION, t: 'msg', b: text });
      sent += 1;
    } catch (err) {
      note(explain(err, 'sending that message failed'));
    }
  }

  // ------------------------------------------------------------------
  // /verify
  // ------------------------------------------------------------------
  //
  // THE SEAM. This is the minimum that works in today's readline chat, and the
  // TUI redesign is expected to replace the prompting around it. What must not
  // be replaced is the rule inside it: marking a peer verified asks a real
  // question and accepts only a real answer, the whole word `yes` typed on its
  // own line. There is no single keystroke anywhere in here that confirms
  // anything, Enter on an empty line cancels rather than confirms, and nothing
  // defaults to yes. A verification is a human saying they compared six words
  // out loud with another human, so it can only ever come from a human.
  //
  // runChat itself knows nothing about where a verification is stored. bin/
  // passes onVerify and owns the trust store, which keeps this file free of any
  // opinion about disk, exactly as it is free of one about the network.
  let awaitingVerify = null;

  function startVerify(label) {
    if (typeof onVerify !== 'function') {
      note('this build has nowhere to record a verification, so /verify does nothing here.');
      return;
    }
    awaitingVerify = { label: label || null };
    note('Read the six safety words aloud with the other person, on a call or in the same room.');
    note('If they read back the SAME six words, type  yes  and press enter. Anything else cancels.');
  }

  function finishVerify(answer) {
    const pending = awaitingVerify;
    awaitingVerify = null;
    if (answer !== 'yes') {
      note('not verified. nothing was recorded.');
      return;
    }
    note('verified. writing it to the peer store.');
    void Promise.resolve(onVerify({ label: pending.label }))
      .then((line) => {
        if (line) note(line);
      })
      .catch((err) => note(explain(err, 'recording that verification failed')));
  }

  /** Best effort. A peer that has already gone will not care that this failed. */
  async function sayGoodbye() {
    try {
      await sealAndSend({ v: PROTOCOL_VERSION, t: 'bye' });
    } catch {
      /* leaving is not allowed to fail */
    }
  }

  function handleLine(raw) {
    if (ended) return;
    term.consumeEcho(raw);
    const text = raw.trim();
    // Before the empty-line branch on purpose, so pressing enter on nothing
    // while a confirmation is open cancels it instead of falling through and
    // leaving it open for whatever gets typed next.
    if (awaitingVerify) {
      finishVerify(text);
      return;
    }
    if (text.length === 0) {
      // Nothing to send, but the prompt still has to come back or the screen
      // is left with no input line at all.
      if (term.interactive) term.drawInput();
      return;
    }
    if (text === '/quit' || text.startsWith('/quit ')) {
      if (term.interactive) term.drawInput();
      void sayGoodbye().then(() => finish('quit'));
      return;
    }
    if (text === '/verify' || text.startsWith('/verify ')) {
      // Everything after the command is the label, spaces and all, so a name
      // with a space in it needs no quoting from someone mid conversation.
      startVerify(text.slice('/verify'.length).trim());
      return;
    }
    // No drawInput after this one: logLine goes through print(), which already
    // redraws the prompt on its way out. Calling both leaves two prompts.
    logLine(you, text);
    void sendText(text);
  }

  async function readLoop() {
    for (;;) {
      let frame;
      try {
        frame = await recvFrame(channel);
      } catch (err) {
        if (!ended) note(`the connection dropped: ${err && err.message ? err.message : String(err)}`);
        finish('error');
        return;
      }
      if (frame === null || frame === undefined) {
        if (!ended) note('the peer disconnected');
        finish('peer-gone');
        return;
      }
      if (ended) return;

      let plaintext;
      try {
        plaintext = await withSession(async () => {
          const result = await engine.open(identity, fromWire(frame), { session });
          if (result.outcome !== 'message') {
            throw new Error(`expected a chat message, got ${result.outcome}`);
          }
          session = result.session;
          return result.plaintext;
        });
      } catch (err) {
        note(explain(err, 'that frame could not be opened'));
        // A frame that will not open means the two ratchets are out of step, and
        // every frame after it opens against the wrong chain. Stopping is the
        // honest move; carrying on would just print noise.
        finish('error');
        return;
      }

      let body;
      try {
        body = parseControl(plaintext, 'a chat frame');
      } catch (err) {
        note(err.message);
        continue;
      }
      if (body.v !== PROTOCOL_VERSION) {
        note(`ignored a frame from protocol v${String(body.v)}, this is v${PROTOCOL_VERSION}`);
        continue;
      }
      if (body.t === 'bye') {
        note('the peer left the chat');
        finish('peer-quit');
        return;
      }
      if (body.t !== 'msg' || typeof body.b !== 'string') {
        note(`ignored an unrecognised ${String(body.t)} frame`);
        continue;
      }
      received += 1;
      logLine(them, body.b);
    }
  }

  try {
    term.rl.on('line', handleLine);
    // Attached BEFORE anything can press it, and on the readline interface
    // rather than the process. readline only forwards Ctrl+C to the process
    // when nothing is listening here, and a process level handler would call
    // process.exit and skip the finally below, which is exactly how a terminal
    // gets left in raw mode.
    term.rl.on('SIGINT', () => {
      void sayGoodbye().then(() => finish('interrupt'));
    });
    // Ctrl+D, or the end of a piped script.
    term.rl.on('close', () => finish('eof'));

    // Prompt first, hint second. note() erases and redraws the input line, so
    // drawing the prompt after it would print a second one.
    term.start();
    note(
      typeof onVerify === 'function'
        ? 'connected. type a message and press enter. /verify NAME to confirm the words, /quit or Ctrl+C to leave.'
        : 'connected. type a message and press enter, /quit or Ctrl+C to leave.',
    );

    void readLoop();
    await finished;
  } finally {
    // Order matters: the terminal comes back first so that whatever the socket
    // does next cannot land on a screen that is still in raw mode.
    term.close();
    await channel.close().catch(() => {});
  }

  output.write(
    `${color.dim('chat closed')}  ${color.bold(String(sent))} sent  ${color.bold(String(received))} received\n`,
  );

  return { sent, received };
}
