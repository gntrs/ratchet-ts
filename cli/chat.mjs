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
import { Writable } from 'node:stream';

import { decodeEnvelope, engine, fingerprint, formatFingerprint } from '../dist/index.js';
import { color, humanMs, words } from './format.mjs';
import { explainError, explainFailure, pairWords, wrapCrypto } from './protocol.mjs';
import {
  blankState,
  completionsFor,
  cursorPosition,
  layout,
  maxScroll,
  renderFrame,
  transcriptHeight,
} from './ui.mjs';

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
 * down a live conversation. Whatever it returns comes back to the caller, which
 * is how the screen learns the trust verdict without this file ever reading the
 * peer store: bin/ classifies, and hands the answer back through here.
 *
 * pairWords is imported from cli/protocol.mjs rather than copied. This file used
 * to carry its own copy with a comment asking whoever edited either one to edit
 * both, which is a rule with no enforcement: the day the two drifted, a user
 * comparing a chat against a file transfer would have seen two different word
 * sets for one pair of identities and concluded, wrongly, that something was
 * wrong.
 */
function announce(onHandshake, peerWords, sessionWords, handshakeMs, peerHex) {
  if (typeof onHandshake !== 'function') return null;
  try {
    return onHandshake({ peerWords, sessionWords, handshakeMs, peerHex }) ?? null;
  } catch {
    /* a broken banner must never fail a chat */
    return null;
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
// Screen
// ---------------------------------------------------------------------------

/** About 30 Hz. One frame at 80x24 is roughly 4 kB, so this is cheap. */
const FRAME_MS = 33;

/** Alternate buffer on, cursor off, autowrap off, clear, home. */
const SCREEN_ON = '\x1b[?1049h\x1b[?25l\x1b[?7l\x1b[2J\x1b[H';

/** The exact inverse, in reverse order. Autowrap and the cursor come back. */
const SCREEN_OFF = '\x1b[?7h\x1b[?25h\x1b[?1049l';

/** Newest entries kept. Old ones fall off the top so a long night stays cheap. */
const TRANSCRIPT_LIMIT = 2000;

/** What the empty input box says when nothing else has a claim on it. */
const DEFAULT_HINT = 'message, / for commands';

/** How long a wire has to be silent before the corner stops saying `live`. */
const QUIET_AFTER_S = 45;

/**
 * Whether the full screen is allowed at all.
 *
 * NO_COLOR is deliberately not in here. A terminal that wants no colour still
 * wants its screen: severity in this UI is carried by the four column speaker
 * field and by words, never by colour alone, so dropping colour loses nothing
 * and dropping the layout would lose the verification badge. RATCHET_TUI=0 is
 * the escape hatch for anyone who disagrees.
 */
function screenCapable(input, output) {
  if (process.env.RATCHET_TUI === '0') return false;
  if (!input.isTTY || !output.isTTY) return false;
  if (typeof input.setRawMode !== 'function') return false;
  if (process.env.TERM === 'dumb') return false;
  return true;
}

/**
 * The full screen view.
 *
 * Everything that decides what the screen looks like lives in cli/ui.mjs as a
 * pure function of state. This is the other half: it owns the terminal, the
 * keyboard, and a timer, and it owns no opinions about layout at all. The split
 * is what makes every screen in here testable without a terminal.
 *
 * Repaint is whole frame, throttled. There is no diffing renderer because at
 * 1920 cells there is nothing to win by it, and a diff engine is a second place
 * for the screen to be wrong.
 *
 * readline keeps its editing behaviour, including history, word erase and
 * Ctrl+U, but its output goes to a sink that discards. We read rl.line and
 * rl.cursor and draw the input row ourselves. That is the only honest way to
 * have readline's editor inside a frame we control: letting it draw would put
 * two writers on one screen.
 */
function makeScreen({ input, output, state, onSubmit, onEscape, onInterrupt, onEof }) {
  const sink = new Writable({
    write(_chunk, _enc, cb) {
      cb();
    },
  });

  const rl = readline.createInterface({
    input,
    output: sink,
    terminal: true,
    prompt: '',
    historySize: 200,
  });

  let closed = false;
  let restored = false;
  let dirty = false;
  let timer = null;
  // The last line we know readline held before a key we intercept. Tab, up and
  // down all mutate rl.line before our handler runs, and this is what puts it
  // back.
  let lastLine = '';
  let lastCursor = 0;

  function restore() {
    if (restored) return;
    restored = true;
    try {
      if (input.isTTY && typeof input.setRawMode === 'function') input.setRawMode(false);
    } catch {
      /* the tty is already gone */
    }
    try {
      output.write(SCREEN_OFF);
    } catch {
      /* nothing left to write to */
    }
  }

  // Registered before anything is drawn. A crash between here and close() still
  // gives the shell its echo back, which matters more than any error message.
  process.on('exit', restore);

  function size() {
    return {
      cols: Math.max(1, output.columns || 80),
      rows: Math.max(1, output.rows || 24),
    };
  }

  function syncLine() {
    lastLine = rl.line ?? '';
    lastCursor = rl.cursor ?? lastLine.length;
    state.input.line = lastLine;
    state.input.cursor = lastCursor;
  }

  function setLine(line, cursor) {
    rl.line = String(line);
    rl.cursor = Math.max(0, Math.min(Number(cursor) || 0, rl.line.length));
    syncLine();
  }

  function flush() {
    if (closed) return;
    dirty = false;
    const dim = size();
    const rows = renderFrame(state, dim);
    const cur = cursorPosition(state, dim);
    // Hide, home, whole frame, then place the caret. Rows are joined with a
    // carriage return and a line feed because the cursor is at the right hand
    // end of the row we just wrote and autowrap is off.
    let out = `\x1b[?25l\x1b[H${rows.join('\r\n')}`;
    out += cur ? `\x1b[${cur.row};${cur.col}H\x1b[?25h` : '';
    output.write(out);
  }

  function paint() {
    if (closed) return;
    if (timer) {
      dirty = true;
      return;
    }
    flush();
    timer = setTimeout(() => {
      timer = null;
      if (dirty) flush();
    }, FRAME_MS);
    if (typeof timer.unref === 'function') timer.unref();
  }

  /**
   * The completion list, recomputed from the line on every keystroke.
   *
   * It closes itself when the line stops being a command prefix and when the
   * line is already exactly one command, because a list with nothing left to
   * add is a list that is only taking rows away from the transcript.
   */
  function recompute() {
    const line = state.input.line;
    if (state.modal || !line.startsWith('/')) {
      state.completion = null;
      return;
    }
    const items = completionsFor(line, { alarm: state.alarm });
    if (items.length === 0 || (items.length === 1 && items[0].name === line)) {
      state.completion = null;
      return;
    }
    const key = items.map((i) => i.name).join(' ');
    const index = state.completion && state.completion.key === key ? state.completion.index : 0;
    state.completion = { items, index: Math.min(index, items.length - 1), key };
  }

  function refresh() {
    syncLine();
    recompute();
    paint();
  }

  function scrollBy(pages) {
    const dim = size();
    const plan = layout(state, dim);
    const page = Math.max(1, plan.content - 1);
    const limit = maxScroll(state, dim);
    state.scroll = Math.max(0, Math.min(state.scroll + pages * page, limit));
    if (state.scroll === 0) state.unseen = 0;
    paint();
  }

  function acceptCompletion() {
    // readline has already put a tab character in the line. Undo that first,
    // always, so a stray tab can never reach the wire.
    setLine(lastLine, lastCursor);
    const c = state.completion;
    if (c && c.items.length > 0) {
      const pick = c.items[Math.min(c.index, c.items.length - 1)];
      setLine(pick.name, pick.name.length);
      state.completion = null;
      paint();
      return;
    }
    paint();
  }

  function moveCompletion(delta) {
    // Up and down are history keys to readline, so it has already swapped the
    // line out from under us. Put it back before moving the list.
    setLine(lastLine, lastCursor);
    const c = state.completion;
    const n = c.items.length;
    c.index = (c.index + delta + n) % n;
    paint();
  }

  function onKey(_str, key) {
    if (closed || !key) return;
    // Ctrl+C arrives here and as SIGINT. The SIGINT handler owns it.
    if (key.ctrl && key.name === 'c') return;
    if (key.ctrl && key.name === 'l') {
      output.write('\x1b[2J');
      flush();
      return;
    }
    if (key.name === 'pageup') {
      scrollBy(1);
      return;
    }
    if (key.name === 'pagedown') {
      scrollBy(-1);
      return;
    }
    if (key.name === 'escape' && !key.ctrl && !key.meta) {
      if (state.completion) {
        state.completion = null;
        paint();
        return;
      }
      onEscape();
      refresh();
      return;
    }
    if (key.name === 'tab') {
      acceptCompletion();
      return;
    }
    if ((key.name === 'up' || key.name === 'down') && state.completion) {
      moveCompletion(key.name === 'up' ? -1 : 1);
      return;
    }
    refresh();
  }

  function onResize() {
    const dim = size();
    // A wider window rewraps the transcript shorter, which can put the view
    // back at the bottom without a key being pressed. If it did, the unread
    // counter has to go with it: it counts what is off screen, and nothing is.
    state.scroll = Math.min(state.scroll, maxScroll(state, dim));
    if (state.scroll === 0) state.unseen = 0;
    flush();
  }

  input.on('keypress', onKey);
  output.on('resize', onResize);
  rl.on('line', (raw) => {
    setLine('', 0);
    state.completion = null;
    onSubmit(String(raw));
  });
  rl.on('SIGINT', () => {
    onInterrupt();
  });
  rl.on('close', () => {
    if (!closed) onEof();
  });

  function append(who, text) {
    const dim = size();
    const before = transcriptHeight(state, dim.cols);
    const at = stamp();
    // One call, one stamp. A block of help or stats is a single event and
    // stamping every line of it turns a table into a fake conversation.
    String(text).split('\n').forEach((part, idx) => {
      state.transcript.push({ who, text: part, at, cont: idx > 0 });
    });
    if (state.transcript.length > TRANSCRIPT_LIMIT) {
      state.transcript.splice(0, state.transcript.length - TRANSCRIPT_LIMIT);
    }
    // Scrolled up means stay put. The view keeps its distance from the bottom
    // by absorbing exactly the rows that were added, and the footer counts what
    // arrived while the user was reading something else.
    if (state.scroll > 0) {
      const added = transcriptHeight(state, dim.cols) - before;
      state.scroll = Math.max(0, Math.min(state.scroll + added, maxScroll(state, dim)));
      if (who === 'them') state.unseen += 1;
    }
    paint();
  }

  function close() {
    if (closed) return;
    closed = true;
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
    input.removeListener('keypress', onKey);
    if (typeof output.removeListener === 'function') output.removeListener('resize', onResize);
    process.off('exit', restore);
    rl.close();
    restore();
  }

  return {
    rl,
    interactive: true,
    screen: true,
    start() {
      output.write(SCREEN_ON);
      syncLine();
      paint();
    },
    close,
    append,
    paint,
    refresh,
    setLine,
    size,
  };
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
  // The banner prints on the real scrollback, before any screen exists. What it
  // hands back is the trust store's verdict, which is the one piece of state the
  // screen cannot work out for itself and must not try to.
  const verdict = announce(onHandshake, peerWords, sessionWords, handshakeMs, peerPrint.hex);

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

  /**
   * Everything the screen will ever look at, in one object.
   *
   * cli/ui.mjs renders a frame from this and touches no I/O, so every change
   * below is "set a field, ask for a repaint". Nothing past this point writes an
   * escape sequence of its own.
   */
  const state = blankState();
  state.peerAddress = typeof channel.remote === 'string' ? channel.remote : '';
  state.sessionWords = sessionWords;
  state.peerWords = peerWords;
  state.trust = openingTrust(verdict, peerPrint.hex, peerWords);
  state.link = {
    state: 'live',
    // ML-KEM-768 was in the handshake or it was not, and nothing after the
    // handshake can change that. Two words in a corner is the whole
    // post-quantum surface in steady state, which is the correct amount of
    // attention for a fact that cannot vary.
    pq: (session.peer && session.peer.pqPublic && session.peer.pqPublic.length > 0) || false,
    quietSeconds: 0,
  };
  state.color = colourOn(output);
  state.ascii = asciiOn();

  const tui = screenCapable(input, output);
  const term = tui
    ? makeScreen({
      input,
      output,
      state,
      onSubmit: (raw) => handleLine(raw),
      onEscape: () => escapeKey(),
      onInterrupt: () => {
        void sayGoodbye().then(() => finish('interrupt'));
      },
      onEof: () => finish('eof'),
    })
    : makeTerminal({ input, output });

  let ended = false;
  let ticker = null;
  let lastHeard = Date.now();
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

  // Three severities, three shapes, and the shape is what carries the severity:
  // ` .. ` for a note, ` !  ` for a warning that stays, ` !! ` for the end. The
  // colour is a second copy of that information, never the only copy, so
  // NO_COLOR loses nothing.
  function note(text) {
    if (tui) {
      term.append('note', text);
      return;
    }
    term.print(color.dim(text));
  }

  function warn(text) {
    if (tui) {
      term.append('warn', text);
      return;
    }
    term.print(color.yellow(text));
  }

  function incoming(text) {
    if (tui) {
      term.append('them', text);
      return;
    }
    logLine(them, text);
  }

  function outgoing(text) {
    if (tui) {
      term.append('you', text);
      return;
    }
    logLine(you, text);
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

  /** The line mode reader. Untouched by the screen work, and still the fallback. */
  function handleLineClassic(raw) {
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

  // ------------------------------------------------------------------
  // Screen mode: state helpers
  // ------------------------------------------------------------------

  /**
   * The trust store's verdict, flattened into what the title bar and the strip
   * need. It classifies nothing itself: cli/peers.mjs owns that, and a second
   * opinion here would be a second thing to keep in step.
   */
  function openingTrust(v, hex, wordsOfPeer) {
    const base = {
      state: 'new', label: null, shortHex: shortKey(hex), words: wordsOfPeer, conflict: null,
    };
    if (!v || typeof v !== 'object') return base;
    const entry = v.entry ?? null;
    return {
      ...base,
      state: v.state === 'verified' || v.state === 'changed' ? v.state : 'new',
      label: entry && entry.label ? entry.label : null,
      conflict: v.conflict ?? null,
    };
  }

  function shortKey(hex) {
    return String(hex ?? '').slice(0, 16);
  }

  /**
   * The same gate cli/format.mjs uses, asked of the stream we were handed
   * rather than of process.stdout, because a test can pass a different one.
   */
  function colourOn(stream) {
    if (process.env.NO_COLOR) return false;
    if (process.env.TERM === 'dumb') return false;
    return Boolean(stream && stream.isTTY);
  }

  function asciiOn() {
    if (process.env.RATCHET_ASCII === '1') return true;
    // A Windows console left on a legacy codepage draws box characters as
    // mojibake, and mojibake in the chrome around a security decision is worse
    // than plain dashes. 65001 is UTF-8; anything else here is a guess we
    // decline to make.
    if (process.platform === 'win32' && process.env.RATCHET_ASCII !== '0') {
      const cp = process.env.RATCHET_CODEPAGE;
      if (cp && cp !== '65001') return true;
    }
    return false;
  }

  function paint() {
    if (tui) term.paint();
  }

  function closeModal() {
    state.modal = null;
    state.input.placeholder = DEFAULT_HINT;
    paint();
  }

  /** Esc: close the completion list, else close a modal, else nothing. */
  function escapeKey() {
    if (state.modal) {
      note('verification cancelled. nothing was recorded.');
      closeModal();
    }
  }

  // ------------------------------------------------------------------
  // Screen mode: /verify
  // ------------------------------------------------------------------
  //
  // Same rule as the line mode seam below it, on a bigger canvas: the whole
  // content region, a real question, and only the word `yes` typed in full
  // counts as an answer. Nothing here confirms on one keystroke and nothing
  // defaults to yes.
  function openVerify() {
    if (typeof onVerify !== 'function') {
      note('this build has nowhere to record a verification, so /verify does nothing here.');
      return;
    }
    if (state.trust.state === 'verified') {
      note(`already verified${state.trust.label ? ` as "${state.trust.label}"` : ''}. /peer shows the record.`);
      return;
    }
    state.modal = { kind: 'verify', step: 'ask' };
    state.input.placeholder = 'type yes to record it, esc to cancel';
    paint();
  }

  function verifyAnswer(text) {
    if (text !== 'yes') {
      note('not verified. nothing was recorded.');
      closeModal();
      return;
    }
    state.modal = { kind: 'verify', step: 'label' };
    state.input.placeholder = 'one word name, or enter to skip';
    paint();
  }

  function labelAnswer(text) {
    const label = text.length > 0 ? text : null;
    closeModal();
    void Promise.resolve(onVerify({ label }))
      .then((line) => {
        // The badge and the strip both read from here, so this one assignment
        // is what collapses two rows of chrome and turns the corner green.
        state.trust = { ...state.trust, state: 'verified', label };
        // And into the transcript as well, because a badge is not scrollback
        // and somebody will want to see when this happened.
        note(`verified${label ? ` as "${label}"` : ''}. ${line || ''}`.trimEnd());
        paint();
      })
      .catch((err) => warn(explain(err, 'recording that verification failed')));
  }

  // ------------------------------------------------------------------
  // Screen mode: alarms
  // ------------------------------------------------------------------

  /**
   * Everything an alarm needs, in the shape cli/ui.mjs draws.
   *
   * Two families. One means somebody may be attacking you. One means the two
   * ends do not match and the session is over anyway. They get the same red
   * region because the consequence is identical, and deliberately different
   * copy because the cause is not: a version skew dressed as an attack teaches
   * people to ignore the next real one.
   */
  const ATTACK_REASONS = new Set(['authentication_failed', 'replay_detected', 'identity_mismatch']);
  const FATAL_TITLES = {
    authentication_failed: 'that frame was not sealed by the peer you started with',
    replay_detected: 'a frame arrived that had already been used',
    identity_mismatch: 'the identity on this session changed mid conversation',
    unknown_version: 'the two ends are running different versions',
    no_session: 'there is no session left to open that frame with',
    skip_limit_exceeded: 'too many messages went missing to catch up',
    malformed_token: 'that frame was not a ratchet token',
  };

  function changedKeyAlarm() {
    const old = state.trust.conflict ?? null;
    const oldName = old && old.label ? ` as "${old.label}"` : '';
    return {
      kind: 'changed',
      title: `the key at ${state.peerAddress || 'this address'} is not the one you verified`,
      body: [
        { kind: 'words', label: `you verified${oldName}`, words: old ? old.words : '', hex: shortKey(old ? old.hex : '') },
        { kind: 'words', label: 'answering now', words: peerWords, hex: shortKey(peerPrint.hex) },
        { kind: 'blank' },
        {
          kind: 'red',
          text: 'Anything already sent in this session went to the NEW key. Assume whoever holds that key has read it.',
        },
        { kind: 'blank' },
        {
          kind: 'text',
          // Two rows, because at 80x24 a third one is the row that pushes the
          // way out of this panel off the bottom of the screen.
          text: 'A peer who reinstalled looks exactly like a stranger in the middle. Ask them, on a call or in person, whether their key changed.',
        },
      ],
      reason: 'peer_key_changed',
      actions: [
        { name: '/trust new', desc: 'accept this key going forward. it stays UNVERIFIED until you /verify it.' },
        { name: '/quit', desc: 'leave now and send nothing more.' },
      ],
    };
  }

  function cryptoAlarm(err, during) {
    const wrapped = wrapCrypto(err, during, 'chat');
    const reason = wrapped && wrapped.reason ? wrapped.reason : null;
    const attack = ATTACK_REASONS.has(reason);
    const body = [
      { kind: 'text', text: (reason && explainFailure(reason, 'chat')) || (wrapped ? wrapped.message : String(err)) },
      { kind: 'blank' },
    ];
    if (attack) {
      body.push({
        kind: 'red',
        text: 'Everything you sent in this session was encrypted to whatever key answered it. If that was not your peer, treat this window as read.',
      });
    } else {
      body.push({
        kind: 'text',
        text: 'This reads as two ends that do not match rather than someone in the middle. It is still over: the ratchet cannot be put back in step, and no further message can be sent or received on this session.',
      });
    }
    return {
      kind: 'fatal',
      title: FATAL_TITLES[reason] || 'this session cannot continue',
      body,
      reason: reason || 'unknown',
      actions: [{ name: '/quit', desc: 'leave and close the socket.' }],
    };
  }

  /**
   * Raise it, or print it. Line mode gets the same words in the same order
   * down the scrollback, because the fallback is not allowed to know less.
   */
  function raiseAlarm(alarm) {
    if (!tui) {
      term.print(color.bold(color.red(`!! ${alarm.title}`)));
      for (const block of alarm.body) {
        if (block.kind === 'words') term.print(`   ${color.dim(block.label)}  ${words(block.words)}  ${color.dim(block.hex)}`);
        else if (block.kind === 'red') term.print(color.red(`   ${block.text}`));
        else if (block.kind === 'text') term.print(color.dim(`   ${block.text}`));
      }
      term.print(color.dim(`   reason code  ${alarm.reason}`));
      for (const act of alarm.actions) term.print(`   ${color.bold(act.name)}  ${color.dim(act.desc)}`);
      return;
    }
    state.alarm = alarm;
    state.modal = null;
    state.completion = null;
    state.input.placeholder = alarm.kind === 'changed' ? 'type /trust new or /quit' : 'type /quit to leave';
    paint();
  }

  /**
   * `/trust new` records the key and drops straight back to unverified.
   *
   * Trusting a change is not the same act as verifying an identity and must
   * never be collapsed into it: all this says is "stop shouting, I know". The
   * six words still have to be read out loud before that badge goes green.
   */
  function trustNew() {
    state.alarm = null;
    state.trust = { ...state.trust, state: 'new', label: null, conflict: null };
    state.input.placeholder = DEFAULT_HINT;
    warn('the new key is accepted for this session and is NOT verified. /verify when you have compared the words aloud.');
    paint();
  }

  // ------------------------------------------------------------------
  // Screen mode: commands
  // ------------------------------------------------------------------
  //
  // Every one of these prints into the transcript rather than onto a panel,
  // so the answer is in scrollback where it can be scrolled back to and, in
  // line mode, copied.

  function cmdPeer() {
    const t = state.trust;
    const seen = t.state === 'verified'
      ? `verified${t.label ? ` as "${t.label}"` : ''}`
      : 'not verified. compare the words aloud, then /verify.';
    note([
      'peer',
      `   words     ${peerWords}`,
      `   key       ${peerPrint.hex}`,
      `   address   ${state.peerAddress || 'unknown'}`,
      `   trust     ${seen}`,
    ].join('\n'));
  }

  function cmdWords() {
    note([
      'compare these aloud, not through this chat',
      `   session   ${sessionWords}`,
      `   peer      ${peerWords}`,
    ].join('\n'));
  }

  function cmdStats() {
    note([
      'session',
      `   sent      ${sent}`,
      `   received  ${received}`,
      `   handshake ${humanMs(handshakeMs)}`,
      `   keys      X25519 + ML-KEM-768`,
      `   peer      ${state.peerAddress || 'unknown'}`,
    ].join('\n'));
  }

  function cmdHelp() {
    note([
      'commands',
      '   /verify   compare the six words and record this peer',
      '   /peer     who is on the other end',
      '   /words    reprint both word lines into the transcript',
      '   /stats    counts and handshake timing',
      '   /help     this',
      '   /quit     send bye and leave',
      'keys',
      '   Enter send   Ctrl+U clear the line   Tab accept a completion',
      '   PgUp / PgDn scroll   Ctrl+L repaint   Ctrl+C leave',
    ].join('\n'));
  }

  /**
   * The screen mode reader.
   *
   * An unknown /command is never sent. A chat client that transmits your
   * typo'd command is a chat client that leaks, and `/verfy 1234` on the wire
   * is the kind of leak nobody notices until it is in someone else's log.
   */
  function handleLineScreen(raw) {
    if (ended) return;
    const text = String(raw).trim();

    if (state.modal) {
      if (state.modal.step === 'label') labelAnswer(text);
      else verifyAnswer(text);
      return;
    }

    if (state.alarm) {
      // Only two typed-in-full commands get through here. Everything else,
      // including Enter on an empty line, leaves the panel exactly where it is.
      if (text === '/quit') {
        void sayGoodbye().then(() => finish('quit'));
        return;
      }
      if (text === '/trust new' && state.alarm.kind === 'changed') {
        trustNew();
        return;
      }
      paint();
      return;
    }

    if (text.length === 0) {
      paint();
      return;
    }

    if (text.startsWith('/')) {
      const name = text.split(/\s+/)[0];
      const rest = text.slice(name.length).trim();
      if (name === '/quit') {
        void sayGoodbye().then(() => finish('quit'));
        return;
      }
      if (name === '/verify') {
        if (rest.length > 0) note('the label is asked for after the words match, so /verify takes no argument here.');
        openVerify();
        return;
      }
      if (name === '/peer') { cmdPeer(); return; }
      if (name === '/words') { cmdWords(); return; }
      if (name === '/stats') { cmdStats(); return; }
      if (name === '/help') { cmdHelp(); return; }
      note(`no command ${name}. try /help.`);
      return;
    }

    outgoing(text);
    void sendText(text);
  }

  function handleLine(raw) {
    if (tui) handleLineScreen(raw);
    else handleLineClassic(raw);
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
      lastHeard = Date.now();

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
        // A frame that will not open means the two ratchets are out of step, and
        // every frame after it opens against the wrong chain. Stopping is the
        // honest move; carrying on would just print noise.
        //
        // On a screen this is an alarm rather than a line, and the session is
        // held open with the panel up so the reason code can be read and
        // copied. In line mode the reason lands in the scrollback and the
        // process ends exactly as it did before.
        if (tui) {
          state.link = { ...state.link, state: 'closed' };
          raiseAlarm(cryptoAlarm(err, 'that frame could not be opened'));
          return;
        }
        note(explain(err, 'that frame could not be opened'));
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
      incoming(body.b);
    }
  }

  try {
    if (!tui) {
      term.rl.on('line', handleLine);
      // Attached BEFORE anything can press it, and on the readline interface
      // rather than the process. readline only forwards Ctrl+C to the process
      // when nothing is listening here, and a process level handler would call
      // process.exit and skip the finally below, which is exactly how a terminal
      // gets left in raw mode. makeScreen wires the same three itself.
      term.rl.on('SIGINT', () => {
        void sayGoodbye().then(() => finish('interrupt'));
      });
      // Ctrl+D, or the end of a piped script.
      term.rl.on('close', () => finish('eof'));
    }

    // Prompt first, hint second. note() erases and redraws the input line, so
    // drawing the prompt after it would print a second one.
    term.start();
    if (tui) {
      if (state.trust.state === 'changed') raiseAlarm(changedKeyAlarm());
      else note('connected. /help for commands and keys.');
      // One second is enough for a corner that only ever counts minutes, and
      // it is unref'd so a chat that is otherwise done can still exit.
      ticker = setInterval(() => {
        if (ended || state.link.state === 'closed') return;
        const idle = Math.floor((Date.now() - lastHeard) / 1000);
        const next = idle >= QUIET_AFTER_S ? 'quiet' : 'live';
        if (next === state.link.state && idle === state.link.quietSeconds) return;
        const was = state.link;
        state.link = { ...was, state: next, quietSeconds: idle };
        // Only when the corner would actually read differently. The token is
        // seconds under a minute and minutes above it, so an all night chat
        // repaints once a minute rather than once a second.
        if (next !== was.state || idle < 60 || idle % 60 === 0) paint();
      }, 1000);
      if (typeof ticker.unref === 'function') ticker.unref();
    } else {
      note(
        typeof onVerify === 'function'
          ? 'connected. type a message and press enter. /verify NAME to confirm the words, /quit or Ctrl+C to leave.'
          : 'connected. type a message and press enter, /quit or Ctrl+C to leave.',
      );
    }

    void readLoop();
    await finished;
  } finally {
    if (ticker) clearInterval(ticker);
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
