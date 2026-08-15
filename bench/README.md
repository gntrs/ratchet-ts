# bench

Two scripts. They report the same way on purpose: median of several runs, a
spread column, and a header line naming the machine.

```
npm run bench          # primitives: keygen, handshake, seal, open
npm run bench:wire     # the wire: bytes, AEAD backends, handshake split
npm run bench:machine  # one publishable row for the charts, takes a few minutes
```

The first two take `--runs N`; `bench:machine` takes `--rounds N`. One run is
already a median over many operations. Repeating the whole run catches the other
kind of noise, the machine that is quiet for two seconds and busy for the next
two. Spread is the gap between the fastest and slowest run as a share of the
median. Under 10 percent the machine was quiet. Over 25 percent something else
was using the CPU and the numbers are worth less.

`bench/machine.mjs` is the one to run if you want to add your machine to the
charts in the README, and it is the only one whose output is meant to be
published next to somebody else's. It costs a few minutes rather than a few
seconds, and it spends them on the things that turned out to matter: a 25 second
sustained warmup, an idle gap and a re-warm burst between phases, and a median of
per-round p50 rather than one long distribution. It prints a row you paste
straight into `bench/charts/generate.mjs`, and it refuses to recommend the run if
the spread says the machine was busy. Before it existed, the method behind the
published row lived only as a sentence in the README, which meant the one number
presented as reproducible was the one nobody could reproduce.

`bench/bench.mjs` is the older script and it times primitives in isolation.
`bench/wire.mjs` is this document's subject. It runs a real transfer over a real
loopback socket, in one process, with a TCP relay in the middle that counts
bytes as they pass. Nothing needs a second machine and nothing needs a manual
step.

---

## The 0.3.2 correction: the numbers below were measuring a dead path

Read this before anything else in this file, including the parts that used to
be the confident parts.

**Every throughput number published in this document before 0.3.2 was measured
against a code path `cli/protocol.mjs` stopped using in 0.3.1.** The correction
is roughly a factor of ten. The old numbers are still here, marked, because
deleting them would hide the mistake rather than fix it.

What happened. `bench/wire.mjs` did not call the CLI. It carried its own copy of
the CLI's frame sequence, and a comment at the top of section 1 said so and
called it a deliberate choice: the copy meant the benchmark kept running while
`cli/protocol.mjs` was mid refactor. Then 0.3.1 moved the CLI's payload path off
`engine.sealBytes` and `engine.openBytes` and onto
`engine.sealToEnvelopeBytes` and `engine.openFromEnvelopeBytes`. The copy never
got the change. For two releases the benchmark base64url encoded a 65535 byte
ciphertext into an 87532 character token and parsed it straight back out, per
frame, at both ends, and reported the result as the library's throughput. The
tell was in plain sight and nobody looked at it: the copy declared
`PROTOCOL_VERSION = 1` while `cli/protocol.mjs` had been on `2` since the binary
frame format landed.

How big the error was, isolated. Both paths driven over the same sockets, in the
same process, against one unchanged build, so nothing else can be moving:

| payload | token path, what the bench measured | bytes path, what the CLI ran | correction |
|---|---|---|---|
| 1.0 MB | 4.49 MB/s | 23.86 MB/s | 5.3x |
| 10.5 MB | 4.37 MB/s | 47.74 MB/s | 10.9x |

The library did not get faster. The benchmark stopped charging it for work it
does not do.

### Two effects, held apart

Independently of the above, `src` got faster in the same window: a native
`node:crypto` X25519 backend, a base64url fast path in `src/bytes.ts`, and two
allocation removals in the decode path. Those are real and they are somebody
else's result, so this file does not fold them into the correction. Same
isolation harness, all four cells, 10.5 MB payload, medians of five:

| | token path | bytes path |
|---|---|---|
| src at the 0.3.2 tag | 4.37 MB/s | 47.74 MB/s |
| src with those changes | 31.13 MB/s | 74.24 MB/s |

Read it column by column, not diagonally. **The benchmark fix is the row move:
4.37 to 47.74, about eleven times.** The `src` work is the column move on the
path that actually ships: 47.74 to 74.24, about 1.6 times. The diagonal, 4.37 to
74.24, is about seventeen times and it is the number to never quote, because it
credits one change with the other's win. That mistake is the same shape as the
one this correction exists to undo.

The `src` work also flatters the token path far more than the real one, 4.37 to
31.13, because a base64url fast path mostly speeds up base64url. Another reason
the old measurement was worse than useless: it was sensitive to work the product
does not perform.

### What changed in the script

- It calls `sendPayload` and `receivePayload` from `cli/protocol.mjs` instead of
  copying them. There is no second implementation left to drift.
- `PROTOCOL_VERSION` and `DEFAULT_CHUNK_BYTES` are imported, not restated.
- A new section 0 prints the guards before any number: the frame sequence and
  kinds the CLI produced, three independent counts of the same wire bytes
  agreeing, and the two seal paths interoperating. If section 0 says FAIL, no
  table under it is worth reading.
- The `transcode ms` column is gone rather than left reading zero. See below.

### What is still stale in this document

The **Measured output** section further down was captured before all of this.
Its section 5 table in particular was taken before the base64url fast path
landed, so its token codec figures are several times too slow to describe the
current build, and its `sender crypto` figure of 21.28 ms is the old copy's
clock, which included base64 the CLI was not doing. It is left in place as a
record of what was published. Re-run the script for current numbers; do not
quote that block.

---

## The one thing to read first

**Only the crypto columns say anything about this library.**

Every throughput number in this benchmark is a property of the transport it was
measured on. On loopback that transport is a memory copy, so the MB/s figures
are large and meaningless as a claim about ratchet-ts. Over a relay the same
figures are small and equally meaningless. The library did not change between
those two measurements. The network did.

The columns that survive a change of network:

| column | what it measures |
|---|---|
| bytes on the wire | protocol. Same on any link. |
| overhead, overhead % | protocol. Same on any link. |
| chunks | protocol. Same on any link. |
| crypto ms | this CPU running this library. Moves with hardware, not with the network. |
| AEAD MB/s | this CPU running one primitive. Moves with hardware, not with the network. |
| token versus bytes ms | this CPU running one codec. Moves with hardware, not with the network. |
| wall ms, MB/s, transport ms | the link. Says nothing about this library. |

If you are quoting a number at somebody, quote one from the first six rows.

One correction to an earlier version of this document, which said that no
comparable throughput measurement existed anywhere in the repository. One does
now. The main README, under **The same file over a real network**, moves the
same 763.5 kB file on 0.2.1 and then on 0.3.0 over the same relayed VPN, minutes
apart, and its 16.5 percent wall time delta is a real before and after because
the link was held still. It is one run each, so it is an order of magnitude and
not a precise figure, and it is still not comparable to anything measured here:
that link is a public relay and this one is a memory copy. Both statements are
true at once. Section 4 keeps saying NOT COMPARABLE because section 4 is
comparing a relay against loopback, which is a different pairing entirely.

---

## Section 1: bytes on the wire

A real transfer of each payload size crosses a loopback socket. A relay sits
between the two ends and counts every byte the kernel carries, framing prefixes
included. That is what "on the wire" means here: not the length of the buffer
handed to `send()`, the length of what actually moved.

The accounting matches what `ratchet send --stats` prints. On the wire is the
sealed header frame plus the sealed chunk frames, sender to receiver. Handshake
frames are counted separately and reported in section 3, because a handshake is
a per conversation cost and a chunk is a per byte cost, and averaging them
together hides both.

Overhead is a fixed cost per chunk, not a percentage. The table runs from 20
bytes to 10 MiB so you can watch the percentage collapse as the fixed cost gets
amortised. A 20 byte message pays several hundred bytes of envelope. A 10 MiB
file pays the same per chunk and it disappears into the noise. That asymmetry is
the honest reason this is a file mover rather than a chat transport.

The second table costs the same envelopes against both wire formats:

- **0.2.1 wire**: the `OCX1.<kind>.<base64url>` token plus a newline delimiter.
  Base64 is four characters per three bytes, so this is a flat 33 percent tax on
  every ciphertext.
- **binary wire**: the self describing binary envelope plus a `u32` length
  prefix.

When `dist` exports `encodeEnvelopeBytes`, the binary number is measured. When
it does not, the script says so at the top and derives the number from the
base64 length instead. Derived is exact arithmetic, but it is arithmetic, and
the output labels it.

### The `transcode ms` column is gone

It used to sit between `receiver crypto ms` and `wall ms`, and this document
used to explain it as an unavoidable artefact: `engine.seal` returns a token
string, so putting the binary form on the wire meant converting at both ends,
and the conversion got its own clock so it could never be folded into
`crypto ms`.

That explanation described the harness, not the product. The only reason the
harness converted was that its copy of the CLI called `engine.sealBytes` and
`engine.openBytes`. The real `cli/protocol.mjs` has called
`engine.sealToEnvelopeBytes` and `engine.openFromEnvelopeBytes` on the payload
path since 0.3.1 and converts nothing there. The column has been deleted rather
than left reading zero, because a zero would suggest a cost that got optimised
away, and there was never a cost in the shipping code to optimise.

Five small frames per transfer do still convert, and that is by design rather
than by omission: the invite and the accept never come out of a seal, and the
ready frame, the header and the acknowledgement are strings that stay on
`engine.seal` so it keeps ownership of the transient UTF-8 copy it wipes. Those
five are inside the CLI's own `cryptoMs`, which is the number the crypto columns
now print. Section 5 sizes what the twelve chunk frames used to pay.

### What section 1 does not mean

- It does not prove `cli/protocol.mjs` is correct, and it never could. The
  difference since 0.3.2 is that it is now the same code: the script calls
  `sendPayload` and `receivePayload` rather than reimplementing them, so a
  divergence introduced there shows up here as a changed number or a section 0
  failure rather than as nothing at all. The test suite is still what checks the
  CLI for correctness.
- The `crypto ms` columns are `cli/protocol.mjs` reporting its own clock, the
  same `cryptoMs` that `ratchet send --stats` prints. They are not computed
  here. That also means they include the handshake opens, which start before
  `wall ms` starts counting, so `crypto ms` can exceed `wall ms` on a small
  payload and that is not a bug.
- One reimplementation survives, in section 3, and it is guarded rather than
  trusted. See below.
- Payload bytes are random, which is the worst case for anything downstream that
  compresses. Nothing here compresses, so it does not matter, but do not read
  these numbers as applying to a compressing transport.

---

## Section 2: AEAD throughput

Two call paths, side by side, at 256 bytes and at one full chunk.

- `@noble/ciphers` is called directly. That column exists on every build and it
  is the reference.
- `src/aead.ts` is called through its public `sealAead` and `openAead`, using
  whichever backend `aeadBackend()` selected on this Node.

Before the throughput table, the script checks byte identity: 200 random
`(key, nonce, plaintext, aad)` tuples, including zero length plaintexts and zero
length AAD, sealed both ways and compared byte for byte, plus a round trip
through `openAead` against a noble ciphertext. A faster backend that produces
different bytes is a faster wrong answer, and it should fail the release rather
than headline it. If that line says FAIL, stop reading the rest of the table.

The 256 byte row is there because `bench/bench.mjs` times a 256 byte message and
the two scripts should be talking about the same thing. At that size per call
setup dominates and the figure is closer to a call rate than a stream rate. The
chunk sized row is the honest bulk number.

MB means 1e6 bytes, not 1048576. That matches `cli/protocol.mjs`, which is where
the `--stats` throughput figure comes from.

### What section 2 does not mean

- If `aeadBackend()` reports `noble`, both columns are the same primitive
  reached through different call paths. The ratio is then wrapper overhead, not
  a backend comparison, and the script prints a line saying so.
- These are single threaded, single process numbers with no batching. They are
  not a ceiling for a server doing many sessions at once.
- A native backend winning here does not mean it wins everywhere. It means it
  won on this Node version, on this CPU, at these two sizes.

---

## Section 3: handshake cost

The handshake is three one way flights before a payload byte can move:

```
receiver -> sender    invite
sender   -> receiver  accept
receiver -> sender    ready
```

Three flights is one and a half round trips. The `ready` frame is not
politeness. The party that accepts an invite is the Double Ratchet responder and
has no send chain until the initiator speaks, so the receiver has to say
something before the sender can send at all.

The table splits each side into `wall ms`, `crypto ms` and `transport ms`, where
transport is wall minus crypto. Underneath it, the script prints a measured
loopback round trip and then does the arithmetic for a 40 ms link, so you can
see the shape of the answer on a real network without running one:

- crypto does not move when the network changes.
- transport is 1.5 round trips, whatever your round trip is.

That is the whole point of the split. A 115 ms handshake over a relay and a 20
ms handshake on loopback are the same library doing the same work.

### Section 3 is the one place the script still drives the engine itself

Everywhere else the benchmark calls `cli/protocol.mjs`. Section 3 cannot,
and the reason is worth stating rather than hiding, because an unguarded copy is
what produced the 0.3.2 correction at the top of this file.

`cli/protocol.mjs` reports one cumulative `cryptoMs` per transfer and has no
handshake-only figure. The `onHandshake` callback fires at exactly the right
moment but carries no clock. So the crypto against transport split that section
3 exists to show cannot be read out of a real transfer: the smallest transfer
that module will perform still seals a header and opens an acknowledgement after
`handshakeMs` has stopped, which would drive the transport column negative on
loopback. Rather than quietly change what section 3 measures, the five engine
calls are driven here.

It is a timing harness for five calls and not a second copy of the wire
protocol. No chunk loop, no header JSON, no framing arithmetic, and
`PROTOCOL_VERSION` comes from the import. The charging matches
`cli/protocol.mjs` call for call, including which conversions sit outside the
clock and why.

And it is checked. Every counted transfer in section 1 hands back the real
`handshakeMs` from `cli/protocol.mjs`, both sides, and the script prints those
medians in a second table next to the harness's own with the ratio between them.
If the two ever disagree by more than a factor of two the script prints `DRIFT`
and names the side. That is the guard the old copy never had.

### What section 3 does not mean

- Sender wall time starts before the first read, matching `cli/protocol.mjs`.
  From that side, waiting for the peer to produce an invite is part of the
  handshake whether or not the CPU was busy. It is not idle time you can
  subtract.
- TCP connection setup is outside the measurement, because the CLI connects
  before the handshake starts. On a real link add one more round trip for the
  TCP handshake, and more if there is TLS underneath.
- Each measured handshake creates a fresh pair of identities. Identity keygen
  itself is timed by `bench/bench.mjs`, not here.

---

## Section 4: the 0.2.1 baseline

The baseline column is hard coded in `bench/wire.mjs` as
`BASELINE_0_2_1`. It was measured once, on ratchet-ts 0.2.1, moving a 763.5 kB
screenshot from a Windows laptop to a WSL box on a different network, **over a
Tailscale DERP relay** rather than a direct route. It is the same measurement
printed in the repository README.

It is not a fresh measurement, nothing in the script reproduces it, and running
the script again will not move it.

The comparison payload is 763500 bytes on purpose, so the byte counts and the
chunk count line up with the baseline exactly rather than being interpolated
from a nearby size.

Of the six rows in that table:

- **plaintext, on the wire, overhead, chunks** are comparable. They are protocol
  arithmetic and they mean the same thing on any link.
- **sender crypto** is loosely comparable. Different CPU, same kind of work.
- **throughput** is not comparable at all and the table says
  `NOT COMPARABLE, relay versus loopback` in the change column rather than
  printing a flattering multiple. 3.00 MB/s was a fact about somebody's DERP
  relay on one afternoon. Beating it on loopback is not an achievement, it is a
  different question.

If you want a throughput before and after that does mean something, it is not
this table and it never will be. It is the **The same file over a real network**
section of the main README: 0.2.1 and 0.3.0, same file, same relayed VPN,
minutes apart, one run each. The script now prints a pointer to it underneath
section 4 so nobody reads the `NOT COMPARABLE` cell as "this was never
measured". It was measured. It was measured somewhere else, on purpose, because
loopback cannot answer that question.

---

## Section 5: representation cost, token versus bytes

This is the only section that measures what 0.3.1 is about, and it measures it
on the machine running the script. Nothing here is quoted from anywhere.

`engine.seal` and `engine.sealBytes` return an OCX1 token, which is base64url
over the envelope body, and `engine.open` and `engine.openBytes` take one. The
wire is binary. Up to and including 0.3.0 that meant every chunk frame got
base64 encoded and then immediately decoded again on each side, purely to cross
an API that speaks strings:

```
sender    engine.sealBytes -> encodeEnvelope      encode
          cli toWire       -> decodeEnvelope      decode
receiver  cli fromWire     -> encodeEnvelope      encode
          engine.openBytes -> decodeEnvelope      decode
```

Each pair is a round trip that ends where it started. Two of them per frame, one
per endpoint, and not one byte on the socket differed either way.

0.3.1 deleted both for chunk frames. `engine.sealToEnvelopeBytes` goes from
plaintext bytes to envelope bytes and `engine.openFromEnvelopeBytes` comes back,
so the token is never built. What this section measures is therefore the size of
what was removed, and it stays in the file because a saving nobody can
re-measure is a claim rather than a result.

The workload is 12 real sealed chunks of 65519 bytes, which is one 763.5 kB file
and the same payload section 4 uses. They are produced by driving an actual
handshake and sealing actual chunks, so the ratchet key, the nonce, the message
numbers and the ciphertext lengths are what a transfer really carries. Each
timed pass covers the whole workload, not one chunk. There is a `us per chunk`
column for the per frame figure.

### Why the byte rows are not subtracted

They are not the alternative. They are what a transfer paid inside `toWire` and
`fromWire` before, and what it goes on paying with the bytes native seal and
open, because something still has to write the envelope out on the sender and
read it back in on the receiver. What disappeared is the token round trip,
whole, twice. So `deleted` is `2 x round trip via token` with nothing taken off
it, and the byte codec row is printed next to it as the cost that survived the
change.

### Byte identity

Above the table the script re-encodes every payload both ways: through the byte
codec back to a token, and through the token codec back to a frame. All 12 have
to match on both routes. A bytes native path is a legitimate shortcut only if
the payload survives either codec unchanged. If that line says FAIL, the saved
milliseconds were bought by changing the wire, which is a different and much
worse release, and the number below it is not worth reading.

### The spread column means something different here

Everywhere else in this file spread is best to worst across runs, over three or
five samples. Section 5 has 21 passes per run, so pooled that is 63 or 105
samples and the extremes are garbage collection: one pause in 105 passes tells
you the machine has a collector, not that the codec is unstable. This table
reports p10 to p90 over the median instead, and prints a `max` column so the
tail stays visible rather than being summarised away.

### What section 5 does not mean

- It is not a measurement of the bytes native API. It times the two codecs in
  `dist` and sizes the detour that used to sit between them. The byte rows are
  the floor `sealToEnvelopeBytes` lands on, not a reading taken through it.
- `deleted` counts chunk frames only. A transfer still builds a token for the
  invite, the accept, the ready frame, the header and the acknowledgement, so it
  is a floor on both counts.
- In 0.3.0 half of this cost appeared in the `cryptoMs` that
  `ratchet send --stats` printed and half did not. The base64 inside
  `engine.sealBytes` and `engine.openBytes` was charged, because those calls sat
  inside `timed()`. The identical base64 inside `toWire` and `fromWire` was not,
  because those sat outside it. That is the worse version of a measurement bug
  than simply excluding the packaging: it counted one pass and hid its twin. In
  0.3.1 the chunk path does not pay either one, and the token conversion the five
  small payload frames still pay is inside `timed()`. The two handshake frames
  are still converted outside `timed()`, which is deliberate and harmless:
  they fall inside the window `handshakeMs` reports end to end, and the
  conversion is about 0.03 ms for the pair.
- The `deleted as a share of that crypto` row divides by a number from section
  4, which is this CPU with the native AEAD backend. On a machine that falls
  back to the noble backend the crypto number is larger and the share is
  smaller, while the deleted milliseconds do not move. The row also divides a
  two-endpoint quantity by a one-endpoint crypto figure, so it overstates by
  about a factor of two as a per-process ratio. Read it as "the packaging cost
  more than the encryption", not as a number.

---

## Measured output

> **STALE, KEPT ON PURPOSE.** This capture predates the 0.3.2 correction at the
> top of this file and the `src` changes described there. Its section 5 token
> codec figures are several times slower than the current build, and its
> `sender crypto` of 21.28 ms is the old copy's clock, which was charged for
> base64 the CLI did not perform. Nothing here has been altered or removed,
> because this is the record of what was published. Do not quote it. Re-run the
> script.

`node bench/wire.mjs --runs 5`, on an idle machine, 2026-08-07:

```
v25.8.0  |  AMD Ryzen 5 7530U with Radeon Graphics  |  win32/x64
5 runs  |  loopback 127.0.0.1 through a counting relay  |  chunk 65519 B
wire: self describing binary envelope, u32 length prefixed frames
aead: @noble/ciphers direct, and src/aead.ts reporting backend "native"
```

Section 5, verbatim except that the two tables are rendered as markdown. Every
other document in this repository is ASCII and `console.table` draws boxes.

```
5. representation cost, token versus bytes
   12 sealed chunks of 65519 B, one 763.5 kB file's worth, encoded and
   decoded 21 times per run across 5 runs. Every number below is one pass over the
   whole workload, not one chunk, and it is measured on this machine.

   round trip is byte identical: token 12/12, frame 12/12 PASS
```

| operation | ms | p10 | p90 | max | spread | us per chunk | vs bytes |
|---|---|---|---|---|---|---|---|
| encode payload -> token | 9.42 | 7.40 | 11.89 | 15.93 | 47.6% | 785.0 | 18.0x |
| encode payload -> bytes | 0.52 | 0.36 | 1.09 | 1.77 | 139.5% | 43.6 | |
| decode token -> payload | 16.29 | 14.81 | 18.99 | 23.84 | 25.6% | 1357.4 | 46.3x |
| decode bytes -> payload | 0.35 | 0.21 | 0.61 | 1.08 | 113.1% | 29.3 | |
| round trip via token | 26.44 | 24.17 | 30.18 | 37.48 | 22.7% | 2202.9 | 25.3x |
| round trip via bytes | 1.04 | 0.66 | 1.86 | 3.05 | 114.9% | 87.1 | |

105 timed passes per row.

| quantity | value | where |
|---|---|---|
| frames per transfer that carry a chunk | 12 | sendPayload chunk loop |
| token round trips per frame, 0.3.0 | 2 | sealBytes + toWire, fromWire + openBytes |
| token round trips per frame, 0.3.1 | 0 | sealToEnvelopeBytes, openFromEnvelopeBytes |
| one token round trip, whole workload | 26.44 ms | the table above |
| deleted per endpoint, 763.5 kB | 26.44 ms | 1 round trip, that side's 12 chunks |
| deleted per 763.5 kB transfer | 52.87 ms | 2 round trips, both endpoints |
| byte codec, paid before and after | 0.87 ms | the envelope still gets written out and read back |
| sender crypto, same payload, section 4 | 21.28 ms | seal and open only, packaging excluded |
| deleted as a share of that crypto | 248.4% | the packaging tax against the real work |

Read that last row twice. On this machine the base64 detour cost more than the
actual encryption of the same file, and in 0.3.0 half of it was invisible in the
number the CLI reported.

The 26.44 ms is one draw. Four independent captures on this laptop, three from
this harness and one from a separate script written to check it, put the token
round trip at 24.4, 25.7, 26.4 and 27.7 ms, so the deletable quantity is a 24 to
28 ms band per endpoint rather than a constant, and the split between the encode
and decode halves moved much more than the total did.

For context from the same run, section 4 put sender crypto for that 763.5 kB
payload at 21.28 ms and loopback throughput at 8.75 MB/s, and section 1 put the
transfer on the wire at 765.3 kB against 763.5 kB of plaintext.

The 7530U is a laptop part and the numbers scale with the machine. What does not
scale is the shape: decoding a token is dozens of times the cost of decoding the
same envelope from bytes, because base64 decoding a 87 kB string is real work
and reading a length prefix is not.

---

## Reproducing

```
npm run bench:wire
npm run bench:wire -- --runs 7
node bench/wire.mjs --runs 7
```

The first two rebuild `dist` first, because `prebench:wire` runs `tsup`. The
third does not, which is what you want while `src` is mid change: the benchmark
then measures the `dist` that is actually there instead of failing to start
because an unrelated file is half converted.

Nothing is downloaded, nothing listens on a fixed port, and no state is written.
The script binds port 0 on 127.0.0.1 twice, once for the framed server and once
for the counting relay, and tears both down when it finishes.

If a number here looks wrong, the useful next step is `--runs 7` on an idle
machine and a look at the spread column. A 7530U row in the main README was
once 13.8 ms because the laptop was building something in the background at the
time. Spread exists so that mistake is visible instead of published.

## Appendix: two machines, one relayed link

Everything above is one machine. This appendix is the other kind of run: a
Windows laptop on Node 25 sending to a Linux box on Node 22, over a private
mesh VPN that was relaying through a public relay rather than holding a direct
path. It is here because it is the only measurement in the repo that includes a
real network, and because it is currently inconclusive, which is worth writing
down rather than leaving as a gap.

Same payload every time: a 763.5 kB screenshot, 763499 plaintext bytes, 765285
bytes on the wire, 12 chunks, SHA-256 `b2030ad109f232af` on both ends, native
AEAD backend on both ends.

| sample | sender | handshake | crypto | wall | throughput |
|---|---|---|---|---|---|
| A | 0.3.0 | 127 ms | 47 ms | 213 ms | 3.58 MB/s |
| B | 0.3.2 | 175 ms | 46 ms | 1.3 s | 0.60 MB/s |
| C | 0.3.0 | 140 ms | 65 ms | 274 ms | 2.79 MB/s |

**These three cannot be compared to each other.** They were taken minutes apart
and the link moved underneath them. The handshake column is the evidence: that
code path is byte for byte identical in 0.3.0, 0.3.1 and 0.3.2, it does no
bulk work, and it still reads 127, 175 and 140 ms across the three samples. A
column that cannot change by version changed by 38 percent, so any other column
moving by less than that is noise.

What is not explained by that noise is sample B. Handshake variance across the
set is about 1.4x. Sample B's throughput is 4.7x off sample A. Two candidate
explanations, neither established:

1. Ordinary relay noise, and one sample simply landed in a bad window. A single
   observation on a shared relay is entirely capable of doing this.
2. A real effect from the 0.3.1 change. Removing the base64 round trip made the
   sender roughly three times faster at producing frames, which means the 12
   chunks arrive at the socket as a tighter burst than they used to. On a link
   with a small window, a burst can stall where a drip did not, and the process
   that got faster at computing can get slower at delivering.

A third candidate arrived after this appendix was written, and it is now the
leading one. A socket drain stall was found in the framed transport and is being
fixed separately: under it, a sender that hands frames to the socket faster than
the kernel buffer drains can park on a `drain` event that arrives late, which
produces exactly sample B's shape, a normal handshake followed by a wall time
several times too long. **Nothing about sample B should be read as a property of
the crypto.** Its handshake and its crypto columns are in line with the other
two samples; only the wall clock is not, and the wall clock is the transport.
Until that fix has been measured over the same link, treat 0.60 MB/s as an
unexplained transport observation and not as a number about this library.

Explanation 2 would still be an interesting result if it survived, and it is the
reason this is not being filed as plain noise. Distinguishing all three needs the same file
sent alternately by both versions inside one window, medians rather than single
runs, against a receiver that stays up. `recv --once` exits after one completed
transfer by design, so an A/B series needs the receiver started without it:

```sh
ratchet recv --out ~/Downloads --stats
```

Six sends per version, interleaved, is enough to see whether sample B survives.

### What this appendix did establish

The `--once` fix from 0.3.2 holds on a second machine and a real link. The
receiver took a bare TCP connect from the sending side, stayed up, and then
exited only after a completed transfer. Under 0.3.1 that first probe would have
switched it off while the person on the other end was still typing the send
command. That was the failure mode that produced the fix, and it is now
confirmed off the machine it was written on.
