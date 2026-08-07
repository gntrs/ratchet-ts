# bench

Two scripts. They report the same way on purpose: median of several runs, a
spread column, and a header line naming the machine.

```
npm run bench          # primitives: keygen, handshake, seal, open
npm run bench:wire     # the wire: bytes, AEAD backends, handshake split
```

Both take `--runs N`. One run is already a median over many operations.
Repeating the whole run catches the other kind of noise, the machine that is
quiet for two seconds and busy for the next two. Spread is the gap between the
fastest and slowest run as a share of the median. Under 10 percent the machine
was quiet. Over 25 percent something else was using the CPU and the numbers are
worth less.

`bench/bench.mjs` is the older script and it times primitives in isolation.
`bench/wire.mjs` is this document's subject. It runs a real transfer over a real
loopback socket, in one process, with a TCP relay in the middle that counts
bytes as they pass. Nothing needs a second machine and nothing needs a manual
step.

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

### What section 1 does not mean

- It does not prove `cli/protocol.mjs` is correct. The script reimplements that
  module's frame sequence rather than calling it, so the bench keeps running
  while the CLI is mid refactor. A divergence introduced there will not show up
  here. The test suite is what checks the CLI.
- The `transcode ms` column is an artefact of this harness. `engine.seal`
  returns a token string, so putting the binary form on the wire means
  converting at both ends. A binary native call path would not pay that. It is
  charged to its own clock precisely so it never gets folded into `crypto ms`.
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
