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
| wall ms, MB/s, transport ms | the link. Says nothing about this library. |

If you are quoting a number at somebody, quote one from the first five rows.

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

---

## Reproducing

```
npm run bench:wire
npm run bench:wire -- --runs 7
```

Nothing is downloaded, nothing listens on a fixed port, and no state is written.
The script binds port 0 on 127.0.0.1 twice, once for the framed server and once
for the counting relay, and tears both down when it finishes.

If a number here looks wrong, the useful next step is `--runs 7` on an idle
machine and a look at the spread column. A 7530U row in the main README was
once 13.8 ms because the laptop was building something in the background at the
time. Spread exists so that mistake is visible instead of published.
