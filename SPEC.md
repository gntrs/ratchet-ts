# OCX3 protocol specification

This document defines OCX3 completely enough to implement it from scratch, in
any language, without reading `src/`. That is the test it is written to pass. If
you find a place where you had to open the TypeScript to resolve an ambiguity,
that is a bug in this document and worth an issue.

`verify/verify.py` is an existing second implementation of the key schedule,
written from this specification against different primitive libraries in a
different language. It reproduces `test/vectors.json` byte for byte and runs in
CI on every push.

**Status.** OCX3 is the wire format of `ratchet-ts` 0.6.x. This is a `0.x`
library and the format can still change; a change will move the version string
and the binary version nibble together, and will be described in
`CHANGELOG.md`. `SECURITY.md` states what has and has not been reviewed. Nothing
here has been independently audited.

## 1. Notation

| | |
| --- | --- |
| `a \|\| b` | concatenation |
| `u16(n)` | big endian unsigned 16 bit integer |
| `u32(n)` | big endian unsigned 32 bit integer |
| `varint(n)` | LEB128 unsigned, see 4.3 |
| `utf8(s)` | UTF-8 encoding of a string, no BOM, no terminator |
| `blob(b)` | `u16(len(b)) \|\| b` |
| `X[i..j]` | bytes `i` inclusive to `j` exclusive |

All multi-byte integers are big endian except the varint, which is
little-endian groups of 7 bits by definition.

## 2. Primitives

| Role | Algorithm | Parameters |
| --- | --- | --- |
| Classical key agreement | X25519 | RFC 7748 |
| Post-quantum KEM | ML-KEM-768 | FIPS 203 |
| Signature | ML-DSA-65 | FIPS 204, hedged |
| Key derivation | HKDF-SHA256 | RFC 5869 |
| Symmetric chain PRF | HMAC-SHA512 | RFC 2104 |
| Message AEAD | ChaCha20-Poly1305 | RFC 8439, 12 byte nonce |
| Identity digest | SHA-256 | |

Key and value sizes, all in bytes:

| | |
| --- | --- |
| X25519 public, X25519 secret | 32, 32 |
| ML-KEM-768 public, secret, ciphertext | 1184, 2400, 1088 |
| ML-DSA-65 public, secret, signature | 1952, 4032, 3309 |
| Root key, chain key, message key | 32, 32, 32 |
| Message nonce | 12 |
| Poly1305 tag | 16 |

An X25519 secret key is used verbatim as the 32 byte scalar; clamping happens
inside the scalar multiplication, so a 32 byte seed IS the secret key. An
ML-KEM-768 keypair is generated from the 64 byte FIPS 203 seed `d || z`.

**ML-DSA-65 signing is hedged, not deterministic.** Two signatures over the same
message under the same key differ. This is deliberate and is the correct default
for a live signer. It means signatures cannot appear in known-answer vectors
without pinning the randomness, which `scripts/gen-vectors.mjs` does and the
library never does.

## 3. Identity

An identity is three keypairs. The public half, `PublicIdentity`, is:

```
classicalPublic   32   X25519
pqPublic        1184   ML-KEM-768
sigPublic       1952   ML-DSA-65
```

### 3.1 Self certificate

Each identity signs its own three public keys once, at creation, and reuses that
signature for every invite it ever sends. The signed message is:

```
utf8("OCX3 identity certificate v1")
  || u32(32) || u32(1184) || u32(1952)
  || classicalPublic || pqPublic || sigPublic
```

The three `u32` lengths appear together, before any key, and are the actual
field lengths. A verifier MUST check this signature before doing any key
agreement with the identity, so that the expensive half of a handshake is not
reachable by anyone who can send bytes.

The certificate carries no conversation id, which is what lets it be signed once
rather than per invite.

### 3.2 Fingerprint

```
digest = SHA-256(
    utf8("OCX1 identity fingerprint v2")
    || u32(32) || u32(1184) || u32(1952)
    || classicalPublic || pqPublic || sigPublic
)
```

The domain string retains the `OCX1` prefix for historical reasons and is a
literal, not a version marker. The trailing `v2` moved when the ML-DSA key
joined the identity in 0.6.0.

Two renderings of the same digest:

- **Words.** Six words, each 11 bits, taken from the 2048 word list in
  `src/wordlist.ts`, read from the most significant bits of `digest` first. Six
  words is **66 bits**.
- **Hex.** `digest[0..16]`, so 128 bits.

Both come from the same digest, so comparing either is a valid check. Users
compare the words aloud over a channel the protocol does not control. 66 bits
stops opportunistic and automated key substitution. It does not stop an
adversary willing to grind 2^66 keypairs at one target.

## 4. Encoding

### 4.1 Token form

A token is ASCII text, safe to paste into a chat box:

```
OCX3.<kind>.<base64url(binary envelope)>
```

`<kind>` is one of `invite`, `accept`, `message`, `intro`. Base64url is
unpadded on encode; a decoder SHOULD accept padding. A decoder MUST reject a
version string other than `OCX3` with a distinct "unknown version" error rather
than attempting to parse the body.

### 4.2 Binary form

Handshake frames (`invite`, `accept`, `intro`):

```
byte 0    0x03                     binary envelope version
byte 1    kind                     1 invite, 2 accept, 3 message, 4 intro
byte 2..  body, see section 5
```

Message frames are packed differently and share byte 0 between three fields; see
section 6.

### 4.3 Varint

Unsigned LEB128, at most 5 bytes, values up to `0xFFFFFFFF`. Each byte carries 7
bits of payload in its low bits, and its high bit set means another byte
follows.

**Canonical form is mandatory.** A decoder MUST reject a varint whose final
group is zero when it is not the first byte, which is the only way to write a
non-minimal encoding. Without this rule the same message number has several
spellings, and since the header is bound as AEAD associated data, several
spellings means several valid tags for one message.

### 4.4 Field framing

Every variable length field in a handshake body is `blob(b)`, that is `u16`
length then bytes. A decoder MUST refuse trailing bytes after the last expected
field. Together these give exactly one encoding of any given handshake frame.

Message frames get uniqueness a different way: canonical varints, fixed length
fields, and a ciphertext that runs to the end of the buffer.

## 5. Handshake frame bodies

Fields in order. All are `blob` except where noted.

**invite**

```
conversationId    blob(utf8(32 lowercase hex chars))
classicalPublic   blob
pqPublic          blob
sigPublic         blob
certificate       blob     ML-DSA-65, see 3.1
```

**accept**

```
conversationId    blob
classicalPublic   blob
pqPublic          blob
sigPublic         blob
kemCiphertext     blob     ML-KEM-768, 1088 bytes
ratchetPublic     blob     X25519, 32 bytes
signature         blob     ML-DSA-65 over the accept transcript, see 7.3
```

**intro**

```
conversationId    blob
classicalPublic   blob
pqPublic          blob
sigPublic         blob
ephemeralPublic   blob
kemCiphertext     blob
ratchetPublic     blob
prekeyClassical   blob
prekeyPq          blob
signature         blob     ML-DSA-65 over the intro transcript, see 8.3
```

A decoder MUST check every fixed size field against its expected length before
handing it to a primitive, and report a malformed token rather than letting the
primitive throw.

## 6. Message frame

### 6.1 Layout

```
offset  size                    field
0       1                       [version:4][kind:2][hasRatchetKey:1][reserved:1]
1       4                       sessionTag, conversationId[0..4]
5       1..5                    varint messageNumber
        1..5                    varint previousChainLength   only if hasRatchetKey
        32                      ratchetPublic                only if hasRatchetKey
        12                      nonce
        rest of buffer          ciphertext || Poly1305 tag
```

Byte 0 for a message is `(0x03 << 4) | (3 << 2) | flags`, so `0x32` when it
carries a ratchet key and `0x30` when it does not. The reserved bit MUST be zero
on encode and MUST be rejected if set on decode.

The version occupies the high nibble so that an OCX1 decoder, which reads byte 0
as a bare version equal to 1, reports an unsupported version rather than walking
into a body it cannot parse.

**The nonce is last, immediately before the ciphertext.** It has no fixed offset
from the front of the frame because two varints and an optional key precede it.
It is random per seal and transmitted in full.

### 6.2 Associated data

This is the part a second implementer cannot see on the wire and will therefore
get wrong silently, so it is stated exactly:

```
AAD = header bytes, byte 0 through the end of the nonce, exactly as transmitted
      || conversationId[4..16]
      || ratchetPublic                    ONLY when hasRatchetKey is 0
```

Twelve bytes of conversation id are bound but never transmitted, because the
receiver already knows which conversation this is. The 32 byte sending ratchet
public key is bound on every message, and travels only on the first
`RATCHET_KEY_RESEND` messages of a chain; on the rest the receiver reconstructs
it from session state.

**This is a security property, not a formatting detail.** Binding the id tail is
what stops a ciphertext being lifted from one conversation into another. Binding
the ratchet key is what stops it being moved between chains. Omitting them from
the wire is free only because they are still bound.

## 7. Live handshake, invite and accept

One and a half round trips. The initiator's contribution is a long term key
rather than an ephemeral one, so the handshake secret has no initiator side
forward secrecy until the first ratchet step. The Double Ratchet takes over from
message one.

### 7.1 Conversation id

128 bits of randomness rendered as 32 lowercase hex characters. Not secret. It
only has to not collide.

### 7.2 Initiator sends invite

Emit an `invite` frame carrying the initiator's `PublicIdentity` and its self
certificate. Retain the conversation id, the role, and **a snapshot of the
identity as sent**. The snapshot is load bearing; see 7.4.

### 7.3 Responder produces accept

On receiving an invite:

1. Check every field length.
2. Verify the self certificate (3.1). **Reject before any key agreement runs.**
3. Generate a fresh X25519 ratchet keypair, `ratchet`.
4. `(kemCiphertext, kemShared) = ML-KEM-768.Encapsulate(invite.pqPublic)`
5. ```
   dh1 = X25519(responder.classicalSecret, invite.classicalPublic)
   dh2 = X25519(ratchet.secret,            invite.classicalPublic)
   ikm = dh1 || dh2 || kemShared
   rootKey = HKDF-SHA256(
       ikm    = ikm,
       salt   = utf8("OCX2 hybrid handshake v1"),
       info   = utf8(conversationId),
       length = 32)
   ```
6. Sign the accept transcript:
   ```
   transcript =
       utf8("OCX2 accept transcript v1")
       || u32(len) for each of the nine parts below, in order, concatenated
       || utf8(conversationId)
       || initiator.classicalPublic || initiator.pqPublic || initiator.sigPublic
       || responder.classicalPublic || responder.pqPublic || responder.sigPublic
       || kemCiphertext
       || ratchet.public
   ```
   All nine `u32` lengths appear as one block, before the first part.
7. Emit the `accept` frame.

The responder now holds a live session at the handshake root and **can receive
but cannot send.** It has no sending chain until the initiator's first message
reveals an initiator ratchet key. This asymmetry matches Signal.

`dh1` binds the responder's identity. `dh2` binds the responder's fresh ratchet
key, and without it the whole handshake would be replayable by anyone holding a
recorded invite.

### 7.4 Initiator completes

1. Reject if the conversation id does not match the pending session.
2. Check every field length.
3. Rebuild the accept transcript using **the initiator identity snapshot taken
   when the invite was sent**, not the currently loaded identity and not
   anything the accept asserts. Verify the signature against
   `accept.sigPublic`. A mismatch means the invite was rewritten in flight.
4. ```
   dh1 = X25519(initiator.classicalSecret, accept.classicalPublic)
   dh2 = X25519(initiator.classicalSecret, accept.ratchetPublic)
   pq  = ML-KEM-768.Decapsulate(accept.kemCiphertext, initiator.pqSecret)
   handshakeRoot = HKDF-SHA256(dh1 || dh2 || pq,
                               salt = utf8("OCX2 hybrid handshake v1"),
                               info = utf8(conversationId), 32)
   ```
5. Immediately take one DH ratchet step (9.1) with a fresh keypair against
   `accept.ratchetPublic`, so message zero is already under a chain the
   responder has never held a private key for.

**ML-KEM decapsulation is implicitly rejecting.** A corrupted ciphertext yields a
well formed but wrong shared secret rather than an error. The mismatch surfaces
as an AEAD tag failure on the first message. This is by design and an
implementation MUST NOT try to detect it earlier.

### 7.5 What the signatures do and do not do

They fix **attribution**, not freshness. An invite is a static offer and is
replayable before and after signing; replaying one buys an attacker a session
with an initiator who is not listening, which wastes a responder's CPU rather
than revealing anything. Freshness comes from the conversation id and from the
initiator having to complete with a key only it holds.

## 8. Offline handshake, prekey bundle and intro

X3DH with a post-quantum arm, which is what Signal ships as PQXDH. The recipient
may be asleep.

### 8.1 Bundle

The recipient publishes, in advance, an X25519 prekey and an ML-KEM-768 prekey,
signed:

```
bundleTranscript =
    utf8("OCX3 prekey bundle v1")
    || u32 lengths block
    || utf8(createdAt)
    || identity.classicalPublic || identity.pqPublic || identity.sigPublic
    || prekeyClassical || prekeyPq
```

`createdAt` is an ISO 8601 timestamp. **The protocol does not enforce a maximum
age**, because only the caller knows its rotation policy, but the value is
signed so a caller that does enforce one cannot be lied to.

A sender MUST verify the bundle signature before use.

### 8.2 Sender derives the root alone

```
ephemeral = fresh X25519 keypair
(kemCiphertext, kemShared) = ML-KEM-768.Encapsulate(bundle.prekeyPq)

dh1 = X25519(ephemeral.secret,       bundle.identity.classicalPublic)
dh2 = X25519(sender.classicalSecret, bundle.prekeyClassical)
dh3 = X25519(ephemeral.secret,       bundle.prekeyClassical)

handshakeRoot = HKDF-SHA256(dh1 || dh2 || dh3 || kemShared,
                            salt = utf8("OCX2 hybrid handshake v1"),
                            info = utf8(conversationId), 32)
```

**The order of those four secrets is part of the specification.** Feeding the
same four in a different order yields a different root and the two sides will
not agree.

What each leg is for:

| | |
| --- | --- |
| `dh1` | binds the recipient's long term identity, so only the intended identity can read it, not merely whoever holds a prekey |
| `dh2` | binds the sender's long term identity, which is what makes the message attributable at all |
| `dh3` | forward secrecy: neither long term key appears in it |
| `kemShared` | the post-quantum arm |

Then take one DH ratchet step against `bundle.prekeyClassical`, exactly as 7.5
does, before sealing anything.

### 8.3 Intro transcript

```
utf8("OCX3 intro transcript v1")
  || u32 lengths block
  || utf8(conversationId)
  || sender.classicalPublic || sender.pqPublic || sender.sigPublic
  || recipient.classicalPublic || recipient.pqPublic || recipient.sigPublic
  || ephemeralPublic || kemCiphertext || ratchetPublic
  || prekeyClassical || prekeyPq
```

### 8.4 Replay, stated honestly

A prekey bundle is a **static offer**, so a recorded intro frame can be
delivered twice. There are no one time prekeys here, because there is no server
to hand them out. The library refuses a conversation id it has already opened
and requires the caller to hold that set, which is the visible version of the
problem rather than the invisible one. **An implementation MUST persist opened
conversation ids or it has no replay defence on this path at all.**

## 9. Double ratchet

### 9.1 Root ratchet

One step per DH exchange:

```
(newRoot, chainKey) = HKDF-SHA256(
    ikm    = dhOutput,
    salt   = currentRootKey,
    info   = utf8("OCX2 root ratchet v1"),
    length = 64)
newRoot  = out[0..32]
chainKey = out[32..64]
```

The current root is the **salt** and the fresh DH output is the **IKM**. That
way round is what makes the new root depend on the whole history of the
conversation rather than only on the newest exchange, so an attacker who learns
one DH output still cannot walk the chain forward.

### 9.2 Symmetric chain

One step per message:

```
out = HMAC-SHA512(key = chainKey, message = 0x01)
nextChainKey = out[0..32]
messageKey   = out[32..64]
```

**Bytes 0 to 31 are the next chain key and bytes 32 to 63 are the message key.**
This is the easiest thing in the protocol to get backwards and it fails
silently: both sides still derive 32 byte keys, they just never agree.

The single byte `0x01` is the whole message. Releases up to 0.3.4 used two
HMAC-SHA256 calls with `0x01` and `0x02`; 0.4.0 replaced them with one
HMAC-SHA512 and a split, which is what HKDF-Expand does by definition and what
the root step above has always done. The security argument is PRF security of
HMAC, and nothing here relies on collision resistance.

### 9.3 Sealing

```
(chainKey, messageKey) = chain step
nonce = 12 fresh random bytes
header = section 6.1
aad    = section 6.2
ciphertext = ChaCha20-Poly1305.Seal(messageKey, nonce, aad, plaintext)
```

The message key MUST be deleted after use. That deletion is what makes forward
secrecy real rather than nominal.

**The nonce MUST come from a CSPRNG on every seal.** A derived counter was built
and rejected: a session restored from a stale snapshot replays a message key,
and a replayed key under a replayed nonce hands an observer the XOR of two
plaintexts.

### 9.4 Opening, and skipped messages

On receiving a header whose `ratchetPublic` differs from the peer key on record,
take a DH ratchet step before deriving keys. Out of order messages within a
chain are handled by walking the chain forward and retaining the message keys
that were stepped over.

Two bounds an implementation MUST enforce:

| | |
| --- | --- |
| `MAX_SKIP` | 1000. Refuse a header that would require deriving more than this many skipped keys in one go, and fail with a distinct "skip limit exceeded" reason. Without it, one forged header with a huge message number is a memory exhaustion attack. |
| `RATCHET_KEY_RESEND` | 3. The number of messages at the start of a sending chain that carry the ratchet public key on the wire. Purely a bandwidth and loss tradeoff; the key is bound as AAD on every message regardless. |

A retained skipped key MUST be deleted once used, and a replayed message whose
key is already gone MUST fail rather than being accepted twice.

## 10. What OCX3 claims

- **Confidentiality and integrity of message contents** against an adversary
  who sees the whole wire, assuming the primitives hold.
- **Forward secrecy.** Compromising current state does not reveal past messages,
  provided message keys are deleted as 9.3 requires.
- **Post-compromise security.** After a compromise, the conversation heals once
  a DH ratchet step happens with a key the attacker does not hold.
- **Hybrid confidentiality of the handshake.** Both X25519 and ML-KEM-768 must
  fall before the handshake secret does. A recorded conversation is not opened
  by a quantum adversary alone. This is pinned by `test/hybrid.test.ts` and
  `test/leg-isolation.test.ts` rather than asserted.
- **Post-quantum authenticity of the handshake**, via ML-DSA-65 over both
  frames.
- **Cross conversation and cross chain separation**, via the AAD binding in 6.2.
- **Exactly one encoding per frame**, via 4.3 and 4.4.

## 11. What OCX3 does not claim

Read this section as carefully as the last one.

- **No audit, no formal model.** The composition has been reviewed by one
  person. Two implementations agreeing proves the design is written down
  precisely; it does not prove the design is sound.
- **No deniability analysis.** Signed handshake frames are a real transcript.
  Nothing here has been checked against the deniability properties Signal
  reasons about.
- **No constant time guarantee** beyond what the underlying primitive libraries
  provide. Nothing in the protocol layer has been analysed for timing leaks.
- **No metadata protection.** A relay sees two addresses meeting at a timestamp
  and how many bytes passed. It cannot read a message or impersonate anyone.
- **No replay defence on the offline path** unless the caller persists opened
  conversation ids, as 8.4 requires.
- **No defence against a compromised runtime.** JavaScript executing in the same
  context as the keys can read them.
- **A pairing code pins 64 bits**, and six fingerprint words pin 66. Neither
  replaces comparing the words aloud for a peer you intend to keep.
- **No initiator side forward secrecy before the first ratchet step**, per 7.

## 12. Test vectors

`test/vectors.json` freezes one complete deterministic run: seeds in, every
public key, shared secret, root key, chain key, message key and wire token out.
Every random choice is replaced by a fixed seed, and the seeds are counter
patterns, byte `i` of the seed at offset `k` being `(k + i) mod 256`, so a
reader can see at a glance that nothing is hidden in them.

Two things check it, and they are not the same check:

| | |
| --- | --- |
| `test/vectors.test.ts` | re-derives every value in TypeScript and hands the tokens to the real ratchet. Catches accidental change. |
| `verify/verify.py` | re-derives every value in Python, using OpenSSL and a pure Python FIPS 203 implementation. Covers the sending side, including deterministic encapsulation. |
| `verify/go` | re-derives every value in Go, against the Go standard library's `crypto/mlkem` and `crypto/hkdf`. Covers the receiving side: Go exposes no deterministic encapsulation, so it checks key generation and decapsulation instead. |
| `verify/rust` | re-derives every value in Rust using RustCrypto. The only one covering both directions of the KEM in one program, since the crate exposes deterministic key generation and deterministic encapsulation. |

None of the three imports anything from this repository, and all three run in
CI. If you write a fourth, in any language, `SPEC.md` should be enough and a
pull request adding it is welcome.

Run the second one:

```sh
python3 -m venv .venv
.venv/bin/pip install -r verify/requirements.txt
.venv/bin/python verify/verify.py
```

It prints one line per check and exits non-zero on any mismatch.
