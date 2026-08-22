#!/usr/bin/env python3
"""
An independent implementation of OCX3's key schedule, in another language.

WHY THIS FILE EXISTS

test/vectors.json pins one deterministic run of the protocol to exact bytes,
and test/vectors.test.ts checks that the TypeScript still produces them. That
catches accidental change, which is worth having, and it is a weaker statement
than it looks: both halves of that check are the same author's understanding of
the protocol, written in the same language, against the same primitive library.
If that understanding is wrong, the generator and the test are wrong together
and agree perfectly.

So this file re-derives every value in vectors.json from the seeds alone, and
shares nothing with the library it is checking:

  language     Python, not TypeScript
  X25519       OpenSSL, through `cryptography`, not @noble/curves
  ML-KEM-768   kyber-py, a pure Python FIPS 203 implementation, not
               @noble/post-quantum
  HKDF, HMAC   OpenSSL, not @noble/hashes
  ChaCha20     OpenSSL, not @noble/ciphers

Nothing here imports, executes, or reads the TypeScript. The only input is
vectors.json and the only shared artefact is the specification in SPEC.md.

WHAT A PASS MEANS

That two implementations, with no code in common, agree byte for byte on every
public key, shared secret, root key, chain key, message key and ciphertext in a
complete conversation. That is what makes vectors.json a specification of a
protocol rather than a description of whatever the TypeScript happens to do,
and it is the thing a reader cannot get from reading src/ no matter how
carefully they read it.

WHAT A PASS DOES NOT MEAN

That the protocol is secure. Two implementations can agree on something
broken. This proves the design is written down precisely enough to be
reimplemented, and that the reference implementation matches what is written
down. Soundness is a separate question and SECURITY.md is honest about it.

RUN

    python3 -m venv .venv
    .venv/bin/pip install cryptography kyber-py
    .venv/bin/python verify/verify.py

Exits 0 if every value matches, 1 otherwise, and prints a line per check.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from kyber_py.ml_kem import ML_KEM_768

VECTORS = Path(__file__).resolve().parent.parent / "test" / "vectors.json"

# Protocol constants. Every one of these is a value a second implementer has to
# get right, so they are spelled out here rather than derived from anything.
HANDSHAKE_SALT = b"OCX2 hybrid handshake v1"
ROOT_INFO = b"OCX2 root ratchet v1"
CHAIN_STEP_CONSTANT = b"\x01"
KEY_LEN = 32
SESSION_TAG_LEN = 4
CONVERSATION_ID_LEN = 16
RATCHET_PUBLIC_LEN = 32
MESSAGE_NONCE_LEN = 12
BINARY_ENVELOPE_VERSION = 0x03
KIND_MESSAGE = 3
FLAG_RATCHET_KEY = 0x02


class Results:
    """Collects checks so every mismatch is reported, not just the first."""

    def __init__(self) -> None:
        self.passed = 0
        self.failed: list[str] = []

    def check(self, label: str, actual: bytes | str, expected: bytes | str) -> None:
        a = actual.hex() if isinstance(actual, bytes) else actual
        e = expected.hex() if isinstance(expected, bytes) else expected
        if a == e:
            self.passed += 1
            print(f"  ok   {label}")
        else:
            self.failed.append(label)
            print(f"  FAIL {label}")
            print(f"       expected {e[:80]}{'...' if len(e) > 80 else ''}")
            print(f"       got      {a[:80]}{'...' if len(a) > 80 else ''}")


# ---------------------------------------------------------------------------
# Primitives, each one line, so the key schedule below reads as the spec does
# ---------------------------------------------------------------------------


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def hmac_sha512(key: bytes, message: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA512())
    h.update(message)
    return h.finalize()


def x25519_public(secret: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(secret).public_key().public_bytes_raw()


def x25519_shared(secret: bytes, public: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(secret).exchange(X25519PublicKey.from_public_bytes(public))


def kdf_handshake(ikm: bytes, conversation_id: str) -> bytes:
    """The hybrid mixer. All secrets arrive as one blob, so the result is only
    as weak as the strongest surviving component."""
    return hkdf_sha256(ikm, HANDSHAKE_SALT, conversation_id.encode(), KEY_LEN)


def kdf_root(root_key: bytes, dh_output: bytes) -> tuple[bytes, bytes]:
    """One DH ratchet step. The current root is the SALT and the fresh DH is the
    IKM, which is the way round that makes the new root depend on the whole
    history rather than only on the newest exchange. Returns (root, chain)."""
    out = hkdf_sha256(dh_output, root_key, ROOT_INFO, KEY_LEN * 2)
    return out[:KEY_LEN], out[KEY_LEN:]


def kdf_chain(chain_key: bytes) -> tuple[bytes, bytes]:
    """One symmetric chain step. Returns (next_chain_key, message_key). The
    split order is the easiest thing in the whole protocol to get backwards:
    bytes 0..31 are the NEXT CHAIN KEY, bytes 32..63 are the message key."""
    out = hmac_sha512(chain_key, CHAIN_STEP_CONSTANT)
    return out[:KEY_LEN], out[KEY_LEN : KEY_LEN * 2]


def conversation_id_to_bytes(conversation_id: str) -> bytes:
    if len(conversation_id) != CONVERSATION_ID_LEN * 2:
        raise ValueError("conversation id must be 32 hex characters")
    return bytes.fromhex(conversation_id)


# ---------------------------------------------------------------------------
# Wire format. Enough of it to open a message envelope from scratch.
# ---------------------------------------------------------------------------


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def read_varint(buf: bytes, at: int) -> tuple[int, int]:
    value = 0
    scale = 1
    cursor = at
    for i in range(5):
        if cursor >= len(buf):
            raise ValueError("truncated varint")
        byte = buf[cursor]
        cursor += 1
        value += (byte & 0x7F) * scale
        if byte & 0x80 == 0:
            if i > 0 and byte == 0:
                raise ValueError("non-canonical varint, trailing zero group")
            if value > 0xFFFFFFFF:
                raise ValueError("varint past the u32 bound")
            return value, cursor
        scale *= 128
    raise ValueError("varint longer than 5 bytes")


def open_message(token: str, message_key: bytes, conversation_id_bytes: bytes) -> bytes:
    """Parses a message envelope and opens it, rebuilding the AAD from scratch.

    The AAD is the thing worth being careful about, because it is the part a
    reimplementer cannot see on the wire and will therefore get wrong silently.
    It is the header bytes exactly as transmitted, followed by conversation id
    bytes 4..16, which never travel, followed by the 32 byte sender ratchet
    public key ONLY when the header did not already carry it. Binding the id
    tail stops a ciphertext being moved between conversations, and binding the
    ratchet key stops it being moved between chains.
    """
    version, kind, payload = token.split(".", 2)
    if version != "OCX3":
        raise ValueError(f"unsupported envelope version {version}")
    if kind != "message":
        raise ValueError(f"expected a message envelope, got {kind}")
    raw = b64url_decode(payload)

    first = raw[0]
    if first >> 4 != BINARY_ENVELOPE_VERSION:
        raise ValueError("unsupported binary envelope version")
    if (first >> 2) & 0x03 != KIND_MESSAGE:
        raise ValueError("kind bits are not a message")
    if first & 0x01:
        raise ValueError("reserved bit must be zero")
    carries_key = bool(first & FLAG_RATCHET_KEY)

    cursor = 1 + SESSION_TAG_LEN
    _message_number, cursor = read_varint(raw, cursor)
    if carries_key:
        _previous, cursor = read_varint(raw, cursor)
        cursor += RATCHET_PUBLIC_LEN
    nonce = raw[cursor : cursor + MESSAGE_NONCE_LEN]
    cursor += MESSAGE_NONCE_LEN

    header = raw[:cursor]
    ciphertext = raw[cursor:]

    aad = header + conversation_id_bytes[SESSION_TAG_LEN:]
    if not carries_key:
        raise ValueError("these vectors carry the ratchet key in every header")

    return ChaCha20Poly1305(message_key).decrypt(nonce, ciphertext, aad)


# ---------------------------------------------------------------------------
# The verification itself, in the order the protocol runs
# ---------------------------------------------------------------------------


def main() -> int:
    vectors = json.loads(VECTORS.read_text())
    seeds = {k: bytes.fromhex(v) for k, v in vectors["seeds"].items()}
    expected = vectors["derived"]
    conversation_id = vectors["conversationId"]
    cid_bytes = conversation_id_to_bytes(conversation_id)
    r = Results()

    print("\nidentities, derived from the seeds alone")
    alice_classical_secret = seeds["aliceIdentityX25519"]
    bob_classical_secret = seeds["bobIdentityX25519"]
    alice_classical_public = x25519_public(alice_classical_secret)
    bob_classical_public = x25519_public(bob_classical_secret)
    r.check("alice X25519 public", alice_classical_public, expected["aliceClassicalPublic"])
    r.check("bob X25519 public", bob_classical_public, expected["bobClassicalPublic"])

    # key_derive takes the 64 byte FIPS 203 seed (d || z) and returns (ek, dk).
    alice_pq_public, alice_pq_secret = ML_KEM_768.key_derive(seeds["aliceIdentityMlKem768"])
    bob_pq_public, _bob_pq_secret = ML_KEM_768.key_derive(seeds["bobIdentityMlKem768"])
    r.check("alice ML-KEM-768 public", alice_pq_public, expected["alicePqPublic"])
    r.check("bob ML-KEM-768 public", bob_pq_public, expected["bobPqPublic"])

    print("\nratchet keys")
    bob_ratchet1_secret = seeds["bobRatchet1X25519"]
    alice_ratchet1_secret = seeds["aliceRatchet1X25519"]
    bob_ratchet2_secret = seeds["bobRatchet2X25519"]
    bob_ratchet1_public = x25519_public(bob_ratchet1_secret)
    alice_ratchet1_public = x25519_public(alice_ratchet1_secret)
    bob_ratchet2_public = x25519_public(bob_ratchet2_secret)
    r.check("bob ratchet 1 public", bob_ratchet1_public, expected["bobRatchet1Public"])
    r.check("alice ratchet 1 public", alice_ratchet1_public, expected["aliceRatchet1Public"])
    r.check("bob ratchet 2 public", bob_ratchet2_public, expected["bobRatchet2Public"])

    print("\nresponder side of the handshake")
    # _encaps_internal takes the 32 byte message m explicitly, which is what
    # makes even the KEM ciphertext reproducible. It returns (shared, ct).
    kem_shared, kem_ciphertext = ML_KEM_768._encaps_internal(alice_pq_public, seeds["kemEncapsulationMsg"][:32])
    r.check("ML-KEM-768 ciphertext", kem_ciphertext, expected["kemCiphertext"])
    r.check("ML-KEM-768 shared secret", kem_shared, expected["kemSharedSecret"])

    dh1 = x25519_shared(bob_classical_secret, alice_classical_public)
    dh2 = x25519_shared(bob_ratchet1_secret, alice_classical_public)
    r.check("dh1, binds the responder identity", dh1, expected["dh1"])
    r.check("dh2, binds the fresh ratchet key", dh2, expected["dh2"])

    handshake_root = kdf_handshake(dh1 + dh2 + kem_shared, conversation_id)
    r.check("handshake root key", handshake_root, expected["handshakeRootKey"])

    print("\ninitiator side, computed independently and required to agree")
    # The whole point of a key agreement is that both sides reach the same
    # secret by different routes. Checking only one route would miss a protocol
    # that is deterministic but not actually an agreement.
    dh1_alice = x25519_shared(alice_classical_secret, bob_classical_public)
    dh2_alice = x25519_shared(alice_classical_secret, bob_ratchet1_public)
    pq_alice = ML_KEM_768.decaps(alice_pq_secret, kem_ciphertext)
    r.check("initiator recovers the same dh1", dh1_alice, expected["dh1"])
    r.check("initiator recovers the same dh2", dh2_alice, expected["dh2"])
    r.check("decapsulation recovers the shared secret", pq_alice, expected["kemSharedSecret"])
    handshake_root_alice = kdf_handshake(dh1_alice + dh2_alice + pq_alice, conversation_id)
    r.check("both sides reach the same handshake root", handshake_root_alice, expected["handshakeRootKey"])

    print("\nroot ratchet")
    step_dh = x25519_shared(alice_ratchet1_secret, bob_ratchet1_public)
    root_after_alice, chain_a_to_b = kdf_root(handshake_root, step_dh)
    r.check("root after the initiator's step", root_after_alice, expected["rootAfterAliceStep"])
    r.check("initiator to responder chain key", chain_a_to_b, expected["chainAliceToBob"])

    bob_send_dh = x25519_shared(bob_ratchet2_secret, alice_ratchet1_public)
    root_after_bob, chain_b_to_a = kdf_root(root_after_alice, bob_send_dh)
    r.check("root after the responder's step", root_after_bob, expected["rootAfterBobStep"])
    r.check("responder to initiator chain key", chain_b_to_a, expected["chainBobToAlice"])

    print("\nsymmetric chains, three steps each direction")

    def walk(chain_key: bytes, count: int) -> list[bytes]:
        keys = []
        ck = chain_key
        for _ in range(count):
            ck, message_key = kdf_chain(ck)
            keys.append(message_key)
        return keys

    a_to_b_keys = walk(chain_a_to_b, len(expected["messageKeysAliceToBob"]))
    b_to_a_keys = walk(chain_b_to_a, len(expected["messageKeysBobToAlice"]))
    for i, (got, want) in enumerate(zip(a_to_b_keys, expected["messageKeysAliceToBob"])):
        r.check(f"message key {i}, initiator to responder", got, want)
    for i, (got, want) in enumerate(zip(b_to_a_keys, expected["messageKeysBobToAlice"])):
        r.check(f"message key {i}, responder to initiator", got, want)

    print("\nthe wire, opened from scratch")
    # The end of the chain. Everything above is key schedule; this is the only
    # part that proves the AAD layout and the envelope encoding were understood
    # correctly, because a wrong AAD fails the Poly1305 tag rather than
    # producing a wrong answer quietly.
    message0 = open_message(vectors["tokens"]["message0"], a_to_b_keys[0], cid_bytes)
    r.check("message 0 opens to the known plaintext", message0.decode(), vectors["plaintexts"]["message0"])
    reply0 = open_message(vectors["tokens"]["reply0"], b_to_a_keys[0], cid_bytes)
    r.check("reply 0 opens to the known plaintext", reply0.decode(), vectors["plaintexts"]["reply0"])

    print()
    if r.failed:
        print(f"{len(r.failed)} of {r.passed + len(r.failed)} checks FAILED:")
        for label in r.failed:
            print(f"  {label}")
        return 1
    print(f"all {r.passed} checks passed. two implementations, no shared code, identical bytes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
