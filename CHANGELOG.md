# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-23

Initial release.

- Hybrid PQXDH-style handshake: 2x X25519 Diffie-Hellman plus ML-KEM-768
  encapsulation, mixed into an HKDF-SHA256 root key.
- Double Ratchet: X25519 DH ratchet with HMAC-SHA256 symmetric chains.
- XChaCha20-Poly1305 AEAD with the message header bound as additional
  authenticated data.
- Out-of-order and skipped-message handling with a MAX_SKIP bound of 1000.
- Replay rejection and fail-closed tamper handling.
- `OCX1` wire format with `invite`, `accept`, and `message` tokens.
- BIP-39 six-word identity fingerprints.
- 20 tests covering secrecy, hardening, envelope round-trips, and sessions.
