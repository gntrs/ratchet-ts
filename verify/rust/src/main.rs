//! A fourth implementation of the OCX3 key schedule, in Rust.
//!
//! WHY RUST, AFTER PYTHON AND GO
//!
//! Not for more of the same. Each verifier is a different bet:
//!
//!   Python  proves the spec is implementable at all, using OpenSSL and a pure
//!           Python FIPS 203 implementation. Covers the sending side.
//!   Go      proves it against a NATIONAL STANDARD LIBRARY, `crypto/mlkem`.
//!           Covers the receiving side; Go exposes no deterministic
//!           encapsulation, deliberately.
//!   Rust    is the only one that covers BOTH DIRECTIONS in one program. The
//!           RustCrypto `ml-kem` crate exposes `generate_deterministic` and
//!           `encapsulate_deterministic`, so this file reproduces the KEM
//!           ciphertext AND recovers the shared secret by decapsulating it.
//!
//! Rust also happens to be the language libsignal is written in, which is the
//! reference this library keeps pointing readers at. If a protocol claims to be
//! a Double Ratchet, being reimplementable in that ecosystem is the least it
//! should manage.
//!
//! This program imports nothing from ratchet-ts. It reads only
//! `test/vectors.json` and would still run if `src/` were deleted. Every
//! primitive comes from a different implementation than the TypeScript uses:
//! `x25519-dalek` rather than @noble/curves, RustCrypto `ml-kem` rather than
//! @noble/post-quantum, `hkdf`/`hmac`/`sha2` rather than @noble/hashes, and
//! `chacha20poly1305` rather than @noble/ciphers.
//!
//! RUN
//!
//!     cd verify/rust && cargo run --release
//!
//! Exits 0 if every value matches, 1 otherwise, printing a line per check.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ml_kem::kem::Decapsulate;
use ml_kem::{EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem768, B32};
use sha2::{Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

// Protocol constants, spelled out rather than derived from anything, because
// every one is a value a second implementer has to get right.
const HANDSHAKE_SALT: &[u8] = b"OCX2 hybrid handshake v1";
const ROOT_INFO: &[u8] = b"OCX2 root ratchet v1";
const CHAIN_STEP_CONSTANT: &[u8] = &[0x01];
const KEY_LEN: usize = 32;
const SESSION_TAG_LEN: usize = 4;
const RATCHET_PUBLIC_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const BIN_VERSION: u8 = 0x03;
const KIND_MESSAGE: u8 = 3;
const FLAG_RATCHET_KEY: u8 = 0x02;

struct Results {
    passed: usize,
    failed: Vec<String>,
}

impl Results {
    fn new() -> Self {
        Results { passed: 0, failed: Vec::new() }
    }
    fn check(&mut self, label: &str, got: &str, want: &str) {
        if got == want {
            self.passed += 1;
            println!("  ok   {label}");
        } else {
            self.failed.push(label.to_string());
            println!("  FAIL {label}");
            println!("       expected {}", trunc(want));
            println!("       got      {}", trunc(got));
        }
    }
}

fn trunc(s: &str) -> String {
    if s.len() <= 80 { s.to_string() } else { format!("{}...", &s[..80]) }
}

fn arr32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[..32]);
    out
}

fn x25519_public(secret: &[u8]) -> Vec<u8> {
    PublicKey::from(&StaticSecret::from(arr32(secret))).as_bytes().to_vec()
}

fn x25519_shared(secret: &[u8], public: &[u8]) -> Vec<u8> {
    StaticSecret::from(arr32(secret))
        .diffie_hellman(&PublicKey::from(arr32(public)))
        .as_bytes()
        .to_vec()
}

fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = vec![0u8; length];
    hk.expand(info, &mut out).expect("hkdf expand");
    out
}

fn hmac_sha512(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// One DH ratchet step. THE CURRENT ROOT IS THE SALT and the fresh DH output is
/// the IKM. That way round is what makes the new root depend on the whole
/// history of the conversation rather than only on the newest exchange.
fn kdf_root(root_key: &[u8], dh_output: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let out = hkdf_sha256(dh_output, root_key, ROOT_INFO, KEY_LEN * 2);
    (out[..KEY_LEN].to_vec(), out[KEY_LEN..].to_vec())
}

/// One symmetric chain step. Bytes 0..32 are the NEXT CHAIN KEY and bytes
/// 32..64 are the message key. This is the easiest thing in the protocol to get
/// backwards and it fails silently: both sides still derive 32 byte keys.
fn kdf_chain(chain_key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let out = hmac_sha512(chain_key, CHAIN_STEP_CONSTANT);
    (out[..KEY_LEN].to_vec(), out[KEY_LEN..KEY_LEN * 2].to_vec())
}

fn read_varint(buf: &[u8], at: usize) -> Result<(u64, usize), String> {
    let mut value: u64 = 0;
    let mut scale: u64 = 1;
    let mut cursor = at;
    for i in 0..5 {
        if cursor >= buf.len() {
            return Err("truncated varint".into());
        }
        let b = buf[cursor];
        cursor += 1;
        value += u64::from(b & 0x7f) * scale;
        if b & 0x80 == 0 {
            if i > 0 && b == 0 {
                return Err("non-canonical varint, trailing zero group".into());
            }
            return Ok((value, cursor));
        }
        scale *= 128;
    }
    Err("varint longer than 5 bytes".into())
}

/// Parses a message envelope and opens it, rebuilding the associated data from
/// scratch.
///
/// The AAD is the part a reimplementer cannot see on the wire and will
/// therefore get wrong silently: the header exactly as transmitted, then
/// conversation id bytes 4..16 which never travel, then the 32 byte sender
/// ratchet public key ONLY when the header did not already carry it.
fn open_message(token: &str, message_key: &[u8], conv_id: &[u8]) -> Result<Vec<u8>, String> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("not a token".into());
    }
    if parts[0] != "OCX3" {
        return Err(format!("unsupported envelope version {}", parts[0]));
    }
    if parts[1] != "message" {
        return Err(format!("expected a message envelope, got {}", parts[1]));
    }
    let raw = URL_SAFE_NO_PAD
        .decode(parts[2].trim_end_matches('='))
        .map_err(|e| e.to_string())?;

    let first = raw[0];
    if first >> 4 != BIN_VERSION {
        return Err("unsupported binary envelope version".into());
    }
    if (first >> 2) & 0x03 != KIND_MESSAGE {
        return Err("kind bits are not a message".into());
    }
    if first & 0x01 != 0 {
        return Err("reserved bit must be zero".into());
    }
    let carries_key = first & FLAG_RATCHET_KEY != 0;

    let mut cursor = 1 + SESSION_TAG_LEN;
    let (_number, next) = read_varint(&raw, cursor)?;
    cursor = next;
    if carries_key {
        let (_prev, next) = read_varint(&raw, cursor)?;
        cursor = next + RATCHET_PUBLIC_LEN;
    } else {
        return Err("these vectors carry the ratchet key in every header".into());
    }
    let nonce = &raw[cursor..cursor + NONCE_LEN];
    cursor += NONCE_LEN;

    let header = &raw[..cursor];
    let ciphertext = &raw[cursor..];

    let mut aad = header.to_vec();
    aad.extend_from_slice(&conv_id[SESSION_TAG_LEN..]);

    let cipher = ChaCha20Poly1305::new_from_slice(message_key).map_err(|e| e.to_string())?;
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad: &aad })
        .map_err(|_| "AEAD authentication failed".to_string())
}

fn main() {
    let path = std::path::Path::new("../../test/vectors.json");
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("cannot read {}: {e}", path.display());
        std::process::exit(2);
    });
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse vectors");
    let want = &v["derived"];
    let conversation_id = v["conversationId"].as_str().unwrap();
    let conv_id = hex::decode(conversation_id).unwrap();
    let seed = |name: &str| hex::decode(v["seeds"][name].as_str().unwrap()).unwrap();
    let s = |k: &str| want[k].as_str().unwrap();
    let mut r = Results::new();

    println!("\nidentities, derived from the seeds alone");
    let alice_classical_secret = seed("aliceIdentityX25519");
    let bob_classical_secret = seed("bobIdentityX25519");
    let alice_classical_public = x25519_public(&alice_classical_secret);
    let bob_classical_public = x25519_public(&bob_classical_secret);
    r.check("alice X25519 public", &hex::encode(&alice_classical_public), s("aliceClassicalPublic"));
    r.check("bob X25519 public", &hex::encode(&bob_classical_public), s("bobClassicalPublic"));

    // The 64 byte FIPS 203 seed is d || z, which is exactly what the vectors
    // pin, so both halves are handed over separately here.
    let alice_kem_seed = seed("aliceIdentityMlKem768");
    let bob_kem_seed = seed("bobIdentityMlKem768");
    let d_a = B32::try_from(&alice_kem_seed[..32]).unwrap();
    let z_a = B32::try_from(&alice_kem_seed[32..64]).unwrap();
    let d_b = B32::try_from(&bob_kem_seed[..32]).unwrap();
    let z_b = B32::try_from(&bob_kem_seed[32..64]).unwrap();
    let (alice_dk, alice_ek) = MlKem768::generate_deterministic(&d_a, &z_a);
    let (_bob_dk, bob_ek) = MlKem768::generate_deterministic(&d_b, &z_b);
    r.check("alice ML-KEM-768 public", &hex::encode(alice_ek.as_bytes()), s("alicePqPublic"));
    r.check("bob ML-KEM-768 public", &hex::encode(bob_ek.as_bytes()), s("bobPqPublic"));

    println!("\nratchet keys");
    let bob_ratchet1_secret = seed("bobRatchet1X25519");
    let alice_ratchet1_secret = seed("aliceRatchet1X25519");
    let bob_ratchet2_secret = seed("bobRatchet2X25519");
    let bob_ratchet1_public = x25519_public(&bob_ratchet1_secret);
    let alice_ratchet1_public = x25519_public(&alice_ratchet1_secret);
    r.check("bob ratchet 1 public", &hex::encode(&bob_ratchet1_public), s("bobRatchet1Public"));
    r.check("alice ratchet 1 public", &hex::encode(&alice_ratchet1_public), s("aliceRatchet1Public"));
    r.check("bob ratchet 2 public", &hex::encode(x25519_public(&bob_ratchet2_secret)), s("bobRatchet2Public"));

    println!("\nML-KEM, both directions, which only this verifier can do");
    // encapsulate_deterministic takes the 32 byte message m explicitly, so the
    // ciphertext itself is reproducible rather than merely openable.
    let m = B32::try_from(&seed("kemEncapsulationMsg")[..32]).unwrap();
    let (kem_ct, kem_shared) = alice_ek.encapsulate_deterministic(&m).expect("encapsulate");
    r.check("ML-KEM-768 ciphertext, re-encapsulated", &hex::encode(&kem_ct), s("kemCiphertext"));
    r.check("ML-KEM-768 shared secret", &hex::encode(kem_shared), s("kemSharedSecret"));

    // And back the other way, from the vectors' own ciphertext bytes.
    let ct_bytes = hex::decode(s("kemCiphertext")).unwrap();
    let ct = ml_kem::Ciphertext::<MlKem768>::try_from(&ct_bytes[..]).expect("ciphertext length");
    let recovered = alice_dk.decapsulate(&ct).expect("decapsulate");
    r.check("decapsulation recovers the shared secret", &hex::encode(recovered), s("kemSharedSecret"));

    println!("\nhandshake");
    let dh1 = x25519_shared(&bob_classical_secret, &alice_classical_public);
    let dh2 = x25519_shared(&bob_ratchet1_secret, &alice_classical_public);
    r.check("dh1, binds the responder identity", &hex::encode(&dh1), s("dh1"));
    r.check("dh2, binds the fresh ratchet key", &hex::encode(&dh2), s("dh2"));

    let mut ikm = dh1.clone();
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&hex::decode(s("kemSharedSecret")).unwrap());
    let handshake_root = hkdf_sha256(&ikm, HANDSHAKE_SALT, conversation_id.as_bytes(), KEY_LEN);
    r.check("handshake root key", &hex::encode(&handshake_root), s("handshakeRootKey"));

    println!("\ninitiator side, computed independently and required to agree");
    // The point of a key agreement is that both sides reach the same secret by
    // different routes. One route would miss a protocol that is deterministic
    // but not actually an agreement.
    let dh1_alice = x25519_shared(&alice_classical_secret, &bob_classical_public);
    let dh2_alice = x25519_shared(&alice_classical_secret, &bob_ratchet1_public);
    r.check("initiator recovers the same dh1", &hex::encode(&dh1_alice), s("dh1"));
    r.check("initiator recovers the same dh2", &hex::encode(&dh2_alice), s("dh2"));
    let mut ikm_a = dh1_alice.clone();
    ikm_a.extend_from_slice(&dh2_alice);
    ikm_a.extend_from_slice(&hex::decode(s("kemSharedSecret")).unwrap());
    let root_alice = hkdf_sha256(&ikm_a, HANDSHAKE_SALT, conversation_id.as_bytes(), KEY_LEN);
    r.check("both sides reach the same handshake root", &hex::encode(&root_alice), s("handshakeRootKey"));

    println!("\nroot ratchet");
    let step_dh = x25519_shared(&alice_ratchet1_secret, &bob_ratchet1_public);
    let (root_after_alice, chain_a_to_b) = kdf_root(&handshake_root, &step_dh);
    r.check("root after the initiator's step", &hex::encode(&root_after_alice), s("rootAfterAliceStep"));
    r.check("initiator to responder chain key", &hex::encode(&chain_a_to_b), s("chainAliceToBob"));

    let bob_send_dh = x25519_shared(&bob_ratchet2_secret, &alice_ratchet1_public);
    let (root_after_bob, chain_b_to_a) = kdf_root(&root_after_alice, &bob_send_dh);
    r.check("root after the responder's step", &hex::encode(&root_after_bob), s("rootAfterBobStep"));
    r.check("responder to initiator chain key", &hex::encode(&chain_b_to_a), s("chainBobToAlice"));

    println!("\nsymmetric chains, three steps each direction");
    let walk = |chain_key: &[u8], count: usize| -> Vec<Vec<u8>> {
        let mut keys = Vec::with_capacity(count);
        let mut ck = chain_key.to_vec();
        for _ in 0..count {
            let (next, mk) = kdf_chain(&ck);
            keys.push(mk);
            ck = next;
        }
        keys
    };
    let want_a = want["messageKeysAliceToBob"].as_array().unwrap();
    let want_b = want["messageKeysBobToAlice"].as_array().unwrap();
    let a_to_b = walk(&chain_a_to_b, want_a.len());
    let b_to_a = walk(&chain_b_to_a, want_b.len());
    for (i, k) in a_to_b.iter().enumerate() {
        r.check(&format!("message key {i}, initiator to responder"), &hex::encode(k), want_a[i].as_str().unwrap());
    }
    for (i, k) in b_to_a.iter().enumerate() {
        r.check(&format!("message key {i}, responder to initiator"), &hex::encode(k), want_b[i].as_str().unwrap());
    }

    println!("\nthe wire, opened from scratch");
    // The only part that proves the AAD layout and the envelope encoding were
    // understood, because a wrong AAD fails the Poly1305 tag rather than
    // producing a wrong answer quietly.
    let msg0 = open_message(v["tokens"]["message0"].as_str().unwrap(), &a_to_b[0], &conv_id)
        .expect("open message0");
    r.check("message 0 opens to the known plaintext", &String::from_utf8_lossy(&msg0), v["plaintexts"]["message0"].as_str().unwrap());
    let reply0 = open_message(v["tokens"]["reply0"].as_str().unwrap(), &b_to_a[0], &conv_id)
        .expect("open reply0");
    r.check("reply 0 opens to the known plaintext", &String::from_utf8_lossy(&reply0), v["plaintexts"]["reply0"].as_str().unwrap());

    println!();
    if !r.failed.is_empty() {
        println!("{} of {} checks FAILED:", r.failed.len(), r.passed + r.failed.len());
        for l in &r.failed {
            println!("  {l}");
        }
        std::process::exit(1);
    }
    println!("all {} checks passed. RustCrypto ML-KEM both directions, no shared code.", r.passed);
}
