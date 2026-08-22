// A third implementation of the OCX3 key schedule, in Go.
//
// WHY A THIRD ONE
//
// verify/verify.py already re-derives test/vectors.json in Python, which is
// what turns the vector file from a description of whatever the TypeScript does
// into a specification of a protocol. A second independent language is not more
// of the same. It is a different bet:
//
//   Python  proves the spec is implementable, using OpenSSL and a pure Python
//           FIPS 203 implementation.
//   Go      proves it against a NATIONAL STANDARD LIBRARY. crypto/mlkem and
//           crypto/hkdf are in the Go standard library, written by the Go
//           cryptography team and reviewed on that team's terms. Agreeing with
//           them is a stronger statement than agreeing with any one package,
//           because nobody chose it to make this repository look good.
//
// This program imports nothing from ratchet-ts, reads only test/vectors.json,
// and would still run if src/ were deleted. Its only non standard library
// dependency is golang.org/x/crypto/chacha20poly1305.
//
// ONE HONEST GAP, STATED UP FRONT
//
// Go's crypto/mlkem deliberately exposes no deterministic Encapsulate: there is
// no way to hand it the 32 byte message m that FIPS 203 encapsulation consumes,
// because a caller who can choose m can break the scheme and the Go team chose
// not to offer that foot-gun. So this program CANNOT reproduce the KEM
// ciphertext in the vectors. It checks the two things it can, and they are the
// ones that matter for interoperability:
//
//   1. deterministic key generation from the 64 byte FIPS 203 seed (d || z)
//      produces the same encapsulation key
//   2. decapsulating the vectors' ciphertext with that key recovers the same
//      shared secret
//
// Point 2 is the receiving side of the exchange. It proves a Go program can
// RECEIVE what ratchet-ts sends, which is the direction interop is usually
// about. verify.py covers the sending side, where kyber-py does expose the
// internal encapsulation. Between the two, both directions are covered, and
// neither file pretends to cover the other's half.
//
// RUN
//
//	cd verify/go && go run .
//
// Exits 0 if every value matches, 1 otherwise, printing a line per check.
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// Protocol constants. Spelled out rather than derived from anything, because
// every one of them is a value a second implementer has to get right.
const (
	handshakeSalt = "OCX2 hybrid handshake v1"
	rootInfo      = "OCX2 root ratchet v1"
	keyLen        = 32
	sessionTagLen = 4
	convIDLen     = 16
	ratchetPubLen = 32
	nonceLen      = 12
	binVersion    = 0x03
	kindMessage   = 3
	flagRatchetKey = 0x02
)

var chainStepConstant = []byte{0x01}

type vectorsFile struct {
	ConversationID string            `json:"conversationId"`
	Seeds          map[string]string `json:"seeds"`
	Plaintexts     map[string]string `json:"plaintexts"`
	Derived        json.RawMessage   `json:"derived"`
	Tokens         map[string]string `json:"tokens"`
}

type derivedFields struct {
	AliceClassicalPublic  string   `json:"aliceClassicalPublic"`
	AlicePqPublic         string   `json:"alicePqPublic"`
	BobClassicalPublic    string   `json:"bobClassicalPublic"`
	BobPqPublic           string   `json:"bobPqPublic"`
	BobRatchet1Public     string   `json:"bobRatchet1Public"`
	AliceRatchet1Public   string   `json:"aliceRatchet1Public"`
	BobRatchet2Public     string   `json:"bobRatchet2Public"`
	KemCiphertext         string   `json:"kemCiphertext"`
	KemSharedSecret       string   `json:"kemSharedSecret"`
	DH1                   string   `json:"dh1"`
	DH2                   string   `json:"dh2"`
	HandshakeRootKey      string   `json:"handshakeRootKey"`
	RootAfterAliceStep    string   `json:"rootAfterAliceStep"`
	RootAfterBobStep      string   `json:"rootAfterBobStep"`
	ChainAliceToBob       string   `json:"chainAliceToBob"`
	ChainBobToAlice       string   `json:"chainBobToAlice"`
	MessageKeysAliceToBob []string `json:"messageKeysAliceToBob"`
	MessageKeysBobToAlice []string `json:"messageKeysBobToAlice"`
}

type results struct {
	passed int
	failed []string
}

func (r *results) check(label string, got, want string) {
	if got == want {
		r.passed++
		fmt.Printf("  ok   %s\n", label)
		return
	}
	r.failed = append(r.failed, label)
	fmt.Printf("  FAIL %s\n", label)
	fmt.Printf("       expected %s\n", truncate(want))
	fmt.Printf("       got      %s\n", truncate(got))
}

func truncate(s string) string {
	if len(s) <= 80 {
		return s
	}
	return s[:80] + "..."
}

func must[T any](v T, err error) T {
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(2)
	}
	return v
}

func unhex(s string) []byte { return must(hex.DecodeString(s)) }

// x25519Public returns the public key for a 32 byte secret used verbatim as the
// scalar, which is how this protocol treats X25519 secrets.
func x25519Public(secret []byte) []byte {
	return must(ecdh.X25519().NewPrivateKey(secret)).PublicKey().Bytes()
}

func x25519Shared(secret, public []byte) []byte {
	priv := must(ecdh.X25519().NewPrivateKey(secret))
	pub := must(ecdh.X25519().NewPublicKey(public))
	return must(priv.ECDH(pub))
}

func hkdfSha256(ikm, salt []byte, info string, length int) []byte {
	return must(hkdf.Key(sha256.New, ikm, salt, info, length))
}

func hmacSha512(key, message []byte) []byte {
	m := hmac.New(sha512.New, key)
	m.Write(message)
	return m.Sum(nil)
}

// kdfRoot is one DH ratchet step. The CURRENT ROOT IS THE SALT and the fresh DH
// output is the IKM. That way round is what makes the new root depend on the
// whole history rather than only on the newest exchange.
func kdfRoot(rootKey, dhOutput []byte) (newRoot, chainKey []byte) {
	out := hkdfSha256(dhOutput, rootKey, rootInfo, keyLen*2)
	return out[:keyLen], out[keyLen:]
}

// kdfChain is one symmetric chain step. Bytes 0..32 are the NEXT CHAIN KEY and
// bytes 32..64 are the message key. This is the easiest thing in the protocol
// to get backwards and it fails silently.
func kdfChain(chainKey []byte) (nextChainKey, messageKey []byte) {
	out := hmacSha512(chainKey, chainStepConstant)
	return out[:keyLen], out[keyLen : keyLen*2]
}

func readVarint(buf []byte, at int) (value int, next int, err error) {
	scale := 1
	cursor := at
	for i := 0; i < 5; i++ {
		if cursor >= len(buf) {
			return 0, 0, fmt.Errorf("truncated varint")
		}
		b := buf[cursor]
		cursor++
		value += int(b&0x7f) * scale
		if b&0x80 == 0 {
			if i > 0 && b == 0 {
				return 0, 0, fmt.Errorf("non-canonical varint, trailing zero group")
			}
			return value, cursor, nil
		}
		scale *= 128
	}
	return 0, 0, fmt.Errorf("varint longer than 5 bytes")
}

// openMessage parses a message envelope and opens it, rebuilding the associated
// data from scratch. The AAD is the part a reimplementer cannot see on the wire
// and will therefore get wrong silently: it is the header exactly as
// transmitted, then conversation id bytes 4..16 which never travel, then the 32
// byte sender ratchet public key ONLY when the header did not already carry it.
func openMessage(token string, messageKey, convID []byte) ([]byte, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a token")
	}
	if parts[0] != "OCX3" {
		return nil, fmt.Errorf("unsupported envelope version %s", parts[0])
	}
	if parts[1] != "message" {
		return nil, fmt.Errorf("expected a message envelope, got %s", parts[1])
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[2], "="))
	if err != nil {
		return nil, err
	}

	first := raw[0]
	if first>>4 != binVersion {
		return nil, fmt.Errorf("unsupported binary envelope version")
	}
	if (first>>2)&0x03 != kindMessage {
		return nil, fmt.Errorf("kind bits are not a message")
	}
	if first&0x01 != 0 {
		return nil, fmt.Errorf("reserved bit must be zero")
	}
	carriesKey := first&flagRatchetKey != 0

	cursor := 1 + sessionTagLen
	if _, cursor, err = readVarint(raw, cursor); err != nil {
		return nil, err
	}
	if carriesKey {
		if _, cursor, err = readVarint(raw, cursor); err != nil {
			return nil, err
		}
		cursor += ratchetPubLen
	}
	nonce := raw[cursor : cursor+nonceLen]
	cursor += nonceLen

	header := raw[:cursor]
	ciphertext := raw[cursor:]

	if !carriesKey {
		return nil, fmt.Errorf("these vectors carry the ratchet key in every header")
	}
	aad := append(append([]byte{}, header...), convID[sessionTagLen:]...)

	aead, err := chacha20poly1305.New(messageKey)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

func main() {
	path := filepath.Join("..", "..", "test", "vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read %s: %v\n", path, err)
		os.Exit(2)
	}
	var vf vectorsFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		fmt.Fprintf(os.Stderr, "cannot parse vectors: %v\n", err)
		os.Exit(2)
	}
	var want derivedFields
	if err := json.Unmarshal(vf.Derived, &want); err != nil {
		fmt.Fprintf(os.Stderr, "cannot parse derived: %v\n", err)
		os.Exit(2)
	}
	seed := func(name string) []byte { return unhex(vf.Seeds[name]) }
	convID := unhex(vf.ConversationID)
	r := &results{}

	fmt.Println("\nidentities, derived from the seeds alone")
	aliceClassicalSecret := seed("aliceIdentityX25519")
	bobClassicalSecret := seed("bobIdentityX25519")
	aliceClassicalPublic := x25519Public(aliceClassicalSecret)
	bobClassicalPublic := x25519Public(bobClassicalSecret)
	r.check("alice X25519 public", hex.EncodeToString(aliceClassicalPublic), want.AliceClassicalPublic)
	r.check("bob X25519 public", hex.EncodeToString(bobClassicalPublic), want.BobClassicalPublic)

	// NewDecapsulationKey768 takes the 64 byte FIPS 203 seed (d || z), which is
	// exactly what the vectors pin.
	aliceDK := must(mlkem.NewDecapsulationKey768(seed("aliceIdentityMlKem768")))
	bobDK := must(mlkem.NewDecapsulationKey768(seed("bobIdentityMlKem768")))
	r.check("alice ML-KEM-768 public", hex.EncodeToString(aliceDK.EncapsulationKey().Bytes()), want.AlicePqPublic)
	r.check("bob ML-KEM-768 public", hex.EncodeToString(bobDK.EncapsulationKey().Bytes()), want.BobPqPublic)

	fmt.Println("\nratchet keys")
	bobRatchet1Secret := seed("bobRatchet1X25519")
	aliceRatchet1Secret := seed("aliceRatchet1X25519")
	bobRatchet2Secret := seed("bobRatchet2X25519")
	bobRatchet1Public := x25519Public(bobRatchet1Secret)
	aliceRatchet1Public := x25519Public(aliceRatchet1Secret)
	r.check("bob ratchet 1 public", hex.EncodeToString(bobRatchet1Public), want.BobRatchet1Public)
	r.check("alice ratchet 1 public", hex.EncodeToString(aliceRatchet1Public), want.AliceRatchet1Public)
	r.check("bob ratchet 2 public", hex.EncodeToString(x25519Public(bobRatchet2Secret)), want.BobRatchet2Public)

	fmt.Println("\nML-KEM decapsulation, the receiving side of the exchange")
	// The Go standard library will not encapsulate deterministically, so the
	// ciphertext cannot be reproduced here. Decapsulating the one in the
	// vectors is the check that is available, and it is the one that proves a
	// Go program can receive what ratchet-ts sends.
	kemShared := must(aliceDK.Decapsulate(unhex(want.KemCiphertext)))
	r.check("decapsulation recovers the shared secret", hex.EncodeToString(kemShared), want.KemSharedSecret)

	fmt.Println("\nhandshake")
	dh1 := x25519Shared(bobClassicalSecret, aliceClassicalPublic)
	dh2 := x25519Shared(bobRatchet1Secret, aliceClassicalPublic)
	r.check("dh1, binds the responder identity", hex.EncodeToString(dh1), want.DH1)
	r.check("dh2, binds the fresh ratchet key", hex.EncodeToString(dh2), want.DH2)

	ikm := bytes.Join([][]byte{dh1, dh2, kemShared}, nil)
	handshakeRoot := hkdfSha256(ikm, []byte(handshakeSalt), vf.ConversationID, keyLen)
	r.check("handshake root key", hex.EncodeToString(handshakeRoot), want.HandshakeRootKey)

	fmt.Println("\ninitiator side, computed independently and required to agree")
	// The point of a key agreement is that both sides reach the same secret by
	// different routes. Checking one route would miss a protocol that is
	// deterministic but not actually an agreement.
	dh1Alice := x25519Shared(aliceClassicalSecret, bobClassicalPublic)
	dh2Alice := x25519Shared(aliceClassicalSecret, bobRatchet1Public)
	r.check("initiator recovers the same dh1", hex.EncodeToString(dh1Alice), want.DH1)
	r.check("initiator recovers the same dh2", hex.EncodeToString(dh2Alice), want.DH2)
	rootAlice := hkdfSha256(bytes.Join([][]byte{dh1Alice, dh2Alice, kemShared}, nil),
		[]byte(handshakeSalt), vf.ConversationID, keyLen)
	r.check("both sides reach the same handshake root", hex.EncodeToString(rootAlice), want.HandshakeRootKey)

	fmt.Println("\nroot ratchet")
	stepDH := x25519Shared(aliceRatchet1Secret, bobRatchet1Public)
	rootAfterAlice, chainAToB := kdfRoot(handshakeRoot, stepDH)
	r.check("root after the initiator's step", hex.EncodeToString(rootAfterAlice), want.RootAfterAliceStep)
	r.check("initiator to responder chain key", hex.EncodeToString(chainAToB), want.ChainAliceToBob)

	bobSendDH := x25519Shared(bobRatchet2Secret, aliceRatchet1Public)
	rootAfterBob, chainBToA := kdfRoot(rootAfterAlice, bobSendDH)
	r.check("root after the responder's step", hex.EncodeToString(rootAfterBob), want.RootAfterBobStep)
	r.check("responder to initiator chain key", hex.EncodeToString(chainBToA), want.ChainBobToAlice)

	fmt.Println("\nsymmetric chains, three steps each direction")
	walk := func(chainKey []byte, count int) [][]byte {
		keys := make([][]byte, 0, count)
		ck := chainKey
		for i := 0; i < count; i++ {
			next, mk := kdfChain(ck)
			keys = append(keys, mk)
			ck = next
		}
		return keys
	}
	aToB := walk(chainAToB, len(want.MessageKeysAliceToBob))
	bToA := walk(chainBToA, len(want.MessageKeysBobToAlice))
	for i, k := range aToB {
		r.check(fmt.Sprintf("message key %d, initiator to responder", i),
			hex.EncodeToString(k), want.MessageKeysAliceToBob[i])
	}
	for i, k := range bToA {
		r.check(fmt.Sprintf("message key %d, responder to initiator", i),
			hex.EncodeToString(k), want.MessageKeysBobToAlice[i])
	}

	fmt.Println("\nthe wire, opened from scratch")
	// The only part that proves the AAD layout and envelope encoding were
	// understood, because a wrong AAD fails the Poly1305 tag rather than
	// producing a wrong answer quietly.
	msg0 := must(openMessage(vf.Tokens["message0"], aToB[0], convID))
	r.check("message 0 opens to the known plaintext", string(msg0), vf.Plaintexts["message0"])
	reply0 := must(openMessage(vf.Tokens["reply0"], bToA[0], convID))
	r.check("reply 0 opens to the known plaintext", string(reply0), vf.Plaintexts["reply0"])

	fmt.Println()
	if len(r.failed) > 0 {
		fmt.Printf("%d of %d checks FAILED:\n", len(r.failed), r.passed+len(r.failed))
		for _, l := range r.failed {
			fmt.Printf("  %s\n", l)
		}
		os.Exit(1)
	}
	fmt.Printf("all %d checks passed. Go standard library ML-KEM and HKDF, no shared code.\n", r.passed)
}
