package kal2

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Domain-separation labels for HKDF. Unique per purpose.
var (
	labelBase          = []byte("mxs-in-v2/transcript")
	labelClientRecord  = []byte("mxs-in-v2/record/client")
	labelServerRecord  = []byte("mxs-in-v2/record/server")
	labelServerSig     = []byte("mxs-in-v2/server-sig-input")
	labelClientPSK     = []byte("mxs-in-v2/client-psk-input")
	labelClientPreauth = []byte("mxs-in-v2/client-preauth")
	labelHandshakeVer  = []byte("mxs-in-v2/handshake-verify")
	labelFinished      = []byte("mxs-in-v2/finished")
	labelNonceBase     = []byte("mxs-in-v2/nonce-base")
	labelExporterBind  = []byte("mxs-in-v2/exporter-bind")
)

// ChannelBinding is optional carrier-provided secret material (a TLS
// exporter per RFC 9266) mixed into the key schedule so the inner session is
// bound to the exact outer session it runs inside.
type ChannelBinding []byte

func transcript(magic []byte, version byte, clientPub, serverPub []byte) []byte {
	t := make([]byte, 0, len(magic)+1+64)
	t = append(t, magic...)
	t = append(t, version)
	t = append(t, clientPub...)
	t = append(t, serverPub...)
	return t
}

func hkdfDerive(info []byte, ikm, transcriptBytes []byte, length int) ([]byte, error) {
	th := sha256.Sum256(transcriptBytes)
	full := append(append(append([]byte{}, labelBase...), '/'), info...)
	full = append(full, '/')
	full = append(full, transcriptBytes...)
	r := hkdf.New(sha256.New, ikm, th[:], full)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// computeSalt mixes the X25519 shared secret with the optional channel
// binding: salt = H(binding_label, shared || binding) — the binding also
// participates in the extract salt (transcript hash), so a mismatched
// binding changes every derived key.
func computeSalt(shared, binding []byte) []byte {
	if len(binding) == 0 {
		return shared
	}
	m := hmac.New(sha256.New, labelExporterBind)
	m.Write(shared)
	m.Write(binding)
	return m.Sum(nil)
}

func clientPreauth(psk, ephRaw, binding []byte) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write(labelClientPreauth)
	m.Write(Magic)
	m.Write([]byte{Version})
	m.Write(ephRaw)
	if len(binding) > 0 {
		m.Write(binding)
	}
	return m.Sum(nil)
}

// ParseClientFirstFlight authenticates and returns the client's ephemeral key
// plus the total flight length (fixed prefix + declared padding) so the
// caller can consume exactly the right number of stream bytes. The padding is
// non-semantic random; it is not in the transcript.
// Every failure must be mapped by the caller to the ordinary cover response.
func ParseClientFirstFlight(flight, psk []byte, binding ChannelBinding) (ephRaw []byte, totalLen int, err error) {
	if len(flight) < FirstFlightMinSize {
		return nil, 0, ErrHandshake
	}
	if !bytes.Equal(flight[:len(Magic)], Magic) {
		return nil, 0, ErrMagic
	}
	if flight[len(Magic)] != Version {
		return nil, 0, ErrVersion
	}
	ks := len(Magic) + 1
	eph := flight[ks : ks+ephemeralKeySize]
	preauth := flight[ks+ephemeralKeySize : ks+ephemeralKeySize+preauthSize]
	padLen := int(binary.LittleEndian.Uint16(flight[ks+ephemeralKeySize+preauthSize:]))
	if padLen > FirstFlightMaxPad {
		return nil, 0, ErrHandshake
	}
	if subtle.ConstantTimeCompare(preauth, clientPreauth(psk, eph, binding)) != 1 {
		return nil, 0, ErrPreauth
	}
	out := make([]byte, ephemeralKeySize)
	copy(out, eph)
	return out, FirstFlightMinSize + padLen, nil
}

// FirstFlightPadBounds returns (min, max) acceptable extra padding length.
func FirstFlightPadBounds() (int, int) { return 0, FirstFlightMaxPad }

// ServerHandshake is the single-use server-side handshake.
type ServerHandshake struct {
	identity ed25519.PrivateKey

	ephPriv    []byte
	ephPub     []byte
	transcript []byte
	salt       []byte
}

// NewServerHandshake creates a server handshake with a fresh ephemeral.
func NewServerHandshake(identity ed25519.PrivateKey) (*ServerHandshake, error) {
	priv, pub, err := genX25519()
	if err != nil {
		return nil, err
	}
	return &ServerHandshake{identity: identity, ephPriv: priv, ephPub: pub}, nil
}

// Start accepts the client's ephemeral public key and returns the server
// flight: ephemeral(32) || Ed25519 signature(64). binding is the carrier's
// channel binding (may be nil).
func (h *ServerHandshake) Start(clientEph []byte, binding ChannelBinding) ([]byte, error) {
	if len(clientEph) != ephemeralKeySize {
		return nil, ErrHandshake
	}
	shared, err := curve25519.X25519(h.ephPriv, clientEph)
	if err != nil {
		return nil, ErrHandshake
	}
	if isLowOrder(shared) {
		return nil, ErrHandshake
	}
	h.transcript = transcript(Magic, Version, clientEph, h.ephPub)
	h.salt = computeSalt(shared, binding)
	sigInput, err := hkdfDerive(labelServerSig, h.salt, h.transcript, 32)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(h.identity, sigInput)
	return append(append([]byte{}, h.ephPub...), sig...), nil
}

// ClientHandshake is the single-use client-side handshake.
type ClientHandshake struct {
	serverPub ed25519.PublicKey
	psk       []byte
	binding   ChannelBinding

	ephPriv    []byte
	ephPub     []byte
	transcript []byte
	salt       []byte
}

// NewClientHandshake creates a client handshake. binding may be nil when the
// carrier provides no channel binding.
func NewClientHandshake(serverPub ed25519.PublicKey, psk []byte, binding ChannelBinding) (*ClientHandshake, error) {
	priv, pub, err := genX25519()
	if err != nil {
		return nil, err
	}
	return &ClientHandshake{serverPub: serverPub, psk: psk, binding: binding, ephPriv: priv, ephPub: pub}, nil
}

// FirstFlight returns magic || version || eph || preauth || padLen(2) || pad.
// padLen selects the padding length (0..FirstFlightMaxPad); <0 picks random.
func (h *ClientHandshake) FirstFlight(padLen int) ([]byte, error) {
	if padLen < 0 {
		var b [2]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		padLen = int(binary.BigEndian.Uint16(b[:]) % (FirstFlightMaxPad + 1))
	}
	if padLen > FirstFlightMaxPad {
		return nil, ErrHandshake
	}
	out := make([]byte, 0, FirstFlightMinSize+padLen)
	out = append(out, Magic...)
	out = append(out, Version)
	out = append(out, h.ephPub...)
	out = append(out, clientPreauth(h.psk, h.ephPub, h.binding)...)
	var lb [2]byte
	binary.LittleEndian.PutUint16(lb[:], uint16(padLen))
	out = append(out, lb[:]...)
	pad := make([]byte, padLen)
	if _, err := rand.Read(pad); err != nil {
		return nil, err
	}
	return append(out, pad...), nil
}

// ServerFlight consumes the server flight, validates the Ed25519 identity
// signature, and returns derived session material.
func (h *ClientHandshake) ServerFlight(msg []byte) (*Session, error) {
	if len(msg) != ServerFlightSize {
		return nil, ErrHandshake
	}
	serverEph := msg[:ephemeralKeySize]
	sig := msg[ephemeralKeySize:]
	shared, err := curve25519.X25519(h.ephPriv, serverEph)
	if err != nil {
		return nil, ErrHandshake
	}
	if isLowOrder(shared) {
		return nil, ErrHandshake
	}
	h.transcript = transcript(Magic, Version, h.ephPub, serverEph)
	h.salt = computeSalt(shared, h.binding)
	sigInput, err := hkdfDerive(labelServerSig, h.salt, h.transcript, 32)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(h.serverPub, sigInput, sig) {
		return nil, ErrSignature
	}
	return h.buildSession()
}

func (h *ClientHandshake) buildSession() (*Session, error) {
	mk, err := deriveSessionKeys(h.transcript, h.salt)
	if err != nil {
		return nil, err
	}
	mk.isClient = true
	return mk, nil
}

// Finish builds the server session after a started handshake.
func (h *ServerHandshake) Finish() (*Session, error) {
	if h.transcript == nil || h.salt == nil {
		return nil, ErrHandshake
	}
	mk, err := deriveSessionKeys(h.transcript, h.salt)
	if err != nil {
		return nil, err
	}
	// Server reads client records and vice versa.
	mk.sendKey, mk.recvKey = mk.recvKey, mk.sendKey
	mk.isClient = false
	return mk, nil
}

// ClientPSKProof is the MAC the client sends after the server flight:
// HMAC(psk, label || transcript || server flight).
func clientPSKProof(psk, transcriptBytes, serverFlight []byte) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write(labelClientPSK)
	m.Write(transcriptBytes)
	m.Write(serverFlight)
	return m.Sum(nil)
}

// ClientAuthFlight returns pskMAC(32) || finished(32) sent by the client as
// its third flight.
func (s *Session) ClientAuthFlight(psk, serverFlight []byte) []byte {
	mac := clientPSKProof(psk, s.transcript, serverFlight)
	fin := s.FinishedValue("client")
	return append(mac, fin...)
}

// VerifyClientAuth checks the client's third flight.
func (s *Session) VerifyClientAuth(psk, serverFlight, auth []byte) error {
	if len(auth) != ClientAuthFlightSize {
		return ErrHandshake
	}
	exp := clientPSKProof(psk, s.transcript, serverFlight)
	if subtle.ConstantTimeCompare(auth[:32], exp) != 1 {
		return ErrHandshake
	}
	if subtle.ConstantTimeCompare(auth[32:], s.FinishedValue("client")) != 1 {
		return ErrHandshake
	}
	return nil
}

// FinishedValue is the role-separated Finished MAC.
func (s *Session) FinishedValue(role string) []byte {
	m := hmac.New(sha256.New, s.verify)
	m.Write(labelFinished)
	m.Write([]byte("/" + role))
	return m.Sum(nil)
}

// deriveSessionKeys derives direction-separated traffic keys, nonce bases and
// the handshake-verify key.
func deriveSessionKeys(transcriptBytes, salt []byte) (*Session, error) {
	ck, err := hkdfDerive(labelClientRecord, salt, transcriptBytes, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	sk, err := hkdfDerive(labelServerRecord, salt, transcriptBytes, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	nb, err := hkdfDerive(labelNonceBase, salt, transcriptBytes, 8)
	if err != nil {
		return nil, err
	}
	v, err := hkdfDerive(labelHandshakeVer, salt, transcriptBytes, 32)
	if err != nil {
		return nil, err
	}
	// Keys are role-relative at the call sites: caller flips send/recv on the
	// server side (Finish) so each side decrypts what the peer encrypts.
	s := &Session{
		transcript: transcriptBytes,
		sendKey:    ck,
		recvKey:    sk,
		nonceBase:  nb,
		verify:     v,
		streams:    map[uint32]*stream{},
		padBucket:  sessionPadBucket(),
	}
	return s, nil
}

// sessionPadBucket picks the record padding multiple for this session:
// 256B×{1..4} (~uniform) so the wire packet-size histogram isn't a constant
// fingerprint across reconnects. Receiver side is bucket-agnostic.
func sessionPadBucket() int {
	var b [1]byte
	_, _ = rand.Read(b[:])
	return PadBucketSize * (1 + int(b[0]&3)) // 256/512/768/1024 — see MaxSessionPadBucket
}

func genX25519() (priv, pub []byte, err error) {
	priv = make([]byte, curve25519.ScalarSize)
	if _, err = rand.Read(priv); err != nil {
		return nil, nil, err
	}
	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// isLowOrder rejects low-order X25519 outputs (all-zero shared secret).
func isLowOrder(shared []byte) bool {
	var acc byte
	for _, b := range shared {
		acc |= b
	}
	return acc == 0
}
