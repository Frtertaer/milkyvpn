// Package kal2 implements the KAL/2 inner session: a mutually authenticated,
// replay-resistant, multiplexed byte-stream protocol designed to run inside an
// outer protected carrier (real TLS, HTTP-shaped requests, a spliced relay
// hop). Wire version 2 adds stream multiplexing, exporter channel binding,
// and variable-length first-flight padding.
//
// No custom cryptographic primitives: X25519 ephemeral agreement, Ed25519
// server identity, HKDF-SHA256 key schedule, ChaCha20-Poly1305 records,
// HMAC-SHA256 pre-authentication.
package kal2

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// Version is the inner protocol version. Bumped for wire-incompatible changes.
const Version byte = 2

// Magic prefixes the client first flight. A PSK pre-authenticator prevents the
// server from emitting protocol bytes to unauthenticated probes; the magic
// remains a cross-protocol disambiguator, not a claim of undetectability.
var Magic = []byte("KLDO-in-")

// Maximum plaintext carried in one record.
const MaxPayload = 1 << 16 // 64 KiB

// Padding buckets: records pad to a multiple of PadBucketSize.
const PadBucketSize = 1 << 8 // 256

// MaxPadBucketsAbove bounds random upward padding steps.
const MaxPadBucketsAbove = 1

// MinPadBytes is the absolute minimum of random padding per record.
const MinPadBytes = 16

// Maximum random padding added to the client first flight so its size is not
// a fixed signature.
const FirstFlightMaxPad = 512

const ephemeralKeySize = 32
const preauthSize = 32
const signatureSize = 64

// MagicLen is the wire magic length.
const MagicLen = 8

// FirstFlightMinSize is the fixed prefix length:
// magic || version || ephemeral || preauth || padLen(2). Declared random
// padding follows it.
const FirstFlightMinSize = MagicLen + 1 + ephemeralKeySize + preauthSize + 2

// ServerFlightSize is ephemeral || Ed25519 signature.
const ServerFlightSize = ephemeralKeySize + signatureSize

// ClientAuthFlightSize is PSK MAC || client Finished.
const ClientAuthFlightSize = 32 + FinishedSize

// FinishedSize is the length of a Finished value.
const FinishedSize = 32

// Record types (stable on the wire; do not renumber).
const (
	MsgOpen      byte = 0x01 // OPEN: open a multiplexed stream (payload = target)
	MsgData      byte = 0x02 // DATA: ordered stream payload
	MsgClose     byte = 0x03 // CLOSE: half-close or close with generic reason
	MsgPing      byte = 0x04 // PING: liveness / path measurement
	MsgPong      byte = 0x05 // PONG
	MsgMigrate   byte = 0x06 // MIGRATE: reserved for a future capability
	MsgRst       byte = 0x07 // RST: reset a stream (error teardown)
	MsgOpenAck   byte = 0x08 // OPEN_ACK: server reports dial result (payload = code)
	MsgChallenge byte = 0x09 // CHALLENGE: reserved anti-replay extension
)

func validMsgType(t byte) bool {
	switch t {
	case MsgOpen, MsgData, MsgClose, MsgPing, MsgPong, MsgMigrate, MsgRst, MsgOpenAck, MsgChallenge:
		return true
	}
	return false
}

// MsgName renders a record type for logs.
func MsgName(t byte) string {
	switch t {
	case MsgOpen:
		return "OPEN"
	case MsgData:
		return "DATA"
	case MsgClose:
		return "CLOSE"
	case MsgPing:
		return "PING"
	case MsgPong:
		return "PONG"
	case MsgMigrate:
		return "MIGRATE"
	case MsgRst:
		return "RST"
	case MsgOpenAck:
		return "OPEN_ACK"
	case MsgChallenge:
		return "CHALLENGE"
	}
	return fmt.Sprintf("UNKNOWN(%#x)", t)
}

// Protocol errors.
type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrHandshake Error = "kal2: handshake failed"
	ErrMagic     Error = "kal2: magic mismatch"
	ErrVersion   Error = "kal2: unsupported version"
	ErrPreauth   Error = "kal2: client pre-authentication failed"
	ErrSignature Error = "kal2: server identity signature invalid"
	ErrReplay    Error = "kal2: replay or out-of-order record"
	ErrFraming   Error = "kal2: record framing error"
	ErrTag       Error = "kal2: record authentication failed"
	ErrClosed    Error = "kal2: session closed"
)

// ---------------------------------------------------------------------------
// Padding
// ---------------------------------------------------------------------------

// NextPaddingLength returns the number of padding bytes for payloadLen so the
// total (payload + 2-byte pad length + pad) lands on a bucket boundary, with a
// ~1/2 chance of one extra bucket.
func NextPaddingLength(payloadLen int) (int, error) {
	if payloadLen < 0 {
		return 0, ErrFraming
	}
	target := payloadLen + 2
	extra := (-target) % PadBucketSize
	if extra < MinPadBytes {
		extra += PadBucketSize
	}
	var roll [1]byte
	if _, err := rand.Read(roll[:]); err != nil {
		return 0, err
	}
	if roll[0] >= 128 {
		extra += PadBucketSize * MaxPadBucketsAbove
	}
	return extra, nil
}

// Pad appends uint16-le length-delimited random padding so
// len(plaintext)+padblock is bucket-aligned.
func Pad(plaintext []byte) ([]byte, error) {
	n, err := NextPaddingLength(len(plaintext))
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(plaintext)+2+n)
	out = append(out, plaintext...)
	padBytes := make([]byte, n)
	if _, err := rand.Read(padBytes); err != nil {
		return nil, err
	}
	out = append(out, padBytes...)
	var lb [2]byte
	binary.LittleEndian.PutUint16(lb[:], uint16(n))
	out = append(out, lb[:]...)
	return out, nil
}

// Unpad strips padding added by Pad.
func Unpad(padded []byte) ([]byte, error) {
	if len(padded) < 2 {
		return nil, ErrFraming
	}
	padLen := int(binary.LittleEndian.Uint16(padded[len(padded)-2:]))
	end := len(padded) - 2 - padLen
	if end < 0 {
		return nil, ErrFraming
	}
	return padded[:end], nil
}

// ---------------------------------------------------------------------------
// Record codec
// ---------------------------------------------------------------------------

// Record frame on the wire (AEAD ciphertext):
//   1 byte  type
//   8 bytes big-endian sequence
//   4 bytes big-endian stream id
//   4 bytes big-endian ciphertext length
//   N bytes AEAD ciphertext (plaintext || pad-block, 16-byte tag)
// The 17-byte header is the AEAD additional data.
const RecordHeaderSize = 17

const aeadTagSize = 16

// MaxRecordCiphertext bounds a single record's ciphertext.
const MaxRecordCiphertext = MaxPayload + 2 + PadBucketSize*(MaxPadBucketsAbove+2) + aeadTagSize

// Record is one decoded inbound record.
type Record struct {
	Type     byte
	Seq      uint64
	StreamID uint32
	Payload  []byte
}

func encodeHeader(t byte, seq uint64, stream uint32, ctLen int) []byte {
	h := make([]byte, RecordHeaderSize)
	h[0] = t
	binary.BigEndian.PutUint64(h[1:9], seq)
	binary.BigEndian.PutUint32(h[9:13], stream)
	binary.BigEndian.PutUint32(h[13:17], uint32(ctLen))
	return h
}

func decodeHeader(b []byte) (t byte, seq uint64, stream uint32, ctLen int, err error) {
	if len(b) < RecordHeaderSize {
		return 0, 0, 0, 0, ErrFraming
	}
	return b[0], binary.BigEndian.Uint64(b[1:9]), binary.BigEndian.Uint32(b[9:13]), int(binary.BigEndian.Uint32(b[13:17])), nil
}

// RecordCiphertextLength validates and returns the ciphertext length in a
// complete header.
func RecordCiphertextLength(header []byte) (int, error) {
	t, _, _, ctLen, err := decodeHeader(header)
	if err != nil {
		return 0, err
	}
	if !validMsgType(t) {
		return 0, ErrFraming
	}
	if ctLen < aeadTagSize+2 || ctLen > MaxRecordCiphertext {
		return 0, ErrFraming
	}
	return ctLen, nil
}
