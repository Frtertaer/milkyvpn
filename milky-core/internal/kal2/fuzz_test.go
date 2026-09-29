package kal2

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// FuzzParseClientFirstFlight feeds arbitrary bytes into the first-flight
// parser — this is the code path an attacker-controlled TLS handshake
// reaches before authentication. Must never panic.
func FuzzParseClientFirstFlight(f *testing.F) {
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)
	h, err := NewClientHandshake(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)), psk, nil)
	if err != nil {
		f.Fatal(err)
	}
	valid, err := h.FirstFlight(0)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add(valid[:4])
	f.Add(make([]byte, 4096))
	f.Add(append(valid, valid...))
	f.Fuzz(func(t *testing.T, flight []byte) {
		_, _, _ = ParseClientFirstFlight(flight, psk, nil)
	})
}

// FuzzDecodeHeader feeds arbitrary bytes into the record-header decoder —
// untrusted bytes off the wire.
func FuzzDecodeHeader(f *testing.F) {
	f.Add([]byte{0x01, 0x00})
	f.Add(make([]byte, 32))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _, _, _ = decodeHeader(b)
	})
}

// FuzzRecordCiphertextLength feeds header-shaped byte strings into the
// ciphertext-length decoder used to bound record reads.
func FuzzRecordCiphertextLength(f *testing.F) {
	f.Add([]byte{0x01})
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = RecordCiphertextLength(b)
	})
}
