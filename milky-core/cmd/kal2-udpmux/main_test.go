package main

import (
	"encoding/binary"
	"testing"
)

func TestClassify(t *testing.T) {
	quic := func(ver uint32) []byte {
		p := make([]byte, 40)
		p[0] = 0xC3 // long header, fixed bit
		binary.BigEndian.PutUint32(p[1:5], ver)
		return p
	}
	if got := classify(quic(0x6b3343cf)); got != "quic2" {
		t.Fatalf("v2 → %s", got)
	}
	for _, v := range []uint32{1, 0x00000000, 0x709a50c4 /* draft-29 */, 0x51303433} {
		if got := classify(quic(v)); got != "hy2" {
			t.Fatalf("v %#x → %s", v, got)
		}
	}
	// Opaque datagrams (quasar AEAD) and short headers → quasar.
	if got := classify([]byte{0x41, 1, 2, 3, 4, 5}); got != "quasar" {
		t.Fatalf("opaque → %s", got)
	}
	if got := classify(nil); got != "quasar" {
		t.Fatalf("empty → %s", got)
	}
}
