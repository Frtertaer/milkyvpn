//go:build linux || darwin

package tun

import (
	"bytes"
	"os"
	"testing"
	"time"
)

// BUG-2026-09-29-11: the 4-byte AF prefix an fd write prepends on utun is
// read by the kernel input path with ntohl — it must be big-endian on the
// wire. A little-endian prefix made write(2) succeed while the kernel
// silently discarded every injected packet: UDP/TCP flowed into the netstack
// but nothing it emitted ever reached the host, seen live as SYN-ACKs on
// the tap with the host stuck in SYN_SENT.
func TestWritePacketAFPrefixBigEndian(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
		want [4]byte
	}{
		{"v4", []byte{0x45, 0x00, 0x00, 0x14}, [4]byte{0, 0, 0, 2}},
		{"v6", []byte{0x60, 0x00, 0x00, 0x00}, [4]byte{0, 0, 0, 30}},
	}
	for _, tc := range cases {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("%s: pipe: %v", tc.name, err)
		}
		d := NewFdDevice(w.Fd(), 256, 4)
		if err := d.WritePacket(tc.pkt); err != nil {
			t.Fatalf("%s: WritePacket: %v", tc.name, err)
		}
		w.Close()
		got := make([]byte, 4+len(tc.pkt))
		done := make(chan struct{})
		go func() {
			_, _ = readFull(r, got)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: read timed out", tc.name)
		}
		r.Close()
		if !bytes.Equal(got[:4], tc.want[:]) {
			t.Fatalf("%s: prefix %x, want %x", tc.name, got[:4], tc.want)
		}
		if !bytes.Equal(got[4:], tc.pkt) {
			t.Fatalf("%s: payload %x, want %x", tc.name, got[4:], tc.pkt)
		}
	}
}

func readFull(f *os.File, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := f.Read(b[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}
