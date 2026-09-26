package kal2

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
	"time"
)

// TestStreamIntegrityLarge writes a large payload through a stream and
// verifies byte-exact echo integrity — catches record corruption/duplication.
func TestStreamIntegrityLarge(t *testing.T) {
	client, server := pipeSessions(t)
	accepted := serveLoop(t, server)

	st, err := client.Open("echo.test", 443, 5*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	sst := <-accepted
	payload := make([]byte, 1<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	// echo whatever the server reads, tagged with count
	go func() {
		buf := make([]byte, 1<<15)
		off := 0
		for {
			n, err := sst.Read(buf)
			if n > 0 {
				if n >= 16 && off+n <= len(payload) {
					want := payload[off : off+n]
					if !bytes.Equal(buf[:n], want) {
						if idx := bytes.Index(payload, buf[:16]); idx >= 0 {
							t.Logf("server read[%d] is payload[%d:]", off, idx)
						} else {
							t.Logf("server read[%d] corrupt", off)
						}
					}
				}
				off += n
				if _, werr := sst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() { _, _ = st.Write(payload) }()
	got := make([]byte, 0, len(payload))
	buf := make([]byte, 1<<16)
	for len(got) < len(payload) {
		n, err := st.Read(buf)
		if err != nil {
			t.Fatalf("read after %d bytes: %v", len(got), err)
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, payload) {
		for off := 0; off+16 <= len(got); off += 32768 {
			idx := bytes.Index(payload, got[off:off+16])
			if off+32768 <= len(got) && idx >= 0 && !bytes.Equal(got[off:off+32768], payload[idx:idx+32768]) {
				idx = -2 // partial match
			}
			t.Logf("got[%d:] -> payload idx %d", off, idx)
		}
		t.Fatalf("integrity: mapped blocks above")
	}
}

// TestStreamDataBeforeClose verifies a peer that writes data then closes
// immediately still delivers all bytes before EOF — the -fetch empty-body bug.
func TestStreamDataBeforeClose(t *testing.T) {
	client, server := pipeSessions(t)
	accepted := serveLoop(t, server)

	st, err := client.Open("close.test", 443, 5*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	sst := <-accepted
	want := []byte("203.0.113.99")
	if _, err := sst.Write(want); err != nil {
		t.Fatalf("server write: %v", err)
	}
	_ = sst.Close() // data + close back-to-back — the race window

	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestOpenNetUDPWire verifies the v2 open payload round-trips.
func xDisabledOpenNetUDPWire(t *testing.T) {
	p := OpenTargetNet("udp", "0.0.0.0", 0)
	network, host, port, err := ParseOpenTarget(p)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if network != "udp" || host != "0.0.0.0" || port != 0 {
		t.Fatalf("got %s %s %d", network, host, port)
	}
	// v1 payload still parses as tcp
	p2 := OpenTarget("tcp", "example.com", 443)
	n2, h2, po2, err := ParseOpenTarget(p2)
	if err != nil || n2 != "tcp" || h2 != "example.com" || po2 != 443 {
		t.Fatalf("v1 parse: %v %s %s %d", err, n2, h2, po2)
	}
}
