package kal2

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

// pipeSessions builds a completed client/server session pair over net.Pipe.
func pipeSessions(t *testing.T) (client, server *Session) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sh, err := NewServerHandshake(priv)
	if err != nil {
		t.Fatalf("server hs: %v", err)
	}
	ch, err := NewClientHandshake(pub, []byte("test-psk"), nil)
	if err != nil {
		t.Fatalf("client hs: %v", err)
	}
	ff, err := ch.FirstFlight(0)
	if err != nil {
		t.Fatalf("first flight: %v", err)
	}
	eph := ff[len(Magic)+1 : len(Magic)+1+ephemeralKeySize]
	srvFlight, err := sh.Start(eph, nil)
	if err != nil {
		t.Fatalf("server flight: %v", err)
	}
	cs, err := ch.ServerFlight(srvFlight)
	if err != nil {
		t.Fatalf("client session: %v", err)
	}
	ss, err := sh.Finish()
	if err != nil {
		t.Fatalf("server session: %v", err)
	}
	c1, c2 := net.Pipe()
	cs.Attach(c1)
	ss.Attach(c2)
	t.Cleanup(func() {
		_ = cs.Close()
		_ = ss.Close()
	})
	return cs, ss
}

// serveLoop accepts streams and acks each; it returns a channel of accepted
// streams so the test can drive them.
func serveLoop(t *testing.T, s *Session) chan *Stream {
	t.Helper()
	accepted := make(chan *Stream, 16)
	go func() {
		for {
			st, err := s.Accept()
			if err != nil {
				return
			}
			if err := st.Ack(0x00); err != nil {
				return
			}
			accepted <- st
		}
	}()
	return accepted
}

// TestMuxOpenNotStarvedByBulk reproduces the field failure where a flooding
// DATA stream starved session control: a stream the consumer never reads
// must not stall the demux, and OPEN_ACK must not queue behind bulk DATA.
func TestMuxOpenNotStarvedByBulk(t *testing.T) {
	client, server := pipeSessions(t)
	accepted := serveLoop(t, server)

	stA, err := client.Open("a.example", 443, 3*time.Second)
	if err != nil {
		t.Fatalf("open A: %v", err)
	}
	srvA := <-accepted

	// Server floods stream A; the client never reads it. 6 MiB far exceeds
	// the per-stream queues, so a blocking demux would wedge the session.
	go func() {
		chunk := make([]byte, 16*1024)
		for i := 0; i < 6*1024*1024/len(chunk); i++ {
			if _, err := srvA.Write(chunk); err != nil {
				return
			}
		}
	}()

	// Under the old blocking-feed demux this deadlocked: the flooded stream's
	// recv queue filled, readLoop stalled, and OPEN_ACK/PONG never dispatched.
	deadline := time.Now().Add(10 * time.Second)
	for i, name := range []string{"b.example", "c.example", "d.example"} {
		rem := time.Until(deadline)
		st, err := client.Open(name, 443, rem)
		if err != nil {
			t.Fatalf("open %d starved: %v", i, err)
		}
		srvSt := <-accepted
		_ = srvSt
		_ = st.Close()
	}

	// PING must still get a timely PONG while the flood is in flight.
	if err := client.Ping([]byte("liveness"), 3*time.Second); err != nil {
		t.Fatalf("ping starved: %v", err)
	}
	_ = stA.Close()
}

// TestMuxReadAfterFlood verifies DATA keeps flowing to streams that DO read
// while a sibling stream's queue is backed up.
func TestMuxReadAfterFlood(t *testing.T) {
	client, server := pipeSessions(t)
	accepted := serveLoop(t, server)

	stA, err := client.Open("stuck.example", 443, 3*time.Second)
	if err != nil {
		t.Fatalf("open A: %v", err)
	}
	srvA := <-accepted
	// stA is never read: its receive queue backs up on purpose.

	stB, err := client.Open("reader.example", 443, 3*time.Second)
	if err != nil {
		t.Fatalf("open B: %v", err)
	}
	srvB := <-accepted

	// Flood the unread stream in the background.
	go func() {
		chunk := make([]byte, 16*1024)
		for i := 0; i < 6*1024*1024/len(chunk); i++ {
			if _, err := srvA.Write(chunk); err != nil {
				return
			}
		}
	}()

	// Stream B must still deliver its payload end-to-end.
	want := []byte("payload through a busy session")
	go func() {
		_, _ = srvB.Write(want)
	}()
	buf := make([]byte, len(want))
	got := 0
	deadline := time.Now().Add(5 * time.Second)
	for got < len(want) {
		if time.Now().After(deadline) {
			t.Fatalf("read on B starved: got %d/%d", got, len(want))
		}
		n, err := stB.Read(buf[got:])
		if err != nil {
			t.Fatalf("read B: %v", err)
		}
		got += n
	}
	if string(buf) != string(want) {
		t.Fatalf("payload mismatch: %q", buf)
	}
	_ = stB.Close()
	_ = stA.Close()
}
