package kal2core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
)

// pipePairKal builds a completed client/server kal2 session pair over
// net.Pipe — the kal2core-side counterpart of kal2's pipeSessions. The
// server's dispatch loop auto-pongs, so the client session pings healthy.
func pipePairKal(t *testing.T) (client, server *kal2.Session) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sh, err := kal2.NewServerHandshake(priv)
	if err != nil {
		t.Fatalf("server hs: %v", err)
	}
	psk := []byte("test-psk")
	ch, err := kal2.NewClientHandshake(pub, psk, nil)
	if err != nil {
		t.Fatalf("client hs: %v", err)
	}
	ff, err := ch.FirstFlight(0)
	if err != nil {
		t.Fatalf("first flight: %v", err)
	}
	eph, _, err := kal2.ParseClientFirstFlight(ff, psk, nil)
	if err != nil {
		t.Fatalf("parse flight: %v", err)
	}
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
	t.Cleanup(func() { cs.Close(); ss.Close() })
	return cs, ss
}

// blackholeSession returns a client session over a pipe whose far end reads
// and discards: writes succeed but nothing is ever answered — the silently
// dead lane the watchdog must kill and redial.
func blackholeSession(t *testing.T) *kal2.Session {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sh, err := kal2.NewServerHandshake(priv)
	if err != nil {
		t.Fatalf("server hs: %v", err)
	}
	psk := []byte("test-psk")
	ch, err := kal2.NewClientHandshake(pub, psk, nil)
	if err != nil {
		t.Fatalf("client hs: %v", err)
	}
	ff, err := ch.FirstFlight(0)
	if err != nil {
		t.Fatalf("first flight: %v", err)
	}
	eph, _, err := kal2.ParseClientFirstFlight(ff, psk, nil)
	if err != nil {
		t.Fatalf("parse flight: %v", err)
	}
	srvFlight, err := sh.Start(eph, nil)
	if err != nil {
		t.Fatalf("server flight: %v", err)
	}
	cs, err := ch.ServerFlight(srvFlight)
	if err != nil {
		t.Fatalf("client session: %v", err)
	}
	if _, err := sh.Finish(); err != nil {
		t.Fatalf("server session: %v", err)
	}
	c1, c2 := net.Pipe()
	cs.Attach(c1)
	go io.Copy(io.Discard, c2) // drain and never answer
	t.Cleanup(func() { cs.Close(); c2.Close() })
	return cs
}

// slowRW delays every Write — a throttled-but-alive lane: pongs arrive, just
// far slower than quarantine allows.
type slowRW struct {
	net.Conn
	delay time.Duration
}

func (s slowRW) Write(p []byte) (int, error) {
	time.Sleep(s.delay)
	return s.Conn.Write(p)
}

func slowSession(t *testing.T, delay time.Duration) *kal2.Session {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sh, err := kal2.NewServerHandshake(priv)
	if err != nil {
		t.Fatalf("server hs: %v", err)
	}
	psk := []byte("test-psk")
	ch, err := kal2.NewClientHandshake(pub, psk, nil)
	if err != nil {
		t.Fatalf("client hs: %v", err)
	}
	ff, err := ch.FirstFlight(0)
	if err != nil {
		t.Fatalf("first flight: %v", err)
	}
	eph, _, err := kal2.ParseClientFirstFlight(ff, psk, nil)
	if err != nil {
		t.Fatalf("parse flight: %v", err)
	}
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
	cs.Attach(slowRW{c1, delay})
	ss.Attach(c2)
	t.Cleanup(func() { cs.Close(); ss.Close() })
	return cs
}

// Kill-vs-quarantine contract, part 1: a lane whose server stopped answering
// (pongs never arrive) must be killed by two real ping failures and replaced
// by a redialed session — it never quarantines, it dies.
func TestLaneDeadKilledAndRedialed(t *testing.T) {
	// Compress the watchdog timeline. The values are left in place for the
	// rest of this package's test run: restoring them while a reconnectLane
	// ping goroutine may still be starting is itself a race, and no other
	// test in the package exercises the lane watchdog.
	lanePingEvery.Store(int64(30 * time.Millisecond))
	lanePingTimeout.Store(int64(150 * time.Millisecond))
	lanePingRetryTimeout.Store(int64(100 * time.Millisecond))
	defer dialOneFn.Store(dialFunc(dialOne))
	redialed := make(chan *kal2.Session, 1)
	dialOneFn.Store(dialFunc(func(ctx context.Context, cfg ClientConfig) (*kal2.Session, error) {
		cs, _ := pipePairKal(t) // healthy session on redial
		select {
		case redialed <- cs:
		default:
		}
		return cs, nil
	}))

	c := &Client{cfg: ClientConfig{}, logf: func(string, ...any) {}, stop: make(chan struct{})}
	c.lanes = make([]atomic.Pointer[kal2.Session], 1)
	c.laneRTT = make([]atomic.Int64, 1)
	dead := blackholeSession(t)
	c.lanes[0].Store(dead)
	go c.reconnectLane(0)
	defer func() { close(c.stop); time.Sleep(100 * time.Millisecond) }() // let the watchdog goroutine exit before var restore

	select {
	case s := <-redialed:
		if s == dead {
			t.Fatal("redial returned the dead session")
		}
		if err := s.Ping([]byte("x"), time.Second); err != nil {
			t.Fatalf("redialed lane not live: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("dead lane was never killed and redialed")
	}
}

// Kill-vs-quarantine contract, part 2: a strangled lane (pongs arrive, but
// slower than laneQuarantineRTT) must NOT be killed — it stays attached —
// but Session() must stop routing new streams to it while a healthy lane
// exists. When it recovers (pongs fast again) it rejoins the pool.
func TestLaneStrangledQuarantinedNotKilled(t *testing.T) {
	lanePingEvery.Store(int64(30 * time.Millisecond))
	lanePingTimeout.Store(int64(2 * time.Second))
	lanePingRetryTimeout.Store(int64(time.Second))
	laneQuarantineRTT.Store(int64(150 * time.Millisecond))
	defer laneQuarantineRTT.Store(int64(3 * time.Second))

	c := &Client{cfg: ClientConfig{}, logf: func(string, ...any) {}, stop: make(chan struct{})}
	c.lanes = make([]atomic.Pointer[kal2.Session], 2)
	c.laneRTT = make([]atomic.Int64, 2)
	healthy, _ := pipePairKal(t)
	strangled := slowSession(t, 200*time.Millisecond) // RTT ≈ 400ms > 150ms
	c.lanes[0].Store(healthy)
	c.lanes[1].Store(strangled)
	go c.reconnectLane(0)
	go c.reconnectLane(1)
	defer func() { close(c.stop); time.Sleep(100 * time.Millisecond) }() // let the watchdog goroutine exit before var restore

	// Wait for the watchdog to measure the strangled lane's slow pong.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && c.laneRTT[1].Load() == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if c.laneRTT[1].Load() == 0 {
		t.Fatal("watchdog never pinged the strangled lane")
	}

	// Strangled lane is NOT killed — it answers pings.
	if c.lanes[1].Load() != strangled {
		t.Fatal("strangled lane was killed instead of quarantined")
	}
	// …but it must not attract streams while a healthy lane exists —
	// the old least-SentBytes picker would pick it (it emitted ~nothing).
	if got := c.Session(); got != healthy {
		t.Fatal("Session() picked the quarantined strangled lane")
	}
}

// Session() must still serve when every live lane is quarantined — the
// least-loaded throttled lane beats failing all streams.
func TestLaneAllQuarantinedFallback(t *testing.T) {
	c := &Client{cfg: ClientConfig{}, logf: func(string, ...any) {}, stop: make(chan struct{})}
	c.lanes = make([]atomic.Pointer[kal2.Session], 2)
	c.laneRTT = make([]atomic.Int64, 2)
	s1, _ := pipePairKal(t)
	s2, _ := pipePairKal(t)
	c.lanes[0].Store(s1)
	c.lanes[1].Store(s2)
	c.laneRTT[0].Store(int64(10 * time.Second))
	c.laneRTT[1].Store(int64(10 * time.Second))
	if got := c.Session(); got != s1 && got != s2 {
		t.Fatal("all quarantined: Session() must still return a lane")
	}
}
