package kal2core

import (
	"encoding/base64"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
)

func TestCarriersExpansion(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", []string{"veil", "drift", "cdn", "mosaic"}},
		{"auto", []string{"veil", "drift", "cdn", "mosaic"}},
		{"veil", []string{"veil"}},
		{"drift", []string{"drift"}},
		{"cdn", []string{"cdn"}},
		{"veil,drift", []string{"veil", "drift"}},
		{"drift,veil", []string{"drift", "veil"}},
	}
	for _, c := range cases {
		got := carriers(ClientConfig{Carrier: c.in})
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("carriers(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// A dead carrier must not block the dial: with Carrier=auto the surviving
// carrier's session wins even when the other fails fast or hangs.
func TestDialHedgedPicksWinner(t *testing.T) {
	defer dialOneFn.Store(dialFunc(dialOne))

	var mu sync.Mutex
	attempted := map[string]int{}
	dialOneFn.Store(dialFunc(func(ctx context.Context, cfg ClientConfig) (*kal2.Session, error) {
		mu.Lock()
		attempted[cfg.Carrier]++
		mu.Unlock()
		if cfg.Carrier == "veil" {
			// Slow AND doomed: veil must not gate the result.
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(2 * time.Second):
				return nil, errors.New("veil dead")
			}
		}
		return &kal2.Session{}, nil // drift wins quickly
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := dialHedged(ctx, ClientConfig{Carrier: "auto"}, nil)
	if err != nil {
		t.Fatalf("hedged dial: %v", err)
	}
	if s == nil {
		t.Fatal("nil session")
	}
	// The losing goroutine may not have entered dialOneFn by the time the
	// winner returns; wait for it (its dial is cancelled via sub-ctx).
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		veil, drift := attempted["veil"], attempted["drift"]
		mu.Unlock()
		if veil == 1 && drift == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("attempts = %v, want veil=1 drift=1", map[string]int{"veil": veil, "drift": drift})
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestDialHedgedAllFail(t *testing.T) {
	defer dialOneFn.Store(dialFunc(dialOne))
	dialOneFn.Store(dialFunc(func(ctx context.Context, cfg ClientConfig) (*kal2.Session, error) {
		return nil, errors.New("dead")
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s, err := dialHedged(ctx, ClientConfig{Carrier: "auto"}, nil)
	if err == nil || s != nil {
		t.Fatalf("want failure, got s=%v err=%v", s, err)
	}
}

// dropConn simulates a silent carrier blackout: while blackhole is set, Read
// never returns — packets vanish without RST, so the link stays open but dead.
type dropConn struct {
	net.Conn
	blackhole atomic.Bool
}

func (d *dropConn) Read(p []byte) (int, error) {
	for d.blackhole.Load() {
		time.Sleep(time.Millisecond)
	}
	return d.Conn.Read(p)
}

// pipeSessionsT builds a real client+server session pair over net.Pipe via
// the exported handshake API; the server side is wrapped in a dropConn the
// caller uses to blackhole the link.
func pipeSessionsT(t *testing.T, psk []byte) (client, server *kal2.Session, drop *dropConn) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sh, err := kal2.NewServerHandshake(priv)
	if err != nil {
		t.Fatalf("server hs: %v", err)
	}
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
		t.Fatalf("parse first flight: %v", err)
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
	d := &dropConn{Conn: c2}
	cs.Attach(c1)
	ss.Attach(d)
	t.Cleanup(func() {
		d.blackhole.Store(false)
		_ = cs.Close()
		_ = ss.Close()
	})
	return cs, ss, d
}

// A blackholed carrier (peer alive but never reading: net_loss / dns_flip on
// Android produce exactly this) used to leave WaitClosed silent forever, so
// EnableReconnect could wait indefinitely. The liveness watchdog must kill
// the dead session so the redialer swaps in a live one.
func TestLivenessRedialsBlackhole(t *testing.T) {
	defer dialOneFn.Store(dialFunc(dialOne))

	psk := []byte("test-psk")
	var calls atomic.Int32
	var first *kal2.Session
	var firstDrop *dropConn
	dialOneFn.Store(dialFunc(func(ctx context.Context, cfg ClientConfig) (*kal2.Session, error) {
		cs, _, d := pipeSessionsT(t, psk)
		if calls.Add(1) == 1 {
			first = cs
			firstDrop = d
		}
		return cs, nil
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cli, err := Dial(ctx, ClientConfig{Addr: "pipe:0", Carrier: "veil", PSK: psk})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	cli.EnableLiveness(50*time.Millisecond, 50*time.Millisecond, 2)
	cli.EnableReconnect()

	if err := cli.Ping(ctx); err != nil {
		t.Fatalf("initial ping: %v", err)
	}

	// Silent blackout: the server keeps the socket open but stops reading.
	firstDrop.blackhole.Store(true)

	deadline := time.Now().Add(5 * time.Second)
	for cli.Session() == nil || cli.Session() == first {
		if time.Now().After(deadline) {
			t.Fatalf("session not redialed after blackhole (dial calls=%d)", calls.Load())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("dial calls = %d, want 2", got)
	}
	// The recovered session must actually pass traffic probes again.
	if err := cli.Ping(ctx); err != nil {
		t.Fatalf("ping after redial: %v", err)
	}
}

// BUG-2026-10-01-02: a padded base64url ech= link param failed BOTH
// StdEncoding (rejects -_) and RawURLEncoding (rejects =) — Android
// startSession died with "bad ech param" before dialing. DecodeBase64 must
// accept std|url × padded|raw, all decoding to the same bytes.
func TestDecodeBase64AllVariants(t *testing.T) {
	raw := []byte("ech-config-list-bytes-1234")
	variants := []string{
		"ZWNoLWNvbmZpZy1saXN0LWJ5dGVzLTEyMzQ=",   // std padded
		"ZWNoLWNvbmZpZy1saXN0LWJ5dGVzLTEyMzQ",     // std raw
		base64.URLEncoding.EncodeToString(raw),     // url padded
		base64.RawURLEncoding.EncodeToString(raw),  // url raw
	}
	for _, v := range variants {
		got, err := DecodeBase64(v)
		if err != nil {
			t.Fatalf("DecodeBase64(%q): %v", v, err)
		}
		if !reflect.DeepEqual(got, raw) {
			t.Fatalf("DecodeBase64(%q) = %q", v, got)
		}
	}
	if _, err := DecodeBase64("!!!not-base64!!!"); err == nil {
		t.Fatal("invalid input must fail")
	}
}
