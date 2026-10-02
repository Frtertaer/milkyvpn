package kal2core

import (
	"encoding/base64"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/carrier"
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
		cs, _, _ := pipeSessionsT(t, []byte("test-psk"))
		return cs, nil // drift wins quickly
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, _, err := dialHedged(ctx, ClientConfig{Carrier: "auto"}, nil)
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
	s, _, err := dialHedged(ctx, ClientConfig{Carrier: "auto"}, nil)
	if err == nil || s != nil {
		t.Fatalf("want failure, got s=%v err=%v", s, err)
	}
}

// A carrier that completes the handshake but drops all payload (the TSPU
// throttling signature seen live: session up, POST_CONNECT_PROBE dead) must
// lose the dial race — otherwise it wins every retry and the tunnel carries
// no traffic forever.
func TestDialHedgedRejectsDataDeadWinner(t *testing.T) {
	defer dialOneFn.Store(dialFunc(dialOne))
	defer func() { dialVerifyTimeout = 8 * time.Second }()
	dialVerifyTimeout = 400 * time.Millisecond

	psk := []byte("test-psk")
	var driftSession *kal2.Session
	dialOneFn.Store(dialFunc(func(ctx context.Context, cfg ClientConfig) (*kal2.Session, error) {
		cs, _, drop := pipeSessionsT(t, psk)
		if cfg.Carrier == "veil" {
			// Handshake completes but the link never delivers payload.
			drop.blackhole.Store(true)
			return cs, nil
		}
		driftSession = cs
		return cs, nil
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, name, err := dialHedged(ctx, ClientConfig{Carrier: "veil,drift"}, nil)
	if err != nil {
		t.Fatalf("hedged dial: %v", err)
	}
	if s != driftSession || name != "drift" {
		t.Fatalf("the data-dead carrier won: session=%v name=%q", s != driftSession, name)
	}
}

// The same check must hold when a single carrier is configured: a session
// that handshakes but cannot carry data is a dial failure, not a success.
func TestDialSingleRejectsDataDeadSession(t *testing.T) {
	defer dialOneFn.Store(dialFunc(dialOne))
	defer func() { dialVerifyTimeout = 8 * time.Second }()
	dialVerifyTimeout = 400 * time.Millisecond

	dialOneFn.Store(dialFunc(func(ctx context.Context, cfg ClientConfig) (*kal2.Session, error) {
		cs, _, drop := pipeSessionsT(t, []byte("test-psk"))
		drop.blackhole.Store(true)
		return cs, nil
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s, _, err := dialHedged(ctx, ClientConfig{Carrier: "veil"}, nil)
	if err == nil || s != nil {
		t.Fatalf("want data-dead failure, got s=%v err=%v", s, err)
	}
	if !strings.Contains(err.Error(), "session dead") {
		t.Fatalf("want session-dead error, got %v", err)
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
	// stdHi produces + and / so the std variants can't be mistaken for
	// url-alphabet strings (the old literal was alphabet-agnostic and let
	// the missing RawStdEncoding case hide).
	stdHi := []byte{0xfb, 0xff, 0xbf, 0xef}
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
	for _, v := range []string{
		base64.StdEncoding.EncodeToString(stdHi),
		base64.RawStdEncoding.EncodeToString(stdHi),
	} {
		got, err := DecodeBase64(v)
		if err != nil {
			t.Fatalf("DecodeBase64(%q): %v", v, err)
		}
		if !reflect.DeepEqual(got, stdHi) {
			t.Fatalf("DecodeBase64(%q) = %v", v, got)
		}
	}
	if _, err := DecodeBase64("!!!not-base64!!!"); err == nil {
		t.Fatal("invalid input must fail")
	}
}

// Decoy pool client side: a comma SNI list must rotate across dial attempts
// (paired with endpoint rotation), so a blocked cover name doesn't kill
// every retry. Attempt i sweeps addrs[i] × snis[i].
func TestDialAnyRotatesSNIAcrossAttempts(t *testing.T) {
	defer dialOneFn.Store(dialFunc(dialOne))
	var mu sync.Mutex
	var got []struct{ addr, sni string }
	dialOneFn.Store(dialFunc(func(ctx context.Context, cfg ClientConfig) (*kal2.Session, error) {
		mu.Lock()
		got = append(got, struct{ addr, sni string }{cfg.Addr, cfg.SNI})
		n := len(got)
		mu.Unlock()
		if n < 2 {
			return nil, errors.New("dead")
		}
		cs, _, _ := pipeSessionsT(t, []byte("test-psk"))
		return cs, nil
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, _, err := dialAny(ctx, ClientConfig{
		Addrs:   []string{"a1:443", "a2:443"},
		SNI:     "s1.test, s2.test",
		Carrier: "veil",
	}, 0, nil)
	if err != nil {
		t.Fatalf("dialAny: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("attempts = %v", got)
	}
	if got[0].addr != "a1:443" || got[0].sni != "s1.test" {
		t.Fatalf("attempt0 = %+v", got[0])
	}
	if got[1].addr != "a2:443" || got[1].sni != "s2.test" {
		t.Fatalf("attempt1 = %+v, want a2+s2", got[1])
	}
}

// Entry-block canary: when every endpoint dies at transport stage (TCP
// refused, UDP dead, TLS killed mid-flight) dialAny must surface
// EntriesBlockedError — the signature the app maps to "entry blocked".
func TestDialAnyEntriesBlocked(t *testing.T) {
	defer dialOneFn.Store(dialFunc(dialOne))
	dialOneFn.Store(dialFunc(func(ctx context.Context, cfg ClientConfig) (*kal2.Session, error) {
		return nil, errors.New("tcp dial: connection refused")
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, _, err := dialAny(ctx, ClientConfig{
		Addrs:   []string{"10.255.255.1:443", "10.255.255.2:443"},
		SNI:     "a.example,b.example",
		Carrier: "veil",
	}, 0, nil)
	var eb *EntriesBlockedError
	if !errors.As(err, &eb) {
		t.Fatalf("want EntriesBlockedError, got %T %v", err, err)
	}
	if !IsEntriesBlocked(err) {
		t.Fatal("IsEntriesBlocked returned false")
	}
	if eb.Attempts != 4 { // 2 addrs x 2 snis
		t.Fatalf("attempts=%d want 4", eb.Attempts)
	}
}

// Positive control: an error from inside the KAL/2 handshake proves the
// server answered — that is auth/config trouble, not a blocked entry, so
// the canary must NOT fire.
func TestDialAnyInnerStageNotBlocked(t *testing.T) {
	defer dialOneFn.Store(dialFunc(dialOne))
	inner := errors.New("kal2: server auth rejected")
	dialOneFn.Store(dialFunc(func(ctx context.Context, cfg ClientConfig) (*kal2.Session, error) {
		return nil, carrier.MarkHandshakeStage(inner)
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, _, err := dialAny(ctx, ClientConfig{
		Addrs:   []string{"10.255.255.1:443"},
		SNI:     "a.example",
		Carrier: "veil",
	}, 0, nil)
	if IsEntriesBlocked(err) {
		t.Fatalf("inner-stage error misclassified as blocked: %v", err)
	}
	if !errors.Is(err, inner) {
		t.Fatalf("want inner error, got %v", err)
	}
}

// Hedged carriers: one lane reaching the inner stage wins the
// classification even when sibling lanes died at transport — the entry is
// alive, no canary.
func TestDialHedgedStageErrorBeatsTransport(t *testing.T) {
	defer dialOneFn.Store(dialFunc(dialOne))
	inner := errors.New("kal2: bad finished")
	dialOneFn.Store(dialFunc(func(ctx context.Context, cfg ClientConfig) (*kal2.Session, error) {
		if cfg.Carrier == "veil" {
			return nil, carrier.MarkHandshakeStage(inner)
		}
		return nil, errors.New("tcp dial: refused")
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := dialHedged(ctx, ClientConfig{Carrier: "veil,drift", SNI: "a.example"}, nil)
	if err == nil {
		t.Fatal("want error")
	}
	if !carrier.IsHandshakeStage(err) {
		t.Fatalf("want stage error, got %v", err)
	}
}

// Universal multi-front sweep: with several fronts the dial tries the
// direct entry first (all configured carriers), then each front in order
// hedged over the HTTP-shaped carriers only. A single front keeps the
// legacy front-only semantics.
func TestDialAnyUniversalFrontSweep(t *testing.T) {
	defer dialOneFn.Store(dialFunc(dialOne))
	var mu sync.Mutex
	var got []struct{ front, car string }
	dialOneFn.Store(dialFunc(func(ctx context.Context, cfg ClientConfig) (*kal2.Session, error) {
		mu.Lock()
		got = append(got, struct{ front, car string }{cfg.Front, cfg.Carrier})
		n := len(got)
		mu.Unlock()
		_ = n
		if cfg.Front == "https://f2.example" {
			cs, _, _ := pipeSessionsT(t, []byte("test-psk"))
			return cs, nil
		}
		return nil, errors.New("dead")
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, _, err := dialAny(ctx, ClientConfig{
		Addrs:  []string{"a1:443"},
		SNI:    "s1.test",
		Carrier: "auto",
		Fronts: []string{"https://f1.example", "https://f2.example"},
	}, 0, nil)
	if err != nil {
		t.Fatalf("dialAny: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	var fronts []string
	direct := 0
	for _, g := range got {
		if g.front == "" {
			direct++
		} else {
			fronts = append(fronts, g.front)
		}
	}
	if direct == 0 {
		t.Fatalf("no direct lanes: %+v", got)
	}
	// f1 lanes run before f2 wins; within a front only HTTP-shaped carriers.
	var f1, f2 int
	for i, g := range got {
		if g.front == "https://f1.example" && f1 == 0 {
			f1 = i
		}
		if g.front == "https://f2.example" && f2 == 0 {
			f2 = i
		}
		if g.front != "" && g.car != "drift" && g.car != "cdn" && g.car != "mosaic" {
			t.Fatalf("non-HTTP carrier %q on front lane", g.car)
		}
	}
	if f1 == 0 || f2 == 0 || f1 > f2 {
		t.Fatalf("front order broken: %+v", got)
	}
}

// Legacy single-front link: every attempt dials through the front (no
// direct context), preserving the front-only semantics existing links rely
// on.
func TestDialAnySingleFrontStaysFrontOnly(t *testing.T) {
	defer dialOneFn.Store(dialFunc(dialOne))
	var mu sync.Mutex
	var got []string
	dialOneFn.Store(dialFunc(func(ctx context.Context, cfg ClientConfig) (*kal2.Session, error) {
		mu.Lock()
		got = append(got, cfg.Front)
		mu.Unlock()
		return nil, errors.New("dead")
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, _, _ = dialAny(ctx, ClientConfig{
		Addrs:  []string{"a1:443", "a2:443"},
		SNI:    "s1.test",
		Carrier: "veil",
		Front:  "https://f1.example",
	}, 0, nil)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("attempts = %v", got)
	}
	for _, f := range got {
		if f != "https://f1.example" {
			t.Fatalf("attempt dialed without front: %v", got)
		}
	}
}

func TestCarrierMemRoundTripAndPrefer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cmem.json")
	carrierMemWrite(path, "wifi", "mosaic", "decoy.example")
	c, s, _ := carrierMemRead(path, "wifi")
	if c != "mosaic" || s != "decoy.example" {
		t.Fatalf("read = %q,%q", c, s)
	}
	if c, _, _ := carrierMemRead(path, "mobile"); c != "" {
		t.Fatalf("unknown netclass = %q", c)
	}
	cs := carriers(ClientConfig{PreferCarrier: "mosaic"})
	if cs[0] != "mosaic" {
		t.Fatalf("prefer not first: %v", cs)
	}
	// Explicit carrier lists are not reordered by memory.
	cs = carriers(ClientConfig{Carrier: "veil,drift", PreferCarrier: "drift"})
	if cs[0] != "veil" {
		t.Fatalf("explicit list reordered: %v", cs)
	}
}

func TestCarrierMemBlocklist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cmem.json")
	// Unblock on a fresh/never-blocked file must not panic (nil map write
	// crashed the :kal2 process on Android — every successful dial calls it).
	carrierMemUnblock(path, "wifi", "dead.example")
	carrierMemBlock(path, "wifi", "dead.example")
	carrierMemBlock(path, "wifi", "dead.example") // dedupe
	carrierMemBlock(path, "wifi", "gone.example")
	_, _, blocked := carrierMemRead(path, "wifi")
	if len(blocked) != 2 {
		t.Fatalf("blocked = %v", blocked)
	}
	if got := unblockedSNIs([]string{"dead.example", "live.example", "gone.example"}, blocked); len(got) != 1 || got[0] != "live.example" {
		t.Fatalf("filtered = %v", got)
	}
	// All blocked → empty so the caller falls back to the full pool.
	if got := unblockedSNIs([]string{"dead.example", "gone.example"}, blocked); len(got) != 0 {
		t.Fatalf("all-blocked should yield empty, got %v", got)
	}
	carrierMemUnblock(path, "wifi", "dead.example")
	_, _, blocked = carrierMemRead(path, "wifi")
	if len(blocked) != 1 || blocked[0] != "gone.example" {
		t.Fatalf("after unblock = %v", blocked)
	}
	// Blocklist must not clobber the carrier memory record.
	carrierMemWrite(path, "wifi", "quic2", "live.example")
	c, _, blocked := carrierMemRead(path, "wifi")
	if c != "quic2" || len(blocked) != 1 {
		t.Fatalf("mem+block lost: %q %v", c, blocked)
	}
}

func TestDialHedgedReportsWinner(t *testing.T) {
	defer dialOneFn.Store(dialFunc(dialOne))
	dialOneFn.Store(dialFunc(func(ctx context.Context, cfg ClientConfig) (*kal2.Session, error) {
		if cfg.Carrier == "veil" {
			return nil, errors.New("veil dead")
		}
		cs, _, _ := pipeSessionsT(t, []byte("test-psk"))
		return cs, nil
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, name, err := dialHedged(ctx, ClientConfig{Carrier: "veil,drift"}, nil)
	if err != nil {
		t.Fatalf("hedged: %v", err)
	}
	if name != "drift" {
		t.Fatalf("winner = %q, want drift", name)
	}
}
