package carrier

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Frtertaer/milkyvpn/milky-core/internal/kal2"
)

func newTestServerResumer(t *testing.T) *testServer {
	ts := newTestServer(t)
	ts.v.cfg.Resumer = kal2.NewSessionRegistry(kal2.NewTicketCodec(), 0)
	return ts
}

func waitTicket(t *testing.T, s *kal2.Session) *kal2.ResumeState {
	t.Helper()
	for i := 0; i < 200; i++ {
		if rs, ok := s.TicketState(); ok {
			return rs
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatal("no TICKET arrived within 3s")
	return nil
}

// v2.1 migration: transport dies → session freezes → KLDO-rs- resume on a
// fresh conn re-attaches the SAME session — streams and in-flight data live.
func TestResumeMigration(t *testing.T) {
	ts := newTestServerResumer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cfg := ClientConfig{
		Addr:               ts.ln.Addr().String(),
		SNI:                "kal.test",
		ServerPub:          ts.pub,
		PSK:                ts.psk,
		InsecureSkipVerify: true,
	}
	sess, bc, err := DialVeil(ctx, cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sess.Close()
	rs := waitTicket(t, sess)

	host, port := startEcho(t)
	st, err := sess.Open(host, port, 5*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := st.Write([]byte("pre-migrate")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("pre-migrate"))
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("pre-migrate echo: %v", err)
	}

	// Transport dies — the session must freeze, not die.
	_ = bc.Close()
	select {
	case <-sess.NeedsMigrate():
	case <-time.After(3 * time.Second):
		t.Fatal("session did not freeze on transport loss")
	}
	if !sess.Frozen() {
		t.Fatal("session not frozen")
	}

	// Write while frozen: the record is queued behind the replay and lands
	// once a resumed transport attaches.
	if _, err := st.Write([]byte("post-freeze")); err != nil {
		t.Fatalf("write on a frozen session: %v", err)
	}

	cfg.Resume = rs
	sess2, _, err := DialVeil(ctx, cfg)
	if err != nil {
		t.Fatalf("resume dial: %v", err)
	}
	if sess2 != sess {
		t.Fatal("resume returned a different session")
	}
	if sess.Frozen() {
		t.Fatal("session still frozen after attach")
	}
	buf = make([]byte, len("post-freeze"))
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("post-migrate echo: %v", err)
	}
	if string(buf) != "post-freeze" {
		t.Fatalf("echo mismatch %q", buf)
	}

	// A second freeze + migration cycle is covered by TestResumeTwice.
}

// A second consecutive migration proves the ticket refresh cycle works:
// after each resume the server re-issues a ticket for the next loss.
func TestResumeTwice(t *testing.T) {
	ts := newTestServerResumer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cfg := ClientConfig{
		Addr:               ts.ln.Addr().String(),
		SNI:                "kal.test",
		ServerPub:          ts.pub,
		PSK:                ts.psk,
		InsecureSkipVerify: true,
	}
	sess, bc1, err := DialVeil(ctx, cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sess.Close()
	waitTicket(t, sess)

	for i := 0; i < 2; i++ {
		// Wait for a live ticket before killing the transport: post-resume
		// the consumed ticket is cleared and only the server's Refresh
		// TICKET makes the session resumable again.
		rs := waitTicket(t, sess)
		_ = bc1.Close()
		select {
		case <-sess.NeedsMigrate():
		case <-time.After(3 * time.Second):
			t.Fatalf("cycle %d: no freeze", i)
		}
		cfg.Resume = rs
		var bc2 BoundConn
		if _, bc2, err = DialVeil(ctx, cfg); err != nil {
			t.Fatalf("cycle %d resume: %v", i, err)
		}
		bc1 = bc2
	}
	streamEchoTest(t, sess)
}

// Session stays usable when a ticket-carrying session's transport dies and
// the resume flight gets a cover response (unknown session → decoy reply).
func TestResumeUnknownSessionFailsClean(t *testing.T) {
	ts := newTestServerResumer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sess, _, err := DialVeil(ctx, ClientConfig{
		Addr:               ts.ln.Addr().String(),
		SNI:                "kal.test",
		ServerPub:          ts.pub,
		PSK:                ts.psk,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sess.Close()
	rs := waitTicket(t, sess)

	// Forged session ID — registry lookup must fail cleanly (cover response,
	// not a crash or a session).
	fakeState := *rs
	fake := &fakeState
	fake.SessionID[0] ^= 0xff
	cfg := ClientConfig{
		Addr:               ts.ln.Addr().String(),
		SNI:                "kal.test",
		ServerPub:          ts.pub,
		PSK:                ts.psk,
		InsecureSkipVerify: true,
		Resume:             fake,
	}
	if _, _, err := DialVeil(ctx, cfg); err == nil {
		t.Fatal("resume with unknown session id must fail")
	}
	// A resumption attempt gives up the old transport before its checkpoint
	// goes out (the server is told "replay from here", so nothing may be
	// received after that). A failed attempt therefore leaves the session
	// frozen — and resumable: a retry with a valid ticket brings it back
	// with its streams.
	if !sess.Frozen() {
		t.Fatal("a failed resumption attempt must leave the session frozen, not half-moved")
	}
	good, ok := sess.TicketState()
	if !ok {
		t.Fatal("no ticket left for the retry")
	}
	cfg.Resume = good
	if _, _, err := DialVeil(ctx, cfg); err != nil {
		t.Fatalf("retry with a valid ticket: %v", err)
	}
	streamEchoTest(t, sess)
}

// Drift-carrier resumption: KLDO-rs- inside the HTTP-shaped transport.
// Uses the WebSocket flavour: after Hijack the conn is plain TCP, so the
// byte stream stays race-clean under -race (the h2 driftServerConn Write
// can outlive the net/http handler's ResponseWriter — a pre-existing
// design limitation the panic-recover in Write covers functionally).
func TestResumeDrift(t *testing.T) {
	ts := newTestServerResumer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cfg := ClientConfig{
		Addr:               ts.ln.Addr().String(),
		SNI:                "kal.test",
		ServerPub:          ts.pub,
		PSK:                ts.psk,
		InsecureSkipVerify: true,
	}
	sess, bc, err := DialDriftWS(ctx, cfg, "")
	if err != nil {
		t.Fatalf("dial drift: %v", err)
	}
	defer sess.Close()
	rs := waitTicket(t, sess)
	_ = bc.Close()
	select {
	case <-sess.NeedsMigrate():
	case <-time.After(3 * time.Second):
		t.Fatal("drift session did not freeze")
	}
	cfg.Resume = rs
	sess2, _, err := DialDriftWS(ctx, cfg, "")
	if err != nil {
		t.Fatalf("drift resume: %v", err)
	}
	if sess2 != sess {
		t.Fatal("drift resume returned a different session")
	}
	streamEchoTest(t, sess)
}

var _ = fmt.Sprint
var _ = ed25519.PublicKey(nil)
var _ = rand.Read
var _ = net.TCPAddr{}
var _ = http.StatusOK
